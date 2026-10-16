"""Binary payload discovery and file operations.

Atomic-red-team tests frequently reference compiled binaries (``bin/`` dirs)
or downloadable tools (``ExternalPayloads/``). Payloads show up either as an
``#{arg}`` whose default value is a ``PathToAtomicsFolder\\...`` path, or as a
hardcoded literal path inside a command string. This module finds those
references, tells whether each file exists locally, and copies/renames them for
use by the deformation strategies and the offline release bundle.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .source import ATOMICS_PATH

# Executable-ish extensions we treat as payloads (covering bin/ + downloads).
_PAYLOAD_EXTS = (
    ".exe", ".dll", ".ps1", ".bat", ".cmd", ".scr", ".msi", ".zip", ".7z",
    ".tar", ".gz", ".js", ".vbs", ".bin",
)

# The three accepted spellings of the atomics-folder token (mirror runner.py).
_PATH_TOKENS = ("{PathToAtomicsFolder}", "$PathToAtomicsFolder", "PathToAtomicsFolder")

# download_url hints found in get_prereq_command (Invoke-WebRequest).
_URI_RE = re.compile(r"""-Uri\s+['"]([^'"]+)['"]""", re.IGNORECASE)
_OUTFILE_RE = re.compile(r"""-OutFile\s+['"]([^'"]+)['"]""", re.IGNORECASE)

# A path token at the start of a filesystem-ish reference.
_TOKEN_PATH_RE = re.compile(
    r"(?:\\{PathToAtomicsFolder}\\|\\?\$PathToAtomicsFolder\\|PathToAtomicsFolder\\)"
)

# ART writes downloads to the sibling of the atomics folder
# (PathToAtomicsFolder\..\ExternalPayloads). The offline bundle keeps those
# files inside atomics\ExternalPayloads, so the ".." must not survive.
_EXT_ESCAPE_RE = re.compile(
    r"((?:\{PathToAtomicsFolder\}|\$PathToAtomicsFolder|PathToAtomicsFolder))"
    r"\\(?:\.\.\\)+ExternalPayloads",
    re.IGNORECASE,
)


@dataclass
class PayloadRef:
    """One reference to a binary payload in an atomic test.

    ``path`` is the resolved absolute source path. ``token`` is the raw
    reference string as it appeared. Exactly one of ``arg_key`` (came from an
    ``#{arg}`` default) or ``literal`` (hardcoded in a command) is set.
    ``source`` classifies where it lives: ``bin``, ``ExternalPayloads`` or
    ``missing`` (couldn't resolve). ``download_url`` is optionally extracted
    from a matching dependency's get_prereq_command.
    """

    path: Path
    token: str
    technique_id: str
    arg_key: Optional[str] = None
    literal: Optional[str] = None
    source: str = "bin"  # bin | ExternalPayloads | missing
    download_url: Optional[str] = None

    @property
    def exists(self) -> bool:
        return self.path.is_file()

    @property
    def display(self) -> str:
        where = f"#{self.arg_key}" if self.arg_key else (
            f'literal "{self.literal}"' if self.literal else self.token
        )
        return f"{self.path.name} ({where})"


def _extract_download_url(text: str | None) -> Optional[str]:
    """Best-effort pull of a download URL from a get_prereq_command string."""
    if not text:
        return None
    m = _URI_RE.search(text)
    if m:
        return m.group(1)
    return None


def _resolve_path_token(token: str, path_to_atomics: Path) -> Path:
    """Turn a raw path token (any spelling) into an absolute Path.

    The extracted token may have junk grafted onto the file name from the
    surrounding command text (a trailing quote, a URL, ``-Destination ...``
    tail, ``C:\\Windows\\...`` copy target, etc.). We keep only the leading
    segment that actually names a candidate file on disk, so the resolved
    path points cleanly at a real payload instead of a mangled name.
    """
    for t in _PATH_TOKENS:
        token = token.replace(t, str(path_to_atomics))
    norm = token.replace("/", "\\")

    # The grafted command text almost always begins at a quote (a ``"``
    # separating the payload path from a URL/copy-target arg). Cut there
    # first so the URL's backslashes don't masquerade as path separators.
    cut = re.split(r'["\']', norm, maxsplit=1)[0]
    candidates = [cut, norm]

    probe = Path(norm)
    if probe.is_file():
        return _prefer_bundled_external(probe, path_to_atomics)

    for cand in candidates:
        if cand != norm:
            p = Path(cand.rstrip())
            if p.is_file():
                return _prefer_bundled_external(p, path_to_atomics)

    # Finally, shorten the tail one path component (or quote/space-run) at a
    # time until a real file is found.
    probe = Path(cut)
    if probe.is_file():
        return _prefer_bundled_external(probe, path_to_atomics)
    tail_parts = re.split(r"[\\/\s]+", cut)
    acc = tail_parts[0]
    for chunk in tail_parts[1:]:
        candidate = Path(acc + "\\" + chunk)
        acc += "\\" + chunk
        if candidate.is_file():
            return _prefer_bundled_external(candidate, path_to_atomics)
    return _prefer_bundled_external(Path(norm), path_to_atomics)


def _prefer_bundled_external(resolved: Path, path_to_atomics: Path) -> Path:
    """Prefer ``atomics/ExternalPayloads`` over the ART sibling folder.

    Offline bundles store those files inside the atomics directory. Discovery
    should see that copy so local-first execution does not recreate
    ``C:\\atomics\\ExternalPayloads``.
    """
    try:
        atomics = Path(path_to_atomics).resolve()
        sibling = atomics.parent / "ExternalPayloads"
        rel = resolved.resolve().relative_to(sibling)
    except (OSError, ValueError):
        return resolved
    inside = atomics / "ExternalPayloads" / rel
    if inside.is_file():
        return inside
    return resolved


def anchor_external_payloads(text: str | None) -> str:
    """Rewrite ``PathToAtomicsFolder\\..\\ExternalPayloads`` to stay inside atomics."""
    if not text or "ExternalPayloads" not in text:
        return text or ""
    return _EXT_ESCAPE_RE.sub(r"\1\\ExternalPayloads", text)


def _arg_default_text(argdef) -> str | None:
    if isinstance(argdef, dict):
        default = argdef.get("default")
    else:
        default = getattr(argdef, "default", None)
    if default is None:
        return None
    return str(default)


def _substitute_arg_tokens(raw: str, input_arguments: "dict | None") -> str:
    """Expand ``#{arg}`` references in a raw path using its argument defaults.

    Some payload paths embed a parameter token (e.g. ``#{arch}`` in
    ``T1055.011_#{arch}.exe``). Resolving the raw token verbatim yields a
    literal ``#{arch}`` directory component that never matches on disk; instead
    we substitute each ``#{arg}`` with its default value so the concrete file
    (``T1055.011_x64.exe``) is found. Unknown tokens are left intact. Nested
    defaults (a default whose text is itself ``#{other}``) are expanded too.
    """
    if "#{" not in (raw or ""):
        return raw
    args = input_arguments or {}
    for _ in range(8):
        prev = raw
        for key, argdef in args.items():
            default = _arg_default_text(argdef)
            if default is None:
                continue
            raw = raw.replace(f"#{{{key}}}", default)
        if raw == prev:
            break
    return raw


def _classify(resolved: Path) -> str:
    s = str(resolved)
    if "ExternalPayloads" in s:
        return "ExternalPayloads"
    if "bin" in s:
        return "bin"
    return "missing"


def _candidate_paths(atom_path: Path, technique_id: str, atomics: Path) -> list[Path]:
    """Return ordered candidate absolute paths for a token.

    The token may already be an absolute/rooted path (it contained the full
    PathToAtomicsFolder prefix) or a bare relative path to the technique dir.
    """
    txt = str(atom_path)
    if any(t in txt for t in _PATH_TOKENS) or Path(txt).is_absolute():
        if _TOKEN_PATH_RE.search(txt) or Path(txt).is_absolute():
            return [_resolve_path_token(txt, atomics)]
        return []
    # Bare relative: assume it is relative to the technique's own folder.
    return [atomics / technique_id / txt]


def discover_payloads(
    atomic: "Atomic",
    path_to_atomics: Path = ATOMICS_PATH,
) -> list[PayloadRef]:
    """Find all binary-payload references in an atomic test.

    Scans (a) every input_arguments default for a payload-ish path and
    (b) hardcoded literal paths in the executor command/cleanup and each
    dependency's prereq/get_prereq_command. Returns deduplicated PayloadRefs
    (unique by resolved path).
    """
    technique_id = getattr(atomic, "attack_technique", "") or ""
    input_arguments = getattr(atomic, "input_arguments", None) or {}

    def _matches_payload(raw: str | None) -> bool:
        if not raw:
            return False
        if _TOKEN_PATH_RE.search(raw):
            return any(raw.lower().endswith(ext) for ext in _PAYLOAD_EXTS)
        return False

    def _source_kind(raw: str) -> str:
        return "bin" if "bin" in raw else ("ExternalPayloads" if "ExternalPayloads" in raw else "missing")

    refs: dict[Path, PayloadRef] = {}
    seen_urls: dict[Path, str] = {}

    # (b) dependencies first so we can attach download_url to the same file
    #     reference when it later appears as an input default or literal.
    for dep in (getattr(atomic, "dependencies", None) or []):
        for cmd in (dep.prereq_command, dep.get_prereq_command):
            if not cmd:
                continue
            url = _extract_download_url(cmd)
            # find any payload token inside this dependency command
            for mt in _TOKEN_PATH_RE.finditer(cmd):
                start = mt.start()
                rest = cmd[start:]
                # grab a likely path tail after the token
                m = re.match(
                    r"(?:\\{PathToAtomicsFolder}\\|\\?\$PathToAtomicsFolder\\|PathToAtomicsFolder\\)"
                    r"([^;'"",\r\n]+)",
                    cmd[start:],
                )
                if not m:
                    continue
                tail = m.group(1).strip().strip('"')
                if tail and tail.lower().endswith(_PAYLOAD_EXTS):
                    stem = m.group(0).rstrip('"')
                    resolved = _resolve_path_token(
                        _substitute_arg_tokens(stem, input_arguments),
                        path_to_atomics,
                    )
                    if url:
                        seen_urls[resolved] = url
                    source = _classify(resolved)
                    if resolved not in refs:
                        refs[resolved] = PayloadRef(
                            path=resolved,
                            token=stem,
                            technique_id=technique_id,
                            source=source,
                            download_url=url if url else None,
                        )
                    elif url and not refs[resolved].download_url:
                        refs[resolved].download_url = url

    # (a) input_arguments defaults.
    for key, argdef in (getattr(atomic, "input_arguments", None) or {}).items():
        default = _arg_default_text(argdef)
        if default is None:
            continue
        raw = default
        if not _matches_payload(raw):
            continue
        resolved = _resolve_path_token(
            _substitute_arg_tokens(raw, input_arguments), path_to_atomics
        )
        source = _classify(resolved)
        if resolved not in refs:
            refs[resolved] = PayloadRef(
                path=resolved,
                token=raw,
                technique_id=technique_id,
                arg_key=key,
                source=source,
                download_url=seen_urls.get(resolved),
            )
        else:
            existing = refs[resolved]
            if existing.arg_key is None:
                existing.arg_key = key
            existing.download_url = existing.download_url or seen_urls.get(resolved)

    # (c) hardcoded literal paths in executor command + cleanup.
    executor = getattr(atomic, "executor", None)
    for cmd in (
        getattr(executor, "command", None),
        getattr(executor, "cleanup_command", None),
    ):
        if not cmd:
            continue
        for m in _TOKEN_PATH_RE.finditer(cmd):
            tail_src = cmd[m.start():]
            m2 = re.match(
                r"(?:\\{PathToAtomicsFolder}\\|\\?\$PathToAtomicsFolder\\|PathToAtomicsFolder\\)"
                r"([^;'"",\r\n]+)",
                tail_src,
            )
            if not m2:
                continue
            tail = m2.group(1).strip().strip('"')
            if not tail or not tail.lower().endswith(_PAYLOAD_EXTS):
                continue
            # group(0) is the full token incl. any quote before the payload
            # name; normalize by dropping a trailing quote so the resolved
            # path points cleanly at the payload file.
            stem = m2.group(0).rstrip('"')
            resolved = _resolve_path_token(
                _substitute_arg_tokens(stem, input_arguments),
                path_to_atomics,
            )
            source = _classify(resolved)
            if resolved not in refs:
                refs[resolved] = PayloadRef(
                    path=resolved,
                    token=stem,
                    technique_id=technique_id,
                    literal=stem,
                    source=source,
                    download_url=seen_urls.get(resolved),
                )
            else:
                existing = refs[resolved]
                if existing.literal is None:
                    existing.literal = stem
                existing.download_url = existing.download_url or seen_urls.get(resolved)

    return list(refs.values())


def local_exists(ref: PayloadRef) -> bool:
    """True if the referenced payload file is present on disk."""
    return ref.exists


def copy_payload(src: Path, dest_dir: Path, new_name: str) -> Path:
    """Copy a payload file to ``dest_dir`` under ``new_name`` and return it.

    Creates ``dest_dir`` if needed. Raises if the source is missing.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / new_name
    shutil.copy2(src, dest)
    return dest


def missing_marker(ref: PayloadRef) -> str:
    """Human-readable note for a payload that is not present locally."""
    return f"payload not present locally: {ref.path} (token: {ref.token})"


def sha256_file(path: Path) -> str:
    """Return the lower-case hex SHA256 of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
