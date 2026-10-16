"""Localize remote HTTP(S) fetches in atomic commands for offline execution.

At generate/release time every ``http(s)://`` URL found in the executor command,
cleanup, dependency commands, and input-argument defaults is ensured under::

    <atomics>/ExternalPayloads/reforge_remote/<sha12>/<filename>

and rewritten to a ``PathToAtomicsFolder\\ExternalPayloads\\reforge_remote\\...``
path. If the URL maps to a file already present in the local ART tree
(``atomics/T.../...``), that file is copied/hardlinked into the cache instead of
re-downloaded. Download cradles such as ``DownloadString('https://...')`` then
read the local file — attack intent is kept; only the transport changes.

Failures leave the original URL in place and are reported so the operator can
see which tests remain network-bound.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse

from .source import ATOMICS_PATH  # noqa: F401 — inserts ref/ onto sys.path
from atomic_red_team.models import Technique

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic

URL_RE = re.compile(r"https?://[^\s'\"<>\)]+", re.IGNORECASE)
_TRAIL_TRIM = ".,;:)]}'\"`"

# Command URLs on these techniques *are* the attack (C2 / exfil / ingress).
# Prereq downloads of tools are still localized.
_OUTBOUND_TID_PREFIXES = (
    "T1001",  # Data Obfuscation (often C2 framing)
    "T1020",  # Automated Exfiltration
    "T1041",  # Exfiltration Over C2 Channel
    "T1048",  # Exfiltration Over Alternative Protocol
    "T1071",  # Application Layer Protocol
    "T1090",  # Proxy
    "T1095",  # Non-Application Layer Protocol
    "T1102",  # Web Service
    "T1104",  # Multi-Stage Channels
    "T1105",  # Ingress Tool Transfer
    "T1132",  # Data Encoding
    "T1567",  # Exfiltration Over Web Service
    "T1568",  # Dynamic Resolution
    "T1571",  # Non-Standard Port
    "T1572",  # Protocol Tunneling
    "T1573",  # Encrypted Channel
)

_PAYLOAD_SUFFIXES = (
    ".exe", ".dll", ".sys", ".scr", ".msi", ".msix", ".zip", ".7z", ".gz",
    ".tar", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta", ".bin",
    ".cs", ".go", ".iso", ".img", ".cab", ".jar",
)

_ART_URL_MARKERS = (
    "redcanaryco/atomic-red-team",
    "redcanaryco/atomicredteam",
)


def is_outbound_technique(technique_id: str | None) -> bool:
    """True when the ATT&CK technique's intent is live network traffic."""
    tid = (technique_id or "").strip().upper()
    if not tid:
        return False
    return any(tid == p or tid.startswith(p + ".") for p in _OUTBOUND_TID_PREFIXES)


def is_payload_artifact_url(url: str) -> bool:
    """True when the URL names a tool, script, or Atomic Red Team repo file."""
    raw = (url or "").strip().rstrip(_TRAIL_TRIM)
    low = raw.lower()
    if any(m in low for m in _ART_URL_MARKERS):
        return True
    if "/releases/download/" in low:
        return True
    path = unquote(urlparse(raw).path or "").lower()
    if any(path.endswith(ext) for ext in _PAYLOAD_SUFFIXES):
        return True
    for hint in filename_hints(raw):
        h = hint.lower()
        if any(h.endswith(ext) for ext in _PAYLOAD_SUFFIXES):
            return True
    return False


def should_rewrite_url(
    url: str,
    *,
    technique_id: str | None = None,
    in_prereq: bool = False,
) -> bool:
    """Whether to replace this URL with a local PathToAtomicsFolder payload.

    Prereq fetches (tools, ART repo copies) always rewrite. On outbound
    techniques the command URL stays remote. Elsewhere, only artifact-shaped
    URLs (exe/zip/ps1/ART) rewrite; bare C2 hosts stay as downloads.
    """
    if in_prereq:
        return True
    if is_outbound_technique(technique_id):
        return False
    return is_payload_artifact_url(url)

# Cache lives under ExternalPayloads so existing payload discovery / release
# mirroring picks the files up automatically.
_CACHE_REL = Path("ExternalPayloads") / "reforge_remote"

# Prefix-style GitHub proxies (append the full original https URL).
# Availability varies by region; failures are skipped and the next is tried.
_GITHUB_PROXY_PREFIXES = (
    "https://ghproxy.net/",
    "https://mirror.ghproxy.com/",
    "https://gh.ddlc.top/",
    "https://ghfast.top/",
)

_RAW_GH = "https://raw.githubusercontent.com/"
_RAW_GITMIRROR = "https://raw.gitmirror.com/"
_JSDELIVR_GH = "https://cdn.jsdelivr.net/gh/"


def _is_github_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in (
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "codeload.github.com",
    )


def github_mirror_candidates(url: str) -> list[str]:
    """Build download URL candidates: original, env override, then public mirrors.

    Env ``ATOMIC_REFORGE_GITHUB_MIRROR`` may be a comma-separated list of
    proxy prefixes (each is prepended to the original URL), tried first after
    the original.
    """
    ordered: list[str] = [url]
    if not _is_github_url(url):
        return ordered

    custom = os.environ.get("ATOMIC_REFORGE_GITHUB_MIRROR", "").strip()
    if custom:
        for prefix in custom.split(","):
            prefix = prefix.strip()
            if not prefix:
                continue
            if not prefix.endswith("/"):
                prefix += "/"
            ordered.append(prefix + url)

    for prefix in _GITHUB_PROXY_PREFIXES:
        ordered.append(prefix + url)

    # raw.githubusercontent.com/user/repo/ref/path
    #   -> raw.gitmirror.com/user/repo/ref/path
    #   -> cdn.jsdelivr.net/gh/user/repo@ref/path
    if url.startswith(_RAW_GH):
        rest = url[len(_RAW_GH) :]
        ordered.append(_RAW_GITMIRROR + rest)
        parts = rest.split("/", 3)
        if len(parts) == 4:
            user, repo, ref, path = parts
            ordered.append(f"{_JSDELIVR_GH}{user}/{repo}@{ref}/{path}")

    # de-dupe preserving order
    seen: dict[str, None] = {}
    for u in ordered:
        seen.setdefault(u, None)
    return list(seen.keys())


def _fetch_bytes(url: str, timeout: int) -> bytes | None:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "atomic-reforge-localize/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        return data or None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return None


@dataclass
class LocalizeResult:
    """Outcome of localizing one atomic."""

    atomic: "Atomic"
    downloaded: list[Path] = field(default_factory=list)
    rewritten_urls: dict[str, str] = field(default_factory=dict)  # url -> token path
    failed_urls: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)  # url -> cache|copy_art|download
    changed: bool = False


# ART atomics/<rel> on raw.githubusercontent.com or github.com, including
# missing raw/blob segments and the atomicredteam slug typo.
_ART_ANY_RE = re.compile(
    r"^https?://(?:raw\.githubusercontent\.com|github\.com)/"
    r"redcanaryco/(?:atomic-red-team|atomicredteam)/"
    r"(?:(?:raw|blob)/[^/]+/|[^/]+/)?"
    r"atomics/(.+)$",
    re.IGNORECASE,
)


def _safe_filename(url: str) -> str:
    path = unquote(urlparse(url).path or "")
    name = Path(path).name or "payload.bin"
    name = re.sub(r"[^\w.\-]+", "_", name).strip("._") or "payload.bin"
    if len(name) > 120:
        stem, suf = Path(name).stem[:80], Path(name).suffix[:20]
        name = stem + suf
    return name


def remote_cache_paths(url: str, atomics: Path | None = None) -> tuple[Path, str]:
    """Return (absolute cache file path, PathToAtomicsFolder token path).

    Layout (must stay stable — prefetch scripts and release both rely on it)::

        <atomics>/ExternalPayloads/reforge_remote/<sha12>/<filename>
    """
    root = Path(atomics) if atomics is not None else ATOMICS_PATH
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    fname = _safe_filename(url)
    abs_path = root / _CACHE_REL / digest / fname
    rel = str(_CACHE_REL / digest / fname).replace("/", "\\")
    token = "PathToAtomicsFolder\\" + rel
    return abs_path, token


def _cache_paths(url: str, atomics: Path) -> tuple[Path, str]:
    return remote_cache_paths(url, atomics)


def parse_art_relative_path(url: str) -> str | None:
    """If ``url`` points at ART ``atomics/<rel>``, return ``rel`` (forward slashes).

    Covers raw.githubusercontent.com and github.com raw/blob forms. Query strings
    such as ``?raw=true`` are stripped from the relative path.
    """
    cleaned = url.strip().rstrip(_TRAIL_TRIM)
    m = _ART_ANY_RE.match(cleaned)
    if not m:
        return None
    rel = unquote(m.group(1))
    rel = rel.split("?", 1)[0]
    # Drop URL fragments (#L10) but keep #{arch} placeholders.
    cut = re.search(r"#(?!\{)", rel)
    if cut:
        rel = rel[: cut.start()]
    rel = rel.rstrip("`")
    rel = rel.replace("\\", "/").lstrip("/")
    if not rel or ".." in rel.split("/"):
        return None
    return rel


def art_placeholder_token(url: str) -> str | None:
    """``PathToAtomicsFolder\\...`` token for an ART URL that still has ``#{arg}``."""
    rel = parse_art_relative_path(url)
    if not rel or "#{" not in rel:
        return None
    return "PathToAtomicsFolder\\" + rel.replace("/", "\\")


def art_local_path(url: str, atomics: Path) -> Path | None:
    """Absolute path under ``atomics`` if ART-relative URL maps to an existing file."""
    rel = parse_art_relative_path(url)
    if not rel:
        return None
    path = Path(atomics) / Path(*rel.split("/"))
    if path.is_file() and path.stat().st_size > 0:
        return path
    return None


def _link_or_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    try:
        os.link(src, dest)
    except OSError:
        shutil.copy2(src, dest)


_ONE_OF_RE = re.compile(r"\(([^)]+)\)")


def _arg_specs(input_arguments) -> dict[str, dict]:
    specs: dict[str, dict] = {}
    for key, argdef in (input_arguments or {}).items():
        if isinstance(argdef, dict):
            specs[key] = {
                "default": _plain_arg_default(argdef),
                "description": str(argdef.get("description") or ""),
            }
        else:
            specs[key] = {
                "default": _plain_arg_default(argdef),
                "description": str(getattr(argdef, "description", "") or ""),
            }
    return specs


def expansion_maps(input_arguments) -> list[dict[str, str]]:
    """Default ``#{arg}`` substitutions, plus enumerated alternates.

    A description such as ``One of (x64, x86)`` yields one map per listed
    value so both local files can be cached. The first map is the default.
    """
    specs = _arg_specs(input_arguments)
    base = {
        key: str(spec["default"])
        for key, spec in specs.items()
        if spec.get("default") is not None
    }
    maps = [base]
    for key, spec in specs.items():
        match = _ONE_OF_RE.search(spec.get("description") or "")
        if not match:
            continue
        for part in re.split(r"[,/|]|(?:\bor\b)", match.group(1)):
            token = part.strip().strip("'\"")
            if not re.fullmatch(r"[\w.\-]+", token):
                continue
            if token == base.get(key):
                continue
            alt = dict(base)
            alt[key] = token
            maps.append(alt)
    return maps


def expand_placeholders(text: str, mapping: dict[str, str]) -> str:
    """Replace ``#{key}`` repeatedly so nested defaults expand."""
    out = text
    for _ in range(8):
        prev = out
        for key, value in mapping.items():
            out = out.replace(f"#{{{key}}}", value)
        if out == prev:
            break
    return out


def _glob_placeholder_urls(url: str, atomics: Path) -> list[str]:
    """Expand ``#{arg}`` in an ART URL by globbing the local atomics tree."""
    if "#{" not in url or "/atomics/" not in url.lower():
        return []
    starred = re.sub(r"#\{[^}]+\}", "*", url.split("?", 1)[0])
    match = re.search(r"/atomics/([^?\s]+)", starred, re.IGNORECASE)
    if not match:
        return []
    rel_glob = unquote(match.group(1)).replace("\\", "/").lstrip("/")
    if not rel_glob or ".." in rel_glob.split("/"):
        return []
    found: list[str] = []
    root = Path(atomics)
    prefix = starred[: match.start()] + "/atomics/"
    for path in sorted(root.glob(rel_glob)):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        concrete = prefix + rel
        if "#{" not in concrete:
            found.append(concrete)
    return found


def filename_hints(url: str) -> list[str]:
    """Candidate payload basenames embedded in a URL path or query."""
    parsed = urlparse(url.strip().rstrip(_TRAIL_TRIM))
    names: list[str] = []
    path_name = Path(unquote(parsed.path or "")).name
    if path_name and "#{" not in path_name:
        names.append(path_name)
    query = unquote(parsed.query or "")
    for part in re.split(r"[?&/=]", query):
        part = part.strip().rstrip(_TRAIL_TRIM)
        if re.search(r"\.[A-Za-z0-9]{1,8}$", part) and "#{" not in part:
            names.append(Path(part).name)
    seen: dict[str, None] = {}
    for name in names:
        seen.setdefault(name, None)
    return list(seen.keys())


def concrete_urls(
    url: str,
    input_arguments,
    atomics: Path | None = None,
) -> list[tuple[str, str]]:
    """Return ``(rewrite_key, concrete_url)`` pairs for one discovered URL.

    Placeholder URLs (``#{arch}``) expand via argument defaults and by globbing
    matching files under ``atomics/``. ``#{...}`` stays in the command text;
    concrete files are cached only.
    """
    if "#{" not in url:
        return [(url, url)]
    concretes: dict[str, None] = {}
    for mapping in expansion_maps(input_arguments):
        concrete = expand_placeholders(url, mapping)
        if "#{" not in concrete:
            concretes.setdefault(concrete, None)
    root = Path(atomics) if atomics is not None else ATOMICS_PATH
    for concrete in _glob_placeholder_urls(url, root):
        concretes.setdefault(concrete, None)
    return [(url, concrete) for concrete in concretes]


def discover_urls(*texts: str | None) -> list[str]:
    """Unique http(s) URLs found across the given texts (stable order)."""
    seen: dict[str, None] = {}
    for text in texts:
        if not text:
            continue
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(_TRAIL_TRIM)
            if url.startswith(("http://", "https://")):
                seen.setdefault(url, None)
    return list(seen.keys())


def download_url(url: str, dest: Path, timeout: int = 60) -> bool:
    """Download ``url`` to ``dest`` if missing. Returns True on success.

    For GitHub hosts, automatically retries via public mirrors / proxies when
    the origin fails (see ``github_mirror_candidates``).
    """
    if dest.is_file() and dest.stat().st_size > 0:
        return True
    if os.environ.get("ATOMIC_REFORGE_LOCAL_ONLY", "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Slightly shorter per-attempt timeout so mirror failover stays responsive.
    per_try = max(15, min(timeout, 45))
    for candidate in github_mirror_candidates(url):
        data = _fetch_bytes(candidate, timeout=per_try)
        if data:
            dest.write_bytes(data)
            return True
    return False


def external_payloads_root(atomics: Path | None = None) -> Path:
    """ART sibling tree: ``<repo>/ExternalPayloads`` (``PathToAtomicsFolder\\..\\``)."""
    root = Path(atomics) if atomics is not None else ATOMICS_PATH
    return root.parent / "ExternalPayloads"


def cache_token_for(atomics: Path, path: Path) -> str:
    rel = path.resolve().relative_to(Path(atomics).resolve())
    return "PathToAtomicsFolder\\" + str(rel).replace("/", "\\")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_cached_same_content(atomics: Path, src: Path) -> Path | None:
    """Return an existing ``reforge_remote`` file with the same name and bytes."""
    cache = Path(atomics) / _CACHE_REL
    if not cache.is_dir() or not src.is_file():
        return None
    try:
        src_size = src.stat().st_size
    except OSError:
        return None
    if src_size <= 0:
        return None
    src_hash: str | None = None
    for cand in cache.rglob(src.name):
        if not cand.is_file():
            continue
        try:
            if cand.resolve() == src.resolve():
                return cand
            if cand.stat().st_size != src_size:
                continue
            if src_hash is None:
                src_hash = _sha256_file(src)
            if _sha256_file(cand) == src_hash:
                return cand
        except OSError:
            continue
    return None


def _materialize(src: Path, preferred: Path, atomics: Path) -> tuple[Path, str, bool]:
    """Place ``src`` in the cache, reusing a same-content file when one exists.

    Returns ``(abs_path, token, reused)``.
    """
    existing = find_cached_same_content(atomics, src)
    if existing is not None:
        return existing, cache_token_for(atomics, existing), True
    _link_or_copy(src, preferred)
    return preferred, cache_token_for(atomics, preferred), False


_EXT_NAME_INDEX: dict[str, dict[str, list[Path]]] = {}


def external_files_named(atomics: Path, filename: str) -> list[Path]:
    """Files under ``../ExternalPayloads`` with this basename (index cached)."""
    root = Path(atomics)
    key = str(root.resolve())
    index = _EXT_NAME_INDEX.get(key)
    if index is None:
        index = {}
        ext_root = external_payloads_root(root)
        if ext_root.is_dir():
            for path in ext_root.rglob("*"):
                if path.is_file():
                    index.setdefault(path.name.lower(), []).append(path)
        _EXT_NAME_INDEX[key] = index
    return list(index.get(filename.lower(), []))


def unique_external_named(atomics: Path, filename: str) -> Path | None:
    hits = external_files_named(atomics, filename)
    if len(hits) == 1:
        return hits[0]
    return None


_EXT_REF_RE = re.compile(
    r"(?:\{PathToAtomicsFolder\}|\$PathToAtomicsFolder|PathToAtomicsFolder)"
    r"(?:\\|/)\.\.(?:\\|/)?ExternalPayloads(?:\\|/)"
    r"([^\s'\"<>|;&]+)",
    re.IGNORECASE,
)


def discover_external_rels(*texts: str | None) -> list[str]:
    """Relative paths under ``../ExternalPayloads`` referenced by path tokens."""
    seen: dict[str, None] = {}
    for text in texts:
        if not text or "ExternalPayloads" not in text:
            continue
        for match in _EXT_REF_RE.finditer(text):
            rel = unquote(match.group(1)).rstrip(_TRAIL_TRIM).replace("\\", "/")
            rel = rel.split("?", 1)[0]
            if not rel or ".." in rel.split("/"):
                continue
            seen.setdefault(rel, None)
    return list(seen.keys())


def ensure_external_rel(
    rel: str,
    atomics: Path | None = None,
) -> tuple[Path, str] | None:
    """Copy one ``../ExternalPayloads/<rel>`` file into ``reforge_remote`` if it exists.

    Same name + same bytes already in the cache are reused (no second copy).
    Missing files (runtime outputs) return ``None``.
    """
    root = Path(atomics) if atomics is not None else ATOMICS_PATH
    rel_norm = rel.replace("\\", "/").lstrip("/")
    src = external_payloads_root(root) / Path(*rel_norm.split("/"))
    if not src.is_file() or src.stat().st_size <= 0:
        return None
    preferred = root / _CACHE_REL / "ext" / Path(*rel_norm.split("/"))
    abs_path, token, _reused = _materialize(src, preferred, root)
    if abs_path.is_file() and abs_path.stat().st_size > 0:
        return abs_path, token
    return None


def rewrite_external_paths(
    text: str | None,
    atomics: Path,
) -> tuple[str | None, dict[str, str]]:
    """Rewrite ``PathToAtomicsFolder\\..\\ExternalPayloads\\<file>`` to cache tokens.

    Only paths whose source file already exists are rewritten. Returns
    ``(new_text, {original_token: cache_token})``.
    """
    if not text or "ExternalPayloads" not in text:
        return text, {}
    mapping: dict[str, str] = {}
    for match in _EXT_REF_RE.finditer(text):
        raw = match.group(0).rstrip(_TRAIL_TRIM)
        rel = unquote(match.group(1)).rstrip(_TRAIL_TRIM).replace("\\", "/")
        if ".." in rel.split("/"):
            continue
        ensured = ensure_external_rel(rel, atomics)
        if ensured is None:
            continue
        _path, token = ensured
        mapping[raw] = token
    if not mapping:
        return text, {}
    out = text
    for raw in sorted(mapping, key=len, reverse=True):
        out = out.replace(raw, mapping[raw])
    return out, mapping


def ensure_remote_cached(
    url: str,
    atomics: Path | None = None,
    *,
    download: bool = True,
    timeout: int = 60,
) -> tuple[Path, str, str] | None:
    """Ensure ``url`` is present under ``reforge_remote`` and return paths.

    Resolution order:

    1. Cache file already present → ``source='cache'``
    2. URL maps to an existing ART ``atomics/<rel>`` file → copy/hardlink
       (reuse same-content cache file) → ``source='copy_art'`` or ``'dedup'``
    3. Unique same-name file under ``../ExternalPayloads`` → same → ``'copy_ext'``
    4. Else download into cache (if ``download``) → ``source='download'``

    Returns ``(abs_path, token, source)`` or ``None`` on failure.
    """
    root = Path(atomics) if atomics is not None else ATOMICS_PATH
    abs_path, token = remote_cache_paths(url, root)

    if abs_path.is_file() and abs_path.stat().st_size > 0:
        return abs_path, token, "cache"

    art_src = art_local_path(url, root)
    if art_src is not None:
        placed, placed_token, reused = _materialize(art_src, abs_path, root)
        if placed.is_file() and placed.stat().st_size > 0:
            return placed, placed_token, ("dedup" if reused else "copy_art")
        return None

    for hint in filename_hints(url):
        ext_src = unique_external_named(root, hint)
        if ext_src is None:
            continue
        placed, placed_token, reused = _materialize(ext_src, abs_path, root)
        if placed.is_file() and placed.stat().st_size > 0:
            return placed, placed_token, ("dedup" if reused else "copy_ext")

    if not download:
        return None

    if download_url(url, abs_path, timeout=timeout):
        return abs_path, token, "download"
    return None


_WEBCLIENT_DS_RE = (
    r"(?i)\(\s*new-object\s+(?:(?:system\.)?net\.)?webclient\s*\)\s*"
    r"\.\s*downloadstring\s*\(\s*(['\"]){url}\1\s*\)"
)
_WEBCLIENT_DD_RE = (
    r"(?i)\(\s*new-object\s+(?:(?:system\.)?net\.)?webclient\s*\)\s*"
    r"\.\s*downloaddata\s*\(\s*(['\"]){url}\1\s*\)"
)
_WEBCLIENT_DF_RE = (
    r"(?i)\(\s*new-object\s+(?:(?:system\.)?net\.)?webclient\s*\)\s*"
    r"\.\s*downloadfile\s*\(\s*(['\"]){url}\1\s*,\s*(.+?)\s*\)"
)
_BARE_DS_RE = r"(?i)\.?downloadstring\s*\(\s*(['\"]){url}\1\s*\)"
_BARE_DD_RE = r"(?i)\.?downloaddata\s*\(\s*(['\"]){url}\1\s*\)"
_BARE_DF_RE = (
    r"(?i)\.?downloadfile\s*\(\s*(['\"]){url}\1\s*,\s*(.+?)\s*\)"
)
_LOOSE_DS_RE = (
    r"(?i)\.?downloadstring\s*\(\s*[`'\"]*{url}[`'\"]*\s*\)"
)
_IWR_STMT_RE = (
    r"(?i)\b(?:invoke-webrequest|iwr)\b[^\n;)]*{url}[^\n;)]*"
)
_BITS_STMT_RE = (
    r"(?i)\bstart-bitstransfer\b[^\n;)]*{url}[^\n;)]*"
)
_CURL_STMT_RE = (
    r"(?i)\bcurl(?:\.exe)?\b[^\n;)]*{url}[^\n;)]*"
)
_BITSADMIN_RE = (
    r"(?i)\bbitsadmin(?:\.exe)?\b[^\n]*{url}[^\n]*"
)
_VERIFY_HASH_RE = (
    r"(?i)invoke-webrequestverifyhash\s+(['\"]?){url}\1\s+"
    r"(?P<dest>(['\"])(?:\\.|.)*?\3|\$\S+|\S+)\s+"
    r"(?P<hash>#\{{[^}}]+\}}|'[^']*'|\"[^\"]*\"|[A-Fa-f0-9]+)"
)
_OUTFILE_RE = re.compile(
    r"(?i)-OutFile\s+(?P<dest>(['\"])(?:\\.|.)*?\2|\S+)"
)
_DESTINATION_RE = re.compile(
    r"(?i)-(?:Destination|Dest)\s+(?P<dest>(['\"])(?:\\.|.)*?\2|\S+)"
)
_OUTPUT_RE = re.compile(
    r"(?i)(?:--output|-o)\s+(?P<dest>(['\"])(?:\\.|.)*?\2|\S+)"
)


def _quoted_local(quote: str, local: str) -> str:
    return f"{quote}{local}{quote}"


def _rewrite_download_cradles(
    text: str, url: str, local: str, *, include_bitsadmin: bool = False
) -> str:
    """Turn HTTP download APIs into local file reads/copies for one URL.

    Replacing only the URL and leaving ``DownloadString`` / ``IWR`` / ``curl``
    in place makes PowerShell treat a filesystem path as a URI (日志里的
    “未能找到路径” / Invalid URI).
    """
    escaped = re.escape(url)

    def ds_paren(match: re.Match) -> str:
        return f"(Get-Content -Raw -LiteralPath {_quoted_local(match.group(1), local)})"

    text = re.sub(_WEBCLIENT_DS_RE.format(url=escaped), ds_paren, text)
    text = re.sub(
        _WEBCLIENT_DD_RE.format(url=escaped),
        lambda m: f"[IO.File]::ReadAllBytes({_quoted_local(m.group(1), local)})",
        text,
    )

    def df_repl(match: re.Match) -> str:
        dest = match.group(2).strip()
        return (
            f"Copy-Item -LiteralPath {_quoted_local(match.group(1), local)} "
            f"-Destination {dest} -Force"
        )

    text = re.sub(_WEBCLIENT_DF_RE.format(url=escaped), df_repl, text)
    text = re.sub(
        _BARE_DS_RE.format(url=escaped),
        lambda m: f"Get-Content -Raw -LiteralPath {_quoted_local(m.group(1), local)}",
        text,
    )
    text = re.sub(
        _BARE_DD_RE.format(url=escaped),
        lambda m: f"[IO.File]::ReadAllBytes({_quoted_local(m.group(1), local)})",
        text,
    )
    text = re.sub(_BARE_DF_RE.format(url=escaped), df_repl, text)
    text = re.sub(
        _LOOSE_DS_RE.format(url=escaped),
        lambda m: f"Get-Content -Raw -LiteralPath '{local}'",
        text,
    )

    def iwr_repl(match: re.Match) -> str:
        stmt = match.group(0)
        of = _OUTFILE_RE.search(stmt)
        qm = re.search(r"(['\"])" + escaped + r"\1", stmt)
        quote = qm.group(1) if qm else "'"
        if of:
            return (
                f"Copy-Item -LiteralPath {_quoted_local(quote, local)} "
                f"-Destination {of.group('dest')} -Force"
            )
        return f"Get-Content -Raw -LiteralPath {_quoted_local(quote, local)}"

    text = re.sub(_IWR_STMT_RE.format(url=escaped), iwr_repl, text)

    def bits_repl(match: re.Match) -> str:
        stmt = match.group(0)
        dest_m = _DESTINATION_RE.search(stmt)
        dest = dest_m.group("dest") if dest_m else "$env:TEMP\\reforge_payload"
        return f"Copy-Item -LiteralPath '{local}' -Destination {dest} -Force"

    text = re.sub(_BITS_STMT_RE.format(url=escaped), bits_repl, text)

    def curl_repl(match: re.Match) -> str:
        stmt = match.group(0)
        dest_m = _OUTPUT_RE.search(stmt)
        dest = dest_m.group("dest") if dest_m else "$env:TEMP\\reforge_payload"
        return f"Copy-Item -LiteralPath '{local}' -Destination {dest} -Force"

    text = re.sub(_CURL_STMT_RE.format(url=escaped), curl_repl, text)

    def verify_repl(match: re.Match) -> str:
        dest = match.group("dest")
        # Keep #{hash} (or the literal hash) so ART unused-arg validation
        # does not reject the rewritten atomic and drop the whole rewrite.
        return (
            f"($null = Copy-Item -LiteralPath '{local}' "
            f"-Destination {dest} -Force; Test-Path {dest}) "
            f"<# {match.group('hash')} #>"
        )

    text = re.sub(_VERIFY_HASH_RE.format(url=escaped), verify_repl, text)

    if include_bitsadmin:
        def bitsadmin_repl(match: re.Match) -> str:
            stmt = match.group(0).rstrip()
            dest = stmt.split()[-1] if stmt.split() else "$env:TEMP\\reforge_payload"
            return f'Copy-Item -LiteralPath "{local}" -Destination {dest} -Force'

        text = re.sub(_BITSADMIN_RE.format(url=escaped), bitsadmin_repl, text)
    return text


def rewrite_urls(
    text: str | None,
    mapping: dict[str, str],
    *,
    include_bitsadmin: bool = False,
) -> str | None:
    """Replace each URL key in ``mapping`` with a local PathToAtomicsFolder token.

    Download cradles are rewritten to ``Get-Content`` / ``Copy-Item`` *before*
    the URL is substituted, including case-insensitive ``downloadstring`` and
    ``IWR``. A leftover URL (assignments, comments) is still string-replaced.
    """
    if not text or not mapping:
        return text
    out = text
    for url in sorted(mapping.keys(), key=len, reverse=True):
        local = mapping[url]
        out = _rewrite_download_cradles(
            out, url, local, include_bitsadmin=include_bitsadmin
        )
        out = out.replace(url, local)
    return out


def _arg_default(argdef) -> object:
    if isinstance(argdef, dict):
        return argdef.get("default")
    return getattr(argdef, "default", None)


def _plain_arg_default(argdef) -> object:
    """Stringify pydantic ``AnyUrl`` defaults so URL rewrite can see them.

    ART ``type: url`` arguments come out of the model as ``AnyUrl``, not
    ``str``. Skipping them left ``#{remote_script}`` pointing at GitHub.
    """
    default = _arg_default(argdef)
    if default is None or isinstance(default, (int, float)):
        return default
    return str(default)


def _placeholder_cradle_map(input_arguments, url_map: dict[str, str]) -> dict[str, str]:
    """Map ``#{arg}`` to itself when that arg's default URL was localized.

    Commands often keep the URL only in the argument default
    (``DownloadString('#{remote_script}')``). Cradle rewrite must run against
    the placeholder or the executor still calls the download API.
    """
    extra: dict[str, str] = {}
    for name, argdef in (input_arguments or {}).items():
        raw = _plain_arg_default(argdef)
        if not isinstance(raw, str) or raw not in url_map:
            continue
        token = f"#{{{name}}}"
        extra[token] = token
    return extra


def _arg_meta(argdef) -> tuple[str, str]:
    if isinstance(argdef, dict):
        return (
            str(argdef.get("description") or ""),
            str(argdef.get("type") or "string"),
        )
    return (
        str(getattr(argdef, "description", "") or ""),
        str(getattr(argdef, "type", "string") or "string"),
    )


def localize_atomic(
    atomic: "Atomic",
    path_to_atomics: Path | None = None,
    *,
    download: bool = True,
    timeout: int = 60,
    technique_id: str | None = None,
) -> LocalizeResult:
    """Return a copy of ``atomic`` with remote URLs localized when possible.

    Tool and Atomic Red Team repository fetches become local payload paths.
    URLs that are the technique itself (C2, exfil, ingress) stay remote.
    """
    atomics = Path(path_to_atomics) if path_to_atomics is not None else ATOMICS_PATH
    executor = atomic.executor
    arg_defaults = {
        k: _plain_arg_default(v) for k, v in (atomic.input_arguments or {}).items()
    }

    exec_texts: list[str | None] = [
        getattr(executor, "command", None),
        getattr(executor, "cleanup_command", None),
    ]
    for val in arg_defaults.values():
        if val is not None:
            exec_texts.append(str(val))
    prereq_texts: list[str | None] = []
    for dep in atomic.dependencies or []:
        prereq_texts.append(getattr(dep, "prereq_command", None))
        prereq_texts.append(getattr(dep, "get_prereq_command", None))

    texts = exec_texts + prereq_texts
    exec_urls = set(discover_urls(*exec_texts))
    prereq_urls = set(discover_urls(*prereq_texts))
    urls = discover_urls(*texts)
    ext_rels = discover_external_rels(*texts)
    if not urls and not ext_rels:
        return LocalizeResult(atomic=atomic, changed=False)

    exec_mapping: dict[str, str] = {}
    prereq_mapping: dict[str, str] = {}
    downloaded: list[Path] = []
    sources: dict[str, str] = {}
    failed: list[str] = []

    for url in urls:
        rewrite_exec = url in exec_urls and should_rewrite_url(
            url, technique_id=technique_id, in_prereq=False
        )
        rewrite_prereq = url in prereq_urls and should_rewrite_url(
            url, technique_id=technique_id, in_prereq=True
        )
        if not rewrite_exec and not rewrite_prereq:
            continue
        pairs = concrete_urls(url, atomic.input_arguments, atomics)
        if not pairs:
            failed.append(url)
            continue
        any_ok = False
        for rewrite_key, concrete in pairs:
            ensured = ensure_remote_cached(
                concrete, atomics, download=download, timeout=timeout
            )
            if ensured is None:
                continue
            any_ok = True
            abs_path, token, source = ensured
            downloaded.append(abs_path)
            # Keep #{arg} in the command so arch (and similar) stays selectable.
            # Concrete files are still cached above. Point the templated ART
            # URL at PathToAtomicsFolder\\...\\file_#{arch}.ext so IWR becomes
            # Copy-Item instead of remaining a GitHub download.
            if "#{" in rewrite_key:
                templated = art_placeholder_token(rewrite_key)
                if templated:
                    sources.setdefault(rewrite_key, "copy_art")
                    if rewrite_exec:
                        exec_mapping.setdefault(rewrite_key, templated)
                    if rewrite_prereq:
                        prereq_mapping.setdefault(rewrite_key, templated)
                continue
            sources.setdefault(rewrite_key, source)
            if rewrite_exec:
                exec_mapping.setdefault(rewrite_key, token)
            if rewrite_prereq:
                prereq_mapping.setdefault(rewrite_key, token)
        if not any_ok:
            failed.append(url)

    mapping = {**exec_mapping, **prereq_mapping}

    def _rewrite(
        text: str | None,
        url_map: dict[str, str],
        *,
        include_bitsadmin: bool = False,
    ) -> str | None:
        rewritten = rewrite_urls(
            text, url_map, include_bitsadmin=include_bitsadmin
        )
        rewritten, ext_map = rewrite_external_paths(rewritten, atomics)
        for raw, token in ext_map.items():
            mapping[raw] = token
            sources[raw] = "ext_path"
        return rewritten

    exec_rewrite = {
        **exec_mapping,
        **_placeholder_cradle_map(atomic.input_arguments, exec_mapping),
    }
    prereq_rewrite = {
        **prereq_mapping,
        **_placeholder_cradle_map(atomic.input_arguments, prereq_mapping),
        **_placeholder_cradle_map(atomic.input_arguments, exec_mapping),
    }

    new_command = _rewrite(executor.command, exec_rewrite)
    new_cleanup = _rewrite(executor.cleanup_command, exec_rewrite)

    new_args: dict[str, dict] = {}
    for name, argdef in (atomic.input_arguments or {}).items():
        desc, typ = _arg_meta(argdef)
        default = _plain_arg_default(argdef)
        if default is not None and isinstance(default, str):
            default = _rewrite(default, exec_mapping)
            # Local payload paths are not http(s) URLs; keep pydantic from
            # dropping the default when the original type was ``url``.
            if typ.lower() == "url" and default and not default.lower().startswith("http"):
                typ = "string"
        new_args[name] = {
            "description": desc,
            "type": typ,
            "default": default,
        }

    deps = []
    for dep in atomic.dependencies or []:
        deps.append(
            {
                "description": dep.description,
                "prereq_command": _rewrite(
                    dep.prereq_command, prereq_rewrite, include_bitsadmin=True
                ),
                "get_prereq_command": _rewrite(
                    dep.get_prereq_command,
                    prereq_rewrite,
                    include_bitsadmin=True,
                ),
            }
        )

    if not mapping:
        return LocalizeResult(
            atomic=atomic,
            downloaded=downloaded,
            failed_urls=failed,
            sources=sources,
            changed=False,
        )

    executor_dict: dict = {
        "name": executor.name,
        "command": new_command,
    }
    if new_cleanup:
        executor_dict["cleanup_command"] = new_cleanup
    if getattr(executor, "elevation_required", None):
        executor_dict["elevation_required"] = executor.elevation_required

    atomic_dict: dict = {
        "name": atomic.name,
        "auto_generated_guid": str(atomic.auto_generated_guid),
        "description": atomic.description,
        "supported_platforms": list(atomic.supported_platforms),
        "executor": executor_dict,
    }
    if new_args:
        atomic_dict["input_arguments"] = new_args
    if deps:
        atomic_dict["dependencies"] = deps
        dep_ex = atomic.dependency_executor_name or executor.name
        if dep_ex:
            atomic_dict["dependency_executor_name"] = dep_ex

    # Validate through upstream model (technique id is only a schema vessel here).
    try:
        tech = Technique(
            attack_technique="T1059.001",
            display_name="localize",
            atomic_tests=[atomic_dict],
        )
        new_atomic = tech.atomic_tests[0]
    except Exception:
        # Fall back to original on schema failure.
        return LocalizeResult(
            atomic=atomic,
            downloaded=downloaded,
            rewritten_urls=mapping,
            failed_urls=failed,
            sources=sources,
            changed=False,
        )

    return LocalizeResult(
        atomic=new_atomic,
        downloaded=downloaded,
        rewritten_urls=mapping,
        failed_urls=failed,
        sources=sources,
        changed=True,
    )
