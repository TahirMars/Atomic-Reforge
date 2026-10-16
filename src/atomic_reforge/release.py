"""Offline release bundle builder: variants + payloads + SHA256 manifest.

Assembles a self-contained directory (optionally archived as zip or tar.gz)
that can be copied wholesale to an offline evaluation machine. It re-runs
generation for the selected techniques, writes variant YAMLs and resolved
scripts, mirrors every locally-present payload under ``atomics/`` (preserving
PathToAtomicsFolder-relative layout), copies rename targets under
``atomics/payloads/<TID>/``, and emits a ``manifest.json`` so offline ``run``
can validate integrity and know which payloads still require a remote fetch.

Offline ``run`` should set ``path_to_atomics`` to ``bundle/atomics``.
"""

from __future__ import annotations

import json
import os
import shutil
import tarfile
from pathlib import Path
from typing import Optional

from .source import ATOMICS_PATH, discover_technique_yamls, load_technique
from .serializer import write_outputs
from .transform import generate_variants
from .strategies import get_strategies
from .payloads import discover_payloads, local_exists, copy_payload, sha256_file
from . import runtime as _runtime

DEFAULT_BUNDLE = Path("outputs/release")

_REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_README = _REPO_ROOT / "README.md"


def _sha256(path: Path) -> str:
    return sha256_file(path)


def _write_manifest(bundle_dir: Path, files: list[dict]) -> Path:
    manifest = bundle_dir / "manifest.json"
    manifest.write_text(
        json.dumps({"files": files}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return manifest


def _write_run_bat(bundle_dir: Path) -> Path:
    """Emit a convenience launcher that runs the CLI via the bundled runtime."""
    bat = bundle_dir / "run_offline.bat"
    bat.write_text(
        '@echo off\r\n'
        'cd /d "%~dp0"\r\n'
        'set PY="%~dp0runtime\\python.exe"\r\n'
        'if not exist %PY% (\r\n'
        '  echo [error] bundled runtime missing: runtime\\python.exe\r\n'
        '  exit /b 1\r\n'
        ')\r\n'
        '%PY% -m atomic_reforge.cli %*\r\n',
        encoding="utf-8",
        newline="",
    )
    return bat


def _record_runtime_files(bundle_dir: Path, manifest_files: list[dict]) -> None:
    """Add every runtime-tree file to the manifest as status 'runtime'."""
    runtime_root = bundle_dir / "runtime"
    if not runtime_root.is_dir():
        return
    for f in runtime_root.rglob("*"):
        if not f.is_file():
            continue
        if "__pycache__" in f.parts or f.suffix == ".pyc":
            continue
        rel = f.relative_to(bundle_dir)
        manifest_files.append(
            {
                "path": str(rel).replace(os.sep, "/"),
                "sha256": _sha256(f),
                "size": f.stat().st_size,
                "status": "runtime",
            }
        )


def _atomics_rel(src: Path, path_to_atomics: Path) -> Optional[Path]:
    """Return path relative to the atomics root, or None if outside it."""
    try:
        return src.resolve().relative_to(path_to_atomics.resolve())
    except ValueError:
        return None


def _bundle_original_payload(
    ref,
    atomics_root: Path,
    path_to_atomics: Path,
    seen: set[str],
    manifest_files: list[dict],
    tid: str,
) -> None:
    """Copy a locally-present payload into bundle/atomics preserving layout."""
    if not local_exists(ref):
        return
    rel = _atomics_rel(ref.path, path_to_atomics)
    if rel is None:
        # Fallback: drop under payloads/<TID>/<basename>
        dest_rel = f"atomics/payloads/{tid}/{ref.path.name}"
    else:
        dest_rel = f"atomics/{rel.as_posix()}"
    if dest_rel in seen:
        return
    seen.add(dest_rel)
    # atomics_root is bundle/atomics; dest_rel starts with atomics/
    dest = atomics_root.parent / dest_rel.replace("/", os.sep)
    try:
        copied = copy_payload(ref.path, dest.parent, dest.name)
    except FileNotFoundError:
        return
    manifest_files.append(
        {
            "path": dest_rel,
            "sha256": _sha256(copied),
            "size": copied.stat().st_size,
            "status": "bundled",
            "provenance": {
                "technique_id": tid,
                "token": ref.token,
                "arg_key": ref.arg_key,
                "literal": ref.literal,
                "kind": "mirror",
            },
        }
    )
    _bundle_sibling_external(
        ref, atomics_root, path_to_atomics, seen, manifest_files, tid
    )


def _bundle_sibling_external(
    ref,
    atomics_root: Path,
    path_to_atomics: Path,
    seen: set[str],
    manifest_files: list[dict],
    tid: str,
) -> None:
    """Copy ``../ExternalPayloads/<rel>`` into ``atomics/ExternalPayloads/<rel>``.

    Variant commands are rewritten to that in-folder path at run time. Leaving
    the file only under ``payloads/<TID>/`` makes Test-Path miss it and the
    prereq then creates ``C:\\atomics\\ExternalPayloads``.
    """
    if not local_exists(ref):
        return
    sibling = Path(path_to_atomics).resolve().parent / "ExternalPayloads"
    try:
        rel = ref.path.resolve().relative_to(sibling)
    except ValueError:
        return
    dest_rel = f"atomics/ExternalPayloads/{rel.as_posix()}"
    if dest_rel in seen:
        return
    seen.add(dest_rel)
    dest = atomics_root / "ExternalPayloads" / rel
    try:
        copied = copy_payload(ref.path, dest.parent, dest.name)
    except FileNotFoundError:
        return
    manifest_files.append(
        {
            "path": dest_rel,
            "sha256": _sha256(copied),
            "size": copied.stat().st_size,
            "status": "bundled",
            "provenance": {
                "technique_id": tid,
                "token": ref.token,
                "arg_key": ref.arg_key,
                "literal": ref.literal,
                "kind": "external",
            },
        }
    )


def build_release(
    tids: list[str],
    strategies: str = "all",
    out_dir: Path = Path("outputs/variants"),
    script_dir: Path = Path("outputs/scripts"),
    bundle_dir: Path = DEFAULT_BUNDLE,
    archive: str = "none",
    path_to_atomics: Path = ATOMICS_PATH,
    bundle_runtime: bool = False,
    runtime_dir: Optional[Path] = None,
) -> dict:
    """Build the offline distribution bundle and return a summary dict.

    ``tids`` filters which techniques to include (pass [] for full scope).
    Returns {techniques, variants, files, payloads, remote_required, archive}.

    Local payloads are mirrored under ``bundle/atomics/`` so offline ``run`` can
    set ``path_to_atomics`` to that directory and resolve every
    ``PathToAtomicsFolder\\...`` reference without the original upstream tree.
    """
    strat_list = get_strategies(strategies)

    bundle_dir.mkdir(parents=True, exist_ok=True)
    atomics_root = bundle_dir / "atomics"
    atomics_root.mkdir(parents=True, exist_ok=True)
    (atomics_root / "payloads").mkdir(parents=True, exist_ok=True)

    if bundle_runtime:
        _runtime.build_runtime(
            bundle_dir / "runtime",
            embed_root=runtime_dir if runtime_dir is not None else None,
        )
        _write_run_bat(bundle_dir)

    manifest_files: list[dict] = []
    seen_payload_dests: set[str] = set()
    seen_mirrors: set[str] = set()

    # Exact technique-id match on the YAML stem (e.g. T1055.yaml / T1055.001.yaml).
    # Substring matching would wrongly pull T1055.002 when the user asked for T1055.
    tid_set = {t.strip() for t in tids if t and t.strip()}
    targets = []
    for p in discover_technique_yamls(path_to_atomics):
        if not tid_set or p.stem in tid_set:
            targets.append(p)

    total_variants = 0
    covered_tids = set()

    for path in targets:
        try:
            tech = load_technique(path)
        except Exception:
            continue
        tid = tech.attack_technique
        covered_tids.add(tid)

        technique_payloads = {}
        remote_seen = set()
        for atomic in tech.atomic_tests:
            for ref in discover_payloads(atomic, path_to_atomics):
                technique_payloads.setdefault(ref.path, ref)
                if local_exists(ref):
                    _bundle_original_payload(
                        ref,
                        atomics_root,
                        path_to_atomics,
                        seen_mirrors,
                        manifest_files,
                        tid,
                    )
                else:
                    remote_seen.add(ref.path)

        for idx, atomic in enumerate(tech.atomic_tests):
            for v in generate_variants(
                tid, atomic, idx, strat_list, path_to_atomics
            ):
                for plan in v.plans:
                    for op in getattr(plan, "payload_ops", []) or []:
                        # Rename/embed targets live under atomics/payloads/...
                        dest_rel = op.dest_rel or (
                            f"payloads/{tid}/{op.new_name}"
                        )
                        if not dest_rel.startswith("atomics/"):
                            dest_rel = f"atomics/{dest_rel}"
                        if dest_rel in seen_payload_dests:
                            continue
                        seen_payload_dests.add(dest_rel)
                        dest = bundle_dir / Path(dest_rel.replace("/", os.sep))
                        if op.kind == "copy_rename":
                            try:
                                copied = copy_payload(
                                    op.src_path, dest.parent, op.new_name
                                )
                            except FileNotFoundError:
                                manifest_files.append(
                                    {
                                        "path": dest_rel,
                                        "status": "remote_required",
                                        "provenance": _provenance(
                                            tid, v, op
                                        ),
                                    }
                                )
                                continue
                            manifest_files.append(
                                {
                                    "path": dest_rel,
                                    "sha256": _sha256(copied),
                                    "size": copied.stat().st_size,
                                    "status": "bundled",
                                    "provenance": _provenance(tid, v, op),
                                }
                            )
                        else:
                            manifest_files.append(
                                {
                                    "path": dest_rel,
                                    "status": "embedded",
                                    "provenance": _provenance(tid, v, op),
                                }
                            )

                for ref in discover_payloads(v.new_atomic, path_to_atomics):
                    if local_exists(ref):
                        _bundle_original_payload(
                            ref,
                            atomics_root,
                            path_to_atomics,
                            seen_mirrors,
                            manifest_files,
                            tid,
                        )
                written = write_outputs(
                    v,
                    out_dir=bundle_dir / "variants",
                    script_dir=bundle_dir / "scripts",
                )
                for kind, p in written.items():
                    rel = p.relative_to(bundle_dir)
                    manifest_files.append(
                        {
                            "path": str(rel).replace(os.sep, "/"),
                            "sha256": _sha256(p),
                            "size": p.stat().st_size,
                            "status": "generated",
                            "provenance": {
                                "technique_id": tid,
                                "variant_guid": v.variant_guid,
                                "kind": kind,
                            },
                        }
                    )
                total_variants += 1

        for p in sorted(remote_seen, key=str):
            ref = technique_payloads[p]
            manifest_files.append(
                {
                    "path": str(p),
                    "status": "remote_required",
                    "download_url": ref.download_url,
                    "provenance": {
                        "technique_id": tid,
                        "token": ref.token,
                        "arg_key": ref.arg_key,
                        "literal": ref.literal,
                    },
                }
            )

    try:
        readme_dest = bundle_dir / "README.md"
        shutil.copy2(PROJECT_README, readme_dest)
        manifest_files.append(
            {
                "path": "README.md",
                "sha256": _sha256(readme_dest),
                "size": readme_dest.stat().st_size,
                "status": "generated",
            }
        )
    except OSError:
        pass

    _write_manifest(bundle_dir, manifest_files)

    if bundle_runtime:
        _record_runtime_files(bundle_dir, manifest_files)
        _write_manifest(bundle_dir, manifest_files)

    archive_out = None
    if archive in ("zip", "tar.gz"):
        if archive == "zip":
            archive_out = shutil.make_archive(str(bundle_dir), "zip", bundle_dir)
        else:
            archive_out = str(bundle_dir) + ".tar.gz"
            with tarfile.open(archive_out, "w:gz") as tf:
                for child in bundle_dir.iterdir():
                    if child.is_dir():
                        for f in child.rglob("*"):
                            if f.is_file():
                                tf.add(f, arcname=f.relative_to(bundle_dir))
                    else:
                        tf.add(child, arcname=child.name)

    n_bundled = sum(1 for f in manifest_files if f.get("status") == "bundled")
    n_remote = sum(1 for f in manifest_files if f.get("status") == "remote_required")
    n_runtime = sum(1 for f in manifest_files if f.get("status") == "runtime")

    return {
        "techniques": len(covered_tids),
        "technique_ids": sorted(covered_tids),
        "variants": total_variants,
        "files": len(manifest_files),
        "payloads_bundled": n_bundled,
        "remote_required": n_remote,
        "runtime_bundled": bool(bundle_runtime),
        "runtime_files": n_runtime,
        "bundle_dir": str(bundle_dir),
        "manifest": str(bundle_dir / "manifest.json"),
        "archive": archive_out,
        "atomics_root": str(atomics_root),
    }


def _provenance(tid: str, variant, op) -> dict:
    return {
        "technique_id": tid,
        "variant_guid": variant.variant_guid,
        "arg_key": op.arg_key,
        "token": op.token,
        "kind": op.kind,
    }
