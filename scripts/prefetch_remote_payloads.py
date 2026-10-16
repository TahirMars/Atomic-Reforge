#!/usr/bin/env python3
"""Prefetch remote http(s) payloads into atomics ExternalPayloads cache.

Scans Atomic Red Team YAMLs for URLs used in commands / args / dependencies,
then either:

* ``--list`` — write a CSV + PowerShell ``Invoke-WebRequest`` helper for *manual* download
* ``--download`` — ensure cache (ART local copy first, then network + mirrors)

Cache layout (must match ``atomic_reforge.localize``)::

    ref/atomic-red-team-master/atomics/ExternalPayloads/reforge_remote/<sha12>/<file>

URLs that already map to files under the local ART ``atomics/T...`` tree are
copied into this cache (status ``COPY_ART``) — no manual download needed.
Only truly external missing URLs appear in ``download_manual.ps1``.

Examples::

    # Full Windows in-scope inventory + manual download helpers
    uv run python scripts/prefetch_remote_payloads.py --list

    # Only selected techniques
    uv run python scripts/prefetch_remote_payloads.py --list --tid T1059.001 --tid T1082

    # Fill cache: copy ART locals + download the rest
    set ATOMIC_REFORGE_GITHUB_MIRROR=https://ghproxy.net/
    uv run python scripts/prefetch_remote_payloads.py --download
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

# Allow running without install: add src/ to path
_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from atomic_reforge.localize import (  # noqa: E402
    art_local_path,
    concrete_urls,
    discover_external_rels,
    discover_urls,
    ensure_external_rel,
    ensure_remote_cached,
    github_mirror_candidates,
    remote_cache_paths,
    unique_external_named,
)
from atomic_reforge.source import ATOMICS_PATH, discover_technique_yamls, load_technique  # noqa: E402
from atomic_reforge.transform import in_scope  # noqa: E402


def _arg_default(argdef):
    if isinstance(argdef, dict):
        return argdef.get("default")
    return getattr(argdef, "default", None)


def _classify(url: str, dest: Path) -> str:
    """OK | COPY_ART | COPY_EXT | MISSING — without mutating the cache."""
    if dest.is_file() and dest.stat().st_size > 0:
        return "OK"
    if art_local_path(url, ATOMICS_PATH) is not None:
        return "COPY_ART"
    name = dest.name
    if unique_external_named(ATOMICS_PATH, name) is not None:
        return "COPY_EXT"
    return "MISSING"


def collect_urls(
    tids: list[str] | None,
    *,
    windows_only: bool,
) -> tuple[dict[str, dict], set[str]]:
    """Return (url map, ExternalPayloads relative paths referenced by tokens)."""
    tid_set = {t.strip() for t in (tids or []) if t.strip()}
    found: dict[str, dict] = {}
    ext_rels: set[str] = set()

    for path in discover_technique_yamls():
        if tid_set and path.stem not in tid_set:
            continue
        try:
            tech = load_technique(path)
        except Exception:
            continue
        tid = tech.attack_technique
        for atomic in tech.atomic_tests:
            if windows_only and not in_scope(atomic):
                continue
            texts: list[str | None] = [
                getattr(atomic.executor, "command", None),
                getattr(atomic.executor, "cleanup_command", None),
            ]
            for dep in atomic.dependencies or []:
                texts.append(getattr(dep, "prereq_command", None))
                texts.append(getattr(dep, "get_prereq_command", None))
            for argdef in (atomic.input_arguments or {}).values():
                d = _arg_default(argdef)
                if d is not None:
                    texts.append(str(d))
            for rel in discover_external_rels(*texts):
                ext_rels.add(rel)
            arg_defs = atomic.input_arguments or {}
            for raw_url in discover_urls(*texts):
                pairs = concrete_urls(raw_url, arg_defs, ATOMICS_PATH) or [
                    (raw_url, raw_url)
                ]
                for _rewrite_key, url in pairs:
                    dest, token = remote_cache_paths(url, ATOMICS_PATH)
                    entry = found.setdefault(
                        url,
                        {
                            "tids": set(),
                            "dest": dest,
                            "token": token,
                            "status": _classify(url, dest),
                        },
                    )
                    entry["tids"].add(tid)
                    entry["status"] = _classify(url, dest)
    return found, ext_rels


def write_helpers(found: dict[str, dict], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "remote_payloads.csv"
    ps1_path = out_dir / "download_manual.ps1"
    bat_path = out_dir / "download_manual.bat"
    md_path = out_dir / "README_prefetch.md"

    status_rank = {"MISSING": 0, "COPY_EXT": 1, "COPY_ART": 2, "OK": 3}
    rows = sorted(
        found.items(),
        key=lambda kv: (
            status_rank.get(kv[1]["status"], 9),
            sorted(kv[1]["tids"])[0],
            kv[0],
        ),
    )

    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["status", "url", "dest", "mirror_hint", "techniques"])
        for url, info in rows:
            mirrors = github_mirror_candidates(url)
            hint = mirrors[1] if len(mirrors) > 1 else mirrors[0]
            w.writerow(
                [
                    info["status"],
                    url,
                    str(info["dest"]),
                    hint,
                    ",".join(sorted(info["tids"])),
                ]
            )

    ps_lines = [
        "# Auto-generated by scripts/prefetch_remote_payloads.py",
        "# Downloads MISSING remote payloads into the reforge_remote cache.",
        "# Uses native Invoke-WebRequest only (no curl.exe).",
        "# COPY_ART / OK rows are omitted — run --download to copy ART locals.",
        "$ErrorActionPreference = 'Continue'",
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
        "",
        "function Save-RemoteFile {",
        "  param([string]$Uri, [string]$OutFile)",
        "  try {",
        "    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 120",
        "    return ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 0))",
        "  } catch {",
        "    Write-Warning $_.Exception.Message",
        "    return $false",
        "  }",
        "}",
        "",
    ]
    bat_lines = [
        "@echo off",
        "REM Auto-generated by scripts/prefetch_remote_payloads.py",
        "REM Launches download_manual.ps1 (native Invoke-WebRequest; no curl.exe).",
        "setlocal",
        'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0download_manual.ps1"',
        "exit /b %ERRORLEVEL%",
        "",
    ]
    missing = 0
    for url, info in rows:
        if info["status"] != "MISSING":
            continue
        missing += 1
        dest: Path = info["dest"]
        mirrors = github_mirror_candidates(url)
        fetch_url = mirrors[1] if len(mirrors) > 1 else url
        dest_posix = str(dest).replace("'", "''")
        fetch_esc = fetch_url.replace("'", "''")
        origin_esc = url.replace("'", "''")
        ps_lines.append(f"# TIDs: {', '.join(sorted(info['tids']))}")
        ps_lines.append(f"$dest = '{dest_posix}'")
        ps_lines.append("New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null")
        ps_lines.append(
            f"Write-Host 'GET {fetch_esc}'\n"
            f"if (-not (Save-RemoteFile -Uri '{fetch_esc}' -OutFile $dest)) {{\n"
            f"  Write-Host 'fallback origin: {origin_esc}'\n"
            f"  [void](Save-RemoteFile -Uri '{origin_esc}' -OutFile $dest)\n"
            f"}}\n"
        )

    ps1_path.write_text("\n".join(ps_lines) + "\n", encoding="utf-8")
    bat_path.write_text("\r\n".join(bat_lines) + "\r\n", encoding="utf-8")

    n_ok = sum(1 for _, i in rows if i["status"] == "OK")
    n_copy = sum(1 for _, i in rows if i["status"] == "COPY_ART")
    n_ext = sum(1 for _, i in rows if i["status"] == "COPY_EXT")
    md_path.write_text(
        "\n".join(
            [
                "# Remote payload prefetch",
                "",
                f"- Atomcs root: `{ATOMICS_PATH}`",
                f"- Unique URLs: **{len(rows)}**",
                f"- Already in cache (OK): **{n_ok}**",
                f"- Copy from local ART (COPY_ART): **{n_copy}**",
                f"- Copy from ../ExternalPayloads (COPY_EXT): **{n_ext}**",
                f"- Need network (MISSING): **{missing}**",
                "",
                "All localized remotes land under:",
                "",
                "```",
                "atomics/ExternalPayloads/reforge_remote/<sha12>/<filename>",
                "```",
                "",
                "## Fill cache without browsing",
                "",
                "```",
                "uv run python scripts/prefetch_remote_payloads.py --download",
                "```",
                "",
                "This copies `COPY_ART` from the local ART tree, then downloads `MISSING`",
                "(with GitHub mirrors).",
                "",
                "## Manual download (MISSING only)",
                "",
                "1. Open `remote_payloads.csv` — rows with `MISSING`.",
                "2. Run `download_manual.ps1` **or** `download_manual.bat` (Invoke-WebRequest).",
                "3. Or browser-download each URL and save exactly to the `dest` path.",
                "",
                "After files are in place, `atomic-reforge release` / `generate` reuse the",
                "cache and rewrite commands to `PathToAtomicsFolder\\ExternalPayloads\\reforge_remote\\...`.",
                "",
                "Optional mirror env:",
                "",
                "```",
                "set ATOMIC_REFORGE_GITHUB_MIRROR=https://ghproxy.net/,https://mirror.ghproxy.com/",
                "```",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"wrote {csv_path}")
    print(f"wrote {ps1_path}")
    print(f"wrote {bat_path}")
    print(f"wrote {md_path}")
    print(
        f"summary: total={len(rows)} OK={n_ok} COPY_ART={n_copy} "
        f"COPY_EXT={n_ext} MISSING={missing}"
    )


def auto_download(found: dict[str, dict]) -> None:
    by_src = defaultdict(int)
    fail = 0
    for url, info in sorted(found.items(), key=lambda kv: kv[0]):
        status = info["status"]
        if status == "OK":
            by_src["cache"] += 1
            continue
        label = status.lower() if status in ("COPY_ART", "COPY_EXT") else "download"
        print(f"[{label}] {url}")
        ensured = ensure_remote_cached(url, ATOMICS_PATH, download=True)
        if ensured is None:
            fail += 1
            print("  -> FAIL")
            continue
        _, dest_token, source = ensured
        by_src[source] += 1
        print(f"  -> {source} {info['dest'].name} ({dest_token})")
    print(
        "done: "
        f"cache={by_src['cache']} copy_art={by_src['copy_art']} "
        f"download={by_src['download']} failed={fail}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--tid",
        action="append",
        default=[],
        help="Technique id filter (repeatable). Default: all YAMLs.",
    )
    ap.add_argument(
        "--all-platforms",
        action="store_true",
        help="Include non-Windows / out-of-scope atomics (default: Windows powershell/cmd only).",
    )
    ap.add_argument(
        "--list",
        action="store_true",
        help="Write CSV + manual download scripts (default if neither --list nor --download).",
    )
    ap.add_argument(
        "--download",
        action="store_true",
        help="Fill cache: copy ART locals first, then download missing (GitHub mirrors).",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=_REPO / "ref" / "remote_prefetch",
        help="Directory for CSV/ps1/bat helpers (default: ref/remote_prefetch)",
    )
    args = ap.parse_args()
    do_list = args.list or not args.download
    do_download = args.download

    print(f"ATOMICS_PATH={ATOMICS_PATH}")
    found, ext_rels = collect_urls(args.tid, windows_only=not args.all_platforms)
    if not found:
        print("no remote URLs found")
        return 0

    by_tid = defaultdict(int)
    for info in found.values():
        for t in info["tids"]:
            by_tid[t] += 1
    print(f"unique_urls={len(found)} techniques_touched={len(by_tid)}")

    if do_list:
        # Materialize ART-local copies into reforge_remote so the cache reflects
        # what generate/release will use — no network, COPY_ART only.
        seeded = 0
        for url, info in found.items():
            if info["status"] not in ("COPY_ART", "COPY_EXT"):
                continue
            if ensure_remote_cached(url, ATOMICS_PATH, download=False):
                seeded += 1
                info["status"] = "OK"
        ext_seeded = 0
        for rel in sorted(ext_rels):
            if ensure_external_rel(rel, ATOMICS_PATH):
                ext_seeded += 1
        if seeded or ext_seeded:
            print(
                f"seeded_copy={seeded} seeded_ext_paths={ext_seeded} into reforge_remote"
            )
        write_helpers(found, args.out)
    if do_download:
        auto_download(found)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
