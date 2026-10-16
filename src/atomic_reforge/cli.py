"""atomic-reforge CLI (Typer)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from . import result_log
from .report import render_csv, render_markdown
from .release import DEFAULT_BUNDLE, build_release
from .serializer import write_outputs
from .source import ATOMICS_PATH, discover_technique_yamls, load_technique
from .strategies import get_strategies
from .transform import generate_variants

app = typer.Typer(
    name="atomic-reforge",
    help="Deform MITRE atomic-red-team tests into same-intent variants "
    "(Windows PowerShell subset) to assess EDR detection coverage.",
    add_completion=False,
)

DEFAULT_OUT = Path("outputs/variants")
DEFAULT_SCRIPTS = Path("outputs/scripts")
DEFAULT_REPORT = Path("outputs/report.md")


def _scope_filter(platform: Optional[str], executor: Optional[str]):
    pass


@app.command("list")
def list_cmd(
    platform: Optional[str] = typer.Option(
        None, "--platform", help="Filter by supported_platforms (e.g. windows)"
    ),
    executor: Optional[str] = typer.Option(
        None, "--executor", help="Filter by executor name (powershell)"
    ),
) -> None:
    """List in-scope techniques/atomics matching the filters."""
    from .transform import WINDOWS_EXECUTORS

    total_tech = 0
    total_atomic = 0
    for path in discover_technique_yamls():
        try:
            tech = load_technique(path)
        except Exception:
            continue
        hit = []
        for atomic in tech.atomic_tests:
            if platform and platform not in atomic.supported_platforms:
                continue
            ex_name = getattr(atomic.executor, "name", None)
            if executor and ex_name != executor:
                continue
            hit.append(atomic)
        if hit:
            total_tech += 1
            total_atomic += len(hit)
            for atomic in hit:
                typer.echo(
                    f"{tech.attack_technique}\t{atomic.name}\t"
                    f"{getattr(atomic.executor, 'name', '?')}"
                )
    typer.echo(f"\n{total_tech} techniques, {total_atomic} atomics in scope")


@app.command("generate")
def generate_cmd(
    tid: Optional[str] = typer.Argument(
        None, help="Technique id, e.g. T1059.001 (omit to scan all in scope)"
    ),
    strategies: Optional[str] = typer.Option(
        "all", "--strategies", help="Comma-separated strategy names, or 'all'"
    ),
    out: Path = typer.Option(
        DEFAULT_OUT, "--out", help="Output dir for variant YAMLs"
    ),
    script_dir: Path = typer.Option(
        DEFAULT_SCRIPTS, "--scripts", help="Output dir for resolved scripts"
    ),
) -> None:
    """Generate variants for a technique (or the whole scope)."""
    targets = (
        [p for p in discover_technique_yamls() if f"/{tid}" in str(p) or tid in str(p)]
        if tid
        else discover_technique_yamls()
    )
    strat_list = get_strategies(strategies)
    typer.echo(f"strategies: {[s.name for s in strat_list]}")
    total = 0
    for path in targets:
        try:
            tech = load_technique(path)
        except Exception as e:
            typer.echo(f"skip {path.name}: {e}", err=True)
            continue
        for idx, atomic in enumerate(tech.atomic_tests):
            for v in generate_variants(
                tech.attack_technique, atomic, idx, strat_list
            ):
                write_outputs(v, out, script_dir)
                total += 1
    typer.echo(f"wrote {total} variants -> {out} / {script_dir}")


@app.command("report")
def report_cmd(
    out: Path = typer.Option(
        DEFAULT_OUT, "--path", help="Variant YAML output dir (rescan)"
    ),
    format: str = typer.Option("md", "--format", help="md or csv"),
    output: Path = typer.Option(
        DEFAULT_REPORT, "--output", help="Report file path"
    ),
) -> None:
    """Regenerate the comparison table from a generated variant tree.

    Since variants on disk are standalone YAMLs (not live Variant objects),
    this command re-derives the table by re-running generation in memory for
    the same scope so we have full traceability metadata.
    """
    # Simplest correct source of metadata: regenerate in memory for the scope
    # and map script paths by variant guid. This keeps the report authoritative
    # without depending on the on-disk layout.
    from .strategies import get_strategies as _gs

    strat_list = _gs("all")
    all_variants = []
    scripts = {}
    for path in discover_technique_yamls():
        try:
            tech = load_technique(path)
        except Exception:
            continue
        for idx, atomic in enumerate(tech.atomic_tests):
            for v in generate_variants(
                tech.attack_technique, atomic, idx, strat_list
            ):
                w = write_outputs(v, out, DEFAULT_SCRIPTS)
                scripts[v.variant_guid] = w.get("script")
                all_variants.append(v)

    output.parent.mkdir(parents=True, exist_ok=True)
    if format == "csv":
        output.write_text(render_csv(all_variants, scripts), encoding="utf-8")
    else:
        output.write_text(
            render_markdown(all_variants, scripts), encoding="utf-8"
        )
    typer.echo(f"report ({format}, {len(all_variants)} rows) -> {output}")


@app.command("release")
def release_cmd(
    tids: list[str] = typer.Argument(
        None, help="Technique ids to include (omit to scan full scope)"
    ),
    strategies: Optional[str] = typer.Option(
        "all", "--strategies", help="Comma-separated strategy names, or 'all'"
    ),
    bundle: Path = typer.Option(
        DEFAULT_BUNDLE, "--bundle", help="Output bundle dir"
    ),
    archive: str = typer.Option(
        "none", "--archive", help="none, zip, or tar.gz"
    ),
    bundle_runtime: bool = typer.Option(
        False,
        "--bundle-runtime",
        help="Bundle a portable embeddable Python runtime + run_offline.bat",
    ),
    runtime_dir: Optional[Path] = typer.Option(
        None,
        "--runtime-dir",
        help="Reuse a pre-built embed root dir instead of downloading one",
    ),
) -> None:
    """Build an offline distribution bundle (variants + payloads + manifest)."""
    summary = build_release(
        tids=list(tids) if tids else [],
        strategies=strategies,
        bundle_dir=bundle,
        archive=archive,
        bundle_runtime=bundle_runtime,
        runtime_dir=runtime_dir,
    )
    typer.echo(
        f"release: {summary['variants']} variant(s) across "
        f"{summary['techniques']} technique(s)"
    )
    typer.echo(
        f"  payloads bundled: {summary['payloads_bundled']}, "
        f"remote_required: {summary['remote_required']}"
    )
    if summary.get("runtime_bundled"):
        typer.echo(
            f"  runtime bundled: {summary['runtime_files']} file(s) "
            f"+ run_offline.bat launcher"
        )
    typer.echo(f"  bundle -> {summary['bundle_dir']}")
    if summary.get("archive"):
        typer.echo(f"  archive -> {summary['archive']}")


# CSV columns for the run log (kept in sync with the runner's LogRecord).
_RUNLOG_CSV_COLUMNS = [
    "technique_id",
    "variant_guid",
    "variant_name",
    "test_index",
    "executor",
    "branch",
    "exit_code",
    "timed_out",
    "duration_s",
    "had_error",
    "simulated",
    "command",
]


def _verify_integrity(path: Path) -> None:
    """Verify all hashed manifest entries under the variant root's bundle.

    Reads ``manifest.json`` in the directory above the variant root (the bundle
    dir) and checks every entry that recorded a sha256 (generated/bundled/
    runtime) matches what's on disk. Exits nonzero on any mismatch/missing
    file, so a tampered or incomplete offline bundle aborts before running.
    """
    if not path.is_dir():
        path = DEFAULT_OUT
    manifest = path.parent / "manifest.json"
    if not manifest.is_file():
        from .source import ATOMICS_PATH

        # No bundle manifest here; allow run only when we're pointed at the
        # ref atomics tree (dev mode), else warn.
        if path != ATOMICS_PATH:
            typer.echo(
                "[integrity] no manifest.json found next to --path; skipping check",
                err=True,
            )
        return

    import json

    from .payloads import sha256_file

    data = json.loads(manifest.read_text(encoding="utf-8"))
    bad = []
    checked = 0
    for f in data.get("files", []):
        sha = f.get("sha256")
        if not sha:
            continue
        p = path.parent / Path(f["path"].replace("/", "\\"))
        if not p.is_file():
            bad.append(f"{f['path']}: missing")
            continue
        if sha256_file(p) != sha:
            bad.append(f"{f['path']}: hash mismatch")
        checked += 1
    if bad:
        typer.echo(f"[integrity] FAILED: {len(bad)} problem(s)", err=True)
        for b in bad:
            typer.echo(f"  - {b}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"[integrity] OK: {checked} file(s) verified against manifest")


def _technique_files(root: Path, tid: str | None) -> list[Path]:
    """Technique YAMLs under ``root``. ``all`` or empty selects every technique."""
    files = discover_technique_yamls(root)
    if not tid or tid.strip().lower() == "all":
        return files
    want = tid.strip()
    return [p for p in files if p.parent.name == want]


@app.command("run")
def run_cmd(
    tid: Optional[str] = typer.Argument(
        None,
        help="Technique id (T1059.001). Omit or pass 'all' to run every technique under --path",
    ),
    variant_guid: Optional[str] = typer.Option(
        None, "--variant-guid", help="Only run this variant guid (default: all)"
    ),
    test_num: Optional[int] = typer.Option(
        None, "--test-num", help="Only run 1-based test index"
    ),
    test_name: Optional[str] = typer.Option(
        None, "--test-name", help="Only run test with matching display name"
    ),
    test_guid: Optional[str] = typer.Option(
        None, "--test-guid", help="Only run test with matching source guid"
    ),
    execute: bool = typer.Option(
        False, "--execute", help="Actually launch subprocesses (default: dry-run)"
    ),
    check_prereqs: bool = typer.Option(
        False, "--check-prereqs", help="Run dependency prereq checks only"
    ),
    get_prereqs: bool = typer.Option(
        False, "--get-prereqs", help="Attempt to satisfy prerequisites, then run"
    ),
    cleanup: bool = typer.Option(
        False, "--cleanup", help="Run the executor cleanup command only"
    ),
    allow_download: bool = typer.Option(
        False,
        "--allow-download",
        help="Allow networked get_prereq_command even when payloads are local",
    ),
    input_args: Optional[str] = typer.Option(
        None, "--input-args", help="Comma-separated k=v overrides for #{arg}"
    ),
    timeout: int = typer.Option(
        120, "--timeout", help="Per-command timeout in seconds"
    ),
    path: Path = typer.Option(
        DEFAULT_OUT, "--path", help="Variant YAML root dir to scan"
    ),
    log: Optional[Path] = typer.Option(
        None, "--log", help="Append CSV run log path (default: none)"
    ),
    log_dir: Optional[Path] = typer.Option(
        None,
        "--log-dir",
        help=f"Execution log dir (default: {result_log.DEFAULT_LOG_DIR})",
    ),
    no_log: bool = typer.Option(
        False, "--no-log", help="Disable file execution logging (screen only)"
    ),
    check_integrity: bool = typer.Option(
        False,
        "--check-integrity",
        help="Verify manifest.json sha256s for the variant root before running",
    ),
) -> None:
    """Schedule in-scope variants (dry-run by default) and record results.

    Without --execute nothing is launched; each match only prints its argv and
    logs a simulated record. With --execute, commands run under --timeout.
    """
    from .runner import (
        RunConfig,
        platform_supported,
        run_atomic,
        target_info,
    )

    _platform, _ = target_info()

    # Verify bundle integrity against manifest.json (if present) before doing
    # any work, so a tampered or incomplete offline bundle aborts early.
    if check_integrity:
        _verify_integrity(path)

    # Resolve execution log dir (may fall back on permission failure) unless
    # logging is disabled.
    eff_log_dir = None
    if not no_log:
        resolved = result_log.resolve_log_dir(log_dir)
        eff_log_dir = resolved
        typer.echo(f"execution log dir -> {resolved}")

    custom_args: dict[str, str] = {}
    if input_args:
        for pair in input_args.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                custom_args[k.strip()] = v.strip()

    cfg = RunConfig(
        execute=execute,
        input_args=custom_args,
        timeout=timeout,
        check_prereqs=check_prereqs,
        get_prereqs=get_prereqs,
        cleanup=cleanup,
        allow_download=allow_download,
    )
    setattr(cfg, "_log_dir", eff_log_dir)
    setattr(cfg, "_session_stamp", result_log.session_stamp())

    # Resolve the variant root to scan. On an offline runtime the ref-derived
    # ATOMICS_PATH points at nothing real, so an explicit --path to a variant
    # tree takes precedence; otherwise fall back to the atomics scan.
    explicit = path != DEFAULT_OUT and path.is_dir()
    variant_root = path if explicit else DEFAULT_OUT

    # Release bundles ship payloads under <bundle>/atomics/. Prefer that root
    # so PathToAtomicsFolder and rename defaults resolve offline.
    bundle_atomics = None
    if variant_root.is_dir():
        if variant_root.name == "variants":
            candidate = variant_root.parent / "atomics"
        else:
            candidate = variant_root / "atomics"
        if candidate.is_dir():
            bundle_atomics = candidate
        elif (variant_root.parent / "atomics").is_dir():
            bundle_atomics = variant_root.parent / "atomics"
    if bundle_atomics is not None:
        cfg.path_to_atomics = bundle_atomics.resolve()
        typer.echo(f"path_to_atomics -> {cfg.path_to_atomics}")

    targets = _technique_files(variant_root, tid) if variant_root.is_dir() else []
    # Fallback: explicit root yielded nothing (missing offline tree).
    if not targets:
        targets = _technique_files(ATOMICS_PATH, tid)
    csv_fh = open(log, "a", encoding="utf-8", newline="") if log else None
    if csv_fh:
        import csv as _csv

        empty = csv_fh.tell() == 0
        writer = _csv.DictWriter(csv_fh, fieldnames=_RUNLOG_CSV_COLUMNS)
        if empty:
            writer.writeheader()
    else:
        writer = None

    def emit_csv(rec_status: dict, command: str) -> None:
        if writer is not None:
            row = {c: rec_status.get(c, "") for c in _RUNLOG_CSV_COLUMNS}
            row["command"] = command
            writer.writerow(row)
            csv_fh.flush()

    total = 0
    for path in targets:
        try:
            tech = load_technique(path)
        except Exception as e:
            typer.echo(f"skip {path.name}: {e}", err=True)
            continue
        for idx, atomic in enumerate(tech.atomic_tests):
            # Skip executors that can't run on this platform (manual, and
            # sh/bash on windows / command_prompt on nix) mirroring upstream.
            if not platform_supported(atomic, _platform):
                continue
            # Test-selection filters (align Invoke-AtomicTest).
            if test_num is not None and idx + 1 != test_num:
                continue
            if test_name and test_name not in (atomic.name or ""):
                continue
            if test_guid and str(atomic.auto_generated_guid) != test_guid:
                continue
            if variant_guid:
                # Only run when this technique directory contains the variant.
                matched = list(path.parent.glob(f"*-{variant_guid[:8]}.yaml"))
                if not matched:
                    typer.echo(
                        f"[dry-run/skip] no variant {variant_guid} for {atomic.name}",
                        err=True,
                    )
                    continue

            res = run_atomic(
                atomic,
                tech.attack_technique,
                cfg,
                variant_guid=variant_guid or "",
                variant_name=atomic.name or "",
                test_index=idx,
            )
            # Mirror each emitted log record into the run CSV.
            for entry in res.prereqs:
                er = entry["exec_result"]
                emit_csv(
                    {
                        "technique_id": tech.attack_technique,
                        "variant_guid": variant_guid or "",
                        "variant_name": atomic.name or "",
                        "test_index": idx,
                        "executor": res.executor,
                        "branch": "prereq",
                        "exit_code": er.exit_code,
                        "timed_out": er.timed_out,
                        "duration_s": er.duration_s,
                        "had_error": er.had_error,
                        "simulated": not execute,
                    },
                    entry.get("description", ""),
                )
                total += 1
            if res.cleanup_res is not None:
                cr = res.cleanup_res
                emit_csv(
                    {
                        "technique_id": tech.attack_technique,
                        "variant_guid": variant_guid or "",
                        "variant_name": atomic.name or "",
                        "test_index": idx,
                        "executor": res.executor,
                        "branch": "cleanup",
                        "exit_code": cr.exit_code,
                        "timed_out": cr.timed_out,
                        "duration_s": cr.duration_s,
                        "had_error": cr.had_error,
                        "simulated": not execute,
                    },
                    atomic.name or "",
                )
                total += 1
            m = res.main
            emit_csv(
                {
                    "technique_id": tech.attack_technique,
                    "variant_guid": variant_guid or "",
                    "variant_name": atomic.name or "",
                    "test_index": idx,
                    "executor": res.executor,
                    "branch": "main",
                    "exit_code": m.exit_code,
                    "timed_out": m.timed_out,
                    "duration_s": m.duration_s,
                    "had_error": m.had_error,
                    "simulated": not execute,
                },
                atomic.executor.command or "",
            )
            total += 1

    if csv_fh:
        csv_fh.close()
    typer.echo(f"ran {total} command(s) for {len(targets)} technique file(s)")


if __name__ == "__main__":
    app()
