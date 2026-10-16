"""Execution-process logging: human-readable .log + machine-parsable .json.

Every execution (or dry-run simulation) produces a single record written to
both files under a default directory of C:\\ProgramData\\atomic_reforge_logs.
File basenames carry the timestamp and, when known, the TTP number
(e.g. run-20261013-120000-T1059.001.log / .json).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

DEFAULT_LOG_DIR = Path(r"C:\ProgramData\atomic_reforge_logs")
_FALLBACK_DIR = Path.home() / ".atomic_reforge_logs"


@dataclass
class LogRecord:
    """One executed (or simulated) command."""

    timestamp: str  # ISO8601 UTC
    technique_id: str
    variant_guid: str
    variant_name: str
    test_index: int | None
    executor: str
    branch: str  # prereq / main / cleanup
    dependency_index: int | None
    simulated: bool
    command: str
    argv: str | None
    exit_code: int | None
    timed_out: bool
    duration_s: float
    stdout: str
    stderr: str
    had_error: bool


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_log_dir(override: Path | None = None) -> Path:
    """Pick a writable log directory, creating it if needed.

    Prefers an explicit override, else DEFAULT_LOG_DIR. If the directory
    cannot be created/written, falls back to ~/.atomic_reforge_logs and
    prints a notice.
    """
    candidates = []
    if override is not None:
        candidates.append(Path(override))
    candidates.append(DEFAULT_LOG_DIR)
    candidates.append(_FALLBACK_DIR)

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # Probe writability with a throwaway file.
            probe = candidate / ".write_test"
            probe.write_text("", encoding="utf-8")
            probe.unlink()
            return candidate
        except OSError:
            continue

    raise RuntimeError(
        f"Could not create any log directory (tried {candidates})"
    )


def session_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def run_prefix(technique_id: str = "", stamp: str = "") -> str:
    """Base filename for a run: timestamp plus the TTP number when known."""
    tid = (technique_id or "").strip()
    stamp = stamp or session_stamp()
    if tid and tid.lower() != "all":
        safe = "".join(c for c in tid if c.isalnum() or c in "._-")
        return f"run-{stamp}-{safe}"
    return f"run-{stamp}"


def session_files(
    log_dir: Path, technique_id: str = "", stamp: str = ""
) -> tuple[Path, Path]:
    """Return (log_path, json_path) using a shared per-session timestamp and,
    when a TTP id is supplied, including it in the basename."""
    prefix = run_prefix(technique_id, stamp)
    return log_dir / f"{prefix}.log", log_dir / f"{prefix}.json"


def _human_line(rec: LogRecord) -> str:
    flag = "sim" if rec.simulated else "exec"
    timeout = "yes" if rec.timed_out else "no"
    exit_part = "exit=-" if rec.exit_code is None else f"exit={rec.exit_code}"
    return (
        f"{rec.timestamp} | {flag} | {rec.technique_id} | "
        f"{rec.variant_guid} | {rec.branch} | {exit_part} | "
        f"timeout={timeout} | {rec.duration_s:.2f}s | {rec.command}"
    )


def write_log_record(
    log_dir: Path | None,
    record: LogRecord,
    log_fh: TextIO | None = None,
    ndjson_fh: TextIO | None = None,
    technique_id: str = "",
    stamp: str = "",
) -> None:
    """Write a record to a human-readable line and a JSON lines file.

    Handles both per-session file handles (from the CLI) and on-demand
    opens, so callers can use whichever is convenient. When opened
    on-demand, the TTP number (if any) is folded into the basename.
    """

    def write_json(fh: TextIO) -> None:
        fh.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")

    if log_fh is not None:
        log_fh.write(_human_line(record) + "\n")
    if ndjson_fh is not None:
        write_json(ndjson_fh)
        return

    if log_dir is None:
        return
    log_dir.mkdir(parents=True, exist_ok=True)
    tid = (technique_id or record.technique_id or "").strip()
    log_path, ndjson_path = session_files(log_dir, tid, stamp)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(_human_line(record) + "\n")
    with open(ndjson_path, "a", encoding="utf-8") as fh:
        write_json(fh)


def open_session(
    log_dir: Path | None, technique_id: str = ""
) -> tuple[TextIO | None, TextIO | None]:
    """Open per-session .log/.json handles, or (None, None) if disabled.

    ``technique_id`` (a TTP number, e.g. T1059.001) is included in the
    basename when provided.
    """
    if log_dir is None:
        return None, None
    log_path, ndjson_path = session_files(log_dir, technique_id)
    log_fh = open(log_path, "w", encoding="utf-8")
    ndjson_fh = open(ndjson_path, "w", encoding="utf-8")
    return log_fh, ndjson_fh


def used_fallback(log_dir: Path, override: Path | None = None) -> bool:
    """True if the effective dir isn't the requested/default one."""
    return log_dir != Path(override) if override is not None else True
