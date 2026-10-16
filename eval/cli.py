"""Offline NGES evaluation CLI: ``python -m eval``."""

from __future__ import annotations

import glob
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer

from .atomic_logs import load_from_path
from .match import MatchConfig, match_episodes
from .nges.parse import load_events
from .report import build_payload, write_reports

app = typer.Typer(
    name="eval",
    help="对照 atomic-reforge 执行日志与 NGES 遥测，生成检出测评报告。",
    add_completion=False,
)

DEFAULT_OUT = Path("outputs/eval")

# 87bc…_telemetry.log / 87bc…_2_telemetry.log / 87bc…_alert.log / 87bc…_2_alert.log
_NGES_LOG_NAME = re.compile(
    r"^(?P<agent>.+?)(?:_(?P<part>\d+))?_(?P<kind>telemetry|alert)\.log$",
    re.IGNORECASE,
)
_NGES_LOG_PATTERNS = ("*_telemetry.log", "*_alert.log")


def _nges_logs_in_dir(directory: Path, *, recursive: bool) -> list[Path]:
    globber = directory.rglob if recursive else directory.glob
    found: list[Path] = []
    for pattern in _NGES_LOG_PATTERNS:
        found.extend(p for p in globber(pattern) if p.is_file())
    return sorted({p.resolve() for p in found}, key=lambda p: str(p).lower())


def _sibling_nges_logs(path: Path) -> list[Path]:
    """If path is one NGES split log, include the same agent id's other parts."""
    match = _NGES_LOG_NAME.match(path.name)
    parent = path.parent
    if not match or not parent.is_dir():
        return [path]
    agent = match.group("agent").lower()
    related: list[Path] = []
    for candidate in parent.iterdir():
        if not candidate.is_file():
            continue
        other = _NGES_LOG_NAME.match(candidate.name)
        if other and other.group("agent").lower() == agent:
            related.append(candidate)
    return sorted(related, key=lambda p: p.name.lower()) or [path]


def expand_telemetry(values: list[str]) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        resolved = path.resolve() if path.exists() else path
        if resolved in seen:
            return
        seen.add(resolved)
        out.append(path)

    def add_file(path: Path) -> None:
        for sibling in _sibling_nges_logs(path):
            add(sibling)

    for raw in values:
        matches = (
            [Path(p) for p in glob.glob(raw)]
            if any(c in raw for c in "*?[")
            else [Path(raw)]
        )
        if not matches:
            matches = [Path(raw)]
        for path in matches:
            if path.is_dir():
                logs = _nges_logs_in_dir(path, recursive=False)
                if not logs:
                    logs = _nges_logs_in_dir(path, recursive=True)
                if not logs:
                    logs = sorted(p for p in path.glob("*.log") if p.is_file())
                if logs:
                    for log in logs:
                        add(log)
                else:
                    add(path)
            else:
                add_file(path)
    return out


def evaluate(
    atomic_logs: Path,
    telemetry: list[Path],
    out_dir: Path,
    *,
    window_sec: float = 60.0,
    parent_match: bool = True,
    stamp: str | None = None,
) -> dict:
    stamp = stamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    episodes, skipped, log_errors = load_from_path(atomic_logs)
    events, tel_errors = load_events(telemetry)
    errors = [*log_errors, *tel_errors]
    result = match_episodes(
        episodes,
        events,
        MatchConfig(window_sec=window_sec, parent_match=parent_match),
    )
    payload = build_payload(
        result=result,
        atomic_paths=[str(atomic_logs)],
        telemetry_paths=[str(p) for p in telemetry],
        skipped=skipped,
        errors=errors,
        stamp=stamp,
    )
    paths = write_reports(payload, out_dir, stamp)
    payload["meta"]["report_paths"] = {k: str(v) for k, v in paths.items()}
    paths["json"].write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return payload


@app.callback(invoke_without_command=True)
def main(
    atomic_logs: Path = typer.Option(
        ...,
        "--atomic-logs",
        help="atomic-reforge 日志目录（读取 run-*.json）或单个 JSONL 文件",
    ),
    telemetry: list[str] = typer.Option(
        ...,
        "--telemetry",
        help=(
            "NGES 遥测/告警 NDJSON（文件、目录或 glob，可重复）。"
            "目录收集 *_telemetry.log / *_alert.log（含 _2_ 分段）；"
            "给其中一个文件会自动带上同主机其余分段。"
        ),
    ),
    out: Path = typer.Option(DEFAULT_OUT, "--out", help="报告输出目录"),
    window_sec: float = typer.Option(60.0, "--window-sec", help="时间窗 Δ（秒）"),
    parent_match: Optional[bool] = typer.Option(
        True,
        "--parent-match/--no-parent-match",
        help="父技术命中是否计入检出（默认计入）",
    ),
) -> None:
    tel_paths = expand_telemetry(telemetry)
    if not tel_paths:
        raise typer.BadParameter("没有匹配到遥测文件")
    typer.echo("NGES 日志 {} 个: {}".format(
        len(tel_paths),
        ", ".join(p.name for p in tel_paths),
    ))
    payload = evaluate(
        atomic_logs,
        tel_paths,
        out,
        window_sec=window_sec,
        parent_match=bool(parent_match),
    )
    summary = payload["summary"]
    paths = payload["meta"]["report_paths"]
    typer.echo(f"测试命令: {summary['main_total']}  执行成功: {summary['executed_ok']}")
    rec = summary["recall"]
    miss = summary["miss_rate"]
    prec = summary["precision"]
    typer.echo(
            "召回: {}  漏报: {}  精确率: {}  「可见」率: {}".format(
            "—" if rec is None else f"{rec:.1%}",
            "—" if miss is None else f"{miss:.1%}",
            "—" if prec is None else f"{prec:.1%}",
            "—" if summary["visibility_rate"] is None else f"{summary['visibility_rate']:.1%}",
        )
    )
    if not summary.get("accuracy_applicable"):
        typer.echo("正确率: 不适用（无足够安静负样本时段）")
    else:
        acc = summary.get("accuracy")
        typer.echo(f"正确率: {'—' if acc is None else f'{acc:.1%}'}")
    typer.echo(f"HTML -> {paths['html']}")
    typer.echo(f"JSON -> {paths['json']}")
    typer.echo(f"CSV  -> {paths['csv']}")
