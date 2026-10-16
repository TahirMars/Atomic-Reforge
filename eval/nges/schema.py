"""NGES event field extraction (slim records, UTC timestamps)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

_NGES_TIME = re.compile(
    r"(?P<dt>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"(?:\s*\((?P<tz>UTC(?P<sign>[+-])(?P<hours>\d+))\))?",
    re.I,
)


def parse_nges_time(value: str | None) -> datetime | None:
    """Parse ``2026-10-08 10:40:41.824 (UTC+8)`` into aware UTC."""
    if not value:
        return None
    match = _NGES_TIME.search(str(value).strip())
    if not match:
        return None
    raw = match.group("dt").replace(" ", "T")
    try:
        local = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if match.group("tz"):
        hours = int(match.group("hours"))
        if match.group("sign") == "-":
            hours = -hours
        local = local.replace(tzinfo=timezone(timedelta(hours=hours)))
    elif local.tzinfo is None:
        local = local.replace(tzinfo=timezone.utc)
    return local.astimezone(timezone.utc)


def _nonempty(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text


def _parse_basic_ttp(raw: Any) -> tuple[list[str], list[str], bool]:
    """Return (techniques, tactics, has_score_ttp)."""
    techniques: list[str] = []
    tactics: list[str] = []
    has_score = False
    if not raw:
        return techniques, tactics, has_score
    if not isinstance(raw, str):
        raw = json.dumps(raw, ensure_ascii=False)
    text = raw.strip()
    if not text:
        return techniques, tactics, has_score
    try:
        blob = json.loads(text)
    except json.JSONDecodeError:
        return techniques, tactics, has_score
    if not isinstance(blob, dict):
        return techniques, tactics, has_score
    for item in blob.get("BasicTtp") or []:
        if not isinstance(item, dict):
            continue
        tech = _nonempty(item.get("Technique"))
        if tech:
            techniques.append(tech)
        tactic = _nonempty(item.get("Tactic"))
        if tactic:
            tactics.append(tactic)
    score = blob.get("ScoreTtp") or []
    has_score = bool(score)
    for item in score:
        if not isinstance(item, dict):
            continue
        tech = _nonempty(item.get("Technique") or item.get("ScoreTtpTechnique"))
        if tech:
            techniques.append(tech)
    return techniques, tactics, has_score


def extract_techniques(event: dict[str, Any]) -> tuple[list[str], list[str], bool]:
    """Union of builtin / custom / basicTtp technique IDs.

    ``labeled`` is True when any Technique string is present *or* ScoreTtp is
    non-empty (architecture: ScoreTtp counts as an annotation even without ID).
    """
    techniques: list[str] = []
    tactics: list[str] = []
    seen: set[str] = set()

    def add_tech(value: Any) -> None:
        text = _nonempty(value)
        if not text:
            return
        key = text.upper()
        if key in seen:
            return
        seen.add(key)
        techniques.append(text)

    def add_tactic(value: Any) -> None:
        text = _nonempty(value)
        if text and text not in tactics:
            tactics.append(text)

    add_tech(event.get("builtinTtpTechnique"))
    add_tech(event.get("customTtpTechnique"))
    add_tactic(event.get("builtinTtpTactic"))
    add_tactic(event.get("customTtpTactic"))
    basic_tech, basic_tactic, has_score = _parse_basic_ttp(event.get("basicTtp"))
    for tech in basic_tech:
        add_tech(tech)
    for tactic in basic_tactic:
        add_tactic(tactic)
    labeled = bool(techniques) or has_score
    return techniques, tactics, labeled


def _collect_paths(obj: Any, keys: Iterable[str]) -> list[str]:
    if not isinstance(obj, dict):
        return []
    out: list[str] = []
    for key in keys:
        text = _nonempty(obj.get(key))
        if text:
            out.append(text)
    return out


@dataclass
class NgesEvent:
    t_utc: datetime
    subtype: str
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    labeled: bool
    rule_name: str
    rule_id: str
    command_line: str
    file_name: str
    file_path: str
    pid: int | None
    haystack: str
    source_file: str = ""
    line_no: int = 0
    extra_paths: tuple[str, ...] = field(default_factory=tuple)
    target_command_line: str = ""
    kind: str = "telemetry"  # telemetry | alert

    @property
    def technique_key(self) -> tuple[str, ...]:
        return tuple(sorted({t.upper() for t in self.techniques}))


def event_from_record(
    record: dict[str, Any],
    *,
    source_file: str = "",
    line_no: int = 0,
    kind: str = "telemetry",
) -> NgesEvent | None:
    ev = record.get("Event") or {}
    if not isinstance(ev, dict):
        return None
    t_utc = parse_nges_time(_nonempty(ev.get("agentDisplayTime")))
    if t_utc is None:
        return None
    src = record.get("SourceProcess") if isinstance(record.get("SourceProcess"), dict) else {}
    tgt_proc = record.get("TargetProcess") if isinstance(record.get("TargetProcess"), dict) else {}
    tgt_file = record.get("TargetFile") if isinstance(record.get("TargetFile"), dict) else {}
    techniques, tactics, labeled = extract_techniques(ev)
    cmd = _nonempty(src.get("commandLine"))
    normal = _nonempty(src.get("normalCommandLine"))
    target_cmd = _nonempty(
        tgt_proc.get("commandLine") or tgt_proc.get("normalCommandLine")
    )
    file_name = _nonempty(src.get("fileName") or src.get("name"))
    file_path = _nonempty(src.get("filePath"))
    extra: list[str] = []
    extra.extend(_collect_paths(tgt_proc, ("commandLine", "normalCommandLine", "fileName", "filePath", "name")))
    extra.extend(_collect_paths(tgt_file, ("path", "name", "displayName", "originalFileName")))
    for key in (
        "TargetNamedPipe",
        "TargetRegistry",
        "TargetScheduledJob",
        "TargetService",
        "TargetDns",
        "TargetNetworkTraffic",
        "TargetWMI",
    ):
        extra.extend(_collect_paths(record.get(key), ("path", "name", "displayName", "query", "url", "remoteAddress")))
    pid_raw = src.get("pid")
    try:
        pid = int(pid_raw) if pid_raw not in (None, "") else None
    except (TypeError, ValueError):
        pid = None
    rule_name = _nonempty(ev.get("builtinTtpRuleName") or ev.get("customTtpRuleName"))
    rule_id = _nonempty(
        ev.get("builtinTtpRuleId")
        or ev.get("customTtpRuleId")
        or ev.get("telemetryRuleId")
        or ev.get("currentRule")
    )
    hay_parts = [cmd, normal, file_name, file_path, *extra]
    haystack = "\n".join(p for p in hay_parts if p).lower()
    return NgesEvent(
        t_utc=t_utc,
        subtype=_nonempty(ev.get("telemetrySubType")),
        techniques=tuple(techniques),
        tactics=tuple(tactics),
        labeled=labeled,
        rule_name=rule_name,
        rule_id=str(rule_id),
        command_line=cmd or normal,
        file_name=file_name,
        file_path=file_path,
        pid=pid,
        haystack=haystack,
        source_file=source_file,
        line_no=line_no,
        extra_paths=tuple(extra),
        target_command_line=target_cmd,
        kind=kind if kind in ("alert", "telemetry") else "telemetry",
    )
