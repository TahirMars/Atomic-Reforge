"""Stream NGES NDJSON telemetry without loading the whole file as one JSON blob."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path

from .schema import NgesEvent, event_from_record


def _first_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        for item in value:
            text = str(item or "").strip()
            if text:
                return text
        return ""
    return str(value).strip()


def expand_nges_records(record: dict) -> list[dict]:
    """Unwrap NGES telemetry rows and alert envelopes into Event/SourceProcess dicts.

    Telemetry lines are ``{Event, SourceProcess, ...}``. Alert lines wrap the
    same pair under ``edgesInfo[]``, with rule/TTP fields also on the envelope.
    """
    if not isinstance(record, dict):
        return []
    if isinstance(record.get("Event"), dict):
        return [record]
    rows: list[dict] = []
    for item in record.get("edgesInfo") or []:
        if not (isinstance(item, dict) and isinstance(item.get("Event"), dict)):
            continue
        ev = dict(item["Event"])
        if not ev.get("builtinTtpTechnique"):
            ev["builtinTtpTechnique"] = _first_str(record.get("techniques"))
        if not ev.get("builtinTtpRuleName"):
            ev["builtinTtpRuleName"] = record.get("ruleName") or ""
        if not ev.get("builtinTtpRuleId"):
            ev["builtinTtpRuleId"] = record.get("ruleId") or ev.get("builtinTtpRuleId") or ""
        cloned = dict(item)
        cloned["Event"] = ev
        rows.append(cloned)
    if rows:
        return rows
    if not (record.get("alertId") or record.get("ruleId") or record.get("ruleName")):
        return []
    when = record.get("firstDetectTime") or record.get("agentDisplayTime")
    if not when:
        return []
    src = record.get("entryProcess") if isinstance(record.get("entryProcess"), dict) else {}
    return [
        {
            "Event": {
                "agentDisplayTime": when,
                "builtinTtpTechnique": _first_str(record.get("techniques")),
                "builtinTtpTactic": _first_str(record.get("tactics")),
                "builtinTtpRuleName": record.get("ruleName") or "",
                "builtinTtpRuleId": record.get("ruleId") or "",
                "telemetrySubType": "Alert",
            },
            "SourceProcess": src,
        }
    ]


def _record_kind(path: Path, record: dict) -> str:
    name = path.name.lower()
    if "alert" in name or record.get("alertId") is not None:
        return "alert"
    return "telemetry"


def iter_events(
    path: Path,
    *,
    skip_errors: list[str] | None = None,
) -> Iterator[NgesEvent]:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                if skip_errors is not None:
                    skip_errors.append(f"{path.name}:{line_no}: {exc}")
                continue
            if not isinstance(record, dict):
                continue
            kind = _record_kind(path, record)
            for sub in expand_nges_records(record):
                event = event_from_record(
                    sub, source_file=str(path), line_no=line_no, kind=kind
                )
                if event is not None:
                    yield event


def load_events(paths: Iterable[Path]) -> tuple[list[NgesEvent], list[str]]:
    events: list[NgesEvent] = []
    errors: list[str] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = Path(path)
        if resolved in seen:
            continue
        seen.add(resolved)
        if not resolved.is_file():
            errors.append(f"missing telemetry file: {resolved}")
            continue
        events.extend(iter_events(resolved, skip_errors=errors))
    events.sort(key=lambda e: (e.t_utc, e.line_no))
    return events, errors
