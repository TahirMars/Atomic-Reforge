"""ATT&CK technique name / tactic lookup for eval reports.

Loads ``attck_enterprise.json`` (MITRE Enterprise matrix via ART STIX) over
``attck_windows.json``. Rebuild with ``python -m eval.build_attck_index``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_PHASE = {
    "Reconnaissance": 0,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation": 5,
    "Stealth": 6,
    "Defense Impairment": 7,
    "Credential Access": 8,
    "Discovery": 9,
    "Lateral Movement": 10,
    "Collection": 11,
    "Command and Control": 12,
    "Exfiltration": 13,
    "Impact": 14,
}

TACTIC_PHASES = tuple(_PHASE.keys())

HIGH_SNR_TACTICS = (
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Stealth",
    "Defense Impairment",
)

TACTIC_ZH = {
    "Reconnaissance": "侦察",
    "Resource Development": "资源开发",
    "Initial Access": "初始访问",
    "Execution": "执行",
    "Persistence": "持久化",
    "Privilege Escalation": "权限提升",
    "Stealth": "隐蔽",
    "Defense Impairment": "防御削弱",
    "Credential Access": "凭证访问",
    "Discovery": "发现",
    "Lateral Movement": "横向移动",
    "Collection": "收集",
    "Command and Control": "命令与控制",
    "Exfiltration": "数据渗出",
    "Impact": "影响",
}

_TA_NAMES = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",
    "TA0112": "Defense Impairment",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def _load_json(path: Path) -> dict[str, dict]:
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}
    return {str(k).upper(): v for k, v in raw.items() if isinstance(v, dict)}


@lru_cache(maxsize=1)
def _index() -> dict[str, dict]:
    here = Path(__file__).resolve().parent
    merged = _load_json(here / "attck_windows.json")
    for tid, rec in _load_json(here / "attck_enterprise.json").items():
        prev = merged.get(tid)
        if prev and prev.get("tactics") and not rec.get("tactics"):
            name = rec.get("name") or prev.get("name")
            merged[tid] = {**prev, "name": name}
            continue
        merged[tid] = rec
    return merged


def technique_name(technique_id: str) -> str:
    rec = _index().get((technique_id or "").upper())
    if not rec:
        parent = (technique_id or "").split(".", 1)[0].upper()
        rec = _index().get(parent)
    return str((rec or {}).get("name") or "")


def technique_tactics(technique_id: str) -> list[str]:
    rec = _index().get((technique_id or "").upper())
    if not rec:
        parent = (technique_id or "").split(".", 1)[0].upper()
        rec = _index().get(parent)
    tactics = [
        normalize_tactic_name(str(t))
        for t in (rec or {}).get("tactics") or []
        if t
    ]
    return sorted(dict.fromkeys(tactics), key=lambda t: _PHASE.get(t, 99))


def tactic_label(technique_id: str, fallback: list[str] | tuple[str, ...] | None = None) -> str:
    tactics = technique_tactics(technique_id)
    if not tactics and fallback:
        mapped: list[str] = []
        for item in fallback:
            text = normalize_tactic_name(_TA_NAMES.get(str(item).upper(), str(item).strip()))
            if text and text not in mapped:
                mapped.append(text)
        tactics = sorted(mapped, key=lambda t: _PHASE.get(t, 99))
    return " / ".join(tactics)


def tactic_phase(label: str) -> int:
    names = split_tactics(label)
    if not names:
        return 99
    return _PHASE.get(names[0], 99)


def normalize_tactic_name(name: str) -> str:
    text = (name or "").strip()
    if text in {"Defense Evasion", "defense-evasion"}:
        return "Stealth"
    return text


def split_tactics(label: str) -> list[str]:
    names = [
        normalize_tactic_name(part)
        for part in (label or "").split("/")
        if part.strip()
    ]
    return list(dict.fromkeys(n for n in names if n))


def tactic_display(name: str) -> str:
    name = normalize_tactic_name(name)
    zh = TACTIC_ZH.get(name)
    return f"{name}（{zh}）" if zh else name
