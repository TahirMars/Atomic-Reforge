"""Build eval/attck_enterprise.json from ART's enterprise-attack STIX bundle."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STIX = ROOT / "ref" / "atomic-red-team-master" / "atomic_red_team" / "enterprise-attack.json"
OUT = Path(__file__).with_name("attck_enterprise.json")

# ATT&CK v19: TA0005 is Stealth; TA0112 is Defense Impairment.
PHASE_DISPLAY = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Stealth",  # retired name; v19 TA0005 is Stealth
    "stealth": "Stealth",
    "defense-impairment": "Defense Impairment",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

PHASE_ORDER = {
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


def _tid(obj: dict) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            ext = str(ref.get("external_id") or "")
            if ext.upper().startswith("T"):
                return ext.upper()
    return ""


def build(stix_path: Path = STIX) -> dict[str, dict]:
    bundle = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = bundle.get("objects") if isinstance(bundle, dict) else bundle
    ranked: dict[str, tuple[int, dict]] = {}
    for obj in objects or []:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        tid = _tid(obj)
        if not tid:
            continue
        tactics: list[str] = []
        for phase in obj.get("kill_chain_phases") or []:
            if not isinstance(phase, dict):
                continue
            if phase.get("kill_chain_name") not in ("mitre-attack", "mitre-enterprise-attack"):
                continue
            label = PHASE_DISPLAY.get(str(phase.get("phase_name") or "").lower())
            if label and label not in tactics:
                tactics.append(label)
        tactics.sort(key=lambda t: PHASE_ORDER.get(t, 99))
        rec = {"name": str(obj.get("name") or ""), "tactics": tactics}
        rank = 0
        if obj.get("revoked"):
            rank += 2
        if obj.get("x_mitre_deprecated"):
            rank += 1
        prev = ranked.get(tid)
        if prev is None or rank < prev[0]:
            ranked[tid] = (rank, rec)
    return {tid: rec for tid, (_rank, rec) in ranked.items()}


def main() -> None:
    data = build()
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    missing_tactics = sum(1 for rec in data.values() if not rec["tactics"])
    print(f"wrote {OUT} techniques={len(data)} missing_tactics={missing_tactics}")
    for tid in ("T1021.004", "T1204.003", "T1592.001", "T1595.003", "T1055.004"):
        print(tid, data.get(tid))


if __name__ == "__main__":
    main()
