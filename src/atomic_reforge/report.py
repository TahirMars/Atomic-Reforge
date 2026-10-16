"""Variants-vs-detection comparison table (markdown / csv)."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from .transform import Variant

COLUMNS = [
    "source_tid",
    "source_test",
    "source_guid",
    "variant_name",
    "variant_guid",
    "source_executor",
    "variant_executor",
    "strategies",
    "deformation",
    "script_path",
]


def _row(v: "Variant", script_path: Path | None) -> dict:
    return {
        "source_tid": v.technique_id,
        "source_test": v.source_atomic.name,
        "source_guid": v.source_guid or "",
        "variant_name": v.new_atomic.name,
        "variant_guid": v.variant_guid,
        "source_executor": v.source_atomic.executor.name,
        "variant_executor": v.new_atomic.executor.name,
        "strategies": ", ".join(v.strategy_tags),
        "deformation": (v.explanations[0] if v.explanations else ""),
        "script_path": str(script_path) if script_path else "",
    }


def render_markdown(
    variants: Iterable["Variant"], scripts: dict[str, Path] | None = None
) -> str:
    """Render the table as a GitHub-flavored markdown document."""
    scripts = scripts or {}
    lines = [
        "# Variant vs Detection Comparison Table",
        "",
        "Each row is one reforge variant: same ATT&CK TTP and attack intent as the "
        "source atomic test, with the execution form deformed. The SAME detection "
        "that catches the original may miss a variant (and vice versa) — that is "
        "the gap this table exposes for EDR coverage assessment.",
        "",
        f"| {' | '.join(COLUMNS)} |",
        f"|{'|'.join(['---'] * len(COLUMNS))}|",
    ]
    for v in variants:
        r = _row(v, scripts.get(v.variant_guid))
        esc = lambda s: s.replace("|", "\\|").replace("\n", " ").strip()
        lines.append("| " + " | ".join(esc(r[c]) for c in COLUMNS) + " |")
    return "\n".join(lines) + "\n"


def render_csv(variants: Iterable["Variant"], scripts: dict[str, Path] | None = None) -> str:
    """Render the table as CSV text."""
    scripts = scripts or {}
    import io

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS)
    writer.writeheader()
    for v in variants:
        writer.writerow(_row(v, scripts.get(v.variant_guid)))
    return buf.getvalue()
