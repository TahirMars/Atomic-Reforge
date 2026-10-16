"""Evaluation metrics. Accuracy is omitted when there is no quiet negative window."""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import median
from typing import Any

from .attck import TACTIC_PHASES, split_tactics, tactic_label, tactic_phase, technique_name
from .match import EpisodeMatch, MatchResult

LOW_RECALL = 0.05


def ratio(num: float, den: float) -> float | None:
    if den == 0:
        return None
    return num / den


def _percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    idx = (len(ordered) - 1) * p
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    frac = idx - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def compute(result: MatchResult) -> dict[str, Any]:
    matches = result.matches
    main_total = len(matches)
    ok = [m for m in matches if m.episode.executed_ok]
    n = len(ok)
    tp = sum(1 for m in ok if m.detected)
    fn = n - tp
    fp = len(result.false_positives)
    observed = sum(1 for m in ok if m.observed)
    alerted = sum(1 for m in ok if m.alerted)
    exact = sum(1 for m in ok if m.detected and m.detection_kind == "exact")
    parent = sum(1 for m in ok if m.detected and m.detection_kind == "parent")
    child = sum(1 for m in ok if m.detected and m.detection_kind == "child")
    # Recall with parent hits included is the default TP set when parent_match
    # is on. Exact-only recall always uses exact+child (finer grain still exact-family).
    exact_or_child = exact + child
    latencies = [m.latency_s for m in ok if m.detected and m.latency_s is not None]

    tn: int | None
    accuracy: float | None
    if result.accuracy_applicable:
        quiet_fps = _quiet_fp_count(result)
        tn = 1 if quiet_fps == 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else None
    else:
        tn = None
        accuracy = None

    status_counts = Counter(m.status for m in ok)
    fail_reasons = Counter(
        m.episode.failure or "unknown" for m in matches if not m.episode.executed_ok
    )

    by_technique = _group_by_technique(matches)
    by_strategy = _group_by_key(ok, lambda m: m.episode.strategy or "(none)")
    tid_tactics = {
        m.episode.technique_id: tactic_label(m.episode.technique_id, m.hit_tactics)
        for m in ok
    }
    by_tactic = count_episodes_by_tactic(
        [
            {
                "technique_id": m.episode.technique_id,
                "executed_ok": True,
                "detected": m.detected,
                "observed": m.observed,
                "status": m.status,
            }
            for m in ok
        ],
        tid_tactics,
    )
    highlights = _phase_highlights(by_technique)

    summary = {
        "main_total": main_total,
        "executed_ok": n,
        "executed_failed": main_total - n,
        "execution_success_rate": ratio(n, main_total),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "recall": ratio(tp, n),
        "miss_rate": ratio(fn, n),
        "precision": ratio(tp, tp + fp),
        "accuracy": accuracy,
        "accuracy_applicable": result.accuracy_applicable,
        "observed": observed,
        "visibility_rate": ratio(observed, n),
        "alerted": alerted,
        "alert_rate": ratio(alerted, n),
        "detected_exact": exact,
        "detected_parent": parent,
        "detected_child": child,
        "recall_exact": ratio(exact_or_child, n),
        "recall_with_parent": ratio(tp, n),
        "latency_s_median": median(latencies) if latencies else None,
        "latency_s_p90": _percentile(latencies, 0.9),
        "status_counts": dict(status_counts),
        "failure_reasons": dict(fail_reasons),
        "quiet_sec": result.quiet_sec,
        "labeled_clusters": len(result.clusters),
        "technique_count": len(by_technique),
        "low_recall_count": highlights["count"],
        "low_recall_threshold": LOW_RECALL,
        "low_recall_by_tactic": highlights["by_tactic"],
    }
    return {
        "summary": summary,
        "by_technique": by_technique,
        "by_strategy": by_strategy,
        "by_tactic": by_tactic,
        "highlights": highlights,
    }


def _quiet_fp_count(result: MatchResult) -> int:
    if result.telemetry_start is None or result.telemetry_end is None:
        return 0
    from .match import _window

    windows = [_window(m.episode, result.config.window_sec) for m in result.matches]
    count = 0
    for cluster in result.false_positives:
        inside = False
        for w0, w1 in windows:
            if cluster.t_start <= w1 and cluster.t_end >= w0:
                inside = True
                break
        if not inside:
            count += 1
    return count


def _group_by_technique(matches: list[EpisodeMatch]) -> list[dict[str, Any]]:
    groups: dict[str, list[EpisodeMatch]] = defaultdict(list)
    for m in matches:
        groups[m.episode.technique_id or "(unknown)"].append(m)
    rows = []
    for tid, items in sorted(groups.items()):
        ok = [m for m in items if m.episode.executed_ok]
        detected = [m for m in ok if m.detected]
        miss = [m for m in ok if not m.detected]
        observed_n = sum(1 for m in ok if m.observed)
        alerted_n = sum(1 for m in ok if m.alerted)
        rec = ratio(len(detected), len(ok))
        tactics = tactic_label(tid)
        rows.append(
            {
                "technique_id": tid,
                "technique_name": technique_name(tid),
                "tactics": tactics,
                "phase": tactic_phase(tactics),
                "main_total": len(items),
                "executed_ok": len(ok),
                "executed_failed": len(items) - len(ok),
                "observed": observed_n,
                "detected": len(detected),
                "alerted": alerted_n,
                "recall": rec,
                "miss_rate": ratio(len(miss), len(ok)),
                "visibility_rate": ratio(observed_n, len(ok)),
                "alert_rate": ratio(alerted_n, len(ok)),
                "miss_variants": [
                    {
                        "variant_guid": m.episode.variant_guid,
                        "variant_name": m.episode.variant_name,
                        "status": m.status,
                    }
                    for m in miss
                ],
                "hit_rule_names": sorted(
                    {r for m in detected for r in m.hit_rules if r}
                ),
                "alert_rule_names": sorted(
                    {r for m in ok if m.alerted for r in m.alert_rules if r}
                ),
                "sample_command_line": next(
                    (m.sample_command_line for m in detected if m.sample_command_line),
                    next((m.sample_command_line for m in ok if m.sample_command_line), ""),
                ),
            }
        )
    return rows


def count_by_tactic_phase(
    rows: list[dict[str, Any]],
    *,
    low_recall_only: bool = False,
) -> list[dict[str, Any]]:
    """Split each TTP onto every tactic it belongs to (a TTP may appear twice)."""
    selected = rows
    if low_recall_only:
        selected = [
            row
            for row in rows
            if row.get("executed_ok")
            and row.get("recall") is not None
            and row["recall"] < LOW_RECALL
        ]
    grouped: dict[str, list[str]] = {name: [] for name in TACTIC_PHASES}
    unknown: list[str] = []
    extra: dict[str, list[str]] = {}
    for row in selected:
        tid = str(row.get("technique_id") or "")
        names = split_tactics(row.get("tactics") or "")
        if not names:
            unknown.append(tid)
            continue
        for name in names:
            if name in grouped:
                grouped[name].append(tid)
            else:
                extra.setdefault(name, []).append(tid)
    out: list[dict[str, Any]] = []
    for name in TACTIC_PHASES:
        ids = grouped[name]
        if ids:
            out.append({"tactics": name, "count": len(ids), "technique_ids": ids})
    for name, ids in extra.items():
        out.append({"tactics": name, "count": len(ids), "technique_ids": ids})
    if unknown:
        out.append({"tactics": "(unknown)", "count": len(unknown), "technique_ids": unknown})
    return out


def _phase_highlights(by_technique: list[dict[str, Any]]) -> dict[str, Any]:
    low = [
        row
        for row in by_technique
        if row.get("executed_ok")
        and row.get("recall") is not None
        and row["recall"] < LOW_RECALL
    ]
    coverage = count_by_tactic_phase(by_technique)
    by_tactic = count_by_tactic_phase(by_technique, low_recall_only=True)
    return {
        "threshold": LOW_RECALL,
        "count": len(low),
        "technique_ids": [row["technique_id"] for row in low],
        "coverage": coverage,
        "by_tactic": by_tactic,
        "high_snr": by_tactic,
    }


def count_episodes_by_tactic(
    episodes: list[dict[str, Any]],
    tid_tactics: dict[str, str],
) -> list[dict[str, Any]]:
    """One row per tactic phase. A TTP that belongs to several phases is counted in each."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ep in episodes:
        if not ep.get("executed_ok"):
            continue
        names = split_tactics(tid_tactics.get(ep.get("technique_id")) or "")
        if not names:
            groups["(unknown)"].append(ep)
            continue
        for name in names:
            groups[name].append(ep)
    order = {name: i for i, name in enumerate(TACTIC_PHASES)}
    rows = []
    for key in sorted(groups, key=lambda k: (order.get(k, 98 if k == "(unknown)" else 99), k)):
        items = groups[key]
        det = sum(1 for e in items if e.get("detected"))
        n = len(items)
        rows.append(
            {
                "key": key,
                "executed_ok": n,
                "detected": det,
                "recall": ratio(det, n),
                "observed": sum(1 for e in items if e.get("observed")),
                "status_counts": dict(Counter(str(e.get("status") or "") for e in items)),
            }
        )
    return rows


def _group_by_key(ok: list[EpisodeMatch], key_fn) -> list[dict[str, Any]]:
    groups: dict[str, list[EpisodeMatch]] = defaultdict(list)
    for m in ok:
        groups[key_fn(m)].append(m)
    rows = []
    for key, items in sorted(groups.items()):
        det = sum(1 for m in items if m.detected)
        rows.append(
            {
                "key": key,
                "executed_ok": len(items),
                "detected": det,
                "recall": ratio(det, len(items)),
                "observed": sum(1 for m in items if m.observed),
                "status_counts": dict(Counter(m.status for m in items)),
            }
        )
    return rows
