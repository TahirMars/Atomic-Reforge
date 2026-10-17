"""HTML / JSON / CSV reports for an evaluation run."""

from __future__ import annotations

import csv
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collections import Counter

from .atomic_logs import (
    Episode,
    display_failure_reason,
    guess_failure,
    normalize_failure_reason,
)
from .match import (
    DetectionCluster,
    EpisodeMatch,
    MatchResult,
    alert_ttp_aligned,
    is_reforge_runner_command,
    normalize_technique,
    technique_relation,
)
from .attck import TACTIC_PHASES, split_tactics, tactic_display
from .metrics import LOW_RECALL, compute, count_by_tactic_phase, count_episodes_by_tactic

CSV_COLUMNS = [
    "technique_id",
    "variant_guid",
    "variant_name",
    "strategy",
    "timestamp",
    "executed_ok",
    "status",
    "observed",
    "detected",
    "alerted",
    "detection_kind",
    "latency_s",
    "hit_techniques",
    "wrong_techniques",
    "wrong_rules",
    "hit_rules",
    "alert_rules",
    "alert_techniques",
    "exit_code",
    "failure_reason",
    "failure_guess",
    "observe_score",
    "sample_command_line",
]


def _tactics_label(label: str) -> str:
    names = split_tactics(label or "")
    return " / ".join(names) if names else (label or "—")


def _pct(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value * 100:.1f}%"


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def build_payload(
    *,
    result: MatchResult,
    atomic_paths: list[str],
    telemetry_paths: list[str],
    skipped: list[dict[str, Any]],
    errors: list[str],
    stamp: str,
) -> dict[str, Any]:
    metrics = compute(result)
    cfg = result.config
    episodes_out = [_episode_row(m) for m in result.matches]
    fps = [_fp_row(c) for c in result.false_positives]
    failed = [row for row in episodes_out if not row["executed_ok"]]
    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "stamp": stamp,
            "atomic_logs": atomic_paths,
            "telemetry": telemetry_paths,
            "window_sec": cfg.window_sec,
            "parent_match": cfg.parent_match,
            "observe_threshold": cfg.observe_threshold,
            "cluster_gap_sec": cfg.cluster_gap_sec,
            "timestamps": "Atomic 日志为 UTC；NGES agentDisplayTime 按自带时区解析后转到 UTC 再比较",
            "detection_definition": (
                "层 B：「可见」且 Technique 对齐。"
                "层 C：「可见」且同一时间窗内有 alert.log 工单。"
            ),
            "errors": errors,
            "skipped_non_main": skipped,
            "telemetry_start": result.telemetry_start.isoformat() if result.telemetry_start else None,
            "telemetry_end": result.telemetry_end.isoformat() if result.telemetry_end else None,
        },
        "summary": metrics["summary"],
        "by_technique": metrics["by_technique"],
        "by_strategy": metrics["by_strategy"],
        "by_tactic": metrics["by_tactic"],
        "highlights": metrics.get("highlights") or {},
        "episodes": episodes_out,
        "failed_executions": failed,
        "false_positives": fps,
    }


def _episode_row(m: EpisodeMatch) -> dict[str, Any]:
    ep: Episode = m.episode
    return {
        "technique_id": ep.technique_id,
        "variant_guid": ep.variant_guid,
        "variant_name": ep.variant_name,
        "strategy": ep.strategy,
        "timestamp": ep.timestamp.isoformat(),
        "duration_s": ep.duration_s,
        "executor": ep.executor,
        "command": ep.command,
        "executed_ok": ep.executed_ok,
        "exit_code": ep.exit_code,
        "timed_out": ep.timed_out,
        "had_error": ep.had_error,
        "stderr": (ep.stderr or "")[:400],
        "failure_reason": normalize_failure_reason(ep.failure),
        "failure_guess": guess_failure(
            {
                "technique_id": ep.technique_id,
                "variant_name": ep.variant_name,
                "command": ep.command,
                "argv": ep.argv,
                "stderr": ep.stderr,
                "timed_out": ep.timed_out,
                "exit_code": ep.exit_code,
                "failure_reason": normalize_failure_reason(ep.failure),
            }
        )
        if not ep.executed_ok
        else "",
        "status": m.status,
        "observed": m.observed,
        "detected": m.detected,
        "alerted": m.alerted,
        "alert_rules": m.alert_rules,
        "alert_rule_techniques": m.alert_rule_techniques,
        "alert_aligned": m.alert_aligned,
        "detection_kind": m.detection_kind,
        "wrong_ttp": m.wrong_ttp,
        "latency_s": m.latency_s,
        "hit_techniques": m.hit_techniques,
        "wrong_techniques": m.wrong_techniques,
        "wrong_rules": m.wrong_rules,
        "hit_tactics": m.hit_tactics,
        "hit_rules": m.hit_rules,
        "observe_score": m.observe_score,
        "matched_signatures": m.matched_signatures,
        "sample_command_line": m.sample_command_line,
    }


def _fp_row(cluster: DetectionCluster) -> dict[str, Any]:
    return {
        "techniques": list(cluster.techniques),
        "rule_id": cluster.rule_id,
        "rule_names": list(cluster.rule_names),
        "t_start": cluster.t_start.isoformat(),
        "t_end": cluster.t_end.isoformat(),
        "event_count": len(cluster.events),
        "sample_command_line": cluster.sample_command,
        "from_alert": any(e.kind == "alert" for e in cluster.events),
    }


STATUS_BADGE = {
    "ttp_detected": ("pass", "标对"),
    "alerted": ("pass", "告警且标对"),
    "ttp_detected_alert_wrong": ("neutral", "标对但告警不对齐"),
    "alerted_wrong_ttp": ("neutral", "告警但 TTP 不对齐"),
    "observed_wrong_ttp": ("fail", "标成别的 TTP"),
    "observed_unlabeled": ("fail", "「可见」未标 TTP"),
    "executed_not_observed": ("fail", "未「可见」"),
    "not_executed": ("neutral", "未执行成功"),
}

STATUS_MEANING = {
    "ttp_detected": "「可见」且 Technique 对齐，但没有 alert.log 工单。算检出（召回的 TP），不算告警。",
    "alerted": "「可见」且 Technique 对齐，并且窗内至少有一张告警工单的 Technique 对齐本次 Atomic（多张工单时其余可以对不齐）。既算检出，也算告警。",
    "ttp_detected_alert_wrong": "遥测 Technique 对齐（算检出），窗内也有告警工单（算告警率），但所有工单的 TTP 都对不上本次 Atomic。不是「告警且标对」。",
    "alerted_wrong_ttp": "「可见」且出了告警工单，但 Technique 对不上本次 Atomic。算告警率，不算检出，计入漏报。",
    "observed_wrong_ttp": "「可见」，窗内对得上的事件打了 Technique，但和本次 technique_id 无关。不算检出，计入漏报。回合明细里红色列出这些错标。不是误报候选（误报候选是没挂上任何成功 Atomic 的簇）。",
    "observed_unlabeled": "「可见」，但对得上的事件没有 Technique 标签。不算检出，计入漏报。",
    "executed_not_observed": "执行成功，但时间窗内没有命令行/路径能对上本次 Atomic。不算检出，计入漏报。不是「日志里完全没事件」。",
    "not_executed": "没跑成功（非 0 退出、超时等）。不进入召回 / 漏报 / 「可见」率 / 告警率的分母。",
}

FP_PREVIEW = 50
FAIL_PREVIEW = 300
CMD_MAX = 160


def enrich_failures(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize legacy scheduler_error labels and attach heuristic guesses."""
    failed = payload.get("failed_executions") or []
    for row in failed:
        row["failure_reason"] = normalize_failure_reason(row.get("failure_reason"))
        row["failure_guess"] = guess_failure(row)
    for row in payload.get("episodes") or []:
        if row.get("failure_reason"):
            row["failure_reason"] = normalize_failure_reason(row.get("failure_reason"))
        if not row.get("executed_ok"):
            row["failure_guess"] = guess_failure(row)
    summary = payload.setdefault("summary", {})
    if failed:
        summary["failure_reasons"] = dict(
            Counter(row.get("failure_reason") or "unknown" for row in failed)
        )
        summary["failure_guesses"] = dict(
            Counter(row.get("failure_guess") or "—" for row in failed)
        )
    return payload


def resolve_episode_status(ep: dict[str, Any]) -> str:
    if not ep.get("executed_ok"):
        return "not_executed"
    detected = bool(ep.get("detected"))
    alerted = bool(ep.get("alerted"))
    observed = bool(ep.get("observed"))
    aligned = bool(ep.get("alert_aligned")) or alert_ttp_aligned(
        str(ep.get("technique_id") or ""), ep.get("alert_rule_techniques") or {}
    )
    if alerted and detected:
        return "alerted" if aligned else "ttp_detected_alert_wrong"
    if alerted and not detected:
        return "alerted_wrong_ttp"
    if detected:
        return "ttp_detected"
    if observed and (ep.get("wrong_ttp") or ep.get("wrong_techniques")):
        return "observed_wrong_ttp"
    if observed:
        return "observed_unlabeled"
    return "executed_not_observed"


def enrich_episode_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Recompute 告警且标对 vs 标对但告警不对齐 from alert TTP alignment."""
    episodes = payload.get("episodes") or []
    for ep in episodes:
        ep["alert_aligned"] = alert_ttp_aligned(
            str(ep.get("technique_id") or ""), ep.get("alert_rule_techniques") or {}
        )
        ep["status"] = resolve_episode_status(ep)
    ok = [e for e in episodes if e.get("executed_ok")]
    payload.setdefault("summary", {})["status_counts"] = dict(
        Counter(str(e.get("status") or "") for e in ok)
    )
    return payload


def _tip(text: str) -> str:
    return f'<span class="tip" tabindex="0" data-tooltip="{_esc(text)}">i</span>'


def _badge(status: str) -> str:
    kind, label = STATUS_BADGE.get(status, ("neutral", status or "—"))
    return f'<span class="badge {kind}">{_esc(label)}</span>'


def _status_chips(counts: dict[str, Any]) -> str:
    parts: list[str] = []
    seen: set[str] = set()
    for status in STATUS_BADGE:
        n = int(counts.get(status) or 0)
        if n:
            parts.append(f"{_badge(status)} <b>{n}</b>")
            seen.add(status)
    for status, n in counts.items():
        if status in seen:
            continue
        n = int(n or 0)
        if n:
            parts.append(f"{_badge(str(status))} <b>{n}</b>")
    return f'<div class="chips">{"".join(parts)}</div>' if parts else "—"


def _by_tactic_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    tid_tactics = {
        row.get("technique_id"): row.get("tactics") or ""
        for row in payload.get("by_technique") or []
    }
    return count_episodes_by_tactic(payload.get("episodes") or [], tid_tactics)


def _episode_sample_cmd(ep: dict[str, Any]) -> str:
    sample = str(ep.get("sample_command_line") or "")
    atomic = str(ep.get("command") or "")
    if is_reforge_runner_command(sample):
        return atomic or sample
    return sample or atomic


def _cmd_cell(text: Any) -> str:
    value = "" if text is None else str(text)
    if not value.strip():
        return "<td class='cmd'>—</td>"
    return f"<td class='wrap cmd'><code>{_esc(value)}</code></td>"


def _short(text: Any, limit: int = CMD_MAX) -> str:
    value = "" if text is None else str(text)
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


_IDENTITY_SUFFIX_RE = re.compile(r"\s*-\s*reforge/identity_original\s*$", re.I)


def _variant_display(name: Any, fallback: str = "—") -> str:
    value = "" if name is None else str(name).strip()
    value = _IDENTITY_SUFFIX_RE.sub("", value).strip()
    return value or fallback


def _edr_rule_labels(tids: list[str], rules: list[str]) -> list[str]:
    n = len(tids)
    if n == 0:
        return []
    labeled = list(rules or [])
    if len(labeled) == n:
        return labeled
    shared = next((r for r in labeled if r), "")
    return [shared] * n


def _tech_pair(tid: str, rule: str, *, hit: bool) -> str:
    css = "ttp-hit" if hit else "ttp-wrong"
    rule_css = "ttp-hit-rule" if hit else "ttp-wrong-rule"
    kind = "标对" if hit else "标错"
    title = f"{kind}：{rule}" if rule else f"{kind}：遥测未给规则名"
    rule_html = (
        f'<span class="{rule_css}">{_esc(rule)}</span>'
        if rule
        else '<span class="ttp-rule-missing">无规则名</span>'
    )
    return (
        f'<span class="ttp-pair">'
        f'<code class="{css}" title="{_esc(title)}">{_esc(tid)}</code>'
        f"{rule_html}"
        "</span>"
    )


def _edr_technique_cell(ep: dict[str, Any]) -> str:
    chunks: list[str] = []
    atomic = str(ep.get("technique_id") or "")
    seen: set[tuple[str, str, bool]] = set()

    def add(tid: str, rule: str, *, hit: bool) -> None:
        key = (normalize_technique(tid), rule or "", hit)
        if key in seen:
            return
        seen.add(key)
        chunks.append(_tech_pair(tid, rule, hit=hit))

    hits = [t for t in (ep.get("hit_techniques") or []) if t]
    for tid, rule in zip(hits, _edr_rule_labels(hits, list(ep.get("hit_rules") or []))):
        aligned = technique_relation(atomic, tid) != "unrelated"
        add(tid, rule, hit=aligned)
    wrong = [t for t in (ep.get("wrong_techniques") or []) if t]
    wrules = list(ep.get("wrong_rules") or [])
    for i, tid in enumerate(wrong):
        rule = wrules[i] if i < len(wrules) else ""
        add(tid, rule, hit=False)
    if not chunks:
        return "—"
    return f'<div class="tids">{"".join(chunks)}</div>'


def _alert_rule_label(name: str) -> str:
    if not name or name == "(无规则名)":
        return ""
    return name


def _alert_rule_cell(ep: dict[str, Any]) -> str:
    by_rule = ep.get("alert_rule_techniques") or {}
    names = [a for a in (ep.get("alert_rules") or []) if a]
    for key in by_rule:
        if key not in names:
            names.append(key)
    if not names:
        return "—"
    atomic = str(ep.get("technique_id") or "")
    chunks: list[str] = []
    seen: set[tuple[str, str, bool]] = set()
    for name in names:
        rule = _alert_rule_label(str(name))
        techs = [t for t in (by_rule.get(name) or []) if t]
        if not techs:
            key = ("", rule, False)
            if key not in seen:
                seen.add(key)
                rule_css = "ttp-wrong-rule"
                body = (
                    f'<span class="{rule_css}">{_esc(rule)}</span>'
                    if rule
                    else '<span class="ttp-rule-missing">无规则名</span>'
                )
                chunks.append(f'<span class="ttp-pair">{body}</span>')
            continue
        for tid in techs:
            aligned = technique_relation(atomic, tid) != "unrelated"
            key = (normalize_technique(tid), rule, aligned)
            if key in seen:
                continue
            seen.add(key)
            chunks.append(_tech_pair(tid, rule, hit=aligned))
    if not chunks:
        return "—"
    return f'<div class="tids">{"".join(chunks)}</div>'


def _status_section() -> str:
    return (
        "<h3>状态说明</h3>"
        '<p class="muted">执行成功回合，互斥，取最强。战术汇总里的彩色标签就是这些状态。'
        "标对 / 告警且标对 / 标对但告警不对齐 = 检出；其余执行成功状态都算漏报。误报候选不是回合状态。</p>"
        '<table class="glossary">'
        "<thead><tr><th>状态</th><th>含义</th></tr></thead>"
        f"<tbody>{_status_glossary_rows()}</tbody>"
        "</table>"
    )


def _status_glossary_rows() -> str:
    rows = []
    for status, meaning in STATUS_MEANING.items():
        rows.append(
            "<tr>"
            f"<td>{_badge(status)}</td>"
            f"<td>{_esc(meaning)}</td>"
            "</tr>"
        )
    return "".join(rows)


def _intro_section(payload: dict[str, Any]) -> str:
    s = payload.get("summary") or {}
    meta = payload.get("meta") or {}
    delta = meta.get("window_sec", 60)
    theta = meta.get("observe_threshold", 2.0)
    gap = meta.get("cluster_gap_sec", 5.0)
    parent_on = bool(meta.get("parent_match"))
    parent_txt = "计入检出（父技术命中算 TP）" if parent_on else "不计入检出（仅精确或更细粒度）"
    n = s.get("executed_ok")
    tp = s.get("tp")
    fn = s.get("fn")
    fp = s.get("fp")
    exact = s.get("detected_exact")
    parent_n = s.get("detected_parent")
    child = s.get("detected_child")
    acc = (
        "不适用（无足够安静负样本时段，不用海量无标签遥测冒充 TN）"
        if not s.get("accuracy_applicable")
        else _pct(s.get("accuracy"))
    )
    atomic_txt = "、".join(str(p) for p in (meta.get("atomic_logs") or [])) or "—"
    tel_txt = "、".join(Path(p).name for p in (meta.get("telemetry") or [])) or "—"
    return f"""
<section>
<h2>方法与口径</h2>
<p class="note">先对齐时间，再判断「可见」，再判断检出与告警。
检出类指标的分母 <em>N</em> 一律是<strong>执行成功</strong>的测试命令（不含前置准备和清理步骤）；未成功执行不计入召回、漏报、「可见」率、告警率。
三层不要混用：<strong>「可见」≠ 检出 ≠ 告警</strong>，也<strong>不等于</strong>时间窗里有任意遥测。</p>
<table class="glossary">
<thead><tr><th>名称</th><th>公式 / 判定</th><th>含义</th><th>本场</th></tr></thead>
<tbody>
<tr>
<td>执行成功</td>
<td>exit_code = 0，未超时、调度未失败</td>
<td>Atomic 真正跑完。失败回合不进召回分母，避免把「没跑起来」算成 EDR 漏报。</td>
<td><em>N</em> = {_esc(n)}</td>
</tr>
<tr>
<td>时间窗</td>
<td class="formula">匹配区间 = [<em>t</em><sub>0</sub> − Δ, <em>t</em><sub>1</sub> + Δ]，<em>t</em><sub>1</sub> = <em>t</em><sub>0</sub> + duration</td>
<td><em>t</em><sub>0</sub> 为回合 timestamp。Atomic 日志按 UTC；NGES <code>agentDisplayTime</code> 带偏移解析后全部转 UTC 再比。</td>
<td>Δ = {_esc(delta)} 秒</td>
</tr>
<tr>
<td>「可见」（层 A）</td>
<td class="formula">observe_score ≥ θ</td>
<td>遥测记到了<strong>这次命令</strong>（命令行/路径能对上）。不是「日志里有事件」，也不是标了 TTP。单独出现 powershell.exe / cmd.exe 不算。</td>
<td>θ = {_esc(theta)}；<em>V</em> = {_esc(s.get('observed'))}</td>
</tr>
<tr>
<td>「可见」率</td>
<td class="formula"><em>V</em> / <em>N</em></td>
<td>跑成功的测试里，有多少被遥测对上。</td>
<td>{_esc(_pct(s.get('visibility_rate')))}</td>
</tr>
<tr>
<td>检出（层 B）</td>
<td class="formula">「可见」 ∧ Technique 对齐</td>
<td>标对了。这是召回的分子 TP。精确 / 子技术算命中；父技术{_esc(parent_txt)}。标成别的 TTP 或未标都不算检出。</td>
<td>TP = {_esc(tp)}</td>
</tr>
<tr>
<td>TTP 召回率</td>
<td class="formula"><em>R</em> = TP / <em>N</em></td>
<td>跑成功的测试里，EDR 标对了多少。</td>
<td>{_esc(_pct(s.get('recall')))}</td>
</tr>
<tr>
<td>漏报率</td>
<td class="formula">1 − <em>R</em> = FN / <em>N</em></td>
<td>执行成功但<strong>未检出</strong>。包括未「可见」、「可见」未标、标成别的 TTP。不是「没出告警」。</td>
<td>{_esc(_pct(s.get('miss_rate')))}（FN={_esc(fn)}）</td>
</tr>
<tr>
<td>告警（层 C）</td>
<td class="formula">「可见」 ∧ 来自 alert.log 工单</td>
<td>出了告警工单。不等于检出：可以「可见」未告警，也可以告警但 TTP 不对齐。</td>
<td><em>A</em> = {_esc(s.get('alerted'))}</td>
</tr>
<tr>
<td>告警率</td>
<td class="formula"><em>A</em> / <em>N</em></td>
<td>跑成功的测试里，多少落到了告警工单。</td>
<td>{_esc(_pct(s.get('alert_rate')))}</td>
</tr>
<tr>
<td>检测簇 / 精确率</td>
<td class="formula">同一规则 ID + 同一组 Technique，间隔 ≤ <em>g</em> 秒收成一团；<em>P</em> = TP / (TP + FP)</td>
<td>召回看「该检出的漏了没」；精确率看「打出去的 TTP 标签有多少能对上本次测评」。
带标签事件按规则 ID + Technique 收成簇，一对一贪心分给成功回合；分不出去的 = 误报候选（FP 簇）。无标签遥测不计入。
精确率低、FP 簇多，说明标签偏吵（规则过宽、系统进程或测评调度器被标成攻击），不是遥测盲区（那看「可见」率）。
回合明细里「标成别的 TTP」是这次 Atomic 看见了但贴错 ID（算漏报）；FP 簇是贴了标签却挂不上任何成功回合。
不是生产误报率，也不能代替告警率。</td>
<td><em>g</em> = {_esc(gap)} 秒；{_esc(_pct(s.get('precision')))}（FP 簇={_esc(fp)}）</td>
</tr>
<tr>
<td>精确命中召回</td>
<td class="formula"><em>R</em><sub>exact</sub> = (exact + child) / <em>N</em></td>
<td>主召回的 TP 默认含三种对齐：精确（Atomic 与 EDR 同一 ID，如都是 T1055.004）、子技术更细（Atomic 是 T1055，EDR 标到 T1055.011）、父技术放宽（Atomic 是 T1055.004，EDR 只标了 T1055）。
本列只把精确 + 子技术算进分子，父技术命中单独列在「本场」里、不进 <em>R</em><sub>exact</sub>。
用来看 EDR 是标到了同一粒度（或更细），还是只贴了父 ID。主召回高、本列低，说明很多检出靠父技术放宽。</td>
<td>{_esc(_pct(s.get('recall_exact')))}（exact={_esc(exact)}，parent={_esc(parent_n)}，child={_esc(child)}）</td>
</tr>
<tr>
<td>正确率</td>
<td class="formula">(TP + TN) / (TP + TN + FP + FN)</td>
<td>TN 只来自「无 Atomic 的安静时段」。没有负样本时段则不适用。</td>
<td>{_esc(acc)}</td>
</tr>
</tbody>
</table>
<p class="muted">Atomic 日志：{_esc(atomic_txt)}　·　NGES 日志：{_esc(tel_txt)}</p>
</section>
"""


def _phase_note() -> str:
    return (
        '<p class="muted phase-note">一个 TTP 技术可能同时属于多个战术阶段，'
        "因此可以出现在多个条形中；各阶段计数之和可以大于 TTP 数。"
        "阶段名按 ATT&amp;CK v19：原 Defense Evasion 已拆成 Stealth（隐蔽）与 Defense Impairment（防御削弱）。</p>"
    )


def _phase_bars(
    rows: list[dict[str, Any]],
    *,
    title: str,
    aria: str,
    fill_class: str = "bar-fill",
) -> str:
    if not rows:
        return f"<h3>{_esc(title)}</h3><p class='muted'>无。</p>"
    peak = max(int(item.get("count") or 0) for item in rows) or 1
    bars = []
    table_rows = []
    for item in rows:
        count = int(item.get("count") or 0)
        width = 100.0 * count / peak
        raw = item.get("tactics") or "—"
        label = tactic_display(str(raw))
        ids = item.get("technique_ids") or []
        chips = "".join(f"<code>{_esc(tid)}</code>" for tid in ids)
        bars.append(
            "<div class=\"bar-row\">"
            f"<span class=\"bar-label\">{_esc(label)}</span>"
            f"<div class=\"bar-track\" title=\"{_esc(label)} {count}\">"
            f"<span class=\"{fill_class}\" style=\"width:{width:.1f}%\"></span></div>"
            f"<span class=\"bar-n\">{count}</span>"
            "</div>"
        )
        table_rows.append(
            "<tr>"
            f"<td>{_esc(label)}</td>"
            f"<td>{count}</td>"
            f"<td><div class=\"tids\">{chips}</div></td>"
            "</tr>"
        )
    return f"""
<h3>{_esc(title)}</h3>
{_phase_note()}
<div class="bars" role="img" aria-label="{_esc(aria)}">
{''.join(bars)}
</div>
<table class="focus-table">
<thead><tr><th>战术阶段</th><th>TTP 数</th><th>TTP</th></tr></thead>
<tbody>
{''.join(table_rows)}
</tbody></table>
"""


def _coverage_and_low_visual(payload: dict[str, Any]) -> str:
    techs = payload.get("by_technique") or []
    hi = payload.get("highlights") or {}
    coverage = count_by_tactic_phase(techs)
    low_rows = count_by_tactic_phase(techs, low_recall_only=True)
    n_tech = (payload.get("summary") or {}).get("technique_count") or len(techs)
    threshold = int(round(float(hi.get("threshold") or LOW_RECALL) * 100))
    low_n = hi.get("count")
    if low_n is None:
        low_n = len({tid for row in low_rows for tid in (row.get("technique_ids") or [])})
    return (
        _phase_bars(
            coverage,
            title=f"本场 {n_tech} 个 TTP 覆盖的战术阶段",
            aria="各战术阶段覆盖的 TTP 数量",
            fill_class="bar-fill bar-fill-cover",
        )
        + (
            _phase_bars(
                low_rows,
                title=f"召回低于 {threshold}% 的 TTP（{low_n} 个）按战术阶段",
                aria=f"召回低于 {threshold}% 的 TTP 按战术阶段",
            )
            if low_rows
            else f"<h3>召回低于 {threshold}%</h3><p class='muted'>没有召回低于 {threshold}% 的已执行 TTP。</p>"
        )
    )


def _narrative(payload: dict[str, Any]) -> str:
    s = payload["summary"]
    hi = payload.get("highlights") or {}
    n_tech = s.get("technique_count") or len(payload.get("by_technique") or [])
    low_n = hi.get("count") or 0
    threshold = int(round((hi.get("threshold") or 0.05) * 100))
    coverage = count_by_tactic_phase(payload.get("by_technique") or [])
    phase_txt = "、".join(tactic_display(str(r.get("tactics"))) for r in coverage) or "—"
    parts = [
        "对照测评机上的 Atomic 执行记录和 NGES 遥测/告警：先按时间窗圈出候选事件，再用命令行、路径判断是否对上这次测试。"
        "「可见」= 遥测对上了这次命令；检出 = 「可见」且 Technique 对齐；"
        "告警只统计 alert.log 工单。未成功执行不计入召回分母。"
        f"本场 <span class=\"method-number\">{_esc(s.get('executed_ok'))}</span> 个测试用例"
        f"（执行成功的测试命令，不含前置准备和清理），涉及 <span class=\"method-number\">{_esc(n_tech)}</span> 个 TTP。"
        f"这 {_esc(n_tech)} 个 TTP 覆盖战术阶段：{_esc(phase_txt)}。"
        f"召回 <span class=\"method-number\">{_esc(_pct(s.get('recall')))}</span>，"
        f"「可见」率 <span class=\"method-number\">{_esc(_pct(s.get('visibility_rate')))}</span>，"
        f"告警率 <span class=\"method-number\">{_esc(_pct(s.get('alert_rate')))}</span>。"
    ]
    if low_n:
        parts.append(
            f"其中 <span class=\"method-number method-risk\">{low_n}</span> 个 TTP "
            f"召回低于 {threshold}%，按最新战术阶段拆分见下方条形图"
            "（同一技术属于多个阶段时，每个阶段各计一次）。"
        )
    else:
        parts.append(f"没有召回低于 {threshold}% 的已执行 TTP。")
    return "<p class=\"method\">" + "".join(parts) + "</p>"


def _num(value: Any, *, risk: bool = False) -> str:
    cls = "method-number method-risk" if risk else "method-number"
    return f'<span class="{cls}">{_esc(value)}</span>'


def _verdict(payload: dict[str, Any]) -> str:
    """Chinese evaluation conclusion from this run's summary cards."""
    s = payload.get("summary") or {}
    sc = s.get("status_counts") or {}
    n_ok = int(s.get("executed_ok") or 0)
    n_all = int(s.get("main_total") or 0)
    n_fail = int(s.get("executed_failed") or 0)
    n_obs = int(s.get("observed") or 0)
    n_tp = int(s.get("tp") or 0)
    n_fn = int(s.get("fn") or 0)
    n_fp = int(s.get("fp") or 0)
    n_alert = int(s.get("alerted") or 0)
    n_hit_alert = int(sc.get("alerted") or 0)
    n_hit_only = int(sc.get("ttp_detected") or 0)
    n_hit_alert_wrong = int(sc.get("ttp_detected_alert_wrong") or 0)
    n_alert_wrong = int(sc.get("alerted_wrong_ttp") or 0)
    vis = s.get("visibility_rate")
    rec = s.get("recall")
    prec = s.get("precision")
    bits: list[str] = [
        "测评结论：本场共 "
        f"{_num(n_all)} 条测试命令，其中 {_num(n_ok)} 条执行成功"
        f"（{_esc(_pct(s.get('execution_success_rate')))}）"
    ]
    if n_fail:
        bits.append(f"，{_num(n_fail)} 条未跑成功、不计入后面的比率。")
    else:
        bits.append("。")
    if n_ok:
        bits.append(
            f"在这 {_esc(n_ok)} 条里，遥测「可见」{_num(n_obs)} 条"
            f"（{_esc(_pct(vis))}）"
        )
        if vis is not None and vis >= 0.9 and rec is not None and rec < 0.5:
            bits.append("，采集基本没有盲区。")
            bits.append(
                f"但检出（标对 TTP）只有 {_num(n_tp, risk=True)} 条"
                f"（召回 {_esc(_pct(rec))}），未检出 {_num(n_fn, risk=True)} 条"
                f"（漏报 {_esc(_pct(s.get('miss_rate')))}），短板在识别而不是采集。"
            )
        else:
            bits.append("。")
            bits.append(
                f"检出 {_num(n_tp)} 条（召回 {_esc(_pct(rec))}），"
                f"未检出 {_num(n_fn)} 条（漏报 {_esc(_pct(s.get('miss_rate')))}）。"
            )
        bits.append(
            f"告警工单 {_num(n_alert)} 条（告警率 {_esc(_pct(s.get('alert_rate')))}）"
        )
        if n_alert:
            bits.append(
                f"：其中告警且标对 {_num(n_hit_alert)} 条（至少一张工单 TTP 对齐），"
            )
            if n_hit_alert_wrong:
                bits.append(
                    f"标对但告警不对齐 {_num(n_hit_alert_wrong)} 条（遥测标对了，工单指到别的技术），"
                )
            bits.append(
                f"告警但 TTP 不对齐 {_num(n_alert_wrong)} 条（出了工单但指向错技术）。"
            )
            if n_hit_only:
                bits.append(
                    f"另有标对但未出工单 {_num(n_hit_only)} 条（识别到了，运营没收到告警）。"
                )
        else:
            bits.append("，没有落到 alert.log。")
        bits.append(
            f"精确率 {_esc(_pct(prec))}（检出 {_esc(n_tp)} / 检出与 FP 簇合计 {_esc(n_tp + n_fp)}）"
        )
        if prec is not None and prec < 0.2:
            bits.append("，标记了大量 TTP 标签但对不上本次测试，噪声偏高。")
        else:
            bits.append("。")
    return '<p class="method verdict">' + "".join(bits) + "</p>"


def _scope_note() -> str:
    return (
        '<p class="note">Atomic Reforge 的测试用例来自 Atomic Red Team（原子红队），'
        "本场只测评 Windows 相关 TTP。"
        "Atomic Red Team（原子红队）的每个用例通常只选择一个代表性 Technique 标签；"
        "真正执行时，命令里往往会包含依赖的其它 TTP，原始用例并没有把实现涉及的全部 Technique 标全。"
        "精确率把「对不上本次标签」的检出都算在分母里，其中一部分可能是测试用例本身的行为，"
        "因此该指标仅供参考。</p>"
    )


def render_html(payload: dict[str, Any]) -> str:
    enrich_failures(payload)
    enrich_episode_status(payload)
    s = payload["summary"]
    meta = payload["meta"]
    n_ok = s.get("executed_ok", 0)
    n_all = s.get("main_total", 0)
    n_tp = s.get("tp", 0)
    n_fn = s.get("fn", 0)
    n_fp = s.get("fp", 0)
    cards = [
        ("执行成功率", _pct(s.get("execution_success_rate")), f"执行成功 {n_ok} / 执行用例总数 {n_all}"),
        ("「可见」率", _pct(s.get("visibility_rate")), f"「可见」 {s.get('observed', 0)} / 执行成功 {n_ok}"),
        ("TTP 召回率", _pct(s.get("recall")), f"检出 {n_tp} / 执行成功 {n_ok}"),
        ("告警率", _pct(s.get("alert_rate")), f"告警 {s.get('alerted', 0)} / 执行成功 {n_ok}"),
        ("漏报率", _pct(s.get("miss_rate")), f"未检出 {n_fn} / 执行成功 {n_ok}"),
        ("精确率", _pct(s.get("precision")), f"检出 {n_tp} / 检出与 FP 簇合计 {n_tp + n_fp}"),
    ]
    card_html = "".join(
        f'<div class="metric"><span>{_esc(k)}</span><b>{_esc(v)}</b>'
        f'<span>{_esc(h)}</span></div>'
        for k, v, h in cards
    )
    tactic_rows = []
    for row in _by_tactic_rows(payload):
        key = row.get("key") or "(unknown)"
        label = tactic_display(str(key)) if key in TACTIC_PHASES else _tactics_label(str(key))
        tactic_rows.append(
            "<tr>"
            f"<td>{_esc(label)}</td>"
            f"<td>{row.get('executed_ok', 0)}</td>"
            f"<td>{row.get('observed', 0)}</td>"
            f"<td>{row.get('detected', 0)}</td>"
            f"<td>{_pct(row.get('recall'))}</td>"
            f"<td>{_status_chips(row.get('status_counts') or {})}</td>"
            "</tr>"
        )
    total_status = _status_chips((payload.get("summary") or {}).get("status_counts") or {})
    tactic_foot = (
        "<tr>"
        f"<td>合计（执行成功回合）</td>"
        f"<td>{s.get('executed_ok', 0)}</td>"
        f"<td>{s.get('observed', 0)}</td>"
        f"<td>{s.get('tp', 0)}</td>"
        f"<td>{_pct(s.get('recall'))}</td>"
        f"<td>{total_status}</td>"
        "</tr>"
    )
    by_tid: dict[str, list[dict[str, Any]]] = {}
    for ep in payload.get("episodes") or []:
        by_tid.setdefault(ep.get("technique_id") or "(unknown)", []).append(ep)

    tech_blocks: list[str] = []
    techniques = sorted(
        payload.get("by_technique") or [],
        key=lambda r: (r.get("phase") or 99, r.get("technique_id") or ""),
    )
    for idx, row in enumerate(techniques):
        tid = row["technique_id"]
        name = row.get("technique_name") or ""
        tactics = _tactics_label(row.get("tactics") or "")
        rec = row.get("recall")
        miss = row.get("miss_rate")
        rec_n = -1.0 if rec is None else float(rec)
        miss_n = -1.0 if miss is None else float(miss)
        search = " ".join(
            str(x).lower()
            for x in (tid, name, tactics, "missing" if rec_n == 0 else "", "matched" if (rec_n or 0) > 0 else "")
            if x
        )
        detail_id = f"ttp-details-{idx}"
        instances = [ep for ep in by_tid.get(tid, []) if ep.get("executed_ok")]
        inst_rows = []
        for ep in instances:
            inst_rows.append(
                "<tr>"
                f"<td class='wrap'><code>{_esc(_variant_display(ep.get('variant_name'), str(ep.get('variant_guid') or '—')))}</code></td>"
                f"<td>{_badge(str(ep.get('status') or ''))}</td>"
                f"<td>{_esc(ep.get('detection_kind') or '—')}</td>"
                f"<td>{_edr_technique_cell(ep)}</td>"
                f"<td>{_alert_rule_cell(ep)}</td>"
                f"{_cmd_cell(_episode_sample_cmd(ep))}"
                "</tr>"
            )
        expand = (
            f'<button class="expand" data-target="{detail_id}">回合明细 ({len(instances)})</button>'
            if instances
            else "—"
        )
        tech_blocks.append(
            "<tr class=\"ttp-row\""
            f" data-search=\"{_esc(search)}\""
            f" data-ttp=\"{_esc(tid)}\""
            f" data-phase=\"{row.get('phase') or 99}\""
            f" data-recall=\"{rec_n}\""
            f" data-miss=\"{miss_n}\""
            f" data-executed=\"{row.get('executed_ok') or 0}\""
            f" data-observed=\"{row.get('observed') or 0}\""
            f" data-detected=\"{row.get('detected') or 0}\""
            f" data-alerted=\"{row.get('alerted') or 0}\">"
            f"<td><code>{_esc(tid)}</code><div class=\"muted\">{_esc(name)}</div></td>"
            f"<td>{_esc(tactics or '—')}</td>"
            f"<td>{row.get('executed_ok', 0)}/{row.get('main_total', 0)}</td>"
            f"<td>{row.get('observed', 0)}</td>"
            f"<td>{row.get('detected', 0)}</td>"
            f"<td>{row.get('alerted', 0)}</td>"
            f"<td>{_pct(rec)}</td>"
            f"<td>{_pct(miss)}</td>"
            f"<td>{expand}</td>"
            "</tr>"
        )
        if instances:
            rules = ", ".join(row.get("hit_rule_names") or []) or "—"
            alerts = ", ".join(row.get("alert_rule_names") or []) or "—"
            tech_blocks.append(
                f'<tr id="{detail_id}" class="detail-row" hidden><td colspan="9">'
                f"<h3><code>{_esc(tid)}</code> 执行成功回合"
                f"<span class=\"muted\">　命中规则 {_esc(rules)}　告警规则 {_esc(alerts)}</span></h3>"
                '<table class="instances"><thead><tr>'
                "<th>变体</th><th>结果</th><th>对齐</th>"
                f"<th>遥测规则 {_tip('时间窗内遥测打上的 Technique 及规则名。绿色对齐本次 Atomic，红色不对齐。无规则名表示该条遥测只有 TTP 标签、没有 builtinTtpRuleName。')}</th>"
                f"<th>告警规则 {_tip('工单上的 Technique 及规则名，展示方式和遥测规则列相同。绿色对齐、红色不对齐。无规则名表示工单没有规则名。多张工单时只要有一张绿色，就算告警且标对。')}</th>"
                f"<th>示例 commandLine {_tip('NGES SourceProcess.commandLine 完整原文；没有窗内命令时回退 Atomic 下发命令。不截断。')}</th>"
                "</tr></thead><tbody>"
                + "".join(inst_rows)
                + "</tbody></table></td></tr>"
            )

    failed = payload.get("failed_executions") or []
    fail_preview = failed[:FAIL_PREVIEW] if len(failed) > FAIL_PREVIEW else failed
    failed_rows = []
    for row in fail_preview:
        failed_rows.append(
            "<tr>"
            f"<td><code>{_esc(row['technique_id'])}</code></td>"
            f"<td class='wrap'>{_esc(_variant_display(row.get('variant_name')))}</td>"
            f"<td>{_esc(display_failure_reason(row.get('failure_reason')))}</td>"
            f"<td>{_esc(row.get('exit_code'))}</td>"
            f"<td>{_esc(row.get('failure_guess') or guess_failure(row))}</td>"
            f"<td class='wrap'><code>{_esc(_short(row.get('command')))}</code></td>"
            "</tr>"
        )
    if not failed:
        fail_extra = "<p class='muted'>本场没有未成功执行的测试命令。</p>"
    elif len(fail_preview) < len(failed):
        fail_extra = (
            f"<p class='muted'>表格预览 {len(fail_preview)}/{len(failed)} 条，"
            "完整清单见同名 JSON / CSV。未成功执行<strong>不计入</strong>召回分母。</p>"
        )
    else:
        fail_extra = (
            f"<p class='muted'>共 {len(failed)} 条。未成功执行<strong>不计入</strong>召回分母。</p>"
        )
    reasons = s.get("failure_reasons") or {}
    reason_txt = (
        "、".join(
            f"{display_failure_reason(k)} {v}"
            for k, v in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        if reasons
        else "无"
    )
    guess_counts = sorted(
        (s.get("failure_guesses") or Counter(guess_failure(r) for r in failed)).items(),
        key=lambda kv: (-kv[1], kv[0]),
    )
    guess_rows = "".join(
        f"<tr><td>{_esc(label)}</td><td>{n}</td></tr>" for label, n in guess_counts
    )
    guess_table = (
        "<table class='guess-summary'><thead><tr><th>推测类型</th><th>条数</th></tr></thead>"
        f"<tbody>{guess_rows}</tbody></table>"
        if guess_rows
        else ""
    )
    fail_note = (
        "<p class=\"note\">「日志原因」来自执行记录：超时、非 0 退出、缺 payload。"
        "不再把非 0 退出写成调度错误。「推测」根据命令行、变体名和技术 ID 启发式归类，"
        "不是进程返回的精确错误码，仅帮助浏览。</p>"
    )
    fail_markup = (
        "<table>"
        "<thead><tr><th>技术</th><th>变体</th><th>日志原因</th><th>退出码</th><th>推测</th><th>命令</th></tr></thead>"
        "<tbody>"
        + ("".join(failed_rows) or "<tr><td colspan='6'>无</td></tr>")
        + "</tbody></table>"
    )
    if failed:
        show_label = f"显示清单（{len(failed)}）"
        fold_btn = (
            f'<button type="button" class="fold" data-target="fail-detail" '
            f'data-show="{_esc(show_label)}" data-hide="隐藏清单" '
            f'aria-expanded="false" aria-controls="fail-detail">{_esc(show_label)}</button>'
        )
        fail_table = (
            f'<div id="fail-detail" hidden>{fail_extra}{fail_markup}</div>'
        )
    else:
        fold_btn = ""
        fail_table = fail_extra

    fps = sorted(
        payload.get("false_positives") or [],
        key=lambda r: (-int(r.get("event_count") or 0), str(r.get("t_start") or "")),
    )
    fp_preview = fps[:FP_PREVIEW]
    fp_rows = []
    for row in fp_preview:
        fp_rows.append(
            "<tr>"
            f"<td>{_esc(', '.join(row.get('techniques') or []) or '(无 Technique 字符串)')}</td>"
            f"<td>{_esc(row.get('rule_id'))}</td>"
            f"<td>{_esc(', '.join(row.get('rule_names') or []) or '—')}</td>"
            f"<td>{row.get('event_count')}</td>"
            f"<td>{'告警' if row.get('from_alert') else '遥测'}</td>"
            f"<td>{_esc(row.get('t_start'))}</td>"
            f"{_cmd_cell(row.get('sample_command_line'))}"
            "</tr>"
        )
    fp_note = (
        "<p class=\"note\">误报候选看的是 <strong>NGES 带 Technique 的检测簇</strong>，"
        "不是 Atomic 回合状态，因此既不是「标成别的 TTP」，也不是「告警但 TTP 不对齐」。"
        "后两者是某次执行成功的 Atomic 落在哪一格；本表是打了 ATT&amp;CK 标签、"
        "却没能一对一挂到任何成功 Atomic 的簇（命令对不上、时间窗外、Technique 无关、"
        "对应测试失败，或簇已被另一条 Atomic 占用）。无 Technique 的普通遥测不会出现在这里。"
        "精确率的 FP 只数这些簇。</p>"
    )
    fp_extra = (
        fp_note
        + (
            f"<p class='muted'>按事件数预览 {len(fp_preview)}/{len(fps)} 个簇。完整清单见同名 JSON。</p>"
            if fps
            else "<p class='muted'>没有未归属的带标注簇。</p>"
        )
    )
    errors = meta.get("errors") or []
    err_html = (
        "<ul>" + "".join(f"<li>{_esc(e)}</li>" for e in errors) + "</ul>"
        if errors
        else "<p>无。</p>"
    )
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>NGES 遥测测评 {_esc(meta.get('stamp'))}</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--line:#30363d;--text:#c9d1d9;--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922}}
*{{box-sizing:border-box}}
body{{margin:0;padding:20px;background:var(--bg);color:var(--text);font:13px/1.5 ui-sans-serif,system-ui,"Segoe UI","PingFang SC",sans-serif}}
main{{max-width:1600px;margin:auto}}
h1{{margin:0 0 4px;font-size:20px}}
h2{{font-size:14px;color:var(--blue);margin:0 0 10px}}
h3{{font-size:12px;color:var(--muted);margin:0 0 9px}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px;margin:16px 0}}
.meta,.muted{{color:var(--muted);font-size:12px}}
.note{{color:var(--text);font-size:13px;line-height:1.65;margin:0 0 10px}}
table.glossary{{max-width:1100px}}
table.glossary td:first-child{{white-space:nowrap;font-weight:600;color:var(--blue)}}
td.formula,.formula{{font-variant-numeric:tabular-nums}}
td.formula em{{font-style:italic;color:var(--text)}}
.guess-summary{{max-width:820px;margin:8px 0 14px}}
.bars{{margin:8px 0 14px;max-width:820px}}
.bar-row{{display:grid;grid-template-columns:minmax(180px,280px) 1fr 2.2em;gap:8px;align-items:center;margin:5px 0}}
.bar-label{{color:var(--text);font-size:12px}}
.bar-track{{background:#0f1419;border:1px solid var(--line);height:10px;border-radius:4px;overflow:hidden}}
.bar-fill{{display:block;height:100%;background:var(--red)}}
.bar-fill-cover{{background:var(--blue)}}
.phase-note{{font-size:12px;margin:0 0 8px}}
.bar-n{{color:var(--red);font-variant-numeric:tabular-nums;text-align:right}}
.focus-table td .tids{{display:flex;flex-wrap:wrap;gap:4px}}
.tids code{{background:#0f1419;border:1px solid var(--line);padding:1px 5px;border-radius:3px;white-space:nowrap}}
code.ttp-hit{{color:var(--green);background:rgba(63,185,80,.15);border-color:rgba(63,185,80,.4)}}
code.ttp-wrong{{color:var(--red);background:rgba(248,81,73,.15);border-color:rgba(248,81,73,.4)}}
.ttp-pair{{display:inline-flex;flex-wrap:wrap;align-items:baseline;gap:4px;margin:0 10px 4px 0}}
.ttp-hit-rule{{color:var(--green);font-size:11px}}
.ttp-wrong-rule{{color:var(--red);font-size:11px}}
.ttp-rule-missing{{color:var(--muted);font-size:11px}}
span.ttp-hit{{color:var(--green)}}
span.ttp-wrong{{color:var(--red)}}
.instances .tids{{display:flex;flex-wrap:wrap;gap:4px;align-items:center}}
.method{{margin:0 0 16px;font-size:14px;line-height:1.7}}
.method-number{{display:inline-block;color:var(--blue);font-weight:700;font-variant-numeric:tabular-nums}}
.method-risk{{color:var(--red)}}
.verdict{{margin-top:12px}}
.method-stage{{color:#d2a8ff;font-weight:600}}
.summary{{display:flex;gap:10px;flex-wrap:wrap}}
.metric{{min-width:140px;border:1px solid var(--line);border-radius:6px;padding:8px 10px;background:#0f1419}}
.metric span{{display:block;color:var(--muted);font-size:11px}}
.metric b{{font-size:19px}}
.chips{{display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
td .chips{{margin:0;gap:6px}}
.table-tools{{display:flex;gap:8px;align-items:center;margin:0 0 10px}}
input,select{{background:#0f1419;border:1px solid var(--line);border-radius:5px;color:var(--text);padding:7px 9px}}
input{{width:320px;max-width:100%}}
select{{min-width:190px}}
.sort-direction{{width:34px;height:32px;border:1px solid var(--line);background:#0f1419;color:var(--blue);border-radius:5px;cursor:pointer;font-size:16px}}
table{{width:100%;border-collapse:collapse}}
th,td{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
th{{color:var(--muted);font-size:11px}}
.table-wrap>table>thead th{{position:sticky;top:0;z-index:3;background:var(--panel);box-shadow:0 1px 0 var(--line)}}
tfoot td{{border-top:1px solid var(--line);color:var(--text);font-weight:600}}
code{{font:11px ui-monospace,monospace}}
.badge{{display:inline-block;border-radius:4px;padding:2px 7px;font-size:11px}}
.pass{{color:var(--green);background:rgba(63,185,80,.15)}}
.fail{{color:var(--red);background:rgba(248,81,73,.15)}}
.neutral{{color:var(--orange);background:rgba(210,153,34,.15)}}
.tip{{display:inline-block;position:relative;margin-left:4px;width:14px;height:14px;border:1px solid var(--muted);border-radius:50%;color:var(--muted);font-size:10px;line-height:12px;text-align:center;cursor:help;outline:none}}
.tip::after{{content:attr(data-tooltip);position:absolute;z-index:10;left:50%;top:calc(100% + 7px);transform:translateX(-50%);width:max-content;max-width:280px;padding:7px 9px;background:#0d1117;border:1px solid var(--line);border-radius:4px;color:var(--text);font:12px/1.4 ui-sans-serif,system-ui,sans-serif;text-align:left;white-space:normal;visibility:hidden;opacity:0;pointer-events:none}}
.tip:hover::after,.tip:focus::after,.tip.active::after{{visibility:visible;opacity:1}}
.section-head{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 10px}}
.section-head h2{{margin:0}}
.expand,.fold{{border:1px solid var(--line);background:#0f1419;color:var(--blue);border-radius:4px;padding:3px 7px;cursor:pointer;white-space:nowrap}}
.detail-row td{{padding:12px 18px;background:#0f1419}}
.instances{{margin-top:10px;background:#0d1117;font-size:11px}}
.instances th,.instances td{{padding:6px}}
td.cmd{{max-width:none;white-space:pre-wrap;word-break:break-word}}
td.cmd code{{display:block;white-space:pre-wrap;word-break:break-word}}
td.wrap{{max-width:420px;word-break:break-all}}
td.wrap.cmd{{max-width:none}}
@media(max-width:900px){{body{{padding:12px}}.table-wrap{{overflow-x:auto}}}}
</style>
</head>
<body>
<main>
<h1>NGES 遥测测评报告</h1>
<div class="meta">生成时间 {_esc(meta.get('generated_at'))}　编号 {_esc(meta.get('stamp'))}</div>
<section>
<h2>Batch Summary</h2>
{_narrative(payload)}
<div class="summary">{card_html}</div>
{_verdict(payload)}
{_scope_note()}
{_coverage_and_low_visual(payload)}
</section>
{_intro_section(payload)}
<section>
<h2>按战术</h2>
<p class="muted">按单个战术阶段汇总。一个 TTP 属于多个阶段时，该回合会同时出现在多行，因此各行之和可以大于合计。状态只统计执行成功的回合，彩色标签见下方「状态说明」。标对 / 告警且标对 / 标对但告警不对齐 = 检出；其余都不算检出。</p>
<table>
<thead><tr><th>战术</th><th>执行成功</th><th>「可见」</th><th>检出</th><th>召回</th><th>状态</th></tr></thead>
<tbody>
{''.join(tactic_rows) or "<tr><td colspan='6'>无</td></tr>"}
</tbody>
<tfoot>{tactic_foot}</tfoot>
</table>
{_status_section()}
</section>
<section>
<h2>TTPs</h2>
<div class="table-tools">
<input id="filter" type="search" placeholder="筛选 TTP / 名称 / 战术"/>
<select id="sort-key">
<option value="phase">按战术阶段</option>
<option value="ttp">按 TTP</option>
<option value="recall">按召回</option>
<option value="miss">按漏报</option>
<option value="executed">按执行成功数</option>
<option value="detected">按检出</option>
<option value="alerted">按告警</option>
</select>
<button id="sort-direction" class="sort-direction" title="升序" aria-label="升序">↑</button>
</div>
<div class="table-wrap">
<table>
<thead><tr>
<th>TTP</th>
<th>ATT&amp;CK 战术</th>
<th>执行成功/总数 {_tip("测试命令次数，不含前置准备和清理。未成功执行不计入召回分母。")}</th>
<th>「可见」 {_tip("层 A：时间窗内命令行/路径能对上本次 Atomic。不是窗内有任意遥测。")}</th>
<th>检出 {_tip("层 B：「可见」且 Technique 与本次 technique_id 对齐。召回的分子。")}</th>
<th>告警 {_tip("层 C：「可见」且来自 alert.log 工单。不等于检出。")}</th>
<th>召回 {_tip("检出 / 执行成功。无成功执行时为 —。")}</th>
<th>漏报率 {_tip("1 − 召回。执行成功但未检出。")}</th>
<th>回合明细</th>
</tr></thead>
<tbody id="ttps">
{''.join(tech_blocks) or "<tr><td colspan='9'>无</td></tr>"}
</tbody>
</table>
</div>
</section>
<section>
<h2>误报候选</h2>
{fp_extra}
<table>
<thead><tr><th>Technique</th><th>规则 ID</th><th>规则名</th><th>事件数</th><th>来源</th><th>起始时间</th><th>示例 commandLine {_tip("簇内命令完整原文，不截断。")}</th></tr></thead>
<tbody>
{''.join(fp_rows) or "<tr><td colspan='7'>无</td></tr>"}
</tbody></table>
</section>
<section>
<div class="section-head">
<h2>未执行成功（不计入漏报）</h2>
{fold_btn}
</div>
<p class="muted">日志原因分布：{_esc(reason_txt)}</p>
{fail_note}
{guess_table}
{fail_table}
</section>
<section>
<h2>解析警告</h2>
{err_html}
</section>
</main>
<script>
const filter=document.getElementById('filter'),sortKey=document.getElementById('sort-key'),sortDirection=document.getElementById('sort-direction'),body=document.getElementById('ttps');
let ascending=true;
function hideDetail(row){{const detail=row.nextElementSibling;if(detail&&detail.classList.contains('detail-row'))detail.hidden=true;}}
function sortRows(){{
  const rows=[...body.querySelectorAll('.ttp-row')];
  rows.sort((a,b)=>{{
    const key=sortKey.value;
    let av=key==='ttp'?a.dataset.ttp:Number(a.dataset[key]),bv=key==='ttp'?b.dataset.ttp:Number(b.dataset[key]);
    let result=typeof av==='string'?av.localeCompare(bv,undefined,{{numeric:true}}):av-bv;
    if(!result&&key==='phase')result=a.dataset.ttp.localeCompare(b.dataset.ttp,undefined,{{numeric:true}});
    return ascending?result:-result;
  }});
  for(const row of rows){{
    const group=[row],detail=row.nextElementSibling;
    if(detail&&detail.classList.contains('detail-row'))group.push(detail);
    body.append(...group);
  }}
}}
filter.addEventListener('input',e=>{{
  const q=e.target.value.trim().toLowerCase();
  document.querySelectorAll('.ttp-row').forEach(r=>{{r.hidden=!!q&&!(r.dataset.search||'').includes(q);hideDetail(r);}});
}});
sortKey.addEventListener('change',sortRows);
sortDirection.addEventListener('click',()=>{{
  ascending=!ascending;
  sortDirection.textContent=ascending?'↑':'↓';
  sortDirection.title=ascending?'升序':'降序';
  sortDirection.setAttribute('aria-label',sortDirection.title);
  sortRows();
}});
document.addEventListener('click',e=>{{
  const tip=e.target.closest('.tip');
  if(tip){{document.querySelectorAll('.tip.active').forEach(item=>{{if(item!==tip)item.classList.remove('active')}});tip.classList.toggle('active');return;}}
  const fold=e.target.closest('.fold');
  if(fold){{
    const panel=document.getElementById(fold.dataset.target);
    if(!panel)return;
    panel.hidden=!panel.hidden;
    fold.setAttribute('aria-expanded',String(!panel.hidden));
    fold.textContent=panel.hidden?(fold.dataset.show||'显示'):(fold.dataset.hide||'隐藏');
    return;
  }}
  const button=e.target.closest('.expand');
  if(button){{const row=document.getElementById(button.dataset.target);if(row)row.hidden=!row.hidden;}}
}});
</script>
</body>
</html>
"""


def write_csv(payload: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in payload.get("episodes") or []:
            writer.writerow(
                {
                    "technique_id": row.get("technique_id"),
                    "variant_guid": row.get("variant_guid"),
                    "variant_name": row.get("variant_name"),
                    "strategy": row.get("strategy"),
                    "timestamp": row.get("timestamp"),
                    "executed_ok": row.get("executed_ok"),
                    "status": row.get("status"),
                    "observed": row.get("observed"),
                    "detected": row.get("detected"),
                    "alerted": row.get("alerted"),
                    "detection_kind": row.get("detection_kind"),
                    "latency_s": row.get("latency_s"),
                    "hit_techniques": ";".join(row.get("hit_techniques") or []),
                    "wrong_techniques": ";".join(row.get("wrong_techniques") or []),
                    "wrong_rules": ";".join(row.get("wrong_rules") or []),
                    "hit_rules": ";".join(row.get("hit_rules") or []),
                    "alert_rules": ";".join(row.get("alert_rules") or []),
                    "alert_techniques": ";".join(
                        tid
                        for techs in (row.get("alert_rule_techniques") or {}).values()
                        for tid in techs
                    ),
                    "exit_code": row.get("exit_code"),
                    "failure_reason": row.get("failure_reason"),
                    "failure_guess": row.get("failure_guess"),
                    "observe_score": row.get("observe_score"),
                    "sample_command_line": row.get("sample_command_line"),
                }
            )


def write_reports(payload: dict[str, Any], out_dir: Path, stamp: str) -> dict[str, Path]:
    enrich_failures(payload)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = out_dir / f"report-{stamp}"
    json_path = Path(str(stem) + ".json")
    html_path = Path(str(stem) + ".html")
    csv_path = Path(str(stem) + ".csv")
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    html_path.write_text(render_html(payload), encoding="utf-8")
    write_csv(payload, csv_path)
    return {"json": json_path, "html": html_path, "csv": csv_path}
