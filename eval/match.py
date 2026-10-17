"""Time-window + command-line + TTP alignment with one-to-one cluster assignment."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from .atomic_logs import Episode
from .nges.schema import NgesEvent

Relation = Literal["exact", "parent", "child", "unrelated"]

OBSERVE_THRESHOLD = 2.0
CLUSTER_GAP_SEC = 5.0
PID_BONUS = 10.0
_RUNNER_MARKERS = ("atomic_reforge.cli", "-m atomic_reforge")


@dataclass
class MatchConfig:
    window_sec: float = 60.0
    parent_match: bool = True
    cluster_gap_sec: float = CLUSTER_GAP_SEC
    observe_threshold: float = OBSERVE_THRESHOLD
    quiet_min_sec: float = 60.0
    quiet_min_frac: float = 0.10


def normalize_technique(technique_id: str) -> str:
    return (technique_id or "").strip().upper()


def parent_technique(technique_id: str) -> str:
    text = normalize_technique(technique_id)
    if "." in text:
        return text.split(".", 1)[0]
    return text


def technique_relation(atomic_id: str, edr_id: str) -> Relation:
    a = normalize_technique(atomic_id)
    e = normalize_technique(edr_id)
    if not a or not e:
        return "unrelated"
    if a == e:
        return "exact"
    if parent_technique(a) == e and a != e:
        return "parent"
    if parent_technique(e) == a and a != e:
        return "child"
    if parent_technique(a) == parent_technique(e) and parent_technique(a):
        # T1055.004 vs T1055.011 — siblings, not a hit
        return "unrelated"
    return "unrelated"


def best_relation(atomic_id: str, edr_ids: tuple[str, ...]) -> Relation:
    order = {"exact": 3, "child": 2, "parent": 1, "unrelated": 0}
    best: Relation = "unrelated"
    for edr_id in edr_ids:
        rel = technique_relation(atomic_id, edr_id)
        if order[rel] > order[best]:
            best = rel
    return best


def alert_ttp_aligned(
    atomic_id: str, alert_rule_techniques: dict[str, list[str]] | None
) -> bool:
    for techs in (alert_rule_techniques or {}).values():
        for tid in techs or []:
            if tid and technique_relation(atomic_id, tid) != "unrelated":
                return True
    return False


def relation_counts_as_hit(rel: Relation, parent_match: bool) -> bool:
    if rel in ("exact", "child"):
        return True
    if rel == "parent" and parent_match:
        return True
    return False


def is_reforge_runner_command(cmd: str) -> bool:
    low = (cmd or "").lower()
    return any(marker in low for marker in _RUNNER_MARKERS)


def display_command_line(event: NgesEvent, fallback: str = "") -> str:
    """Prefer the payload command over the atomic-reforge scheduler wrapper."""
    src = event.command_line or ""
    tgt = event.target_command_line or ""
    if tgt and not is_reforge_runner_command(tgt):
        return tgt
    if src and not is_reforge_runner_command(src):
        return src
    if fallback:
        return fallback
    return src or tgt


def observe_score(episode: Episode, event: NgesEvent) -> tuple[float, list[str]]:
    """Layer A: command/path overlap. Executor image alone is not enough."""
    hay = event.haystack
    if not hay:
        return 0.0, []
    score = 0.0
    matched: list[str] = []
    tid = normalize_technique(episode.technique_id).lower()
    runner_src = is_reforge_runner_command(event.command_line)
    payload_hay = "\n".join(
        p
        for p in (event.target_command_line, *event.extra_paths)
        if p
    ).lower()
    if episode.pid is not None and event.pid is not None and episode.pid == event.pid:
        score += PID_BONUS
        matched.append(f"pid:{episode.pid}")
    for sig in episode.signatures:
        if not sig:
            continue
        if sig == tid and runner_src and sig not in payload_hay:
            # `python ... run T1622` is the scheduler, not the Atomic payload.
            continue
        if sig not in hay:
            continue
        if "\\" in sig or "/" in sig or len(sig) >= 12:
            score += 3.0
        elif sig == tid:
            score += 2.0
        else:
            score += 1.0
        matched.append(sig)
    if score > 0 and episode.executor_images:
        if any(img in hay for img in episode.executor_images):
            score += 0.5
    return score, matched


@dataclass
class DetectionCluster:
    events: list[NgesEvent]
    techniques: tuple[str, ...]
    rule_id: str
    rule_names: tuple[str, ...]
    t_start: datetime
    t_end: datetime
    assigned_episode_key: tuple[str, str, str] | None = None

    @property
    def labeled(self) -> bool:
        return True

    @property
    def sample_command(self) -> str:
        for ev in self.events:
            shown = display_command_line(ev)
            if shown:
                return shown
        return ""


def _keep_rule(store: dict[str, str], tid: str, name: str) -> None:
    tid = (tid or "").strip()
    if not tid:
        return
    name = name or ""
    prev = store.get(tid)
    if prev is None or (not prev and name):
        store[tid] = name


def _rules_for_techniques(
    techniques: tuple[str, ...] | list[str],
    events: list[NgesEvent],
    fallback_names: tuple[str, ...] = (),
) -> list[str]:
    per: dict[str, str] = {}
    for ev in events:
        for tid in ev.techniques:
            _keep_rule(per, tid, ev.rule_name)
    shared = next((n for n in fallback_names if n), "")
    return [per.get(tid) or shared for tid in techniques]


def cluster_labeled_events(
    events: list[NgesEvent], gap_sec: float = CLUSTER_GAP_SEC
) -> list[DetectionCluster]:
    labeled = [e for e in events if e.labeled]
    labeled.sort(key=lambda e: (e.rule_id, e.technique_key, e.t_utc, e.line_no))
    clusters: list[DetectionCluster] = []
    gap = timedelta(seconds=gap_sec)
    for ev in labeled:
        key_id = ev.rule_id
        key_tech = ev.technique_key
        if (
            clusters
            and clusters[-1].rule_id == key_id
            and clusters[-1].techniques == key_tech
            and ev.t_utc - clusters[-1].t_end <= gap
        ):
            clusters[-1].events.append(ev)
            clusters[-1].t_end = ev.t_utc
            names = set(clusters[-1].rule_names)
            if ev.rule_name:
                names.add(ev.rule_name)
            clusters[-1].rule_names = tuple(sorted(names))
        else:
            clusters.append(
                DetectionCluster(
                    events=[ev],
                    techniques=key_tech,
                    rule_id=key_id,
                    rule_names=(ev.rule_name,) if ev.rule_name else (),
                    t_start=ev.t_utc,
                    t_end=ev.t_utc,
                )
            )
    return clusters


@dataclass
class EpisodeMatch:
    episode: Episode
    observed: bool = False
    detected: bool = False
    detection_kind: str = ""  # exact / parent / child
    wrong_ttp: bool = False
    observe_score: float = 0.0
    matched_signatures: list[str] = field(default_factory=list)
    latency_s: float | None = None
    hit_techniques: list[str] = field(default_factory=list)
    hit_tactics: list[str] = field(default_factory=list)
    hit_rules: list[str] = field(default_factory=list)
    wrong_techniques: list[str] = field(default_factory=list)
    wrong_rules: list[str] = field(default_factory=list)
    sample_command_line: str = ""
    status: str = ""
    cluster_index: int | None = None
    alerted: bool = False
    alert_rules: list[str] = field(default_factory=list)
    alert_rule_techniques: dict[str, list[str]] = field(default_factory=dict)
    alert_aligned: bool = False

    def finalize(self) -> None:
        ep = self.episode
        if not ep.executed_ok:
            self.status = "not_executed"
            return
        self.alert_aligned = self.alerted and alert_ttp_aligned(
            ep.technique_id, self.alert_rule_techniques
        )
        if self.alerted and self.detected:
            self.status = "alerted" if self.alert_aligned else "ttp_detected_alert_wrong"
            return
        if self.alerted and not self.detected:
            self.status = "alerted_wrong_ttp"
            return
        if self.detected:
            self.status = "ttp_detected"
            return
        if self.observed and self.wrong_ttp:
            self.status = "observed_wrong_ttp"
            return
        if self.observed:
            self.status = "observed_unlabeled"
            return
        self.status = "executed_not_observed"


@dataclass
class MatchResult:
    matches: list[EpisodeMatch]
    clusters: list[DetectionCluster]
    false_positives: list[DetectionCluster]
    config: MatchConfig
    telemetry_start: datetime | None
    telemetry_end: datetime | None
    quiet_sec: float
    accuracy_applicable: bool


def _window(episode: Episode, window_sec: float) -> tuple[datetime, datetime]:
    delta = timedelta(seconds=window_sec)
    return episode.t0 - delta, episode.t1 + delta


def _overlaps(
    start: datetime, end: datetime, w0: datetime, w1: datetime
) -> bool:
    return start <= w1 and end >= w0


def _events_in_window(
    events: list[NgesEvent], w0: datetime, w1: datetime
) -> list[NgesEvent]:
    # events are sorted by time
    out: list[NgesEvent] = []
    for ev in events:
        if ev.t_utc < w0:
            continue
        if ev.t_utc > w1:
            break
        out.append(ev)
    return out


def _cluster_observe(
    episode: Episode, cluster: DetectionCluster, threshold: float
) -> tuple[float, list[str], NgesEvent | None]:
    best = 0.0
    best_matched: list[str] = []
    best_event: NgesEvent | None = None
    for ev in cluster.events:
        score, matched = observe_score(episode, ev)
        if score > best:
            best = score
            best_matched = matched
            best_event = ev
    if best < threshold:
        return 0.0, [], None
    return best, best_matched, best_event


def _note_alert(
    ev: NgesEvent,
    alert_rules: list[str],
    alert_techs: dict[str, list[str]],
) -> None:
    name = ev.rule_name or "(无规则名)"
    if name not in alert_rules:
        alert_rules.append(name)
    bucket = alert_techs.setdefault(name, [])
    for tid in ev.techniques:
        if tid and tid not in bucket:
            bucket.append(tid)


def _rank(rel: Relation, observe: float, dt_abs: float) -> float:
    base = {"exact": 300.0, "child": 250.0, "parent": 200.0, "unrelated": 0.0}[rel]
    return base + observe - min(dt_abs, 60.0) * 0.01


def match_episodes(
    episodes: list[Episode],
    events: list[NgesEvent],
    config: MatchConfig | None = None,
) -> MatchResult:
    config = config or MatchConfig()
    clusters = cluster_labeled_events(events, config.cluster_gap_sec)
    matches = [EpisodeMatch(episode=ep) for ep in episodes]

    # Layer A (observed / alerted) per episode — independent, no exclusivity.
    for m in matches:
        if not m.episode.executed_ok:
            m.finalize()
            continue
        w0, w1 = _window(m.episode, config.window_sec)
        window_events = _events_in_window(events, w0, w1)
        best = 0.0
        best_matched: list[str] = []
        best_cmd = ""
        labeled_unrelated = False
        alert_obs = False
        alert_rules: list[str] = []
        alert_techs: dict[str, list[str]] = {}
        wrong_techs: dict[str, str] = {}
        best_wrong_cmd = ""
        best_wrong_score = -1.0
        for ev in window_events:
            score, matched = observe_score(m.episode, ev)
            if score >= config.observe_threshold:
                if score > best:
                    best = score
                    best_matched = matched
                    best_cmd = display_command_line(ev, m.episode.command)
                if ev.kind == "alert":
                    alert_obs = True
                    _note_alert(ev, alert_rules, alert_techs)
                if ev.labeled:
                    rel = best_relation(m.episode.technique_id, ev.techniques)
                    hit = relation_counts_as_hit(rel, config.parent_match)
                    for tid in ev.techniques:
                        if (
                            tid
                            and technique_relation(m.episode.technique_id, tid)
                            == "unrelated"
                        ):
                            _keep_rule(wrong_techs, tid, ev.rule_name)
                    if not hit:
                        labeled_unrelated = True
                        if score > best_wrong_score:
                            best_wrong_score = score
                            best_wrong_cmd = display_command_line(ev, m.episode.command)
        m.observed = best >= config.observe_threshold
        m.observe_score = best
        m.matched_signatures = best_matched
        m.sample_command_line = best_wrong_cmd or best_cmd
        m.wrong_ttp = labeled_unrelated
        m.wrong_techniques = list(wrong_techs)
        m.wrong_rules = [wrong_techs[t] for t in wrong_techs]
        m.alerted = alert_obs
        m.alert_rules = alert_rules
        m.alert_rule_techniques = alert_techs

    # Layer B: greedy 1-1 assignment of labeled clusters to successful episodes.
    candidates: list[tuple[float, int, int, Relation, list[str], NgesEvent]] = []
    for ci, cluster in enumerate(clusters):
        for mi, m in enumerate(matches):
            if not m.episode.executed_ok:
                continue
            w0, w1 = _window(m.episode, config.window_sec)
            if not _overlaps(cluster.t_start, cluster.t_end, w0, w1):
                continue
            score, matched, ev = _cluster_observe(
                m.episode, cluster, config.observe_threshold
            )
            if ev is None:
                continue
            rel = best_relation(m.episode.technique_id, cluster.techniques)
            if not relation_counts_as_hit(rel, config.parent_match):
                continue
            dt = abs((ev.t_utc - m.episode.t0).total_seconds())
            rank = _rank(rel, score, dt)
            candidates.append((rank, mi, ci, rel, matched, ev))

    candidates.sort(key=lambda row: (-row[0], row[1], row[2]))
    used_clusters: set[int] = set()
    used_episodes: set[int] = set()
    for rank, mi, ci, rel, matched, ev in candidates:
        if mi in used_episodes or ci in used_clusters:
            continue
        used_episodes.add(mi)
        used_clusters.add(ci)
        m = matches[mi]
        cluster = clusters[ci]
        cluster.assigned_episode_key = m.episode.key
        m.detected = True
        m.detection_kind = rel
        m.observed = True
        m.cluster_index = ci
        aligned_tids = [
            t
            for t in cluster.techniques
            if t and technique_relation(m.episode.technique_id, t) != "unrelated"
        ]
        extra_tids = [
            t
            for t in cluster.techniques
            if t and technique_relation(m.episode.technique_id, t) == "unrelated"
        ]
        m.hit_techniques = aligned_tids
        m.hit_tactics = list(
            dict.fromkeys(t for ev in cluster.events for t in ev.tactics)
        )
        m.hit_rules = _rules_for_techniques(
            m.hit_techniques, cluster.events, cluster.rule_names
        )
        if extra_tids:
            extra_rules = _rules_for_techniques(
                extra_tids, cluster.events, cluster.rule_names
            )
            wrong_map = dict(zip(m.wrong_techniques, m.wrong_rules))
            for tid, rule in zip(extra_tids, extra_rules):
                _keep_rule(wrong_map, tid, rule)
            m.wrong_techniques = list(wrong_map)
            m.wrong_rules = [wrong_map[t] for t in wrong_map]
        m.latency_s = (ev.t_utc - m.episode.t0).total_seconds()
        shown = display_command_line(ev, m.episode.command)
        if shown:
            m.sample_command_line = shown
        if matched:
            m.matched_signatures = matched
        if any(ev.kind == "alert" for ev in cluster.events):
            m.alerted = True
            for ev in cluster.events:
                if ev.kind == "alert":
                    _note_alert(ev, m.alert_rules, m.alert_rule_techniques)

    for m in matches:
        m.finalize()

    fps = [c for i, c in enumerate(clusters) if i not in used_clusters]

    telemetry_start = events[0].t_utc if events else None
    telemetry_end = events[-1].t_utc if events else None
    quiet_sec, accuracy_ok = _quiet_and_accuracy(
        episodes, events, config, telemetry_start, telemetry_end
    )
    return MatchResult(
        matches=matches,
        clusters=clusters,
        false_positives=fps,
        config=config,
        telemetry_start=telemetry_start,
        telemetry_end=telemetry_end,
        quiet_sec=quiet_sec,
        accuracy_applicable=accuracy_ok,
    )


def _merge_intervals(
    intervals: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_s, last_e = merged[-1]
        if start <= last_e:
            merged[-1] = (last_s, max(last_e, end))
        else:
            merged.append((start, end))
    return merged


def _quiet_and_accuracy(
    episodes: list[Episode],
    events: list[NgesEvent],
    config: MatchConfig,
    t0: datetime | None,
    t1: datetime | None,
) -> tuple[float, bool]:
    if t0 is None or t1 is None or t1 <= t0:
        return 0.0, False
    span = (t1 - t0).total_seconds()
    covered = _merge_intervals(
        [_window(ep, config.window_sec) for ep in episodes]
    )
    quiet = span
    for start, end in covered:
        a = max(start, t0)
        b = min(end, t1)
        if b > a:
            quiet -= (b - a).total_seconds()
    quiet = max(0.0, quiet)
    applicable = quiet >= config.quiet_min_sec and (
        span <= 0 or quiet / span >= config.quiet_min_frac
    )
    return quiet, applicable
