"""NGES evaluation: parsers, matching, metrics, fixture report."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from eval.atomic_logs import extract_signatures, load_jsonl, strategy_from_name
from eval.cli import evaluate, expand_telemetry
from eval.report import _variant_display
from eval.match import MatchConfig, match_episodes, observe_score, technique_relation
from eval.metrics import compute
from eval.nges.parse import expand_nges_records, load_events
from eval.nges.schema import NgesEvent, extract_techniques, parse_nges_time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ATOMIC = ROOT / "eval" / "testdata" / "run-fixture.json"
FIXTURE_TEL = ROOT / "eval" / "testdata" / "telemetry.ndjson"


def _utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def _event(
    ts: str,
    *,
    techniques: tuple[str, ...] = (),
    command: str = "",
    labeled: bool | None = None,
    rule_id: str = "1",
    tactics: tuple[str, ...] = (),
    rule_name: str = "",
    pid: int | None = None,
    file_name: str = "",
    kind: str = "telemetry",
) -> NgesEvent:
    hay = "\n".join(p for p in (command, file_name) if p).lower()
    if labeled is None:
        labeled = bool(techniques)
    return NgesEvent(
        t_utc=_utc(ts) if "T" in ts else parse_nges_time(ts) or _utc("2026-10-08T00:00:00Z"),
        subtype="ProcessCreate",
        techniques=techniques,
        tactics=tactics,
        labeled=labeled,
        rule_name=rule_name,
        rule_id=rule_id,
        command_line=command,
        file_name=file_name,
        file_path="",
        pid=pid,
        haystack=hay,
        kind=kind,
    )


def test_parse_nges_time_utc8():
    dt = parse_nges_time("2026-10-08 10:41:05.100 (UTC+8)")
    assert dt is not None
    assert dt == _utc("2026-10-08T02:41:05.100Z")


def test_extract_techniques_union():
    ev = {
        "builtinTtpTechnique": "",
        "customTtpTechnique": "",
        "basicTtp": '{"BasicTtp":[{"Tactic":"TA0005","Technique":"T1055"}],"ScoreTtp":[]}',
    }
    techs, tactics, labeled = extract_techniques(ev)
    assert labeled
    assert techs == ["T1055"]
    assert tactics == ["TA0005"]


def test_extract_techniques_score_ttp_without_id():
    ev = {"basicTtp": '{"BasicTtp":[],"ScoreTtp":[{"ScoreTtpRuleId":1}]}'}
    techs, _, labeled = extract_techniques(ev)
    assert labeled
    assert techs == []


def test_strategy_from_variant_name():
    assert strategy_from_name("x - reforge/identity_original") == "identity/original"


def test_variant_display_strips_identity_suffix():
    assert _variant_display("Early Cascade - reforge/identity_original") == "Early Cascade"
    assert _variant_display("Keep other - reforge/obfuscate_cmd") == "Keep other - reforge/obfuscate_cmd"
    assert _variant_display("") == "—"


def test_signatures_skip_generic_powershell():
    sigs = extract_signatures(
        "powershell.exe -Command Get-Process",
        "powershell.exe -NoProfile -Command Get-Process",
        "T1057",
    )
    assert "powershell.exe" not in sigs
    assert "t1057" in sigs


def test_technique_relation():
    assert technique_relation("T1055.004", "T1055.004") == "exact"
    assert technique_relation("T1055.004", "T1055") == "parent"
    assert technique_relation("T1055", "T1055.011") == "child"
    assert technique_relation("T1055.004", "T1055.011") == "unrelated"
    assert technique_relation("T1059.001", "T1574.001") == "unrelated"


def test_observe_ignores_executor_only():
    from eval.atomic_logs import Episode

    ep = Episode(
        technique_id="T1057",
        variant_guid="g",
        variant_name="n",
        timestamp=_utc("2026-10-08T02:41:00Z"),
        duration_s=1,
        executor="powershell",
        command="Get-Process",
        argv="Get-Process",
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures("Get-Process", "Get-Process", "T1057"),
        executor_images=("powershell.exe",),
    )
    ev = _event(
        "2026-10-08T02:41:01Z",
        command="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        file_name="powershell.exe",
    )
    score, _ = observe_score(ep, ev)
    assert score < 2


def test_reforge_runner_is_not_the_payload_command():
    from eval.atomic_logs import Episode
    from eval.match import display_command_line, is_reforge_runner_command
    from eval.nges.schema import event_from_record
    from eval.report import _episode_sample_cmd

    payload_cmd = (
        "powershell.exe -NoProfile -NonInteractive -Command "
        "& {$debuggerProcesses = Get-Process | Where-Object { $_.ProcessName -match \"dbg\" }}"
    )
    runner = (
        r'"C:\Users\AHunter\Desktop\infected\release\runtime\python.exe"'
        "  -m atomic_reforge.cli run T1622 --path variants --execute --execute --get-prereqs"
    )
    assert is_reforge_runner_command(runner)
    rec = {
        "Event": {
            "agentDisplayTime": "2026-10-08 10:51:45.000 (UTC+8)",
            "telemetrySubType": "ProcessCreate",
        },
        "SourceProcess": {"commandLine": runner, "fileName": "python.exe"},
        "TargetProcess": {"commandLine": payload_cmd, "fileName": "powershell.exe"},
    }
    ev = event_from_record(rec)
    assert ev is not None
    assert ev.target_command_line == payload_cmd
    assert display_command_line(ev, fallback="fallback") == payload_cmd

    ep = Episode(
        technique_id="T1622",
        variant_guid="g",
        variant_name="n",
        timestamp=_utc("2026-10-08T02:51:45Z"),
        duration_s=1,
        executor="powershell",
        command=payload_cmd,
        argv=payload_cmd,
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures(payload_cmd, payload_cmd, "T1622"),
        executor_images=("powershell.exe",),
    )
    score, matched = observe_score(ep, ev)
    assert score >= 2.0
    assert any("debugger" in s for s in matched)

    runner_only = event_from_record(
        {
            "Event": {"agentDisplayTime": "2026-10-08 10:51:45.000 (UTC+8)"},
            "SourceProcess": {"commandLine": runner, "fileName": "python.exe"},
        }
    )
    assert runner_only is not None
    score_only, matched_only = observe_score(ep, runner_only)
    assert score_only < 2.0
    assert "t1622" not in matched_only
    assert _episode_sample_cmd(
        {"sample_command_line": runner, "command": payload_cmd}
    ) == payload_cmd


def test_fixture_metrics(tmp_path: Path):
    payload = evaluate(
        FIXTURE_ATOMIC,
        [FIXTURE_TEL],
        tmp_path,
        stamp="fixture",
    )
    s = payload["summary"]
    assert s["main_total"] == 5  # prereq/cleanup/sim dropped
    assert s["executed_ok"] == 4  # failed dump excluded from N
    assert s["executed_failed"] == 1
    assert s["tp"] == 2  # exact T1055.004 + parent T1055.011
    assert s["fn"] == 2  # T1059 unlabeled, T1547 unlabeled
    assert s["recall"] == 0.5
    assert s["miss_rate"] == 0.5
    assert s["fp"] == 1  # T1574.001 explorer cluster
    assert s["precision"] == 2 / 3
    assert s["accuracy_applicable"] is False
    assert s["accuracy"] is None
    assert s["detected_exact"] == 1
    assert s["detected_parent"] == 1
    statuses = {row["variant_guid"]: row["status"] for row in payload["episodes"]}
    assert statuses["guid-exact"] == "ttp_detected"
    assert statuses["guid-parent"] == "ttp_detected"
    assert statuses["guid-unlabeled"] == "observed_unlabeled"
    assert statuses["guid-visible"] == "observed_unlabeled"
    assert statuses["guid-fail"] == "not_executed"
    fail = payload["failed_executions"]
    assert len(fail) == 1
    assert fail[0]["failure_reason"] == "missing_payload"
    assert "缺文件" in (fail[0].get("failure_guess") or "")
    html = (tmp_path / "report-fixture.html").read_text(encoding="utf-8")
    assert "不适用" in html
    assert "不计入" in html
    assert "不是「标成别的 TTP」" in html
    assert "bar-row" in html
    assert "测试用例" in html
    assert "不含前置准备和清理" in html
    assert "main 回合" not in html
    assert "先按时间窗圈出候选事件" in html
    assert "多个战术阶段" in html
    assert "Stealth（隐蔽）" in html
    assert "合计（执行成功回合）" in html
    assert "执行成功 4 / 执行用例总数 5" in html
    assert "「可见」 4 / 执行成功 4" in html
    assert "检出 2 / 执行成功 4" in html
    assert "未检出 2 / 执行成功 4" in html
    assert "检出 2 / 检出与 FP 簇合计 3" in html
    assert html.find("Batch Summary") < html.find("<h2>方法与口径</h2>")
    assert "匹配区间" in html
    assert "Layer B" not in html
    assert html.find("Batch Summary") < html.find("<h2>按战术</h2>")
    assert "「可见」" in html
    assert "时间窗里有任意遥测" in html
    glossary = html[html.find("方法与口径"):html.find("<h2>按战术</h2>")]
    assert "标成别的 TTP" in glossary
    assert "标签偏吵" in glossary
    assert "不是生产误报率" in glossary
    assert "不能代替告警率" in glossary
    assert "精确命中召回" in glossary
    assert "父技术放宽" in glossary
    summary = html[html.find("Batch Summary"):html.find("<h2>方法与口径</h2>")]
    assert "测评结论" in summary
    assert "短板在识别而不是采集" not in summary
    assert "没有落到 alert.log" in summary
    assert "Atomic Red Team" in summary
    assert "Windows" in summary
    assert "仅供参考" in summary
    assert "算在分母里" in summary
    assert "ttp-row" in html
    assert 'id="filter"' in html
    assert "推测" in html
    assert "缺文件" in html
    assert "不再把非 0 退出写成调度错误" in html
    assert 'id="fail-detail"' in html
    assert 'class="fold"' in html
    assert "显示清单" in html
    assert html.find("误报候选") < html.find("未执行成功（不计入漏报）")
    fp_section = html[html.find("<h2>误报候选</h2>"): html.find("<h2>未执行成功")]
    assert "class='wrap cmd'" in fp_section
    assert "C:\\Windows\\Explorer.EXE" in fp_section
    assert payload["highlights"]["threshold"] == 0.05
    t1055 = next(r for r in payload["by_technique"] if r["technique_id"] == "T1055.004")
    assert "Stealth" in (t1055.get("tactics") or "")
    tactic_keys = [row["key"] for row in payload["by_tactic"]]
    assert all("/" not in key for key in tactic_keys)
    assert "Stealth" in tactic_keys
    assert "Privilege Escalation" in tactic_keys
    section = html[html.find("<h2>按战术</h2>"): html.find("<h2>TTPs</h2>")]
    tbody = section[section.find("<tbody>"): section.find("</tbody>")]
    assert " / " not in tbody
    assert "Stealth（隐蔽）" in tbody
    assert "<h3>状态说明</h3>" in section
    assert "告警且标对" in section
    assert "标对但告警不对齐" in section
    assert "至少有一张告警工单" in section
    assert "告警但 TTP 不对齐" in section
    assert "不是误报候选" in section
    assert "回合状态（执行成功回合，互斥，取最强）" not in html
    exact = next(e for e in payload["episodes"] if e["variant_guid"] == "guid-exact")
    cmd = exact.get("sample_command_line") or exact.get("command") or ""
    assert cmd
    assert cmd in html
    assert "class='wrap cmd'" in html
    assert "ttp-hit-rule" in html
    assert "遥测规则" in html
    assert "EDR Technique" not in html
    assert "Process injection via Early Cascade APC" in html
    assert "Early Cascade" in html
    assert "- reforge/identity_original" not in html
    assert "无规则名" in html
    assert "ttp-pair" in html


def test_enterprise_matrix_covers_non_windows_ids():
    from eval.attck import tactic_label, technique_name

    assert technique_name("T1021.004") == "SSH"
    assert tactic_label("T1021.004") == "Lateral Movement"
    assert tactic_label("T1204.003") == "Execution"
    assert tactic_label("T1592.001") == "Reconnaissance"
    assert tactic_label("T1595.003") == "Reconnaissance"
    assert tactic_label("T1685") == "Defense Impairment"
    assert tactic_label("T1222") == "Defense Impairment"


def test_parent_match_off_is_miss():
    episodes, _, _ = load_jsonl(FIXTURE_ATOMIC)
    events, _ = load_events([FIXTURE_TEL])
    parent_ep = next(e for e in episodes if e.variant_guid == "guid-parent")
    result = match_episodes(
        [parent_ep],
        events,
        MatchConfig(parent_match=False),
    )
    assert result.matches[0].detected is False
    result_on = match_episodes([parent_ep], events, MatchConfig(parent_match=True))
    assert result_on.matches[0].detected is True
    assert result_on.matches[0].detection_kind == "parent"


def test_failed_execution_not_in_recall_even_with_ttp():
    from eval.atomic_logs import Episode

    ep = Episode(
        technique_id="T1003.001",
        variant_guid="fail",
        variant_name="x - reforge/identity_original",
        timestamp=_utc("2026-10-08T02:53:00Z"),
        duration_s=1,
        executor="powershell",
        command=r"C:\atomics\T1003.001\src\dump.exe",
        argv=r"C:\atomics\T1003.001\src\dump.exe",
        exit_code=1,
        timed_out=False,
        had_error=False,
        executed_ok=False,
        strategy="identity/original",
        failure="exit_1",
        signatures=extract_signatures(
            r"C:\atomics\T1003.001\src\dump.exe",
            r"C:\atomics\T1003.001\src\dump.exe",
            "T1003.001",
        ),
    )
    ev = _event(
        "2026-10-08T02:53:01Z",
        techniques=("T1003.001",),
        command=r"C:\atomics\T1003.001\src\dump.exe",
        rule_id="9",
    )
    result = match_episodes([ep], [ev], MatchConfig())
    summary = compute(result)["summary"]
    assert summary["executed_ok"] == 0
    assert summary["recall"] is None
    assert summary["tp"] == 0
    assert result.matches[0].status == "not_executed"


def test_accuracy_applicable_with_quiet_span():
    from eval.atomic_logs import Episode

    ep = Episode(
        technique_id="T1055.004",
        variant_guid="g",
        variant_name="n - reforge/identity_original",
        timestamp=_utc("2026-10-08T03:00:00Z"),
        duration_s=1,
        executor="powershell",
        command=r"C:\atomics\T1055.004\src\inject.ps1",
        argv=r"C:\atomics\T1055.004\src\inject.ps1",
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures(
            r"C:\atomics\T1055.004\src\inject.ps1",
            r"C:\atomics\T1055.004\src\inject.ps1",
            "T1055.004",
        ),
    )
    events = [
        _event(
            "2026-10-08T02:00:00Z",
            command="C:\\Windows\\Explorer.EXE",
            file_name="explorer.exe",
        ),
        _event(
            "2026-10-08T03:00:01Z",
            techniques=("T1055.004",),
            command=r"C:\atomics\T1055.004\src\inject.ps1",
            rule_id="1",
        ),
        _event(
            "2026-10-08T04:00:00Z",
            command="C:\\Windows\\Explorer.EXE",
            file_name="explorer.exe",
        ),
    ]
    result = match_episodes([ep], events, MatchConfig())
    summary = compute(result)["summary"]
    assert result.accuracy_applicable is True
    assert summary["tp"] == 1
    assert summary["fp"] == 0
    assert summary["tn"] == 1
    assert summary["accuracy"] == 1.0


def test_expand_telemetry_directory_lists_log_files(tmp_path: Path):
    (tmp_path / "host_telemetry.log").write_text("{}\n", encoding="utf-8")
    (tmp_path / "host_alert.log").write_text("{}\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("skip", encoding="utf-8")
    paths = expand_telemetry([str(tmp_path)])
    names = sorted(p.name for p in paths)
    assert names == ["host_alert.log", "host_telemetry.log"]


def test_expand_telemetry_split_nges_logs(tmp_path: Path):
    agent = "87bc957b4715c19c66dd541638914612"
    names = [
        f"{agent}_telemetry.log",
        f"{agent}_2_telemetry.log",
        f"{agent}_alert.log",
        f"{agent}_2_alert.log",
    ]
    for name in names:
        (tmp_path / name).write_text("{}\n", encoding="utf-8")
    (tmp_path / "otherhost_telemetry.log").write_text("{}\n", encoding="utf-8")
    (tmp_path / "noise.log").write_text("{}\n", encoding="utf-8")

    from_dir = sorted(p.name for p in expand_telemetry([str(tmp_path)]))
    assert from_dir == sorted(names + ["otherhost_telemetry.log"])

    one = tmp_path / f"{agent}_telemetry.log"
    from_one = sorted(p.name for p in expand_telemetry([str(one)]))
    assert from_one == sorted(names)

    parent = tmp_path / "batch"
    nested = parent / "nges_report"
    nested.mkdir(parents=True)
    (parent / "run-x.json").write_text("{}", encoding="utf-8")
    for name in names:
        (nested / name).write_text("{}\n", encoding="utf-8")
    from_nested = sorted(p.name for p in expand_telemetry([str(parent)]))
    assert from_nested == sorted(names)


def test_expand_alert_edges_info():
    import json

    raw = (ROOT / "eval" / "testdata" / "alert.ndjson").read_text(encoding="utf-8")
    record = json.loads(raw.splitlines()[0])
    rows = expand_nges_records(record)
    assert len(rows) == 1
    assert rows[0]["Event"]["builtinTtpTechnique"] == "T1003.004"
    events, errors = load_events([ROOT / "eval" / "testdata" / "alert.ndjson"])
    assert errors == []
    assert len(events) == 1
    assert events[0].kind == "alert"
    assert events[0].labeled
    assert "T1003.004" in events[0].techniques
    assert "gsecdump.exe" in events[0].command_line.lower()


def test_failure_reason_nonzero_not_scheduler():
    from eval.atomic_logs import display_failure_reason, failure_reason, guess_failure

    assert (
        failure_reason({"had_error": True, "exit_code": 1, "timed_out": False})
        == "nonzero_exit"
    )
    assert (
        failure_reason({"timed_out": True, "had_error": True, "exit_code": -1})
        == "timeout"
    )
    assert display_failure_reason("scheduler_error") == "非 0 退出"
    assert "域" in guess_failure(
        {
            "command": "nltest /dclist:lab.local",
            "failure_reason": "scheduler_error",
            "technique_id": "T1482",
        }
    )
    assert "注册表" in guess_failure(
        {
            "command": r"reg add HKLM\Software\x /v y /d 1",
            "failure_reason": "nonzero_exit",
            "technique_id": "T1112",
        }
    )
    assert "WinPwn" in guess_failure(
        {
            "timed_out": True,
            "command": "powershell.exe WinPwn",
            "failure_reason": "timeout",
        }
    )


def test_wrong_ttp_lists_edr_technique_in_report(tmp_path: Path):
    from eval.atomic_logs import Episode
    from eval.report import build_payload, render_html

    cmd = r"C:\atomics\T1137.006\bin\Addins\ExcelVBAaddin.xlam"
    ep = Episode(
        technique_id="T1137.006",
        variant_guid="guid-wrong",
        variant_name="Persistent Code Execution Via Excel VBA Add-in File (XLAM)",
        timestamp=_utc("2026-10-08T02:41:00Z"),
        duration_s=2,
        executor="powershell",
        command=cmd,
        argv=cmd,
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures(cmd, cmd, "T1137.006"),
    )
    ev = _event(
        "2026-10-08T02:41:01Z",
        techniques=("T1112",),
        command=rf'powershell.exe Copy "{cmd}" "$env:APPDATA\Microsoft\Excel\XLSTART\notepad.xlam"',
        rule_id="2200",
        rule_name="Suspicious Office add-in persistence",
        tactics=("TA0003",),
    )
    result = match_episodes([ep], [ev], MatchConfig())
    m = result.matches[0]
    assert m.status == "observed_wrong_ttp"
    assert m.wrong_techniques == ["T1112"]
    assert m.wrong_rules == ["Suspicious Office add-in persistence"]
    assert "ExcelVBAaddin.xlam" in (m.sample_command_line or "")
    payload = build_payload(
        result=result,
        atomic_paths=["fixture"],
        telemetry_paths=["fixture"],
        skipped=[],
        errors=[],
        stamp="wrong-ttp",
    )
    html = render_html(payload)
    assert "ttp-wrong" in html
    assert "T1112" in html
    assert "Suspicious Office add-in persistence" in html
    (tmp_path / "wrong.html").write_text(html, encoding="utf-8")


def test_wrong_rule_prefers_nonempty_name():
    from eval.atomic_logs import Episode

    cmd = r"C:\atomics\T1137.006\bin\Addins\ExcelVBAaddin.xlam"
    ep = Episode(
        technique_id="T1137.006",
        variant_guid="guid-empty-then-named",
        variant_name="XLAM",
        timestamp=_utc("2026-10-08T02:41:00Z"),
        duration_s=2,
        executor="powershell",
        command=cmd,
        argv=cmd,
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures(cmd, cmd, "T1137.006"),
    )
    command = rf'powershell.exe Copy "{cmd}" "$env:APPDATA\Microsoft\Excel\XLSTART\notepad.xlam"'
    empty = _event(
        "2026-10-08T02:41:01Z",
        techniques=("T1574.001",),
        command=command,
        rule_id="1",
        rule_name="",
    )
    named = _event(
        "2026-10-08T02:41:02Z",
        techniques=("T1574.001",),
        command=command,
        rule_id="2",
        rule_name="Potential DLL search order hijack",
    )
    m = match_episodes([ep], [empty, named], MatchConfig()).matches[0]
    assert m.wrong_techniques == ["T1574.001"]
    assert m.wrong_rules == ["Potential DLL search order hijack"]


def test_hit_rule_shown_beside_each_technique():
    from eval.atomic_logs import Episode
    from eval.report import build_payload, render_html

    cmd = r"C:\atomics\T1055.004\src\inject.ps1"
    ep = Episode(
        technique_id="T1055.004",
        variant_guid="guid-pair",
        variant_name="Early Cascade",
        timestamp=_utc("2026-10-08T02:41:00Z"),
        duration_s=2,
        executor="powershell",
        command=cmd,
        argv=cmd,
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures(cmd, cmd, "T1055.004"),
    )
    ev = _event(
        "2026-10-08T02:41:01Z",
        techniques=("T1055", "T1055.004"),
        command=f"powershell.exe -Command {cmd}",
        rule_id="1001",
        rule_name="Process injection via Early Cascade APC",
        tactics=("TA0005",),
    )
    result = match_episodes([ep], [ev], MatchConfig())
    m = result.matches[0]
    assert m.hit_techniques == ["T1055", "T1055.004"]
    assert m.hit_rules == [
        "Process injection via Early Cascade APC",
        "Process injection via Early Cascade APC",
    ]
    html = render_html(
        build_payload(
            result=result,
            atomic_paths=["fixture"],
            telemetry_paths=["fixture"],
            skipped=[],
            errors=[],
            stamp="pair",
        )
    )
    assert html.count("ttp-pair") >= 2
    assert html.count("Process injection via Early Cascade APC") >= 2


def test_alerted_status_from_alert_event():
    from eval.atomic_logs import Episode

    ep = Episode(
        technique_id="T1003.004",
        variant_guid="g",
        variant_name="gsecdump",
        timestamp=_utc("2026-10-08T02:41:00Z"),
        duration_s=1,
        executor="command_prompt",
        command=r"C:\atomics\ExternalPayloads\reforge_remote\ext\gsecdump.exe -a",
        argv=r"C:\atomics\ExternalPayloads\reforge_remote\ext\gsecdump.exe -a",
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures(
            r"C:\atomics\ExternalPayloads\reforge_remote\ext\gsecdump.exe -a",
            r"C:\atomics\ExternalPayloads\reforge_remote\ext\gsecdump.exe -a",
            "T1003.004",
        ),
    )
    ev = _event(
        "2026-10-08T02:41:01Z",
        techniques=("T1003.004",),
        command=r"cmd.exe /c C:\atomics\ExternalPayloads\reforge_remote\ext\gsecdump.exe -a",
        rule_id="1100",
        rule_name="LSA secrets registry export using tools",
        kind="alert",
    )
    result = match_episodes([ep], [ev], MatchConfig())
    m = result.matches[0]
    assert m.alerted is True
    assert m.detected is True
    assert m.status == "alerted"
    assert m.alert_rule_techniques.get("LSA secrets registry export using tools") == [
        "T1003.004"
    ]
    from eval.report import _alert_rule_cell

    cell = _alert_rule_cell(
        {
            "technique_id": "T1003.004",
            "status": "alerted",
            "alert_rules": ["LSA secrets registry export using tools"],
            "alert_rule_techniques": {
                "LSA secrets registry export using tools": ["T1003.004"]
            },
        }
    )
    assert "T1003.004" in cell
    assert "ttp-hit" in cell
    assert "ttp-hit-rule" in cell
    assert "LSA secrets registry export using tools" in cell
    missing = _alert_rule_cell(
        {
            "technique_id": "T1003.004",
            "status": "alerted",
            "alert_rules": ["(无规则名)"],
            "alert_rule_techniques": {"(无规则名)": ["T1112"]},
        }
    )
    assert "T1112" in missing
    assert "ttp-wrong" in missing
    assert "无规则名" in missing
    summary = compute(result)["summary"]
    assert summary["alerted"] == 1
    assert summary["alert_rate"] == 1.0
    assert m.alert_aligned is True


def test_one_aligned_alert_among_many_is_告警且标对():
    from eval.atomic_logs import Episode

    cmd = r"C:\atomics\ExternalPayloads\reforge_remote\ext\gsecdump.exe -a"
    ep = Episode(
        technique_id="T1003.004",
        variant_guid="g-multi-alert",
        variant_name="gsecdump",
        timestamp=_utc("2026-10-08T02:41:00Z"),
        duration_s=1,
        executor="command_prompt",
        command=cmd,
        argv=cmd,
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures(cmd, cmd, "T1003.004"),
    )
    hay = r"cmd.exe /c " + cmd
    wrong = _event(
        "2026-10-08T02:41:01Z",
        techniques=("T1550.002",),
        command=hay,
        rule_id="3001",
        rule_name="Overpass-the-hash attack using hacktools",
        kind="alert",
    )
    right = _event(
        "2026-10-08T02:41:02Z",
        techniques=("T1003.004",),
        command=hay,
        rule_id="1100",
        rule_name="LSA secrets registry export using tools",
        kind="alert",
    )
    m = match_episodes([ep], [wrong, right], MatchConfig()).matches[0]
    assert m.alerted is True
    assert m.detected is True
    assert m.alert_aligned is True
    assert m.status == "alerted"


def test_unrelated_alert_is_not_告警且标对():
    from eval.atomic_logs import Episode
    from eval.report import build_payload, render_html

    cmd = r"SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10"
    ep = Episode(
        technique_id="T1053.005",
        variant_guid="guid-sched",
        variant_name="Scheduled task Local",
        timestamp=_utc("2026-10-08T02:41:00Z"),
        duration_s=2,
        executor="command_prompt",
        command=cmd,
        argv=cmd,
        exit_code=0,
        timed_out=False,
        had_error=False,
        executed_ok=True,
        strategy="identity/original",
        signatures=extract_signatures(cmd, cmd, "T1053.005"),
    )
    tel = _event(
        "2026-10-08T02:41:01Z",
        techniques=("T1021", "T1053.005"),
        command=cmd,
        rule_id="2001",
        rule_name="Scheduled task creation or modification using white hat tools",
    )
    alert = _event(
        "2026-10-08T02:41:02Z",
        techniques=("T1550.002", "T1059", "T1021"),
        command=cmd,
        rule_id="3001",
        rule_name="Overpass-the-hash attack using hacktools",
        kind="alert",
    )
    result = match_episodes([ep], [tel, alert], MatchConfig())
    m = result.matches[0]
    assert m.detected is True
    assert m.detection_kind == "exact"
    assert m.alerted is True
    assert m.alert_aligned is False
    assert m.status == "ttp_detected_alert_wrong"
    assert m.hit_techniques == ["T1053.005"]
    assert "T1021" in m.wrong_techniques
    html = render_html(
        build_payload(
            result=result,
            atomic_paths=["fixture"],
            telemetry_paths=["fixture"],
            skipped=[],
            errors=[],
            stamp="sched-alert",
        )
    )
    assert "标对但告警不对齐" in html
    assert "Overpass-the-hash attack using hacktools" in html
