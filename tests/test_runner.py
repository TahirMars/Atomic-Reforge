"""Tests for the execution runner + execution logging (result_log)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from atomic_reforge import result_log
from atomic_reforge.result_log import LogRecord
from atomic_reforge.runner import (
    RunConfig,
    build_exec_argv,
    execute_command,
    format_argv_display,
    merge_input_args,
    prereq_executor,
    run_atomic,
    target_info,
    windows_cmd_line,
)


def _arg(name: str, default) -> dict:
    return {"default": default, "description": f"arg {name}", "type": "string"}


def _atomic(**kw):
    from atomic_red_team.models import Technique

    base = {
        "name": "test",
        "auto_generated_guid": "11111111-1111-1111-1111-111111111111",
        "description": "d",
        "supported_platforms": ["windows"],
        "executor": {"name": "powershell", "command": "Write-Host ok"},
        "input_arguments": kw.pop("_input", {}),
    }
    base.update(kw)
    t = Technique(
        attack_technique="T1059.001",
        display_name="T1059.001",
        atomic_tests=[base],
    )
    return t.atomic_tests[0]


# ---- build_exec_argv (pure, no side effects) ----
def test_argv_command_prompt():
    res = build_exec_argv("command_prompt", "echo a\n echo b", "windows")
    assert res is not None
    exe, argv, display = res
    assert exe == "cmd.exe"
    assert argv == ["/c", "echo a &  echo b"]


def test_argv_powershell_windows():
    res = build_exec_argv("powershell", 'Write-Host "hi"', "windows")
    assert res is not None
    exe, argv, display = res
    assert exe == "powershell.exe"
    assert argv[:3] == ["-NoProfile", "-NonInteractive", "-Command"]
    assert 'Write-Host "hi"' in argv[3]
    assert '\\"' not in argv[3]


def test_argv_sh():
    res = build_exec_argv("bash", "echo a\necho b", "linux")
    assert res is not None
    exe, argv, display = res
    assert exe == "bash"
    assert argv[0] == "-c"
    assert "echo a; echo b" in argv[1]


def test_argv_unknown():
    assert build_exec_argv("manual", "x", "windows") is None


def test_windows_cmd_line_does_not_escape_inner_quotes():
    joined = (
        'reg query "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Internet Explorer"'
        " /v svcVersion"
    )
    line = windows_cmd_line("cmd.exe", ["/c", joined])
    assert '\\"' not in line
    assert line.startswith("cmd.exe /c ")
    assert '"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Internet Explorer"' in line
    import subprocess as sp

    via_list = sp.list2cmdline(["cmd.exe", "/c", joined])
    assert '\\"' in via_list


# ---- merge_input_args ----
def test_merge_default_and_override():
    atomic = _atomic(
        _input={
            "mimpath": _arg("mimpath", r"PathToAtomicsFolder\..\bin\mimi.exe"),
            "user": _arg("user", "alice"),
        },
        executor={"name": "powershell", "command": "run #{mimpath} as #{user}"},
    )
    out = merge_input_args(atomic.executor.command, atomic)
    assert "mimi.exe" in out
    assert "as alice" in out
    # PathToAtomicsFolder token replaced with the real path.
    assert "PathToAtomicsFolder" not in out

    out2 = merge_input_args(
        atomic.executor.command, atomic, {"user": "bob"}
    )
    assert "as bob" in out2


def test_merge_expands_nested_placeholder():
    """A default of '#{other}' must be expanded, otherwise PowerShell sees '#' as a comment."""
    atomic = _atomic(
        _input={
            "program_path": _arg("program_path", r"$env:TEMP\program.bat"),
            "exe_binary": _arg("exe_binary", r"C:\Tools\payload.exe"),
            "reforge_arg": _arg("reforge_arg", "#{program_path}"),
            "reforge_exe": _arg("reforge_exe", "#{exe_binary}"),
        },
        executor={
            "name": "powershell",
            "command": (
                "Split-Path #{reforge_arg}\n"
                "Start-Process #{reforge_exe}\n"
                "Write-Host #{program_path} #{exe_binary}"
            ),
        },
    )
    out = merge_input_args(atomic.executor.command, atomic)
    assert "#{" not in out
    assert r"Split-Path $env:TEMP\program.bat" in out
    assert r"Start-Process C:\Tools\payload.exe" in out


def test_merge_external_payloads_stay_inside_atomics(tmp_path):
    atomics = tmp_path / "release_lite" / "atomics"
    atomics.mkdir(parents=True)
    atomic = _atomic(
        _input={
            "exe": _arg("exe", r"PathToAtomicsFolder\..\ExternalPayloads\calc.dll"),
            "named": _arg("named", r"PathToAtomicsFolder\bin\61 Akagi64.exe"),
        },
        executor={
            "name": "powershell",
            "command": 'Start-Process "#{exe}"\nTest-Path #{named}',
        },
    )
    out = merge_input_args(
        atomic.executor.command, atomic, path_to_atomics=atomics
    )
    inside = str((atomics / "ExternalPayloads" / "calc.dll").resolve())
    named = str((atomics / "bin" / "61 Akagi64.exe").resolve())
    assert inside in out
    assert r"\..\ExternalPayloads" not in out
    assert f'"{named}"' in out


def test_merge_cmd_quotes_with_cmd_escaping_not_backtick():
    atomic = _atomic(
        executor={"name": "command_prompt", "command": "copy #{src} C:\\out"},
        _input={"src": _arg("src", r"C:\Program Files\app\tool.exe")},
    )
    out = merge_input_args(
        atomic.executor.command, atomic, executor_name="command_prompt"
    )
    assert 'copy "C:\\Program Files\\app\\tool.exe" C:\\out' in out
    assert "`\"" not in out


def test_merge_quoted_placeholder_trailing_backslash():
    atomic = _atomic(
        executor={"name": "command_prompt", "command": 'xcopy "#{src}" dest'},
        _input={"src": _arg("src", "C:\\payloads\\bin\\")},
    )
    out = merge_input_args(
        atomic.executor.command, atomic, executor_name="command_prompt"
    )
    # One trailing \\ is doubled so the closing quote is not eaten.
    assert out == 'xcopy "C:\\payloads\\bin\\\\" dest'


# ---- prereq_executor ----
def test_prereq_executor():
    a = _atomic()
    assert prereq_executor(a) == "powershell"
    a2 = _atomic(
        dependency_executor_name="command_prompt",
        dependencies=[
            {
                "description": "d",
                "prereq_command": "echo x",
                "get_prereq_command": "echo y",
            }
        ],
    )
    assert prereq_executor(a2) == "command_prompt"


# ---- target_info ----
def test_target_info_windows_platform():
    platform, _ = target_info()
    assert platform in ("windows", "linux", "macos")


# ---- result_log ----
def test_resolve_log_dir(tmp_path):
    d = result_log.resolve_log_dir(tmp_path / "logs")
    assert d == tmp_path / "logs"
    assert d.exists()


def test_write_log_record(tmp_path):
    rec = LogRecord(
        timestamp="2026-10-12T00:00:00Z",
        technique_id="T1059.001",
        variant_guid="g1",
        variant_name="v",
        test_index=0,
        executor="powershell",
        branch="main",
        dependency_index=None,
        simulated=True,
        command="Write-Host ok",
        argv="powershell.exe & {Write-Host ok}",
        exit_code=0,
        timed_out=False,
        duration_s=0.0,
        stdout="",
        stderr="",
        had_error=False,
    )
    log_dir = tmp_path / "rl"
    log_dir.mkdir()
    log_fh, ndjson_fh = result_log.open_session(log_dir)
    result_log.write_log_record(log_dir, rec, log_fh, ndjson_fh)
    log_fh.close()
    ndjson_fh.close()

    log_file = list(log_dir.glob("run-*.log"))[0]
    ndjson_file = list(log_dir.glob("run-*.json"))[0]

    # Basename carries the timestamp (no TTP here since open_session was
    # called without one), and the JSON side is .json, not .ndjson.
    assert log_file.suffix == ".log"
    assert ndjson_file.suffix == ".json"

    text = log_file.read_text(encoding="utf-8")
    assert "T1059.001" in text
    assert "g1" in text
    assert "exit=0" in text

    obj = json.loads(ndjson_file.read_text(encoding="utf-8").strip().splitlines()[0])
    assert obj["technique_id"] == "T1059.001"
    assert obj["exit_code"] == 0
    assert obj["simulated"] is True


# ---- execute_command (harmless, cross-platform) ----
def test_execute_command_ok():
    res = execute_command("python", ["-c", "print(42)"], 30, "linux")
    assert res.exit_code == 0
    assert res.stdout.strip() == "42"


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="cmd.exe")
def test_execute_cmd_inner_quotes_on_windows():
    res = execute_command(
        "cmd.exe",
        ["/c", 'echo "hello world"'],
        30,
        "windows",
    )
    assert res.had_error is False
    assert "hello world" in res.stdout
    assert "Invalid syntax" not in (res.stderr or "")


def test_format_argv_display():
    assert format_argv_display("cmd.exe", ["/c", "x"]) == "cmd.exe /c x"


# ---- dry-run does not spawn (simulate path) ----
def test_run_atomic_dry_run_simulated(tmp_path):
    atomic = _atomic(
        executor={"name": "powershell", "command": "Write-Host nope"}
    )
    cfg = RunConfig(execute=False)
    setattr(cfg, "_log_dir", tmp_path / "sim")
    out = run_atomic(atomic, "T1059.001", cfg, variant_guid="g", variant_name="v")
    # Dry-run fills a simulated result: exit 0, no pid, no process started.
    assert out.main.exit_code == 0
    assert out.main.pid is None
    assert out.main.duration_s == 0.0
