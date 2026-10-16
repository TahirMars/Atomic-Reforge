"""Execution engine: replicate Invoke-AtomicRedTeam's scheduling in Python.

Fully dry-run by default; only ``execute=True`` launches subprocesses. Every
execution (or simulation) is emitted to the execution log via result_log.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic

from .payloads import anchor_external_payloads, discover_payloads, local_exists
from .source import ATOMICS_PATH
from . import result_log
from .result_log import LogRecord

_KNOWN_EXECUTORS = ("command_prompt", "sh", "bash", "powershell")
_CMD_SPECIAL = frozenset(' \t&|<>^()%!"')


@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int
    pid: int | None
    timed_out: bool
    duration_s: float

    @property
    def had_error(self) -> bool:
        return self.exit_code != 0 or self.timed_out


@dataclass
class RunConfig:
    execute: bool = False
    input_args: dict = field(default_factory=dict)
    timeout: int = 120
    check_prereqs: bool = False
    get_prereqs: bool = False
    cleanup: bool = False
    path_to_atomics: Path = field(default_factory=lambda: ATOMICS_PATH)
    allow_download: bool = False


@dataclass
class RunOutcome:
    """Aggregated outcome of one run_atomic call for one variant/test."""

    technique_id: str
    variant_guid: str
    variant_name: str
    test_index: int | None
    executor: str
    main: ExecResult = field(
        default_factory=lambda: ExecResult("", "", 0, None, False, 0.0)
    )
    prereqs: list[dict] = field(default_factory=list)
    cleanup_res: ExecResult | None = None


def target_info() -> tuple[str, bool]:
    """Return (platform, is_elevated). platform is 'windows'|'linux'|'macos'."""
    if sys.platform == "win32":
        elevated = False
        try:
            import ctypes

            elevated = bool(
                ctypes.windll.shell32.IsUserAnAdmin()
            )
        except Exception:
            elevated = False
        return "windows", elevated

    platform = "macos" if sys.platform == "darwin" else "linux"
    elevated = False
    try:
        elevated = os.geteuid() == 0
    except AttributeError:
        elevated = False
    return platform, elevated


def platform_supported(atomic: "Atomic", platform: str) -> bool:
    """Align Invoke-AtomicTest platform filter (windows skips sh/bash, etc.).

    Manual executors have no command and are never executed upstream.
    """
    ex = getattr(atomic.executor, "name", None)
    if ex == "manual":
        return False
    if platform not in atomic.supported_platforms:
        return False
    if platform == "windows":
        return ex not in ("sh", "bash")
    if platform in ("linux", "macos"):
        return ex != "command_prompt"
    return True


def merge_input_args(
    command: str | None,
    atomic: "Atomic",
    custom_args: dict | None = None,
    path_to_atomics: Path | None = None,
    executor_name: str | None = None,
) -> str:
    """Replace #{key} with defaults (or user values) and path tokens."""
    custom_args = custom_args or {}
    path = Path(path_to_atomics) if path_to_atomics is not None else ATOMICS_PATH
    try:
        path = path.resolve()
    except OSError:
        path = path.absolute()
    custom_args = custom_args or {}
    if not command:
        return ""

    executor = (executor_name or getattr(atomic.executor, "name", "") or "").lower()

    # Defaults from input_arguments, then user overrides.
    # Values may be plain dicts or argument models.
    argdefs = atomic.input_arguments or {}
    final_args: dict[str, str] = {}
    for key, argdef in argdefs.items():
        if isinstance(argdef, dict):
            default = argdef.get("default")
        else:
            default = getattr(argdef, "default", None)
        final_args[key] = "" if default is None else str(default)
    for key, val in custom_args.items():
        if key in final_args:
            final_args[key] = str(val)

    # Repeat so a default that is itself "#{other}" is expanded. A single
    # pass leaves "#{other}" in the command; PowerShell then treats "#" as
    # a comment and prompts for the missing mandatory parameter.
    # Unquoted values that contain spaces are quoted, otherwise Test-Path /
    # Start-Process split the path and the file or process name disappears.
    out = command
    for _ in range(8):
        prev = out
        for key, val in final_args.items():
            out = _replace_placeholder(out, key, val, executor=executor)
        if out == prev:
            break

    # Keep ExternalPayloads inside the atomics folder. ART's "\..\ExternalPayloads"
    # walks out to the parent and, with a relative root, lands on C:\atomics.
    out = anchor_external_payloads(out)
    root = str(path)
    out = out.replace("{PathToAtomicsFolder}", root)
    out = out.replace("$PathToAtomicsFolder", root)
    out = out.replace("PathToAtomicsFolder", root)
    return out


def _double_trailing_backslashes(val: str) -> str:
    """Make a following ``\"`` keep the closing quote (even count of ``\\``)."""
    n = len(val) - len(val.rstrip("\\"))
    if n == 0:
        return val
    return val + ("\\" * n)


def _quote_for_executor(val: str, executor: str) -> str:
    if executor in ("command_prompt", "cmd"):
        return '"' + _double_trailing_backslashes(val.replace('"', '""')) + '"'
    return '"' + val.replace('"', '`"') + '"'


def _needs_quotes(val: str, executor: str) -> bool:
    if "\n" in val or "\r" in val:
        return False
    if executor in ("command_prompt", "cmd"):
        return any(c in val for c in _CMD_SPECIAL)
    return any(c in val for c in " \t")


def _replace_placeholder(
    text: str, key: str, val: str, *, executor: str = "powershell"
) -> str:
    token = "#{" + key + "}"
    if token not in text:
        return text
    needs_quote = _needs_quotes(val, executor)
    if not needs_quote and not val.endswith("\\"):
        return text.replace(token, val)
    out: list[str] = []
    i = 0
    in_single = False
    in_double = False
    while i < len(text):
        ch = text[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            i += 1
            continue
        if text.startswith(token, i):
            if in_double and val.endswith("\\"):
                out.append(_double_trailing_backslashes(val))
            elif in_single or in_double:
                out.append(val)
            elif needs_quote:
                out.append(_quote_for_executor(val, executor))
            else:
                out.append(val)
            i += len(token)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def prereq_executor(atomic: "Atomic") -> str:
    dep = getattr(atomic, "dependency_executor_name", None)
    if dep:
        return dep
    return getattr(atomic.executor, "name", "")


def build_exec_argv(
    executor_name: str,
    final_command: str,
    platform: str,
) -> tuple[str, list[str], str] | None:
    """Assemble (exe, argv_list, display) mirroring Invoke-ExecuteCommand.

    Returns None for unknown executors. argv_list is prepared without any
    shell wrapping; display is the human-readable command line.
    """
    cmd = (final_command or "").strip()

    if executor_name == "command_prompt":
        joined = cmd.replace("\n", " & ")
        argv = ["/c", joined]
        return "cmd.exe", argv, f"cmd.exe /c {joined}"

    if executor_name in ("sh", "bash"):
        # Mirror upstream escaping: backslash and double-quote are escaped.
        escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
        joined = escaped.replace("\n", "; ")
        argv = ["-c", joined]
        return executor_name, argv, f'{executor_name} -c "{joined}"'

    if executor_name == "powershell":
        if platform == "windows":
            # Do not pre-escape quotes. Popen already quotes the argument;
            # a manual \" turns "C:\atomics\..." into a root-relative
            # \atomics\... path, which Windows creates as C:\atomics.
            # A trailing backslash before a closing quote would also swallow
            # the quote, so double those backslashes.
            body = re.sub(r'\\+(?=")', lambda m: "\\" * (len(m.group(0)) * 2), cmd)
            script = "& {" + body + "}"
            argv = ["-NoProfile", "-NonInteractive", "-Command", script]
            exe = "powershell.exe"
        else:
            argv = ["-Command", cmd]
            exe = "pwsh"
        return exe, argv, f"{exe} {' '.join(argv)}"

    return None


def _bundle_cwd(cfg: RunConfig) -> Path | None:
    """Directory a child process should start in: the bundle root, not C:\\."""
    root = getattr(cfg, "path_to_atomics", None)
    if root is None:
        return None
    root = Path(root)
    parent = root.parent
    if parent.is_dir():
        return parent
    if root.is_dir():
        return root
    return None


def format_argv_display(exe: str, argv: list[str]) -> str:
    return " ".join([exe, *(str(a) for a in argv)])


def windows_cmd_line(exe: str, argv: list[str]) -> str:
    """Command line for CreateProcess that keeps inner quotes intact.

    ``subprocess.list2cmdline(["cmd.exe", "/c", 'reg query "HKLM\\.."'])``
    becomes ``cmd.exe /c "reg query \\"HKLM\\.."`` which cmd.exe misparses
    (T1518 Invalid syntax, T1491 plink ``'\\\"C:\\...``). Passing the /c
    payload unescaped matches how operators type the same command.
    """
    if argv and argv[0].lower() == "/c":
        rest = " ".join(argv[1:])
        return f"{exe} /c {rest}"
    return subprocess.list2cmdline([exe, *argv])


def _kill_tree(proc: subprocess.Popen, platform: str) -> None:
    try:
        if platform == "windows":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
            )
        else:
            try:
                os.killpg(proc.pid, 9)
            except ProcessLookupError:
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def execute_command(
    exe: str,
    argv: list[str],
    timeout: int,
    platform: str,
    cwd: "Path | None" = None,
) -> ExecResult:
    """Run a process with redirected stdout/stderr and a timeout kill-tree.

    Never uses shell=True. On Windows, ``cmd.exe /c`` is launched as a raw
    command-line string so nested quotes are not turned into ``\\"``.
    """
    import time

    start = time.time()
    proc = None
    try:
        # groups keyed by start_new_session allow posix killpg.
        kwargs = {}
        if platform != "windows":
            kwargs["start_new_session"] = True
        popen_args: str | list[str]
        if (
            platform == "windows"
            and Path(exe).name.lower() in ("cmd.exe", "cmd")
        ):
            popen_args = windows_cmd_line(exe, argv)
        else:
            popen_args = [exe, *argv]
        proc = subprocess.Popen(
            popen_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd is not None else None,
            **kwargs,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        timed_out = False
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        _kill_tree(proc, platform)
        stdout, stderr = proc.communicate()
        timed_out = True
        exit_code = -1
    finally:
        pass

    duration = time.time() - start
    return ExecResult(
        stdout=(stdout or b"").decode("utf-8", errors="replace").strip(),
        stderr=(stderr or b"").decode("utf-8", errors="replace").strip(),
        exit_code=exit_code,
        pid=proc.pid if proc else None,
        timed_out=timed_out,
        duration_s=round(duration, 3),
    )


def _simulate(exe: str, argv: list[str]) -> ExecResult:
    return ExecResult(
        stdout="",
        stderr="",
        exit_code=0,
        pid=None,
        timed_out=False,
        duration_s=0.0,
    )


def run_atomic(
    atomic: "Atomic",
    technique_id: str,
    cfg: RunConfig,
    variant_guid: str = "",
    variant_name: str = "",
    test_index: int | None = None,
) -> RunOutcome:
    """Schedule one atomic through prereqs/cleanup/main per the config.

    Replicates Invoke-AtomicTestSingle: branch selection is driven by cfg
    (check_prereqs / get_prereqs / cleanup / main). Every command invocation
    emits a LogRecord via result_log.write_log_record.
    """
    platform, _is_elevated = target_info()
    executor = getattr(atomic.executor, "name", "")
    log_dir = getattr(cfg, "_log_dir", None)
    work_dir = _bundle_cwd(cfg)

    def emit(
        branch: str,
        command: str,
        res: ExecResult,
        simulated: bool,
        dependency_index: int | None = None,
    ) -> None:
        rec = LogRecord(
            timestamp=result_log.now_iso(),
            technique_id=technique_id,
            variant_guid=variant_guid,
            variant_name=variant_name,
            test_index=test_index,
            executor=executor,
            branch=branch,
            dependency_index=dependency_index,
            simulated=simulated,
            command=command,
            argv=format_argv_display(exe, argv) if not simulated else None,
            exit_code=res.exit_code,
            timed_out=res.timed_out,
            duration_s=res.duration_s,
            stdout=res.stdout,
            stderr=res.stderr,
            had_error=res.had_error,
        )
        result_log.write_log_record(
            log_dir,
            rec,
            technique_id=technique_id,
            stamp=getattr(cfg, "_session_stamp", "") or "",
        )

    outcome = RunOutcome(
        technique_id=technique_id,
        variant_guid=variant_guid,
        variant_name=variant_name,
        test_index=test_index,
        executor=executor,
    )

    # ---- prereq handling ----
    if (cfg.check_prereqs or cfg.get_prereqs) and atomic.dependencies:
        pexec = prereq_executor(atomic)
        # Local-first: if this atomic's payloads already exist on disk, the
        # dependency is considered satisfiable offline without hitting the
        # network get_prereq_command (unless the user explicitly allows it).
        payloads_local = (
            all(local_exists(r) for r in discover_payloads(atomic, cfg.path_to_atomics))
            if discover_payloads(atomic, cfg.path_to_atomics)
            else False
        )
        for i, dep in enumerate(atomic.dependencies):
            prereq = merge_input_args(
                dep.prereq_command,
                atomic,
                cfg.input_args,
                cfg.path_to_atomics,
                executor_name=pexec,
            )
            built = build_exec_argv(pexec, prereq, platform)
            if built is None:
                continue
            exe, argv, display = built
            if not cfg.execute:
                res = _simulate(exe, argv)
            else:
                res = execute_command(exe, argv, cfg.timeout, platform, cwd=work_dir)
            emit("prereq", display, res, not cfg.execute, dependency_index=i)
            entry = {
                "description": dep.description,
                "satisfied": res.exit_code == 0,
                "exec_result": res,
            }
            skip_get = payloads_local and not cfg.allow_download
            if (
                cfg.get_prereqs
                and res.exit_code != 0
                and dep.get_prereq_command
                and not skip_get
            ):
                get_cmd = merge_input_args(
                    dep.get_prereq_command,
                    atomic,
                    cfg.input_args,
                    cfg.path_to_atomics,
                    executor_name=pexec,
                )
                gbuilt = build_exec_argv(pexec, get_cmd, platform)
                if gbuilt is not None:
                    gexe, gargv, gdisplay = gbuilt
                    if not cfg.execute:
                        gres = _simulate(gexe, gargv)
                    else:
                        gres = execute_command(gexe, gargv, cfg.timeout, platform, cwd=work_dir)
                    emit(
                        "prereq",
                        gdisplay,
                        gres,
                        not cfg.execute,
                        dependency_index=i,
                    )
                # Rerun prereq to see if the dependency is now met.
                if not cfg.execute:
                    res = _simulate(exe, argv)
                else:
                    res = execute_command(exe, argv, cfg.timeout, platform, cwd=work_dir)
                emit("prereq", display, res, not cfg.execute, dependency_index=i)
                entry["satisfied"] = res.exit_code == 0
            outcome.prereqs.append(entry)
        if cfg.get_prereqs and not cfg.execute:
            # get_prereqs-only runs do not execute the main command.
            return outcome
    if cfg.get_prereqs:
        # If not executing, we already returned above; if executing, get_prereqs
        # still performs the main command in Invoke-AtomicRedTeam? It does not —
        # GetPrereqs returns after the dependency loop.
        pass

    # ---- cleanup branch ----
    if cfg.cleanup:
        cleanup = merge_input_args(
            getattr(atomic.executor, "cleanup_command", None),
            atomic,
            cfg.input_args,
            cfg.path_to_atomics,
            executor_name=executor,
        )
        if cleanup:
            built = build_exec_argv(executor, cleanup, platform)
            if built is not None:
                exe, argv, display = built
                res = (
                    _simulate(exe, argv)
                    if not cfg.execute
                    else execute_command(exe, argv, cfg.timeout, platform, cwd=work_dir)
                )
                emit("cleanup", display, res, not cfg.execute)
                outcome.cleanup_res = res
        return outcome

    # ---- main command ----
    if cfg.check_prereqs:
        # check_prereqs returns after printing dependency status.
        return outcome

    main_cmd = merge_input_args(
        getattr(atomic.executor, "command", None),
        atomic,
        cfg.input_args,
        cfg.path_to_atomics,
        executor_name=executor,
    )
    built = build_exec_argv(executor, main_cmd, platform)
    if built is None:
        outcome.main = ExecResult("", "", -1, None, False, 0.0)
        return outcome
    exe, argv, display = built
    if not cfg.execute:
        res = _simulate(exe, argv)
    else:
        res = execute_command(exe, argv, cfg.timeout, platform, cwd=work_dir)
    emit("main", display, res, not cfg.execute)
    outcome.main = res
    return outcome
