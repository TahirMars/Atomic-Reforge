"""Host-swap strategies: change the process carrier / invocation of a payload."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from .base import Strategy, TransformPlan

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor


def _single_line(command: str | None) -> bool:
    return "\n" not in (command or "")


class HostSwapStrategy(Strategy):
    """Swap powershell.exe carrier to pwsh via an embedded invocation.

    Keeps the YAML executor name as ``powershell`` (runner knows that host) but
    rewrites the command to ``pwsh -NoProfile -Command '...'`` so the observed
    process is pwsh.exe. Restricted to single-line payloads.
    """

    name = "host_swap/powershell_alt"
    family = "host_swap"

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        if executor.name != "powershell":
            return False
        return _single_line(executor.command)

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        cmd = (executor.command or "").strip()
        # Single-quote for -Command; escape embedded single quotes the PS way.
        escaped = cmd.replace("'", "''")
        wrapped = f"pwsh -NoProfile -Command '{escaped}'"
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Keeps the PowerShell payload but changes the invoking host "
                "from powershell.exe to pwsh via -NoProfile -Command, so the "
                "process/commandline signature differs (pwsh.exe instead of "
                "powershell.exe)."
            ),
            applied_to="command",
            new_command=wrapped,
            new_executor_name="powershell",
            template_based=True,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        return command


class CmdAltStrategy(Strategy):
    """Run a command_prompt payload via ``powershell -Command`` + cmd.exe /c.

    Changes the outer executor to powershell while preserving the original CMD
    script body through ``cmd.exe /c``, altering the process tree signature.
    """

    name = "host_swap/cmd_alt"
    family = "host_swap"

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        if executor.name != "command_prompt":
            return False
        return _single_line(executor.command)

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        cmd = (executor.command or "").strip()
        # Escape for embedding inside a PowerShell double-quoted -Command string.
        escaped = (
            cmd.replace("`", "``")
            .replace('"', '`"')
            .replace("$", "`$")
        )
        wrapped = f'cmd.exe /c "{escaped}"'
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Invokes the original command_prompt payload through "
                "powershell.exe running cmd.exe /c, so the process carrier "
                "signature differs while the CMD body and attack intent stay "
                "the same."
            ),
            applied_to="command",
            new_command=wrapped,
            new_executor_name="powershell",
            template_based=True,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        return command
