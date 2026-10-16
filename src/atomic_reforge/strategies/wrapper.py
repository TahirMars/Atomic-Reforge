"""Wrapper strategies: wrap a payload in innocuous operations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from .base import Strategy, TransformPlan

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor


class NoopWrapperStrategy(Strategy):
    """Prepend/append harmless operations around the core payload.

    Works on the *template* (keeps ``#{arg}`` intact) so it composes cleanly
    with other strategies and stays schema-valid. Applies to both PowerShell
    and CMD executors with executor-appropriate wrapper syntax.
    """

    name = "wrapper/noop"
    family = "wrapper"

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        return executor.name in ("powershell", "command_prompt")

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        cmd = executor.command or ""
        if executor.name == "command_prompt":
            wrapped = (
                "rem reforge wrapper/noop\n"
                "echo Running system maintenance check...\n"
                + cmd
                + ("\n" if cmd and not cmd.endswith("\n") else "")
                + "rem end of diagnostic block"
            )
        else:
            wrapped = (
                "# reforge wrapper/noop\n"
                "Write-Host 'Running system maintenance check...' -ForegroundColor Gray\n"
                "Start-Sleep -Milliseconds 150\n"
                + cmd
                + ("\n" if cmd and not cmd.endswith("\n") else "")
                + "# end of diagnostic block"
            )
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Wraps the core payload in innocuous operations (a title echo / "
                "Start-Sleep and a trailing comment) so the command line begins "
                "and ends with benign-looking content, perturbing simple "
                "process-start filters while leaving the core attack intent intact."
            ),
            applied_to="command",
            new_command=wrapped,
            template_based=True,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        # Materialized in plan().new_command.
        return command
