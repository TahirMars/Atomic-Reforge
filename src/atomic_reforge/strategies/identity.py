"""Identity strategy: keep the original Atomic Red Team command."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from .base import Strategy, TransformPlan

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor


class OriginalStrategy(Strategy):
    """Emit the source test unchanged (Windows PowerShell / cmd only).

    Remote tool and Atomic Red Team repo fetches are rewritten to local
    payload paths by ``localize_atomic`` before this strategy runs. Command
    URLs that *are* the technique (C2, exfil, ingress transfer) stay remote.
    """

    name = "identity/original"
    family = "identity"

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        if "windows" not in (atomic.supported_platforms or []):
            return False
        return executor.name in ("powershell", "command_prompt")

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        cmd = executor.command or ""
        if not cmd.strip():
            return None
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Keeps the original Atomic Red Team command, executor, and "
                "arguments. Tool and Atomic Red Team repository downloads are "
                "rewritten to PathToAtomicsFolder payload paths when local "
                "files exist; techniques whose intent is outbound traffic "
                "(C2, exfil, ingress transfer) keep their live URLs."
            ),
            applied_to="command",
            new_command=cmd,
            template_based=True,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        return command
