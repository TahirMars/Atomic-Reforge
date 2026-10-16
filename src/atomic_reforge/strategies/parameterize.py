"""Parameterization strategy: promote constants to new templated arguments."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

from .base import Strategy, TransformPlan

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor


class ParameterizeConstantStrategy(Strategy):
    """Extract a literal constant from the template into a new ``#{arg}``.

    Operating on the *template* (template_based=True), it finds a simple
    quoted literal command argument and replaces it with a fresh ``#{arg}``
    placeholder, recording the original value as the new argument's default.
    The engine adds the new argument to ``input_arguments`` so the upstream
    balance validation still passes. Requires at least one such literal.
    """

    name = "parameterize/constant"
    family = "parameterize"

    _LITERAL = re.compile(r"'([^']{4,})'|\"([^\"]{4,})\"")

    @classmethod
    def _quoted_value(cls, match: "re.Match") -> str:
        return match.group(1) if match.group(1) is not None else match.group(2)

    @classmethod
    def _first_constant(cls, command: str) -> Optional["re.Match"]:
        """First quoted literal that is not already a ``#{arg}`` template.

        Existing placeholders must stay put. Replacing ``\"#{path}\"`` with a
        bare ``#{reforge_arg}`` makes PowerShell treat ``#`` as a comment, so
        ``Split-Path`` / ``Start-Process`` lose Path and FilePath and prompt.
        """
        for match in cls._LITERAL.finditer(command or ""):
            if "#{" not in cls._quoted_value(match):
                return match
        return None

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        return executor.name in ("powershell", "command_prompt")

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        match = self._first_constant(executor.command or "")
        if match is None:
            return None
        value = self._quoted_value(match)
        arg_name = "reforge_arg"
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Promotes a hard-coded literal to a templated '#{reforge_arg}' "
                "input argument (defaulted to the original value), turning a "
                "fixed payload into a parameterized one so the same technique "
                "can be emitted with varying values."
            ),
            applied_to="command",
            added_args={arg_name: value},
            new_executor_name=None,
            template_based=True,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        if not template_based:
            return command

        match = self._first_constant(command)
        if match is None:
            return command
        quote = "'" if match.group(1) is not None else '"'
        replacement = f"{quote}#{{reforge_arg}}{quote}"
        return command[: match.start()] + replacement + command[match.end() :]
