"""String obfuscation strategies."""

from __future__ import annotations

import random
import re
from typing import TYPE_CHECKING, Optional

from .base import Strategy, TransformPlan

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor

_PS_LITERAL = re.compile(r"'[^']*'|\"[^\"]*\"")


class CharConcatStrategy(Strategy):
    """Split string literals and reassemble at runtime (PowerShell + CMD).

    PowerShell: literal pieces are joined with ``+`` on the fly.
    CMD: for simple ``echo "text"`` style literals we intentionally fall
    through without deforming (to avoid breaking %VAR% env expansion); the
    strategy primarily targets PowerShell string literals.
    """

    name = "obfuscation/char_concat"
    family = "obfuscation"

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        return executor.name == "powershell"

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Splits literal string(s) into single characters and reassembles "
                "them at runtime with '+', defeating naive string-signature "
                "matching while preserving attack intent."
            ),
            applied_to="command",
            template_based=True,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        if not template_based:
            return command
        return _PS_LITERAL.sub(self._obfuscate_literal, command)

    def _obfuscate_literal(self, m: "re.Match") -> str:
        literal = m.group(0)
        quote = literal[0]
        inner = literal[1:-1]
        if not inner or len(inner) < 3 or "#{" in inner or "PathToAtomicsFolder" in inner:
            return literal
        # Split into runs of word/identifier chars (kept together as chars) and
        # punctuation/space runs. Every run becomes a char-joined expression.
        parts = re.findall(r"[A-Za-z0-9_.:\\/\\-]+|[^A-Za-z0-9_.:\\/\\-]+", inner)
        expr = " + ".join(
            " + ".join(f"'{c}'" for c in part) for part in parts
        )
        var = f"$b{self._rng.randrange(100,999)}"
        return f"({var} = {expr})"


class StringReverseStrategy(Strategy):
    """Reverse a string and un-reverse it at runtime (PowerShell)."""

    name = "obfuscation/string_reverse"
    family = "obfuscation"

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        return executor.name == "powershell"

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Reverses literal string(s) in the payload and un-reverses them "
                "at runtime via a char-array negation index, so the readable "
                "string is not present in forward form on disk/in memory."
            ),
            applied_to="command",
            template_based=True,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        if not template_based:
            return command
        var = "s9"
        return _PS_LITERAL.sub(self._make_unreverse(var), command)

    def _make_unreverse(self, var: str):
        def _rev(m: "re.Match") -> str:
            literal = m.group(0)
            inner = literal[1:-1]
            if not inner or len(inner) < 5 or "#{" in inner or "PathToAtomicsFolder" in inner:
                return literal
            rev = inner[::-1]
            # `$s9 = -join ("<rev>".ToCharArray()[-1..-N])` un-reverses
            return f"({var} = -join (\"{rev}\".ToCharArray()[-1..-{len(rev)}]))"

        return _rev
