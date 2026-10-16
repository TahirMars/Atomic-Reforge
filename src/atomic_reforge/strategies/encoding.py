"""Payload encoding strategies (Base64 / Hex with inline decoders)."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Optional

from ..payloads import anchor_external_payloads
from .base import Strategy, TransformPlan

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor

# Sentinel substituted for PathToAtomicsFolder tokens before encoding so the
# outer wrapper can keep a live PathToAtomicsFolder reference for run-time
# rewrite (offline release / merge_input_args).
_PTA_SENTINEL = "__REFORGE_PTA__"
_PATH_TOKENS = (
    "{PathToAtomicsFolder}",
    "$PathToAtomicsFolder",
    "PathToAtomicsFolder",
)


def _seal_path_tokens(command: str) -> str:
    out = command
    for tok in _PATH_TOKENS:
        out = out.replace(tok, _PTA_SENTINEL)
    return out


def _ps_decode_wrapper(encoded: str, decoder_body: str) -> str:
    """Outer PS that restores PathToAtomicsFolder then Invoke-Expression."""
    return (
        "$__rpta='PathToAtomicsFolder';"
        + decoder_body.format(encoded=encoded, sentinel=_PTA_SENTINEL)
    )


class Base64Strategy(Strategy):
    """Base64-encode a resolved PowerShell payload and run via decode+iex.

    Operates on the concrete command after ``#{arg}`` substitution (engine
    resolves defaults before calling ``apply``). Path tokens are sealed into a
    sentinel and restored from an outer ``PathToAtomicsFolder`` reference so
    offline ``run`` can remap the atomics root.
    """

    name = "encoding/base64"
    family = "encoding"

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        return executor.name == "powershell"

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Base64-encodes the resolved PowerShell payload and executes it "
                "via an inline [Convert]::FromBase64String + Invoke-Expression "
                "decoder, so the plaintext command is not present on disk/in "
                "process memory in a readable form."
            ),
            applied_to="command",
            template_based=False,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        sealed = _seal_path_tokens(anchor_external_payloads(command))
        encoded = base64.b64encode(sealed.encode("utf-16-le")).decode("ascii")
        body = (
            "$p=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}'));"
            "iex ($p.Replace('{sentinel}',$__rpta))"
        )
        return _ps_decode_wrapper(encoded, body)


class HexStrategy(Strategy):
    """Hex-encode each character of a resolved PowerShell payload."""

    name = "encoding/hex"
    family = "encoding"

    def applies(self, atomic, executor, path_to_atomics=None) -> bool:
        return executor.name == "powershell"

    def plan(self, technique_id, atomic, executor, path_to_atomics=None) -> Optional[TransformPlan]:
        return TransformPlan(
            tag=self.name,
            family=self.family,
            explanation=(
                "Hex-encodes the resolved PowerShell payload and reconstructs it "
                "at runtime by converting hex pairs back to [char] and joining, "
                "then Invoke-Expression — no plaintext payload on disk."
            ),
            applied_to="command",
            template_based=False,
        )

    def apply(self, command: str, template_based: bool = False) -> str:
        sealed = _seal_path_tokens(anchor_external_payloads(command))
        hexu = sealed.encode("utf-8").hex()
        body = (
            "$h='{encoded}';$c=for($i=0;$i -lt $h.Length;$i+=2)"
            "{{[char][Convert]::ToInt32($h.Substring($i,2),16)}};"
            "$p=($c -join '');iex ($p.Replace('{sentinel}',$__rpta))"
        )
        return _ps_decode_wrapper(hexu, body)
