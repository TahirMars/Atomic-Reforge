"""Strategy interface and TransformPlan shared by all deformation strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor

VALID_FAMILIES = {
    "obfuscation", "encoding", "host_swap", "wrapper", "parameterize", "binary",
    "identity",
}


@dataclass
class TransformPlan:
    """A plan produced by a Strategy describing a single deformation.

    `added_args` maps a new input argument name to its default value. The
    engine adds all ``#{name}`` keys that appear in the *new* command back into
    ``input_arguments`` so the upstream ``#{arg}`` <-> input_arguments balance
    validation still passes.
    """

    tag: str
    family: str
    explanation: str
    applied_to: str = "command"  # "command" | "cleanup" | "both"
    new_command: Optional[str] = None
    new_cleanup: Optional[str] = None
    new_executor_name: Optional[str] = None
    added_args: dict[str, object] = field(default_factory=dict)
    template_based: bool = False
    # Payload file operations to realize at materialization/release time.
    # Elements are PayloadOp objects (defined in strategies/binary.py) with
    # kind in {"copy_rename", "embed_base64"}.
    payload_ops: list = field(default_factory=list)


class Strategy(ABC):
    """Base class for a deformation strategy.

    A strategy inspects an Atomic test and its executor, and (if applicable)
    produces a plan describing how to transform the commands. It works in one
    of two modes:

    * ``template_based=True`` — operate on the *raw template* before ``#{arg}``
      substitution. This keeps ``#{}`` intact so the resulting command stays
      schema-valid (used by obfuscation, wrapper, host_swap whole-command
      wrapping, parameterize).
    * ``template_based=False`` — operate on the *resolved concrete* command
      (used by encoding, host_swap that re-encodes the actual payload).
    """

    name: str = ""
    family: str = ""

    @abstractmethod
    def applies(
        self,
        atomic: "Atomic",
        executor: "CommandExecutor",
        path_to_atomics=None,
    ) -> bool:
        """Return True if this strategy can deform the given atomic test."""

    @abstractmethod
    def plan(
        self,
        technique_id: str,
        atomic: "Atomic",
        executor: "CommandExecutor",
        path_to_atomics=None,
    ) -> Optional[TransformPlan]:
        """Inspect the atomic (template-level) and produce a plan, or None.

        ``technique_id`` (e.g. ``T1059.001``) is provided so strategies can
        build physical payload destinations that are grouped by technique inside
        a release bundle (``payloads/<TID>/...``). ``path_to_atomics`` anchors
        payload resolution (defaults to the project's real atomics root)."""


    def apply(self, command: str, template_based: bool = False) -> str:
        """Transform the command string according to the strategy.

        Subclasses may override; the default returns the command unchanged.
        `template_based` tells the strategy whether it is operating on the raw
        template (True) or the resolved concrete command (False).
        """
        return command

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} {self.name}>"
