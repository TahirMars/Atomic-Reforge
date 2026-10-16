"""Transformation engine: compose deformation strategies into variant Atomics."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic, CommandExecutor

from atomic_red_team.models import Technique  # noqa: E402

from .strategies import Strategy  # noqa: E402
from .strategies.base import TransformPlan  # noqa: E402

WINDOWS_EXECUTORS = ("powershell", "command_prompt")


@dataclass
class Variant:
    """A produced variant: the new Atomic plus traceability metadata."""

    technique_id: str
    source_atomic: "Atomic"
    source_test_index: int
    new_atomic: "Atomic"
    strategy_tags: list[str]
    plans: list[TransformPlan] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)
    variant_guid: str = ""

    @property
    def source_guid(self) -> Optional[str]:
        g = self.source_atomic.auto_generated_guid
        return str(g) if g else None


def in_scope(atomic: "Atomic") -> bool:
    """True if this atomic is in the first-pipeline Windows scope."""
    if "windows" not in atomic.supported_platforms:
        return False
    if (
        hasattr(atomic.executor, "name")
        and atomic.executor.name in WINDOWS_EXECUTORS
    ):
        return True
    return False


def _substitute_arg_defaults(command: str, args: dict[str, dict]) -> str:
    """Replace ``#{key}`` with each argument's default (leave path tokens).

    Repeats until stable so nested placeholders inside defaults (e.g.
    ``exe_binary`` default containing ``#{arch}``) are also expanded.
    Empty-string defaults are applied; ``None`` defaults are skipped.
    """
    out = command or ""
    for _ in range(8):
        prev = out
        for key, argdef in args.items():
            default = argdef.get("default") if isinstance(argdef, dict) else None
            if default is None:
                continue
            out = out.replace(f"#{{{key}}}", str(default))
        if out == prev:
            break
    return out


def _materialize_command(
    strategy: Strategy,
    plan: TransformPlan,
    executor: "CommandExecutor",
    args: dict[str, dict],
) -> str:
    """Produce the variant command from plan and/or strategy.apply.

    Prefer ``plan.new_command`` when strategies already built the full text
    (binary/package_extract, wrapper, host_swap). Otherwise call ``apply``.
    Resolved (non-template) strategies get ``#{arg}`` defaults substituted
    first so encoding does not bake unresolved placeholders.
    """
    if plan.new_command is not None:
        return plan.new_command

    source = executor.command or ""
    if plan.template_based:
        return strategy.apply(source, template_based=True)

    resolved = _substitute_arg_defaults(source, args)
    return strategy.apply(resolved, template_based=False)


def build_variant(
    technique_id: str,
    source_atomic: "Atomic",
    source_index: int,
    strategy: Strategy,
    executor: "CommandExecutor",
    path_to_atomics=None,
) -> Optional[Variant]:
    """Apply a single strategy to an atomic and return a Variant, or None."""
    plan = strategy.plan(technique_id, source_atomic, executor, path_to_atomics)
    if plan is None:
        return None

    # --- input_arguments (start from source, add parameterized ones) ---
    args: dict[str, dict] = {}
    for name, argdef in (source_atomic.input_arguments or {}).items():
        args[name] = {
            "description": argdef.get("description", ""),
            "type": argdef.get("type", "string"),
            "default": argdef.get("default"),
        }
    for aname, adefault in (plan.added_args or {}).items():
        args[aname] = {
            "description": "Reforge-generated parameter (original constant).",
            "type": "string",
            "default": adefault,
        }

    new_command = _materialize_command(strategy, plan, executor, args)
    cleanup = executor.cleanup_command

    # Rebalance mustache keys against input_arguments. Strategies that operate
    # on the template keep #{..}; strategies that resolve (e.g. base64/hex)
    # consume the whole command. For resolved strategies any arg that is only
    # referenced in a now-consumed command is removed, but we must still keep
    # every arg referenced anywhere in the surviving text — the transformed
    # command, the kept cleanup_command, and each dependency's
    # prereq_command/get_prereq_command — because the upstream balance
    # validator enforces each #{key} in those strings to exist in
    # input_arguments (and forbids unused args).
    to_scan: list[str | None] = [new_command if plan.template_based else ""]
    to_scan.append(cleanup)
    to_scan.extend(d.prereq_command for d in (source_atomic.dependencies or []))
    to_scan.extend(
        d.get_prereq_command for d in (source_atomic.dependencies or [])
    )

    referenced = set()
    for text in to_scan:
        if text:
            referenced.update(re.findall(r"#\{([^}]+)\}", text))

    for key in list(args.keys()):
        if key not in referenced:
            args.pop(key, None)
    for key in referenced:
        if key not in args:
            args[key] = {
                "description": "Reforge re-added placeholder.",
                "type": "string",
                "default": None,
            }

    executor_dict: dict = {
        "name": plan.new_executor_name or executor.name,
        "command": new_command,
    }
    if cleanup:
        executor_dict["cleanup_command"] = cleanup
    if executor.elevation_required:
        executor_dict["elevation_required"] = executor.elevation_required

    new_guid = str(uuid.uuid4())
    tag_suffix = plan.tag.replace("/", "_")
    new_name = f"{source_atomic.name} - reforge/{tag_suffix}"

    atomic_dict = {
        "name": new_name,
        "description": _build_description(source_atomic, plan),
        "supported_platforms": list(source_atomic.supported_platforms),
        "executor": executor_dict,
        "input_arguments": args,
        "auto_generated_guid": new_guid,
    }
    if source_atomic.dependencies:
        atomic_dict["dependencies"] = [
            {
                "description": d.description,
                "prereq_command": d.prereq_command,
                "get_prereq_command": d.get_prereq_command,
            }
            for d in source_atomic.dependencies
        ]
        # Upstream rejects an explicit null dependency_executor_name; default
        # to the main executor when the source YAML omitted the key.
        dep_ex = source_atomic.dependency_executor_name or executor.name
        if dep_ex:
            atomic_dict["dependency_executor_name"] = dep_ex

    try:
        technique = Technique(
            attack_technique=technique_id,
            display_name=f"Technique {technique_id}",
            atomic_tests=[atomic_dict],
        )
    except Exception:
        return None
    new_atomic = technique.atomic_tests[0]

    return Variant(
        technique_id=technique_id,
        source_atomic=source_atomic,
        source_test_index=source_index,
        new_atomic=new_atomic,
        strategy_tags=[plan.tag],
        plans=[plan],
        explanations=[plan.explanation],
        variant_guid=new_guid,
    )


def generate_variants(
    technique_id: str,
    source_atomic: "Atomic",
    source_index: int,
    strategies: list[Strategy],
    path_to_atomics=None,
    *,
    localize: bool = True,
) -> list[Variant]:
    """Generate all applicable variants for one atomic test.

    When ``localize`` is true (default), remote ``http(s)://`` fetches in the
    source command/args/deps are downloaded into
    ``ExternalPayloads/reforge_remote/`` and rewritten to
    ``PathToAtomicsFolder\\...`` paths so every subsequent strategy variant is
    offline-capable.
    """
    if not in_scope(source_atomic):
        return []
    if source_atomic.executor.name not in WINDOWS_EXECUTORS:
        return []

    work = source_atomic
    if localize:
        from .localize import localize_atomic

        result = localize_atomic(
            source_atomic, path_to_atomics, technique_id=technique_id
        )
        work = result.atomic

    executor = work.executor
    variants = []
    for strategy in strategies:
        if not strategy.applies(work, executor, path_to_atomics):
            continue
        v = build_variant(
            technique_id, work, source_index, strategy, executor,
            path_to_atomics,
        )
        if v is not None:
            variants.append(v)
    return variants


def _build_description(atomic: "Atomic", plan: TransformPlan) -> str:
    base = str(atomic.description or "").strip() or str(atomic.name)
    base = base.rstrip()
    return (
        f"{base}\n\n---\nReforge variant.\n"
        f"Strategy: {plan.tag}\nSource test: {atomic.name}\n"
        f"Source GUID: {atomic.auto_generated_guid}\n"
        f"Deformation: {plan.explanation}"
    )
