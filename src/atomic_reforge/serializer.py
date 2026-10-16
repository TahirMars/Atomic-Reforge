"""Serialize produced variants back out to disk (YAML + executable scripts)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic

    from .transform import Variant

from .resolve import build_script

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.sort_base_mapping_type = False
# Prevent folded-style wrapping that can insert a space after a Windows
# path backslash (e.g. ``System32\inetsrv`` -> ``System32\ inetsrv``).
_yaml.width = 10**9
_yaml.representer.ignore_aliases = lambda *args: True


def _plain(value):
    """Coerce rich pydantic scalar defaults (AnyUrl etc.) to plain strings."""
    if value is None:
        return None
    return str(value)


def _literal(value: str | None) -> LiteralScalarString | None:
    """Force literal block scalars so command text is never line-folded."""
    if value is None:
        return None
    return LiteralScalarString(value)


def _arg_field(argdef, key: str, default=""):
    """Read a field from either a plain dict or a pydantic Argument-like object."""
    if isinstance(argdef, dict):
        return argdef.get(key, default)
    return getattr(argdef, key, default)


def atomic_to_dict(atomic: "Atomic") -> dict:
    """Dump an Atomic model (from the reforge engine) back to a plain dict."""
    executor = atomic.executor
    executor_dict: dict = {
        "name": getattr(executor, "name", None),
        "command": _literal(executor.command),
    }
    if getattr(executor, "cleanup_command", None):
        executor_dict["cleanup_command"] = _literal(executor.cleanup_command)
    if getattr(executor, "elevation_required", None):
        executor_dict["elevation_required"] = executor.elevation_required

    d: dict = {
        "name": atomic.name,
        "auto_generated_guid": str(atomic.auto_generated_guid),
        "description": _literal(atomic.description),
        "supported_platforms": list(atomic.supported_platforms),
        "input_arguments": {
            name: {
                "default": _plain(_arg_field(argdef, "default", None)),
                "description": _arg_field(argdef, "description", "") or "",
                "type": _arg_field(argdef, "type", "string") or "string",
            }
            for name, argdef in (atomic.input_arguments or {}).items()
        },
        "executor": executor_dict,
    }
    if atomic.dependencies:
        deps = []
        for dep in atomic.dependencies:
            ddep = {"description": dep.description}
            if getattr(dep, "prereq_command", None):
                ddep["prereq_command"] = _literal(dep.prereq_command)
            if getattr(dep, "get_prereq_command", None):
                ddep["get_prereq_command"] = _literal(dep.get_prereq_command)
            deps.append(ddep)
        d["dependencies"] = deps
        d["dependency_executor_name"] = atomic.dependency_executor_name
    return d


def _script_name(executor_name: str) -> str:
    if executor_name == "powershell":
        return ".ps1"
    if executor_name == "command_prompt":
        return ".bat"
    return ".sh"


def write_outputs(
    variant: "Variant",
    out_dir: Path,
    script_dir: Path,
    include_script: bool = True,
) -> dict[str, Path]:
    """Write the variant YAML (and its resolved script) to disk.

    Returns a mapping of kind -> path.
    """
    tid = variant.technique_id
    vdir = out_dir / tid
    vdir.mkdir(parents=True, exist_ok=True)

    atomic: "Atomic" = variant.new_atomic
    stem = f"{variant.source_guid or 'src'}-{variant.variant_guid[:8]}"
    yaml_path = vdir / f"{stem}.yaml"

    await_write_yaml(yaml_path, atomic, tid)

    written: dict[str, Path] = {"yaml": yaml_path}

    if include_script:
        sdir = script_dir / tid
        sdir.mkdir(parents=True, exist_ok=True)
        ext = _script_name(atomic.executor.name)
        script_path = sdir / f"{stem}{ext}"
        body = build_script(atomic, atomic.executor.name)
        script_path.write_text(body, encoding="utf-8")
        written["script"] = script_path

    return written


def await_write_yaml(path: Path, atomic: "Atomic", technique_id: str) -> None:
    """Write one atomic to a YAML file (non-blocking helper naming preserved)."""
    data = atomic_to_dict(atomic)
    with open(path, "w", encoding="utf-8") as fh:
        _yaml.dump(
            {
                "attack_technique": technique_id,
                "display_name": f"Technique {technique_id}",
                "atomic_tests": [data],
            },
            fh,
        )


def write_all_variants(
    variants: Iterable["Variant"],
    out_dir: Path,
    script_dir: Path,
) -> list[dict[str, Path]]:
    return [write_outputs(v, out_dir, script_dir) for v in variants]
