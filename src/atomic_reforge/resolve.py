"""Resolve a variant's templated command into an executable script payload.

Replaces every ``#{arg}`` in the command/cleanup with the argument's default
value, and rewrites the ``PathToAtomicsFolder`` placeholder to the actual
absolute atomics path so the produced .ps1/.bat is directly runnable on a
target host.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from atomic_red_team.models import Atomic

from .source import ATOMICS_PATH

_PATH_TOKEN = "{PathToAtomicsFolder}"

_MUSTACHE = re.compile(r"#\{([^}]+)\}")


def _arg_default(atomic: "Atomic", key: str) -> str:
    """Look up an input argument's default value (or the bare key)."""
    argdef = (atomic.input_arguments or {}).get(key)
    if argdef is None:
        return ""
    if isinstance(argdef, dict):
        default = argdef.get("default")
    else:
        default = getattr(argdef, "default", None)
    if default is None:
        return ""
    return str(default)


def resolve_command(atomic: "Atomic", command: str | None) -> str:
    """Replace ``#{arg}`` with defaults and the atomics-folder token with a path."""
    if not command:
        return ""

    out = command
    for _ in range(8):
        prev = out
        out = _MUSTACHE.sub(lambda m: _arg_default(atomic, m.group(1)), out)
        if out == prev:
            break
    out = out.replace(_PATH_TOKEN, str(ATOMICS_PATH))
    return out


def build_script(atomic: "Atomic", executor_name: str) -> str:
    """Assemble the full runnable script body for an executor."""
    command = resolve_command(atomic, atomic.executor.command)
    cleanup = resolve_command(atomic, atomic.executor.cleanup_command)

    if executor_name == "powershell":
        parts = [command, ""]
        if cleanup:
            parts.extend(
                [
                    "# cleanup",
                    "try { " + cleanup + " } catch {}",
                    "",
                ]
            )
        return "\n".join(parts)
    if executor_name == "command_prompt":
        parts = ["@echo off", command, ""]
        if cleanup:
            parts.extend(["rem cleanup", cleanup, ""])
        return "\n".join(parts)
    # Fallback: an sh-like plain script.
    return command + ("\n" if not command.endswith("\n") else "")
