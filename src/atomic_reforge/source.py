"""Load the upstream atomic_red_team package from the frozen ref/ copy via sys.path."""

import importlib.util
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REF_TEAM_DIR = _REPO_ROOT / "ref" / "atomic-red-team-master"

if str(_REF_TEAM_DIR) not in sys.path:
    sys.path.insert(0, str(_REF_TEAM_DIR))

from atomic_red_team.common import atomics_path  # noqa: E402
from atomic_red_team.models import (  # noqa: E402
    Atomic,
    CommandExecutor,
    ManualExecutor,
    Technique,
)
from atomic_red_team.validator import format_validation_error, yaml  # noqa: E402

ATOMICS_PATH = Path(atomics_path)


def discover_technique_yamls(root: Path = ATOMICS_PATH) -> list[Path]:
    """Return all technique YAML files under ``root/<T*>/`` for a technique root.

    Handles both layouts: the upstream atomics tree (exactly one
    ``T<id>/T<id>.yaml`` per technique) and a generated variant tree (one
    ``*.yaml`` per variant, all sharing the ``T<id>/`` directory). Returns YAML
    files sorted by path. Tolerates a missing or non-directory root (e.g. the
    ref-derived ATOMICS_PATH on an offline runtime, where resolution happens
    against the bundle's own variant tree) by returning an empty list rather
    than raising.
    """
    if not root.is_dir():
        return []
    files = []
    for d in sorted(root.iterdir()):
        if not d.is_dir() or not d.name.startswith("T"):
            continue
        for f in sorted(d.glob("*.yaml")):
            if f.is_file():
                files.append(f)
    return files


def load_technique(path: Path) -> Technique:
    """Load and validate a technique YAML into the upstream Technique model."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.load(fh)
    return Technique(**data)
