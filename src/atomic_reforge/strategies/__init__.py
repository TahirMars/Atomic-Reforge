"""Strategy registry for atomic-reforge."""

from .base import Strategy, TransformPlan, VALID_FAMILIES
from .binary import BinaryPackageStrategy, BinaryRenameStrategy
from .encoding import Base64Strategy, HexStrategy
from .host_swap import CmdAltStrategy, HostSwapStrategy
from .obfuscation import CharConcatStrategy, StringReverseStrategy
from .parameterize import ParameterizeConstantStrategy
from .identity import OriginalStrategy
from .wrapper import NoopWrapperStrategy

ALL_STRATEGIES: list[Strategy] = [
    OriginalStrategy(),
    CharConcatStrategy(),
    StringReverseStrategy(),
    Base64Strategy(),
    HexStrategy(),
    HostSwapStrategy(),
    CmdAltStrategy(),
    NoopWrapperStrategy(),
    ParameterizeConstantStrategy(),
    BinaryRenameStrategy(),
    BinaryPackageStrategy(),
]


def get_strategies(names: str | list[str] | None) -> list[Strategy]:
    """Resolve strategies by name; 'all' or None returns everything."""
    if names is None or names == "all":
        return list(ALL_STRATEGIES)
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    lookup = {s.name: s for s in ALL_STRATEGIES}
    return [lookup[n] for n in names if n in lookup]


def strategy_names(strategies: list[Strategy]) -> list[str]:
    return [s.name for s in strategies]


__all__ = [
    "ALL_STRATEGIES",
    "Strategy",
    "TransformPlan",
    "VALID_FAMILIES",
    "get_strategies",
    "strategy_names",
]
