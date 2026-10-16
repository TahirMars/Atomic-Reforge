"""identity/original keeps the source command."""

from atomic_reforge.strategies import get_strategies
from atomic_reforge.strategies.identity import OriginalStrategy
from atomic_reforge.transform import generate_variants
from atomic_red_team.models import Technique


class _Exec:
    def __init__(self, command: str, name: str = "powershell"):
        self.command = command
        self.name = name


class _Atomic:
    supported_platforms = ["windows"]


def test_original_is_registered():
    names = [s.name for s in get_strategies("all")]
    assert "identity/original" in names
    assert names[0] == "identity/original"


def test_original_command_unchanged():
    strategy = OriginalStrategy()
    cmd = 'Get-Process | Select-Object Name'
    executor = _Exec(cmd)
    assert strategy.applies(_Atomic(), executor)
    plan = strategy.plan("T1057", _Atomic(), executor)
    assert plan is not None
    assert plan.new_command == cmd
    assert plan.template_based is True


def test_original_skips_non_windows():
    strategy = OriginalStrategy()
    atomic = type("A", (), {"supported_platforms": ["linux"]})()
    assert not strategy.applies(atomic, _Exec("echo x"))


def test_generate_original_matches_source():
    atomic = Technique(
        attack_technique="T1057",
        display_name="T1057",
        atomic_tests=[
            {
                "name": "list processes",
                "description": "d",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "command": "Get-Process\n",
                },
            }
        ],
    ).atomic_tests[0]
    variants = generate_variants(
        "T1057",
        atomic,
        0,
        get_strategies(["identity/original"]),
        localize=False,
    )
    assert len(variants) == 1
    assert variants[0].new_atomic.executor.command == atomic.executor.command
    assert "identity/original" in variants[0].strategy_tags
