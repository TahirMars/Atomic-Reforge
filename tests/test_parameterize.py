"""parameterize/constant must not turn existing #{args} into bare tokens."""

from atomic_reforge.strategies.parameterize import ParameterizeConstantStrategy


class _Exec:
    def __init__(self, command: str):
        self.command = command
        self.name = "powershell"


def test_skips_placeholder_only_command():
    strategy = ParameterizeConstantStrategy()
    executor = _Exec('Start-Process "#{script_path}"')
    assert strategy.plan("T1059.003", None, executor) is None
    assert strategy.apply(executor.command, template_based=True) == executor.command


def test_keeps_quotes_and_skips_existing_placeholders():
    strategy = ParameterizeConstantStrategy()
    command = (
        'Split-Path "#{program_path}"\n'
        'New-Item -ItemType Directory -Path "$parent" -Force\n'
        'Start-Process "#{program_path}"'
    )
    executor = _Exec(command)
    plan = strategy.plan("T1047", None, executor)
    assert plan is not None
    assert plan.added_args == {"reforge_arg": "$parent"}
    out = strategy.apply(command, template_based=True)
    assert 'Split-Path "#{program_path}"' in out
    assert 'Start-Process "#{program_path}"' in out
    assert '-Path "#{reforge_arg}"' in out
    assert " #{reforge_arg}" not in out


def test_obfuscation_keeps_atomics_token():
    from atomic_reforge.strategies.obfuscation import (
        CharConcatStrategy,
        StringReverseStrategy,
    )

    command = 'Start-Process "PathToAtomicsFolder\\..\\ExternalPayloads\\calc.dll"'
    assert "PathToAtomicsFolder" in CharConcatStrategy().apply(command, template_based=True)
    assert "PathToAtomicsFolder" in StringReverseStrategy().apply(command, template_based=True)


def test_preserves_single_quotes():
    strategy = ParameterizeConstantStrategy()
    command = "Write-Host 'hello-world'"
    out = strategy.apply(command, template_based=True)
    assert out == "Write-Host '#{reforge_arg}'"
