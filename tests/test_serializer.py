"""Serializer must not corrupt Windows paths via YAML folded line breaks."""

from __future__ import annotations

from pathlib import Path

import yaml

from atomic_reforge.serializer import await_write_yaml
from atomic_red_team.models import Technique


def _atomic_with_cmd(command: str):
    tech = Technique(
        attack_technique="T1036.003",
        display_name="T1036.003",
        atomic_tests=[
            {
                "name": "path wrap probe",
                "auto_generated_guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "description": "d",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "command_prompt",
                    "command": command,
                },
            }
        ],
    )
    return tech.atomic_tests[0]


def test_yaml_dump_preserves_backslash_paths(tmp_path: Path):
    # Long command that previously got folded after a backslash, inserting a
    # space (System32\inetsrv -> System32\ inetsrv).
    command = (
        "C:\\Windows\\System32\\inetsrv\\appcmd.exe list apppool /config\n"
        "copy %SystemRoot%\\System32\\cmd.exe %SystemRoot%\\Temp\\lsass.exe\n"
        "%SystemRoot%\\Temp\\lsass.exe /B"
    )
    atomic = _atomic_with_cmd(command)
    out = tmp_path / "probe.yaml"
    await_write_yaml(out, atomic, "T1036.003")

    text = out.read_text(encoding="utf-8")
    assert "\\ " not in text, f"folded space after backslash in:\n{text}"

    loaded = yaml.safe_load(text)
    roundtrip = loaded["atomic_tests"][0]["executor"]["command"]
    assert "System32\\inetsrv" in roundtrip
    assert "System32\\ inetsrv" not in roundtrip
    assert "%SystemRoot%\\Temp\\lsass.exe" in roundtrip
    assert roundtrip.replace("\r\n", "\n") == command
