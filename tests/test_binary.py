"""Tests for binary payload deformation + local-first execution + release bundle."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from atomic_reforge import payloads as pl
from atomic_reforge.release import build_release
from atomic_reforge.runner import RunConfig, run_atomic
from atomic_reforge.strategies.base import TransformPlan
from atomic_reforge.transform import build_variant, generate_variants
from atomic_reforge.payloads import discover_payloads, local_exists


def _arg(name: str, default) -> dict:
    return {"default": default, "description": f"arg {name}", "type": "string"}


def _technique(**test_kw):
    from atomic_red_team.models import Technique

    base = {
        "name": "test",
        "auto_generated_guid": "22222222-2222-2222-2222-222222222222",
        "description": "d",
        "supported_platforms": ["windows"],
        "executor": {
            "name": "powershell",
            "command": "Write-Host ok",
        },
    }
    base.update(test_kw)
    t = Technique(
        attack_technique="T1059.001",
        display_name="T1059.001",
        atomic_tests=[base],
    )
    return t


def _with_bin(tmp_path, tech_dir="T1059.001", fname="SOAPHound.exe"):
    """Create a fake local payload and an atomic referencing it via an arg."""
    tid = "T1059.001"
    atomics = tmp_path / "atomics"
    bin_dir = atomics / tid / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    payload = bin_dir / fname
    payload.write_bytes(b"MZ fake binary payload bytes")
    # Mirror upstream: default references the payload via the plain
    # PathToAtomicsFolder token (no braces, no $) so discovery can resolve it
    # against the provided atomics root.
    default_token = f"{atomics}\\{tid}\\bin\\{fname}"
    # discovery resolves the "PathToAtomicsFolder" spelling -> atomics root.
    token_form = fr"PathToAtomicsFolder\{tid}\bin\{fname}"
    tech = _technique(
        input_arguments={
            "soaphound_path": _arg("soaphound_path", token_form),
            "user": _arg("user", "alice"),
        },
        executor={
            "name": "powershell",
            "command": "#{soaphound_path} --user #{user}",
        },
        dependencies=[],
    )
    # patch the resolved payload location so path_to_atomics points at atomics.
    return tech, payload


# ---- payload discovery ----
def test_discover_arg_keyed_payload(tmp_path):
    tech, payload = _with_bin(tmp_path)
    atomic = tech.atomic_tests[0]
    refs = discover_payloads(atomic, tmp_path / "atomics")
    assert len(refs) == 1
    ref = refs[0]
    assert ref.arg_key == "soaphound_path"
    assert ref.exists
    assert local_exists(ref)


def test_discover_literal_payload(tmp_path):
    from atomic_red_team.models import Technique

    bin_dir = tmp_path / "atomics" / "T1055" / "bin" / "x64"
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.joinpath("InjectView.exe").write_bytes(b"MZ literal binary")
    tech = _technique(
        executor={
            "name": "powershell",
            "command": 'Start-Process "$PathToAtomicsFolder\\T1055\\bin\\x64\\InjectView.exe"',
        },
    )
    tech.attack_technique = "T1055"
    atomic = tech.atomic_tests[0]
    refs = discover_payloads(atomic, tmp_path / "atomics")
    # literal path resolves against the atomics root; our fake root lacks it.
    literal_refs = [r for r in refs if r.literal]
    assert literal_refs


# ---- BinaryRenameStrategy ----
def test_rename_strategy_plan(tmp_path):
    from atomic_reforge.strategies.binary import (
        BinaryRenameStrategy,
        PayloadOp,
    )

    tech, payload = _with_bin(tmp_path)
    atomic = tech.atomic_tests[0]
    strat = BinaryRenameStrategy()
    assert strat.applies(atomic, atomic.executor, tmp_path / "atomics")
    plan = strat.plan("T1059.001", atomic, atomic.executor, tmp_path / "atomics")
    assert plan is not None
    assert plan.payload_ops
    op = plan.payload_ops[0]
    assert op.kind == "copy_rename"
    assert op.src_path == payload
    assert op.new_name.endswith(".exe")
    assert op.new_name != payload.name
    # The arg-key default points at the new name.
    assert plan.added_args


def test_rename_build_variant_valid(tmp_path):
    from atomic_reforge.strategies.binary import BinaryRenameStrategy

    tech, payload = _with_bin(tmp_path)
    atomic = tech.atomic_tests[0]
    atomics = tmp_path / "atomics"
    strat = BinaryRenameStrategy()
    v = build_variant(
        "T1059.001", atomic, 0, strat, atomic.executor, atomics
    )
    assert v is not None
    assert v.new_atomic is not None
    arg = v.new_atomic.input_arguments["soaphound_path"]
    default = arg["default"] if isinstance(arg, dict) else arg.default
    assert str(default).startswith("PathToAtomicsFolder\\payloads\\T1059.001\\")
    assert str(default).endswith(".exe")


def test_package_build_variant_has_loader(tmp_path):
    from atomic_reforge.strategies.binary import BinaryPackageStrategy

    tech, payload = _with_bin(tmp_path)
    atomic = tech.atomic_tests[0]
    atomics = tmp_path / "atomics"
    strat = BinaryPackageStrategy()
    v = build_variant(
        "T1059.001", atomic, 0, strat, atomic.executor, atomics
    )
    assert v is not None
    cmd = v.new_atomic.executor.command
    assert "WriteAllBytes" in cmd
    assert "reforge binary/package_extract" in cmd
    assert "reforge_payload_0" in (v.new_atomic.input_arguments or {})


# ---- BinaryPackageStrategy ----
def test_package_strategy_plan(tmp_path):
    from atomic_reforge.strategies.binary import BinaryPackageStrategy

    tech, payload = _with_bin(tmp_path)
    atomic = tech.atomic_tests[0]
    strat = BinaryPackageStrategy()
    assert strat.applies(atomic, atomic.executor, tmp_path / "atomics")
    plan = strat.plan("T1059.001", atomic, atomic.executor, tmp_path / "atomics")
    assert plan is not None
    assert plan.added_args
    # Embedded base64 octets round-trip.
    blob_key = list(plan.added_args)[0]
    import base64 as _b64

    assert _b64.b64decode(plan.added_args[blob_key]) == payload.read_bytes()


# ---- local-first short-circuit (runner) ----
# In dry-run the runner simulates every command as exit_code=0, so a
# `Test-Path` prereq always "succeeds" and the get branch is unreachable via
# prereq failure. To exercise the skip_get local-first decision, we monkeypatch
# the simulation so the prereq is modeled as FAILING (payload absent) — then
# the only thing that prevents the download get-command is skip_get itself.
def _failure_run(tmp_path, allow_download, monkeypatch):
    import atomic_reforge.runner as runner_mod

    tech, payload = _with_bin(tmp_path)
    atomic = tech.atomic_tests[0]
    atomic.dependencies = [
        {
            "description": "ensure payload",
            "prereq_command": "Test-Path '#{soaphound_path}'",
            "get_prereq_command": (
                "Invoke-WebRequest -Uri 'http://x/sh.exe' "
                "-OutFile '#{soaphound_path}'"
            ),
        }
    ]
    atomic.dependency_executor_name = "powershell"

    real = runner_mod._simulate

    def failing_sim(exe, argv):
        # Model the payload as absent: prereq (Test-Path) fails.
        if any("Test-Path" in a for a in argv):
            return runner_mod.ExecResult(
                stdout="", stderr="", exit_code=1, pid=None,
                timed_out=False, duration_s=0.0,
            )
        return real(exe, argv)

    monkeypatch.setattr(runner_mod, "_simulate", failing_sim)

    cfg = RunConfig(
        get_prereqs=True, execute=False, allow_download=allow_download,
        path_to_atomics=tmp_path / "atomics",
    )
    setattr(cfg, "_log_dir", tmp_path / "logs")
    out = run_atomic(atomic, "T1059.001", cfg, variant_guid="g", variant_name="v")
    return cfg, out


def test_local_first_skips_download(tmp_path, monkeypatch):
    # Payload present locally + no --allow-download => the failing prereq must
    # NOT trigger the networked get command (local-first short-circuit).
    cfg, out = _failure_run(tmp_path, allow_download=False, monkeypatch=monkeypatch)
    logs = _collect_commands(cfg)
    assert not any("Invoke-WebRequest" in c for c in logs)


def test_allow_download_runs_get(tmp_path, monkeypatch):
    # With --allow-download the failing prereq DOES run the get command.
    cfg, out = _failure_run(tmp_path, allow_download=True, monkeypatch=monkeypatch)
    logs = _collect_commands(cfg)
    assert any("Invoke-WebRequest" in c for c in logs)


def _collect_commands(cfg) -> list[str]:
    # Every emitted command (prereq + get + rerun) is written as a LogRecord
    # to the NDJSON session file under cfg._log_dir. Read them back.
    import json

    cmds = []
    log_dir = getattr(cfg, "_log_dir", None)
    if log_dir is not None:
        for ndjson in Path(log_dir).glob("*.json"):
            for line in ndjson.read_text(encoding="utf-8").splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("command"):
                    cmds.append(rec["command"])
    return cmds


# ---- release bundle + manifest sha256 ----
def test_release_manifest_hashes(tmp_path):
    # Build a real technique YAML tree so discover_technique_yamls finds it.
    tid = "T1059.001"
    atomics = tmp_path / "atomics"
    bin_dir = atomics / tid / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    payload = bin_dir / "SOAPHound.exe"
    payload.write_bytes(b"MZ fake payload for release")

    import yaml as _yaml

    tech_dict = {
        "attack_technique": tid,
        "display_name": tid,
        "atomic_tests": [
            {
                "name": "releasetest",
                "auto_generated_guid": "33333333-3333-3333-3333-333333333333",
                "description": "d",
                "supported_platforms": ["windows"],
                "input_arguments": {
                    "soaphound_path": {
                        "default": fr"PathToAtomicsFolder\{tid}\bin\SOAPHound.exe",
                        "description": "p",
                        "type": "string",
                    },
                    "user": {
                        "default": "alice",
                        "description": "u",
                        "type": "string",
                    },
                },
                "executor": {
                    "name": "powershell",
                    "command": "#{soaphound_path} --user #{user}",
                },
            }
        ],
    }
    (atomics / tid / f"{tid}.yaml").write_text(
        _yaml.safe_dump(tech_dict), encoding="utf-8"
    )

    bundle = tmp_path / "release"
    summary = build_release(
        tids=[tid],
        strategies="all",
        bundle_dir=bundle,
        archive="none",
        path_to_atomics=atomics,
    )
    assert summary["techniques"] >= 1
    assert summary["variants"] >= 1

    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["files"]

    # Every 'generated' or 'bundled' file's recorded sha256 must match on disk.
    for f in manifest["files"]:
        if f.get("status") in ("generated", "bundled") and f.get("sha256"):
            p = bundle / Path(f["path"])
            assert p.is_file(), f"missing {f['path']}"
            from atomic_reforge.payloads import sha256_file

            assert sha256_file(p) == f["sha256"], f"hash mismatch {f['path']}"

    assert summary["payloads_bundled"] >= 1

    # Original layout mirrored under bundle/atomics for offline PathToAtomicsFolder.
    mirrored = bundle / "atomics" / tid / "bin" / "SOAPHound.exe"
    assert mirrored.is_file()
    assert mirrored.read_bytes() == payload.read_bytes()

    # Rename targets land under atomics/payloads/<TID>/.
    rename_dir = bundle / "atomics" / "payloads" / tid
    assert rename_dir.is_dir()
    assert any(rename_dir.glob("*.exe"))
