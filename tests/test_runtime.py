"""Tests for the embeddable-Python offline runtime + release wiring."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from atomic_reforge.runtime import (
    RUNTIME_TAG,
    _EXT_MARKER,
    _PTH_NAME,
    build_runtime,
)
from atomic_reforge.release import build_release


def _skip_unless_downloadable():
    """Skip tests that need to download the embeddable CPython archive."""
    try:
        import urllib.request

        urllib.request.urlopen("https://www.python.org", timeout=15).close()
    except Exception:
        pytest.skip("network unavailable for embed download")


def _build(tmp_path) -> Path:
    """Build a runtime and return its dir (downloads the embed archive once)."""
    _skip_unless_downloadable()
    dest = tmp_path / "runtime"
    build_runtime(dest, verbose=False)
    return dest


def test_build_runtime_layout(tmp_path):
    dest = _build(tmp_path)
    # Launcher + interpreter present.
    assert (dest / "python.exe").is_file()
    # import site enabled in the ._pth.
    pth = (dest / _PTH_NAME).read_text(encoding="utf-8")
    assert any(l.strip() == "import site" for l in pth.splitlines())
    # Vendored packages present.
    sp = dest / "Lib" / "site-packages"
    assert (sp / "atomic_reforge" / "cli.py").is_file()
    assert (sp / "atomic_red_team").is_dir()
    assert (sp / "pydantic").is_dir()
    assert (sp / "pydantic_core").is_dir()


def test_runtime_imports_cli(tmp_path):
    dest = _build(tmp_path)
    exe = dest / "python.exe"
    r = subprocess.run(
        [str(exe), "-m", "atomic_reforge.cli", "run", "--help"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert r.returncode == 0, r.stderr
    assert "technique id" in (r.stdout + r.stderr).lower() or "--test" in r.stdout


def test_runtime_run_offline_variant_tree(tmp_path):
    """The bundled runtime can dry-run a variant tree without the ref atomics."""
    dest = _build(tmp_path)
    # A minimal variant YAML tree (bundled-style: one *.yaml per variant).
    variants = tmp_path / "variants" / "T1059.001"
    variants.mkdir(parents=True, exist_ok=True)
    (variants / "v1.yaml").write_text(
        json.dumps(
            {
                "attack_technique": "T1059.001",
                "display_name": "T1059.001",
                "atomic_tests": [
                    {
                        "name": "test",
                        "auto_generated_guid": "11111111-1111-1111-1111-111111111111",
                        "description": "d",
                        "supported_platforms": ["windows"],
                        "executor": {
                            "name": "powershell",
                            "command": "Write-Host hi",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    exe = dest / "python.exe"
    r = subprocess.run(
        [
            str(exe),
            "-m",
            "atomic_reforge.cli",
            "run",
            "T1059.001",
            "--path",
            str(variants.parent),
            "--no-log",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert r.returncode == 0, r.stderr
    assert "1 command(s)" in r.stdout


# ---- the release `_pth` tag helpers are stable ----
def test_tag_helpers():
    assert RUNTIME_TAG
    assert _EXT_MARKER.endswith("-win_amd64.pyd")


# ---- release bundles a runtime only when asked ----
def test_release_bundles_runtime_only_when_requested(tmp_path):
    from atomic_reforge.strategies import get_strategies

    # Build a tiny atomics tree so generation has a source.
    atomics = tmp_path / "atomics" / "T1059.001"
    bin_dir = atomics / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    payload = bin_dir / "tool.exe"
    payload.write_bytes(b"MZ fake")
    import yaml as _yaml

    (atomics / "T1059.001.yaml").write_text(
        _yaml.safe_dump(
            {
                "attack_technique": "T1059.001",
                "display_name": "T1059.001",
                "atomic_tests": [
                    {
                        "name": "t",
                        "auto_generated_guid": "44444444-4444-4444-4444-444444444444",
                        "description": "d",
                        "supported_platforms": ["windows"],
                        "input_arguments": {
                            "p": {
                                "default": r"PathToAtomicsFolder\T1059.001\bin\tool.exe",
                                "description": "p",
                                "type": "string",
                            }
                        },
                        "executor": {
                            "name": "powershell",
                            "command": "#{p} --x",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    # Default: no runtime bundled.
    b1 = tmp_path / "rel_default"
    s1 = build_release(
        tids=["T1059.001"],
        bundle_dir=b1,
        path_to_atomics=tmp_path / "atomics",
    )
    assert s1["runtime_bundled"] is False
    assert not (b1 / "runtime").exists()
    assert not (b1 / "run_offline.bat").exists()

    # With --bundle-runtime: runtime + launcher + manifest runtime entries.
    b2 = tmp_path / "rel_runtime"
    s2 = build_release(
        tids=["T1059.001"],
        bundle_dir=b2,
        path_to_atomics=tmp_path / "atomics",
        bundle_runtime=True,
        runtime_dir=_prebuilt_embed(tmp_path),
    )
    assert s2["runtime_bundled"] is True
    assert s2["runtime_files"] > 0
    assert (b2 / "runtime" / "python.exe").is_file()
    assert (b2 / "run_offline.bat").is_file()

    manifest = json.loads((b2 / "manifest.json").read_text(encoding="utf-8"))
    runtime_entries = [f for f in manifest["files"] if f.get("status") == "runtime"]
    assert runtime_entries
    # Every runtime entry's sha256 matches disk.
    for f in runtime_entries:
        p = b2 / Path(f["path"].replace("/", "\\"))
        assert p.is_file(), f"missing {f['path']}"
        from atomic_reforge.payloads import sha256_file

        assert sha256_file(p) == f["sha256"], f"hash mismatch {f['path']}"


def _prebuilt_embed(tmp_path) -> Path:
    """Return a reusable embed root (or None if we can build one)."""
    _skip_unless_downloadable()
    from atomic_reforge.runtime import download_embed

    root = tmp_path / "embed"
    return download_embed(root)


def test_run_check_integrity(tmp_path):
    from atomic_reforge.payloads import sha256_file

    # Build a small bundle without a runtime to test integrity quickly.
    atomics = tmp_path / "atomics" / "T1059.001"
    atomics.mkdir(parents=True, exist_ok=True)
    import yaml as _yaml

    (atomics / "T1059.001.yaml").write_text(
        _yaml.safe_dump(
            {
                "attack_technique": "T1059.001",
                "display_name": "T1059.001",
                "atomic_tests": [
                    {
                        "name": "t",
                        "auto_generated_guid": "55555555-5555-5555-5555-555555555555",
                        "description": "d",
                        "supported_platforms": ["windows"],
                        "executor": {
                            "name": "powershell",
                            "command": "Write-Host hi",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    b = tmp_path / "bundle"
    build_release(tids=["T1059.001"], bundle_dir=b, path_to_atomics=tmp_path / "atomics")

    from atomic_reforge.cli import _verify_integrity
    import typer

    # Untampered: passes.
    _verify_integrity(b / "variants")

    # Tamper a generated file -> fails (typer.Exit, a RuntimeError) with code 2.
    variant_yaml = next((b / "variants").rglob("*.yaml"))
    original = variant_yaml.read_bytes()
    variant_yaml.write_bytes(b"## tampered: " + original)
    with pytest.raises(typer.Exit) as exc:
        _verify_integrity(b / "variants")
    assert exc.value.exit_code == 2
    variant_yaml.write_bytes(original)
