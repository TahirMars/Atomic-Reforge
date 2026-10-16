"""End-to-end tests for the atomic-reforge transform engine."""

from __future__ import annotations

import base64
import re

import pytest

from atomic_reforge.serializer import atomic_to_dict
from atomic_reforge.source import discover_technique_yamls, load_technique
from atomic_reforge.strategies import get_strategies
from atomic_reforge.transform import generate_variants


def _technique(tid: str):
    path = next(
        p for p in discover_technique_yamls() if p.name == f"{tid}.yaml"
    )
    return load_technique(path)


@pytest.fixture(scope="module")
def t1059():
    return _technique("T1059.001")


def test_strategies_load():
    strat = get_strategies("all")
    assert len(strat) >= 7


def test_generate_schema_valid_and_args_balanced(t1059):
    """All produced variants must validate and keep #{arg} balance."""
    strategies = get_strategies("all")
    for atomic in t1059.atomic_tests:
        for v in generate_variants(
            t1059.attack_technique, atomic, 0, strategies, localize=False
        ):
            # Validating through the upstream model already enforces balance;
            # ensure we can round-trip to a plain dict without errors.
            d = atomic_to_dict(v.new_atomic)
            assert d["auto_generated_guid"]
            assert d["executor"]["command"]


def test_base64_roundtrip_recovers_intent(t1059):
    """Base64 variant must decode back to the original payload intent."""
    strategies = get_strategies(["encoding/base64"])
    atomic = t1059.atomic_tests[0]  # Mimikatz
    variants = generate_variants(
        t1059.attack_technique, atomic, 0, strategies, localize=False
    )
    assert variants, "expected a base64 variant for Mimikatz"
    cmd = variants[0].new_atomic.executor.command
    m = re.search(r"FromBase64String\('([^']+)'\)", cmd)
    assert m, f"no base64 blob found: {cmd[:120]}"
    decoded = base64.b64decode(m.group(1)).decode("utf-16-le")
    assert "Invoke-Mimikatz" in decoded
    # Args must be resolved before encode; path tokens become a sentinel.
    assert "#{" not in decoded
    assert "PathToAtomicsFolder" in cmd  # outer wrapper keeps live token


def test_dep_executor_name_none_still_generates():
    """Atomics with dependencies but null dependency_executor_name must work."""
    tech = _technique("T1056.001")
    strategies = get_strategies(["wrapper/noop"])
    atomic = tech.atomic_tests[0]
    assert atomic.dependencies
    assert atomic.dependency_executor_name is None
    variants = generate_variants(
        tech.attack_technique, atomic, 0, strategies, localize=False
    )
    assert variants, "expected variants despite null dependency_executor_name"
    assert variants[0].new_atomic.dependency_executor_name == "powershell"


def test_source_guid_preserved_and_variant_guid_unique(t1059):
    """source_guid must equal source atomic guid; variant guids new/unique."""
    strategies = get_strategies("all")
    seen = set()
    for atomic in t1059.atomic_tests:
        for v in generate_variants(
            t1059.attack_technique, atomic, 0, strategies, localize=False
        ):
            assert v.source_guid == str(atomic.auto_generated_guid)
            assert v.variant_guid not in seen
            assert v.variant_guid != v.source_guid
            seen.add(v.variant_guid)


def test_template_strategies_keep_placeholders(t1059):
    """Template-based strategies must leave #{arg} intact in the command."""
    strategies = get_strategies(["obfuscation/char_concat"])
    atomic = t1059.atomic_tests[0]  # Mimikatz uses #{mimpath}
    variants = generate_variants(
        t1059.attack_technique, atomic, 0, strategies, localize=False
    )
    assert variants
    cmd = variants[0].new_atomic.executor.command
    assert "#{mimpath}" in cmd


def test_scope_skips_non_windows(t1059):
    """CMD-only atomics must not gain powershell-only strategies."""
    strategies = get_strategies(["encoding/base64"])  # powershell-only
    for atomic in t1059.atomic_tests:
        if getattr(atomic.executor, "name", "") != "powershell":
            assert generate_variants(
                t1059.attack_technique, atomic, 0, strategies, localize=False
            ) == []
