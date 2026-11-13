"""Guards on the surface taxonomy.

The taxonomy hardcodes ATLAS technique ids. When a release renumbers or
retires one, these tests fail loudly instead of the server quietly returning a
shorter list.
"""

from __future__ import annotations

import pytest

from mitre_atlas_mcp.data.loader import PLATFORMS, get_atlas
from mitre_atlas_mcp.profile import (
    COMPOUND_RISKS,
    SURFACES,
    SURFACES_BY_KEY,
    compound_risks_for,
    unknown_surface_keys,
)


@pytest.fixture(scope="module")
def atlas():
    return get_atlas()


@pytest.mark.parametrize("surface", SURFACES, ids=lambda s: s.key)
def test_every_seed_technique_exists(surface, atlas):
    missing = [t for t in surface.techniques if t not in atlas.techniques]
    assert not missing, f"{surface.key} references unknown technique ids: {missing}"


@pytest.mark.parametrize("surface", SURFACES, ids=lambda s: s.key)
def test_seed_techniques_are_top_level(surface):
    """Seeds stay top-level; sub-techniques are reached by graph expansion."""
    subs = [t for t in surface.techniques if t.count(".") > 1]
    assert not subs, f"{surface.key} seeds sub-techniques directly: {subs}"


@pytest.mark.parametrize("surface", SURFACES, ids=lambda s: s.key)
def test_seed_techniques_carry_a_declared_platform(surface, atlas):
    """Each seed must be tagged with at least one platform the surface claims."""
    for tid in surface.techniques:
        tagged = set(atlas.techniques[tid].get("platforms") or ())
        assert tagged & set(surface.platforms), (
            f"{surface.key} seeds {tid}, tagged {sorted(tagged)}, "
            f"but the surface declares {surface.platforms}"
        )


@pytest.mark.parametrize("surface", SURFACES, ids=lambda s: s.key)
def test_surface_platforms_are_known(surface):
    assert set(surface.platforms) <= set(PLATFORMS)


def test_no_duplicate_surface_keys():
    keys = [s.key for s in SURFACES]
    assert len(keys) == len(set(keys))


def test_surface_seeds_are_disjoint():
    """No technique is seeded by two surfaces.

    profile_ai_system ranks by exposure count before maturity, so this
    documents why that first term is currently inert. If a future taxonomy
    edit deliberately shares a technique between surfaces, update
    test_profile_orders_by_maturity_and_attributes_surfaces alongside it.
    """
    owners: dict[str, list[str]] = {}
    for s in SURFACES:
        for tid in s.techniques:
            owners.setdefault(tid, []).append(s.key)
    shared = {tid: who for tid, who in owners.items() if len(who) > 1}
    assert not shared, f"techniques seeded by multiple surfaces: {shared}"


def test_taxonomy_coverage_of_atlas(atlas):
    """How much of ATLAS the taxonomy reaches, pinned so regressions show.

    94 of 221 techniques. The remainder are largely Predictive-AI,
    physical-access and Enterprise-only techniques that no agentic surface
    maps onto; see docs/roadmap.md.
    """
    reached: set[str] = set()
    for s in SURFACES:
        for tid in s.techniques:
            reached.add(tid)
            reached.update(atlas.subtechniques_of(tid))
    assert len(reached) == 94

    # Graph expansion is platform-agnostic, so a sub-technique may be narrower
    # than its parent (AML.T0137.002 "Invert AI Model" is Predictive AI only).
    # The platform filter in profile_ai_system drops those. What must hold is
    # that nothing is reached except through an Agentic AI seed.
    agentic = set(atlas.techniques_for_platform("Agentic AI"))
    for tid in reached:
        parent = atlas.parent_of(tid)
        assert tid in agentic or (parent and parent in agentic), (
            f"{tid} is reachable but neither it nor its parent is tagged Agentic AI"
        )


def test_compound_risks_reference_real_surfaces():
    for pair, _ in COMPOUND_RISKS:
        assert set(pair) <= set(SURFACES_BY_KEY), f"{pair} names an unknown surface"
        assert pair[0] != pair[1]


def test_compound_risks_require_both_halves():
    assert compound_risks_for(["untrusted_input"]) == []
    hits = compound_risks_for(["untrusted_input", "tool_use"])
    assert len(hits) == 1
    assert set(hits[0]["surfaces"]) == {"untrusted_input", "tool_use"}


def test_unknown_surface_keys():
    assert unknown_surface_keys(["tool_use", "nope"]) == ["nope"]
    assert unknown_surface_keys(["tool_use"]) == []
