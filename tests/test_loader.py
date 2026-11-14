"""Loader and index correctness against the pinned ATLAS release."""

from __future__ import annotations

import pytest

from mitre_atlas_mcp.data.loader import AtlasData, PLATFORMS, get_atlas, pinned_release


@pytest.fixture(scope="module")
def atlas():
    return get_atlas()


def test_pinned_release_matches_dataset(atlas):
    assert pinned_release() == "v2026.10"
    assert atlas.release_version == "2026.10"
    assert atlas.format_version.startswith("6.")


def test_collection_sizes(atlas):
    stats = atlas.stats()
    assert stats["tactics"] == 16
    assert stats["techniques"] == 221
    assert stats["mitigations"] == 44
    assert stats["case_studies"] == 77
    assert stats["entities"] == 44
    assert stats["software"] == 37


def test_every_id_resolves_in_unified_index(atlas):
    for collection in (atlas.tactics, atlas.techniques, atlas.mitigations, atlas.case_studies):
        for oid in collection:
            assert oid in atlas.by_id


def test_reverse_index_is_consistent_with_forward(atlas):
    """Every out-edge must appear as the matching in-edge."""
    for source, by_type in atlas.edges_out.items():
        for rel_type, edges in by_type.items():
            for edge in edges:
                target = edge.get("target")
                if target:
                    assert edge in atlas.edges_in[target][rel_type]


def test_technique_tactic_linkage_comes_from_relationships(atlas):
    # 6.1.0 techniques carry no `tactics` field; linkage is `achieves` edges.
    assert "tactics" not in atlas.techniques["AML.T0000"]
    assert atlas.tactics_for_technique("AML.T0000") == ["AML.TA0002"]


def test_every_technique_declares_its_own_tactics(atlas):
    """In v2026.10 all 221 techniques carry their own `achieves` edge.

    Documented as an invariant because `tactics_for_technique` has a
    parent-inheritance fallback that this release never exercises. See
    test_tactics_fallback_to_parent for direct coverage of that branch.
    """
    missing = [t for t in atlas.techniques if not atlas.targets(t, "achieves")]
    assert missing == []


def test_subtechnique_tactics_agree_with_parent(atlas):
    for tid in atlas.techniques:
        parent = atlas.parent_of(tid)
        if parent and parent in atlas.techniques:
            assert set(atlas.targets(tid, "achieves")) == set(atlas.targets(parent, "achieves"))


def test_tactics_fallback_to_parent():
    """A sub-technique with no tactic edge of its own inherits the parent's.

    Built from a synthetic dataset rather than the real one, since no shipped
    technique currently hits this path.
    """
    atlas = AtlasData(
        {
            "format-version": "6.1.0",
            "collection": {"version": "test"},
            "tactics": {"AML.TA0005": {"name": "Execution"}},
            "techniques": {
                "AML.T0001": {"name": "Parent"},
                "AML.T0001.000": {"name": "Child"},
            },
            "relationships": {
                "AML.T0001": {
                    "achieves": [
                        {"source": "AML.T0001", "target": "AML.TA0005", "relationship-type": "achieves"}
                    ]
                },
                "AML.T0001.000": {
                    "specializes": [
                        {
                            "source": "AML.T0001.000",
                            "target": "AML.T0001",
                            "relationship-type": "specializes",
                        }
                    ]
                },
            },
        }
    )
    assert atlas.targets("AML.T0001.000", "achieves") == []
    assert atlas.tactics_for_technique("AML.T0001.000") == ["AML.TA0005"]


def test_parent_of_falls_back_to_id_form():
    """The hierarchy is recoverable from the id even with no specializes edge."""
    atlas = AtlasData(
        {
            "format-version": "6.1.0",
            "collection": {"version": "test"},
            "techniques": {"AML.T0001": {"name": "Parent"}, "AML.T0001.000": {"name": "Child"}},
        }
    )
    assert atlas.parent_of("AML.T0001.000") == "AML.T0001"
    assert atlas.parent_of("AML.T0001") is None


def test_parent_and_subtechnique_round_trip(atlas):
    assert atlas.parent_of("AML.T0000.000") == "AML.T0000"
    assert "AML.T0000.000" in atlas.subtechniques_of("AML.T0000")
    assert atlas.parent_of("AML.T0000") is None


def test_mitigation_linkage_is_bidirectional(atlas):
    for tid in atlas.techniques_for_mitigation("AML.M0000"):
        assert "AML.M0000" in atlas.mitigations_for_technique(tid)


def test_case_study_attack_flow_is_ordered_and_linked(atlas):
    steps = atlas.steps_for_case_study("AML.CS0000")
    assert len(steps) > 1
    step_ids = [s["step-id"] for s in steps]
    assert step_ids == sorted(step_ids)
    # The flow is a chain: each leads-to names a later step in the same study.
    known = set(step_ids)
    for s in steps:
        for nxt in s.get("leads-to") or []:
            assert nxt in known
    # And every step targets a real technique.
    for s in steps:
        assert s["target"] in atlas.techniques


def test_case_study_technique_linkage_is_bidirectional(atlas):
    for tid in {s["target"] for s in atlas.steps_for_case_study("AML.CS0000")}:
        assert "AML.CS0000" in atlas.case_studies_for_technique(tid)


def test_platform_filter(atlas):
    agentic = atlas.techniques_for_platform("Agentic AI")
    assert len(agentic) == 148
    assert atlas.techniques_for_platform("agentic ai") == agentic  # case-insensitive
    assert atlas.techniques_for_platform("No Such Platform") == []


def test_all_declared_platforms_are_present_in_data(atlas):
    for platform in PLATFORMS:
        assert atlas.techniques_for_platform(platform), f"{platform} matched nothing"


def test_loader_is_cached(atlas):
    assert get_atlas() is atlas
