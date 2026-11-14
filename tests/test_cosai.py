"""CoSAI Risk Map integration.

The important tests here are the ones asserting the two vendored datasets still
line up. CoSAI pins its own ATLAS version, so a CoSAI refresh can introduce
references to ATLAS ids that our pinned release does not have. These fail
loudly instead of letting enrichment quietly return nothing.
"""

from __future__ import annotations

import pytest

from mitre_atlas_mcp.data.cosai_loader import OTHER_FRAMEWORKS, get_cosai, pinned_commit
from mitre_atlas_mcp.data.loader import get_atlas
from mitre_atlas_mcp.tools import crossmap, reference
from mitre_atlas_mcp.views import cosai_controls_view


@pytest.fixture(scope="module")
def cosai():
    return get_cosai()


@pytest.fixture(scope="module")
def atlas():
    return get_atlas()


def test_pinned_commit_recorded():
    assert len(pinned_commit()) == 40


def test_collection_sizes(cosai):
    stats = cosai.stats()
    assert stats["risks"] == 28
    assert stats["controls"] == 29
    assert stats["personas"] == 10
    assert stats["components"] == 23


# -- dataset alignment ----------------------------------------------------


def test_every_cited_mitigation_id_resolves(cosai, atlas):
    """The mitigation bridge must resolve completely.

    This is the bridge the enrichment depends on, and all 13 cited ids
    currently resolve. If a CoSAI refresh cites a mitigation our ATLAS release
    does not have, enrichment would silently drop it.
    """
    cited = cosai.all_cited_atlas_ids()["mitigations"]
    assert cited, "CoSAI cites no ATLAS mitigations; the enrichment bridge is gone"
    missing = [m for m in cited if m not in atlas.mitigations]
    assert not missing, f"CoSAI cites unknown ATLAS mitigations: {missing}"


def test_cited_technique_ids_are_mostly_resolvable(cosai, atlas):
    """The technique bridge is allowed to be stale, but not wholly broken.

    CoSAI pins ATLAS 5.0.1 and two cited ids (AML.T0019, AML.T0024.002) no
    longer exist in 2026.10. That is tolerated and reported in tool output;
    a majority failing would mean the datasets have diverged badly.
    """
    cited = cosai.all_cited_atlas_ids()["techniques"]
    assert cited
    resolved = [t for t in cited if t in atlas.techniques]
    assert len(resolved) / len(cited) > 0.8, (
        f"only {len(resolved)}/{len(cited)} cited technique ids resolve; "
        "the vendored CoSAI and ATLAS releases may have diverged"
    )


def test_control_references_are_internally_consistent(cosai):
    for cid, c in cosai.controls.items():
        for rid in cosai.risks_for_control(cid):
            assert rid in cosai.risks, f"{cid} references unknown risk {rid}"
        for pid in c.get("personas") or ():
            assert pid in cosai.personas, f"{cid} references unknown persona {pid}"


def test_all_and_none_sentinels_are_expanded(cosai):
    """`risks: all` and `components: none` are strings, not lists.

    Iterating them as sequences would yield one entry per character, so the
    loader resolves them explicitly.
    """
    # controlRedTeaming declares risks: all, components: all
    assert cosai.applies_to_all_risks("controlRedTeaming")
    assert len(cosai.risks_for_control("controlRedTeaming")) == len(cosai.risks)
    assert len(cosai.components_for_control("controlRedTeaming")) == len(cosai.components)

    # controlProductGovernance declares risks: all, components: none
    assert cosai.components_for_control("controlProductGovernance") == []

    # No single-character ids anywhere, which is what the bug produced.
    for cid in cosai.controls:
        for value in (*cosai.risks_for_control(cid), *cosai.components_for_control(cid)):
            assert len(value) > 1, f"{cid} produced a single-character id {value!r}"


def test_cross_cutting_controls_reach_every_risk(cosai):
    cross_cutting = [c for c in cosai.controls if cosai.applies_to_all_risks(c)]
    assert cross_cutting, "expected some controls to declare risks: all"
    for rid in cosai.risks:
        for cid in cross_cutting:
            assert cid in cosai.controls_by_risk[rid]


def test_dangling_component_refs_do_not_grow(cosai):
    """Upstream leaves a few component ids behind after a rename.

    componentInputHandling and componentOutputHandling were split into
    per-layer ids (componentAgentInputHandling and so on) but three controls
    still reference the old names. Pinned so a CoSAI refresh that worsens this
    is visible, and so a refresh that fixes it prompts removing this test.
    """
    dangling = cosai.dangling_component_refs()
    assert set(dangling) == {
        "controlRuntimePrivacyEnhancingTechnologies",
        "controlInputValidationAndSanitization",
        "controlOutputValidationAndSanitization",
    }
    assert all(
        m in {"componentInputHandling", "componentOutputHandling"}
        for v in dangling.values()
        for m in v
    )


def test_reverse_indexes_agree_with_source(cosai):
    for mid, control_ids in cosai.controls_by_mitigation.items():
        for cid in control_ids:
            assert mid in (cosai.controls[cid].get("mappings") or {})["mitre-atlas"]
    for rid, control_ids in cosai.controls_by_risk.items():
        for cid in control_ids:
            assert rid in cosai.risks_for_control(cid)


# -- enrichment -----------------------------------------------------------


def test_enrichment_attaches_owners_and_components():
    # AML.M0028 Enforce Access Controls for AI Agent Tools -> Agent Permissions
    controls = cosai_controls_view("AML.M0028")
    assert controls, "expected a CoSAI control for AML.M0028"
    c = controls[0]
    assert c["title"] == "Agent Permissions"
    assert any(o["name"] == "Application Developer" for o in c["owners"])
    assert c["components"], "control should name the components it applies to"
    assert c["addresses_risks"]


def test_enrichment_is_empty_not_broken_for_unmapped_mitigation(atlas):
    """31 of 44 ATLAS mitigations have no CoSAI control; that must be graceful."""
    unmapped = [
        m for m in atlas.mitigations if not get_cosai().controls_for_mitigation(m)
    ]
    assert unmapped, "expected some mitigations to have no CoSAI control"
    assert cosai_controls_view(unmapped[0]) == []


def test_mitigation_view_carries_controls_and_can_opt_out(atlas):
    from mitre_atlas_mcp.views import mitigation_view

    with_controls = mitigation_view(atlas, "AML.M0028")
    assert with_controls["cosai_controls"]
    without = mitigation_view(atlas, "AML.M0028", include_controls=False)
    assert "cosai_controls" not in without


def test_brief_mitigation_view_names_owners(atlas):
    from mitre_atlas_mcp.views import mitigation_view

    brief = mitigation_view(atlas, "AML.M0028", brief=True)
    assert brief["owners"], "a ranked mitigation line should name who implements it"


def test_get_mitigations_for_technique_includes_controls():
    out = reference.get_mitigations_for_technique("AML.T0053")  # AI Agent Tool Invocation
    assert out["count"] > 0
    assert any(m.get("cosai_controls") for m in out["mitigations"])


def test_profile_mitigations_name_owners():
    from mitre_atlas_mcp.tools.threatmodel import profile_ai_system

    out = profile_ai_system(["tool_use", "untrusted_input"])
    assert any(m.get("owners") for m in out["mitigations"]), (
        "at least some ranked mitigations should carry CoSAI owners"
    )


def test_atlas_info_reports_cosai_provenance():
    info = reference.get_atlas_info()
    assert "cosai_risk_map" in info
    assert info["cosai_risk_map"]["controls"] == 29
    assert len(info["cosai_risk_map"]["cosai_commit"]) == 12


# -- cross-framework tool -------------------------------------------------


def test_map_technique_to_frameworks_prompt_injection():
    out = crossmap.map_technique_to_frameworks("AML.T0051")
    names = {f["framework"] for f in out["other_frameworks"]}
    assert "OWASP Top 10 for LLM" in names
    assert "STRIDE" in names
    owasp = next(f for f in out["other_frameworks"] if f["framework"] == "OWASP Top 10 for LLM")
    assert "LLM01" in owasp["ids"]
    assert owasp["version"] and owasp["url"]
    assert out["cosai_risks"]
    assert any(r["controls"] for r in out["cosai_risks"])
    assert any(c["owners"] for r in out["cosai_risks"] for c in r["controls"])


def test_map_technique_to_frameworks_reports_coverage_when_empty():
    """An agentic technique CoSAI has not caught up to must say so."""
    out = crossmap.map_technique_to_frameworks("AML.T0080")  # AI Agent Context Poisoning
    assert out["other_frameworks"] == [] or out["cosai_risks"] == []
    assert "cosai" in out["coverage"]["note"].lower()
    assert out["coverage"]["atlas_techniques_cited_by_cosai"] > 0


def test_map_technique_to_frameworks_includes_attack_when_known():
    out = crossmap.map_technique_to_frameworks("AML.T0000")
    assert out["attack"]["id"] == "T1596"


def test_map_technique_to_frameworks_unknown_id():
    assert "error" in crossmap.map_technique_to_frameworks("AML.T9999")


def test_declared_frameworks_exist_in_metadata(cosai):
    for fw in OTHER_FRAMEWORKS:
        assert fw in cosai.frameworks, f"{fw} is not declared in frameworks.yaml"
