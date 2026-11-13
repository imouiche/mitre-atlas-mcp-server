"""Behaviour of the registered tools, including their error paths."""

from __future__ import annotations

from mitre_atlas_mcp.tools import crossmap, reference, threatmodel

# -- reference layer ------------------------------------------------------


def test_get_atlas_info():
    info = reference.get_atlas_info()
    assert info["pinned_release"] == "v2026.10"
    assert info["techniques_by_platform"]["Agentic AI"] == 148


def test_list_tactics():
    out = reference.list_tactics()
    assert out["count"] == 16
    assert out["tactics"][0]["id"] == "AML.TA0000"
    assert all(t["technique_count"] > 0 for t in out["tactics"])


def test_get_technique_resolves_and_links():
    t = reference.get_technique("AML.T0051")  # LLM Prompt Injection
    assert t["name"] == "LLM Prompt Injection"
    assert "Agentic AI" in t["platforms"]
    assert t["maturity"] == "Realized"
    assert t["sub_techniques"]
    assert t["mitigations"]
    assert t["case_study_ids"]


def test_get_technique_is_case_insensitive():
    assert reference.get_technique("aml.t0051")["id"] == "AML.T0051"


def test_get_technique_unknown_id_returns_error():
    out = reference.get_technique("AML.T9999")
    assert "error" in out and "hint" in out


def test_search_techniques_ranks_name_matches_first():
    out = reference.search_techniques("prompt injection")
    assert out["total_matches"] > 0
    assert out["techniques"][0]["name"] == "LLM Prompt Injection"


def test_search_techniques_platform_filter():
    out = reference.search_techniques("poisoning", platform="Agentic AI")
    assert out["total_matches"] > 0
    assert all("Agentic AI" in t["platforms"] for t in out["techniques"])


def test_search_techniques_maturity_filter():
    out = reference.search_techniques("agent", maturity="Realized")
    assert all(t["maturity"] == "Realized" for t in out["techniques"])


def test_search_techniques_rejects_bad_filters():
    assert "error" in reference.search_techniques("x", platform="Quantum AI")
    assert "error" in reference.search_techniques("x", maturity="Hypothetical")
    assert "error" in reference.search_techniques("   ")


def test_search_techniques_limit_is_respected():
    out = reference.search_techniques("ai", limit=3)
    assert len(out["techniques"]) == 3
    assert out["total_matches"] > 3


def test_get_techniques_by_tactic_accepts_id_or_name():
    by_id = reference.get_techniques_by_tactic("AML.TA0005")
    by_name = reference.get_techniques_by_tactic("Execution")
    assert by_id["count"] == by_name["count"] > 0
    assert "error" in reference.get_techniques_by_tactic("Nonsense")


def test_get_mitigations_for_technique_inherits_from_parent():
    """26 of 92 sub-techniques carry no mitigations; 18 inherit the parent's."""
    out = reference.get_mitigations_for_technique("AML.T0000.000")
    assert out["inherited_from"] == "AML.T0000"
    assert out["count"] > 0


def test_get_mitigations_for_technique_direct_is_not_marked_inherited():
    out = reference.get_mitigations_for_technique("AML.T0051")
    assert out["count"] > 0
    assert out["inherited_from"] is None


def test_get_case_study_returns_ordered_flow():
    cs = reference.get_case_study("AML.CS0000")
    assert cs["type"] in {"Incident", "Exercise"}
    flow = cs["attack_flow"]
    assert len(flow) > 1
    assert [s["step"] for s in flow] == sorted(s["step"] for s in flow)
    assert flow[0]["technique"]["id"].startswith("AML.T")
    assert flow[0]["what_happened"]


def test_search_case_studies_filters_combine():
    incidents = reference.search_case_studies(case_study_type="Incident", limit=100)
    assert incidents["total_matches"] == 27
    assert all(c["type"] == "Incident" for c in incidents["case_studies"])

    by_technique = reference.search_case_studies(technique_id="AML.T0051", limit=100)
    assert by_technique["total_matches"] > 0

    both = reference.search_case_studies(
        case_study_type="Incident", technique_id="AML.T0051", limit=100
    )
    assert both["total_matches"] <= by_technique["total_matches"]


def test_search_case_studies_no_filters_returns_all():
    assert reference.search_case_studies(limit=200)["total_matches"] == 77


def test_search_case_studies_rejects_bad_type():
    assert "error" in reference.search_case_studies(case_study_type="Rumour")


def test_get_software():
    s = reference.get_software("AML.S0000")
    assert s["name"] == "Proof Pudding"
    assert s["software_type"]


# -- threat-model layer ---------------------------------------------------


def test_list_surfaces():
    out = threatmodel.list_surfaces()
    assert out["count"] == 10
    keys = {s["key"] for s in out["surfaces"]}
    assert {"tool_use", "rag", "untrusted_input", "agent_memory"} <= keys
    assert all(s["question"] for s in out["surfaces"])


def test_map_surface_expands_subtechniques():
    narrow = threatmodel.map_surface_to_techniques("tool_use", include_sub_techniques=False)
    wide = threatmodel.map_surface_to_techniques("tool_use", include_sub_techniques=True)
    assert wide["count"] >= narrow["count"]
    assert wide["mitigations"]


def test_map_surface_orders_by_maturity():
    out = threatmodel.map_surface_to_techniques("untrusted_input")
    maturities = [t["maturity"] for t in out["techniques"]]
    rank = {"Realized": 0, "Demonstrated": 1, "Feasible": 2}
    assert maturities == sorted(maturities, key=lambda m: rank.get(m, 3))


def test_map_surface_normalises_key_spelling():
    for spelling in ("tool_use", "tool-use", "Tool Use", " TOOL_USE "):
        assert threatmodel.map_surface_to_techniques(spelling)["surface"]["key"] == "tool_use"


def test_map_surface_unknown_key_lists_valid_ones():
    out = threatmodel.map_surface_to_techniques("blockchain")
    assert "error" in out and "tool_use" in out["valid"]


def test_profile_ai_system_reports_compound_risk():
    out = threatmodel.profile_ai_system(["untrusted_input", "tool_use"])
    assert out["summary"]["techniques_in_scope"] > 0
    risks = out["compound_risks"]
    assert any(set(r["surfaces"]) == {"untrusted_input", "tool_use"} for r in risks)


def test_profile_orders_by_maturity_and_attributes_surfaces():
    out = threatmodel.profile_ai_system(["untrusted_input", "tool_use", "rag", "agent_memory"])
    rank = {"Realized": 0, "Demonstrated": 1, "Feasible": 2}
    maturities = [t["maturity"] for t in out["techniques"]]
    assert maturities == sorted(maturities, key=lambda m: rank.get(m, 3))
    # Every technique says which surface put it in scope.
    for t in out["techniques"]:
        assert t["exposed_by_surfaces"]
        assert set(t["exposed_by_surfaces"]) <= {
            "untrusted_input",
            "tool_use",
            "rag",
            "agent_memory",
        }


def test_profile_mitigations_ranked_by_coverage():
    out = threatmodel.profile_ai_system(["untrusted_input", "tool_use"])
    covers = [m["covers_count"] for m in out["mitigations"]]
    assert covers == sorted(covers, reverse=True)
    assert all(m["covers_count"] > 0 for m in out["mitigations"])


def test_profile_maturity_cutoff_narrows_scope():
    strict = threatmodel.profile_ai_system(["tool_use"], min_maturity="Realized")
    loose = threatmodel.profile_ai_system(["tool_use"], min_maturity="Feasible")
    assert strict["summary"]["techniques_in_scope"] <= loose["summary"]["techniques_in_scope"]


def test_profile_platform_filter_applies():
    out = threatmodel.profile_ai_system(["tool_use"], platform="Agentic AI")
    assert all("Agentic AI" in t["platforms"] for t in out["techniques"])


def test_profile_rejects_empty_and_unknown_surfaces():
    assert "error" in threatmodel.profile_ai_system([])
    assert "error" in threatmodel.profile_ai_system(["tool_use", "nope"])


def test_find_analogous_incidents_ranks_by_overlap():
    out = threatmodel.find_analogous_incidents(surfaces=["untrusted_input", "tool_use"])
    assert out["total_matches"] > 0
    overlaps = [c["overlap_count"] for c in out["case_studies"]]
    assert overlaps == sorted(overlaps, reverse=True)
    # Relevance is checkable: the overlapping techniques are named.
    assert all(c["overlapping_techniques"] for c in out["case_studies"])


def test_find_analogous_incidents_type_filter():
    out = threatmodel.find_analogous_incidents(surfaces=["rag"], case_study_type="Incident")
    assert all(c["type"] == "Incident" for c in out["case_studies"])


def test_find_analogous_incidents_accepts_explicit_techniques():
    out = threatmodel.find_analogous_incidents(technique_ids=["AML.T0051"])
    assert out["total_matches"] > 0


def test_find_analogous_incidents_requires_input():
    assert "error" in threatmodel.find_analogous_incidents()
    assert "error" in threatmodel.find_analogous_incidents(technique_ids=["AML.T9999"])


# -- cross-mapping --------------------------------------------------------


def test_map_atlas_to_attack():
    out = crossmap.map_atlas_to_attack("AML.T0000")
    assert out["attack_technique"]["id"] == "T1596"
    assert out["coverage"]["techniques_with_attack_mapping"] == 48


def test_map_atlas_to_attack_absent_mapping_is_explicit():
    out = crossmap.map_atlas_to_attack("AML.T0053")  # AI Agent Tool Invocation
    assert out["attack_technique"] is None
    assert "coverage" in out  # so an empty result can't be misread


def test_map_attack_to_atlas_round_trips():
    out = crossmap.map_attack_to_atlas("T1596")
    assert out["count"] > 0
    assert "AML.T0000" in [t["id"] for t in out["atlas_techniques"]]


def test_map_attack_to_atlas_unknown_id_is_empty_not_error():
    out = crossmap.map_attack_to_atlas("T9999")
    assert out["count"] == 0 and "error" not in out
