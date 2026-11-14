"""Reference-layer tools: direct lookup and search over ATLAS objects."""

from __future__ import annotations

from typing import Any

from ..data.cosai_loader import get_cosai
from ..data.loader import MATURITY_ORDER, PLATFORMS, get_atlas, pinned_release
from ..views import (
    case_study_view,
    clean_text,
    mitigation_view,
    tactic_view,
    technique_view,
)


def _maturity_rank(value: str | None) -> int:
    try:
        return MATURITY_ORDER.index(value or "")
    except ValueError:
        return len(MATURITY_ORDER)


def get_atlas_info() -> dict[str, Any]:
    """Which datasets this server serves, and how much of each there is.

    Covers the vendored ATLAS release and the vendored CoSAI Risk Map, which
    supplies the control owners attached to mitigations and the STRIDE, OWASP
    and NIST cross-mappings.
    """
    atlas = get_atlas()
    return {
        "pinned_release": pinned_release(),
        **atlas.stats(),
        "cosai_risk_map": get_cosai().stats(),
    }


def list_tactics() -> dict[str, Any]:
    """All 16 ATLAS tactics, in matrix order, with technique counts."""
    atlas = get_atlas()
    return {
        "tactics": [tactic_view(atlas, tid) for tid in atlas.tactics],
        "count": len(atlas.tactics),
    }


def get_technique(technique_id: str) -> dict[str, Any]:
    """Full detail for one technique or sub-technique, e.g. ``AML.T0051``."""
    atlas = get_atlas()
    tid = technique_id.strip().upper()
    if tid not in atlas.techniques:
        return {
            "error": f"Unknown technique id: {technique_id}",
            "hint": "Ids look like AML.T0051 or AML.T0051.000. Use search_techniques to find one.",
        }
    return technique_view(atlas, tid)


def search_techniques(
    keyword: str,
    platform: str | None = None,
    maturity: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Search technique names and descriptions.

    ``platform`` filters to one of Agentic AI, Generative AI, Predictive AI,
    Enterprise. ``maturity`` filters to Realized, Demonstrated or Feasible.
    Name matches rank above description matches, then by maturity.
    """
    atlas = get_atlas()
    needle = keyword.strip().casefold()
    if not needle:
        return {"error": "keyword must not be empty"}

    if platform and not any(p.casefold() == platform.strip().casefold() for p in PLATFORMS):
        return {"error": f"Unknown platform: {platform}", "valid": list(PLATFORMS)}
    if maturity and not any(m.casefold() == maturity.strip().casefold() for m in MATURITY_ORDER):
        return {"error": f"Unknown maturity: {maturity}", "valid": list(MATURITY_ORDER)}

    hits: list[tuple[int, int, str]] = []
    for tid, t in atlas.techniques.items():
        if platform and not any(
            p.casefold() == platform.strip().casefold() for p in (t.get("platforms") or ())
        ):
            continue
        if maturity and (t.get("maturity") or "").casefold() != maturity.strip().casefold():
            continue
        in_name = needle in t["name"].casefold()
        in_desc = needle in (t.get("description") or "").casefold()
        if in_name or in_desc:
            hits.append((0 if in_name else 1, _maturity_rank(t.get("maturity")), tid))

    hits.sort()
    return {
        "query": {"keyword": keyword, "platform": platform, "maturity": maturity},
        "total_matches": len(hits),
        "returned": min(len(hits), max(limit, 0)),
        "techniques": [technique_view(atlas, tid) for _, _, tid in hits[: max(limit, 0)]],
    }


def get_techniques_by_tactic(tactic: str, platform: str | None = None) -> dict[str, Any]:
    """Techniques that achieve a tactic, by id (``AML.TA0005``) or name ("Execution")."""
    atlas = get_atlas()
    needle = tactic.strip()
    tid = needle.upper() if needle.upper() in atlas.tactics else None
    if tid is None:
        for candidate, t in atlas.tactics.items():
            if t["name"].casefold() == needle.casefold():
                tid = candidate
                break
    if tid is None:
        return {
            "error": f"Unknown tactic: {tactic}",
            "valid": [{"id": k, "name": v["name"]} for k, v in atlas.tactics.items()],
        }

    ids = sorted(atlas.techniques_for_tactic(tid))
    if platform:
        want = platform.strip().casefold()
        ids = [
            i
            for i in ids
            if any(p.casefold() == want for p in (atlas.techniques[i].get("platforms") or ()))
        ]
    return {
        "tactic": tactic_view(atlas, tid),
        "techniques": [technique_view(atlas, i, brief=True) for i in ids],
        "count": len(ids),
    }


def get_mitigation(mitigation_id: str) -> dict[str, Any]:
    """Full detail for one mitigation, e.g. ``AML.M0000``."""
    atlas = get_atlas()
    mid = mitigation_id.strip().upper()
    if mid not in atlas.mitigations:
        return {"error": f"Unknown mitigation id: {mitigation_id}", "hint": "Ids look like AML.M0000."}
    return mitigation_view(atlas, mid)


def get_mitigations_for_technique(technique_id: str) -> dict[str, Any]:
    """Mitigations ATLAS maps to a technique.

    Sub-techniques often carry no mitigations of their own; when that happens
    the parent's mitigations are returned and ``inherited_from`` says so.
    """
    atlas = get_atlas()
    tid = technique_id.strip().upper()
    if tid not in atlas.techniques:
        return {"error": f"Unknown technique id: {technique_id}"}

    ids = sorted(atlas.mitigations_for_technique(tid))
    inherited_from = None
    if not ids:
        parent = atlas.parent_of(tid)
        if parent:
            ids = sorted(atlas.mitigations_for_technique(parent))
            inherited_from = parent if ids else None

    return {
        "technique": technique_view(atlas, tid, brief=True),
        "inherited_from": inherited_from,
        "mitigations": [mitigation_view(atlas, m) for m in ids],
        "count": len(ids),
    }


def get_case_study(case_study_id: str) -> dict[str, Any]:
    """One case study with its ordered attack flow, e.g. ``AML.CS0000``.

    The flow comes from ATLAS ``employs`` edges, each carrying a step id, the
    tactic it served, what the operator actually did, and which steps it led
    to, so the result is a sequence, not an unordered technique list.
    """
    atlas = get_atlas()
    cid = case_study_id.strip().upper()
    if cid not in atlas.case_studies:
        return {"error": f"Unknown case study id: {case_study_id}", "hint": "Ids look like AML.CS0000."}
    return case_study_view(atlas, cid)


def search_case_studies(
    keyword: str | None = None,
    case_study_type: str | None = None,
    technique_id: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Search case studies by text, type, or a technique they employed.

    ``case_study_type`` is "Incident" (27 real-world events) or "Exercise"
    (50 red-team exercises). Filters combine with AND; all three are optional,
    so passing none returns the full catalogue.
    """
    atlas = get_atlas()

    if case_study_type and case_study_type.strip().casefold() not in {"incident", "exercise"}:
        return {"error": f"Unknown type: {case_study_type}", "valid": ["Incident", "Exercise"]}

    candidates = set(atlas.case_studies)
    if technique_id:
        tid = technique_id.strip().upper()
        if tid not in atlas.techniques:
            return {"error": f"Unknown technique id: {technique_id}"}
        candidates &= set(atlas.case_studies_for_technique(tid))

    results = []
    for cid in sorted(candidates):
        c = atlas.case_studies[cid]
        if case_study_type and (c.get("type") or "").casefold() != case_study_type.strip().casefold():
            continue
        if keyword:
            needle = keyword.strip().casefold()
            haystack = f"{c['name']} {c.get('description') or ''} {c.get('actor') or ''} {c.get('target') or ''}"
            if needle not in haystack.casefold():
                continue
        results.append(cid)

    return {
        "query": {
            "keyword": keyword,
            "type": case_study_type,
            "technique_id": technique_id,
        },
        "total_matches": len(results),
        "returned": min(len(results), max(limit, 0)),
        "case_studies": [
            case_study_view(atlas, cid, include_steps=False) for cid in results[: max(limit, 0)]
        ],
    }


def get_software(software_id: str) -> dict[str, Any]:
    """An attacker tool catalogued by ATLAS, e.g. ``AML.S0000``."""
    atlas = get_atlas()
    sid = software_id.strip().upper()
    if sid not in atlas.software:
        return {"error": f"Unknown software id: {software_id}", "hint": "Ids look like AML.S0000."}
    s = atlas.software[sid]
    used_for = sorted({t for rel in ("uses", "implements") for t in atlas.targets(sid, rel)})
    return {
        "id": sid,
        "name": s["name"],
        "description": clean_text(s.get("description")),
        "software_type": s.get("software-type"),
        "categories": list(s.get("software-categories") or []),
        "aliases": list(s.get("aliases") or []),
        "techniques": [
            technique_view(atlas, t, brief=True) for t in used_for if t in atlas.techniques
        ],
        "references": [
            {"title": r.get("title", ""), "url": r.get("url", "")} for r in (s.get("references") or [])
        ],
    }
