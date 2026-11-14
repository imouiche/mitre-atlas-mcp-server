"""Threat-modelling tools: architecture in, ATLAS out.

These are the tools that distinguish this server from a lookup wrapper. The
input is how an engineer describes a system; the output is the ATLAS subset
that applies, with the compounding risks named explicitly.
"""

from __future__ import annotations

from typing import Any

from ..data.loader import MATURITY_ORDER, get_atlas
from ..profile import SURFACES, SURFACES_BY_KEY, compound_risks_for, unknown_surface_keys
from ..views import case_study_view, mitigation_view, technique_view


def _maturity_rank(value: str | None) -> int:
    try:
        return MATURITY_ORDER.index(value or "")
    except ValueError:
        return len(MATURITY_ORDER)


def list_surfaces() -> dict[str, Any]:
    """The architectural surfaces this server can threat-model against.

    Call this first. Each entry has a "key" to pass to the other
    threat-model tools and "question" that decides whether the system
    under review has that surface.
    """
    return {
        "surfaces": [
            {
                "key": s.key,
                "label": s.label,
                "question": s.question,
                "platforms": list(s.platforms),
                "seed_technique_count": len(s.techniques),
                "notes": s.notes or None,
            }
            for s in SURFACES
        ],
        "count": len(SURFACES),
        "usage": (
            "Pass the keys that apply to map_surface_to_techniques (one at a "
            "time) or profile_ai_system (all at once, which also reports "
            "compounding risks between them)."
        ),
    }


def _expand(atlas, seeds: tuple[str, ...]) -> list[str]:
    """Seed techniques plus their sub-techniques, deduped."""
    out: list[str] = []
    for tid in seeds:
        if tid not in atlas.techniques:
            continue
        out.append(tid)
        out.extend(atlas.subtechniques_of(tid))
    seen: set[str] = set()
    return [t for t in out if not (t in seen or seen.add(t))]


def map_surface_to_techniques(
    surface: str,
    include_sub_techniques: bool = True,
    include_mitigations: bool = True,
) -> dict[str, Any]:
    """ATLAS techniques that apply to one architectural surface.

    Use "list_surfaces" for valid keys. Results are ordered by ATLAS
    maturity, so techniques observed in the wild come before theoretical ones.
    """
    atlas = get_atlas()
    key = surface.strip().casefold().replace("-", "_").replace(" ", "_")
    if key not in SURFACES_BY_KEY:
        return {
            "error": f"Unknown surface: {surface}",
            "valid": sorted(SURFACES_BY_KEY),
            "hint": "Call list_surfaces for descriptions of each.",
        }

    s = SURFACES_BY_KEY[key]
    ids = _expand(atlas, s.techniques) if include_sub_techniques else list(s.techniques)
    ids = [t for t in ids if t in atlas.techniques]
    ids.sort(key=lambda t: (_maturity_rank(atlas.techniques[t].get("maturity")), t))

    result: dict[str, Any] = {
        "surface": {"key": s.key, "label": s.label, "question": s.question, "notes": s.notes or None},
        "techniques": [technique_view(atlas, t) for t in ids],
        "count": len(ids),
    }
    if include_mitigations:
        mitigation_ids: set[str] = set()
        for t in ids:
            mitigation_ids.update(atlas.mitigations_for_technique(t))
        result["mitigations"] = [
            mitigation_view(atlas, m) for m in sorted(mitigation_ids) if m in atlas.mitigations
        ]
    return result


def profile_ai_system(
    surfaces: list[str],
    platform: str = "Agentic AI",
    min_maturity: str | None = "Demonstrated",
) -> dict[str, Any]:
    """Threat-model a system from the surfaces it has.

    Pass the surface keys that describe the architecture (see
    "list_surfaces"). Returns the applicable ATLAS techniques ordered by
    maturity — observed in the wild before theoretical — each tagged with the
    surface that put it in scope; the mitigations that cover them, ranked by
    how many in-scope techniques each one covers; and the compounding risks
    that arise from surface *combinations*, which is where most real agentic
    exposure lives.

    "min_maturity" of "Demonstrated" (the default) drops purely theoretical
    techniques; pass "Feasible" to include everything, or None for no filter.
    """
    atlas = get_atlas()
    keys = [s.strip().casefold().replace("-", "_").replace(" ", "_") for s in surfaces]
    if not keys:
        return {
            "error": "surfaces must not be empty",
            "hint": "Call list_surfaces and pass the keys that describe the system.",
        }
    unknown = unknown_surface_keys(keys)
    if unknown:
        return {"error": f"Unknown surface keys: {unknown}", "valid": sorted(SURFACES_BY_KEY)}

    cutoff = _maturity_rank(min_maturity) if min_maturity else len(MATURITY_ORDER)

    # Which surfaces expose each technique. the count is the ranking signal.
    exposure: dict[str, list[str]] = {}
    for key in keys:
        for tid in _expand(atlas, SURFACES_BY_KEY[key].techniques):
            if tid not in atlas.techniques:
                continue
            if _maturity_rank(atlas.techniques[tid].get("maturity")) > cutoff:
                continue
            if platform and not any(
                p.casefold() == platform.strip().casefold()
                for p in (atlas.techniques[tid].get("platforms") or ())
            ):
                continue
            exposure.setdefault(tid, []).append(key)

    # Maturity first. The exposure count leads only when a technique is seeded
    # by more than one surface; the shipped taxonomy has disjoint seed sets
    # (asserted by test_surface_seeds_are_disjoint), so in practice this
    # orders by maturity today and stays correct if that ever changes.
    ranked = sorted(
        exposure,
        key=lambda t: (
            -len(exposure[t]),
            _maturity_rank(atlas.techniques[t].get("maturity")),
            t,
        ),
    )

    # Mitigations, ordered by how many of the in-scope techniques they cover.
    coverage: dict[str, list[str]] = {}
    for tid in ranked:
        for mid in atlas.mitigations_for_technique(tid):
            if mid in atlas.mitigations:
                coverage.setdefault(mid, []).append(tid)
    mitigations = sorted(coverage, key=lambda m: (-len(coverage[m]), m))

    uncovered = [t for t in ranked if not atlas.mitigations_for_technique(t)]
    tactics_hit = sorted({
        tid for t in ranked for tid in atlas.tactics_for_technique(t) if tid in atlas.tactics
    })

    return {
        "profile": {
            "surfaces": keys,
            "platform": platform,
            "min_maturity": min_maturity,
        },
        "summary": {
            "techniques_in_scope": len(ranked),
            "tactics_reachable": len(tactics_hit),
            "mitigations_available": len(mitigations),
            "techniques_without_mitigations": len(uncovered),
        },
        "compound_risks": compound_risks_for(keys),
        "techniques": [
            technique_view(atlas, t) | {"exposed_by_surfaces": exposure[t]} for t in ranked
        ],
        "mitigations": [
            mitigation_view(atlas, m, brief=True)
            | {"covers_technique_ids": sorted(coverage[m]), "covers_count": len(coverage[m])}
            for m in mitigations
        ],
        "techniques_without_mitigations": [
            technique_view(atlas, t, brief=True) for t in uncovered
        ],
        "tactics_reachable": [
            {"id": tid, "name": atlas.tactics[tid]["name"]} for tid in tactics_hit
        ],
    }


def find_analogous_incidents(
    surfaces: list[str] | None = None,
    technique_ids: list[str] | None = None,
    case_study_type: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Real ATLAS case studies that overlap a system's exposure.

    Give surfaces, explicit technique ids, or both. Case studies are ranked by
    how many of the in-scope techniques they actually employed, and each result
    names the overlapping techniques so the relevance is checkable rather than
    asserted. ``case_study_type="Incident"`` restricts to real-world events
    rather than red-team exercises.
    """
    atlas = get_atlas()
    if case_study_type and case_study_type.strip().casefold() not in {"incident", "exercise"}:
        return {"error": f"Unknown type: {case_study_type}", "valid": ["Incident", "Exercise"]}

    in_scope: set[str] = set()
    keys = [s.strip().casefold().replace("-", "_").replace(" ", "_") for s in (surfaces or [])]
    unknown = unknown_surface_keys(keys)
    if unknown:
        return {"error": f"Unknown surface keys: {unknown}", "valid": sorted(SURFACES_BY_KEY)}
    for key in keys:
        in_scope.update(_expand(atlas, SURFACES_BY_KEY[key].techniques))
    for tid in technique_ids or []:
        t = tid.strip().upper()
        if t not in atlas.techniques:
            return {"error": f"Unknown technique id: {tid}"}
        in_scope.add(t)
        in_scope.update(atlas.subtechniques_of(t))

    if not in_scope:
        return {
            "error": "Provide at least one surface or technique id",
            "hint": "Call list_surfaces for valid surface keys.",
        }

    overlap: dict[str, list[str]] = {}
    for tid in in_scope:
        for cid in atlas.case_studies_for_technique(tid):
            overlap.setdefault(cid, []).append(tid)

    if case_study_type:
        want = case_study_type.strip().casefold()
        overlap = {
            cid: v
            for cid, v in overlap.items()
            if (atlas.case_studies[cid].get("type") or "").casefold() == want
        }

    ranked = sorted(overlap, key=lambda c: (-len(overlap[c]), c))
    return {
        "query": {
            "surfaces": keys,
            "technique_ids": sorted(technique_ids or []),
            "type": case_study_type,
            "techniques_in_scope": len(in_scope),
        },
        "total_matches": len(ranked),
        "case_studies": [
            case_study_view(atlas, cid, include_steps=False)
            | {
                "overlap_count": len(overlap[cid]),
                "overlapping_techniques": [
                    technique_view(atlas, t, brief=True) for t in sorted(overlap[cid])
                ],
            }
            for cid in ranked[: max(limit, 0)]
        ],
    }
