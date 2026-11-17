"""Cross-mapping ATLAS to other security frameworks.

ATT&CK comes from ATLAS itself, via each technique's "attack-reference".
STRIDE, the OWASP Top 10 for LLM Applications and NIST AI RMF come from the
CoSAI Risk Map, which maps its own risks to those frameworks and to ATLAS.

Coverage is partial in both directions and never silently so: ATLAS asserts an
ATT&CK parallel for 48 of 221 techniques, and CoSAI cites ATLAS technique ids
for only a fraction more. Every response carries its coverage figures, so an
empty result is never mistaken for "no equivalent exists".
"""

from __future__ import annotations

from typing import Any

from ..data.cosai_loader import get_cosai, pinned_commit
from ..app import mcp
from ..data.loader import get_atlas
from ..views import technique_view

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


def _coverage(atlas) -> dict[str, Any]:
    mapped = [t for t in atlas.techniques.values() if (t.get("attack-reference") or {}).get("id")]
    return {
        "techniques_with_attack_mapping": len(mapped),
        "techniques_total": len(atlas.techniques),
        "note": (
            "ATLAS maps only some techniques to ATT&CK. An absent mapping means "
            "ATLAS does not assert one, not that no parallel exists."
        ),
    }


@mcp.tool()
def map_atlas_to_attack(technique_id: str) -> dict[str, Any]:
    """The ATT&CK technique an ATLAS technique parallels, if ATLAS asserts one.

    Falls back to the parent technique's mapping for sub-techniques, which is
    where ATLAS usually records it.
    """
    atlas = get_atlas()
    tid = technique_id.strip().upper()
    if tid not in atlas.techniques:
        return {"error": f"Unknown ATLAS technique id: {technique_id}"}

    ref = atlas.techniques[tid].get("attack-reference") or {}
    inherited_from = None
    if not ref.get("id"):
        parent = atlas.parent_of(tid)
        if parent and parent in atlas.techniques:
            parent_ref = atlas.techniques[parent].get("attack-reference") or {}
            if parent_ref.get("id"):
                ref, inherited_from = parent_ref, parent

    return {
        "atlas_technique": technique_view(atlas, tid, brief=True),
        "attack_technique": (
            {
                "id": ref["id"],
                "url": ref.get("url") or ATTACK_URL.format(ref["id"].replace(".", "/")),
            }
            if ref.get("id")
            else None
        ),
        "inherited_from": inherited_from,
        "coverage": _coverage(atlas),
    }


@mcp.tool()
def map_attack_to_atlas(attack_id: str) -> dict[str, Any]:
    """ATLAS techniques that reference a given ATT&CK technique, e.g. ``T1596``.

    Useful coming the other way: you already threat-model against ATT&CK and
    want the AI-specific techniques that attach to a technique you know.
    """
    atlas = get_atlas()
    want = attack_id.strip().upper()
    if not want:
        return {"error": "attack_id must not be empty"}

    matches = [
        tid
        for tid, t in atlas.techniques.items()
        if ((t.get("attack-reference") or {}).get("id") or "").upper() == want
    ]
    return {
        "attack_technique": {"id": want, "url": ATTACK_URL.format(want.replace(".", "/"))},
        "atlas_techniques": [technique_view(atlas, t) for t in sorted(matches)],
        "count": len(matches),
        "coverage": _coverage(atlas),
    }


@mcp.tool()
def map_technique_to_frameworks(technique_id: str) -> dict[str, Any]:
    """Every framework an ATLAS technique maps to: ATT&CK, STRIDE, OWASP, NIST.

    ATT&CK comes from ATLAS directly. The rest are reached through the CoSAI
    Risk Map: an ATLAS technique is cited by one or more CoSAI risks, and those
    risks carry STRIDE categories, OWASP Top 10 for LLM ids and NIST AI RMF
    references. The CoSAI risks themselves are returned too, each with the
    controls that address it and the personas who own them.

    Useful for answering a compliance question in the caller's own vocabulary
    rather than ATLAS's.
    """
    atlas = get_atlas()
    cosai = get_cosai()
    tid = technique_id.strip().upper()
    if tid not in atlas.techniques:
        return {"error": f"Unknown ATLAS technique id: {technique_id}"}

    # ATT&CK, inheriting from the parent as map_atlas_to_attack does.
    ref = atlas.techniques[tid].get("attack-reference") or {}
    inherited = None
    if not ref.get("id"):
        parent = atlas.parent_of(tid)
        if parent and parent in atlas.techniques:
            parent_ref = atlas.techniques[parent].get("attack-reference") or {}
            if parent_ref.get("id"):
                ref, inherited = parent_ref, parent

    # CoSAI risks citing this technique, or its parent when it cites none.
    risk_ids = cosai.risks_by_technique.get(tid, [])
    risks_inherited_from = None
    if not risk_ids:
        parent = atlas.parent_of(tid)
        if parent:
            risk_ids = cosai.risks_by_technique.get(parent, [])
            risks_inherited_from = parent if risk_ids else None

    frameworks = cosai.frameworks_for_technique(tid)
    if not frameworks and risks_inherited_from:
        frameworks = cosai.frameworks_for_technique(risks_inherited_from)

    def framework_block(fw_id: str, ids: list[str]) -> dict[str, Any]:
        meta = cosai.frameworks.get(fw_id) or {}
        return {
            "framework": meta.get("name", fw_id),
            "full_name": meta.get("fullName"),
            "version": meta.get("version"),
            "url": meta.get("baseUri"),
            "ids": ids,
        }

    risks = []
    for rid in sorted(set(risk_ids)):
        r = cosai.risks[rid]
        control_ids = cosai.controls_by_risk.get(rid, [])
        risks.append(
            {
                "id": rid,
                "title": r.get("title"),
                "summary": r.get("shortDescription"),
                "lifecycle_stages": list(r.get("lifecycleStage") or []),
                "impact_types": list(r.get("impactType") or []),
                "actor_access": list(r.get("actorAccess") or []),
                "controls": [
                    {
                        "id": cid,
                        "title": (cosai.controls.get(cid) or {}).get("title"),
                        "owners": [
                            cosai.persona_name(p)
                            for p in ((cosai.controls.get(cid) or {}).get("personas") or [])
                        ],
                    }
                    for cid in sorted(control_ids)
                ],
            }
        )

    return {
        "atlas_technique": technique_view(atlas, tid, brief=True),
        "attack": (
            {
                "id": ref["id"],
                "url": ref.get("url") or ATTACK_URL.format(ref["id"].replace(".", "/")),
                "inherited_from": inherited,
            }
            if ref.get("id")
            else None
        ),
        "other_frameworks": [framework_block(fw, ids) for fw, ids in frameworks.items()],
        "cosai_risks": risks,
        "cosai_risks_inherited_from": risks_inherited_from,
        "coverage": {
            **_coverage(atlas),
            "cosai_commit": pinned_commit()[:12],
            "atlas_techniques_cited_by_cosai": len(cosai.risks_by_technique),
            "note": (
                "An empty other_frameworks list means CoSAI maps nothing to "
                "this technique, not that no parallel exists."
            ),
        },
    }
