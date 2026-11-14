"""Shaping ATLAS objects into tool responses.

ATLAS prose carries two markup conventions that are noise to a model reading a
tool result: relative cross-reference links ("[Name](/techniques/AML.T0005)")
and citation markers ("[[ref-id]]"). Links are flattened to their text with
the id appended so the reference survives in a form a model can act on;
citation markers are dropped, since the full reference list is returned
separately as structured data.
"""

from __future__ import annotations

import re
from typing import Any

from .data.cosai_loader import get_cosai
from .data.loader import AtlasData

_CITATION = re.compile(r"\[\[[^\]]+\]\]")
_REL_LINK = re.compile(r"\[([^\]]+)\]\(/(?:techniques|tactics|mitigations|case-studies|entities|software)/([A-Za-z0-9.]+)\)")


def clean_text(text: str | None) -> str:
    """Normalise ATLAS prose for model consumption."""
    if not text:
        return ""
    out = _REL_LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})", text)
    out = _CITATION.sub("", out)
    # ATLAS wraps prose with hard newlines; collapse to paragraphs.
    paragraphs = [" ".join(p.split()) for p in out.split("\n\n")]
    return "\n\n".join(p for p in paragraphs if p)


def references(obj: dict) -> list[dict[str, str]]:
    return [
        {"title": r.get("title", ""), "url": r.get("url", "")}
        for r in (obj.get("references") or [])
        if r.get("url") or r.get("title")
    ]


def tactic_view(atlas: AtlasData, tactic_id: str, *, brief: bool = False) -> dict[str, Any]:
    t = atlas.tactics[tactic_id]
    view: dict[str, Any] = {"id": tactic_id, "name": t["name"]}
    if brief:
        return view
    view |= {
        "description": clean_text(t.get("description")),
        "technique_count": len(atlas.techniques_for_tactic(tactic_id)),
        "references": references(t),
    }
    return view


def technique_view(
    atlas: AtlasData,
    technique_id: str,
    *,
    brief: bool = False,
) -> dict[str, Any]:
    t = atlas.techniques[technique_id]
    parent = atlas.parent_of(technique_id)
    view: dict[str, Any] = {
        "id": technique_id,
        "name": t["name"],
        "platforms": list(t.get("platforms") or []),
        "maturity": t.get("maturity"),
    }
    if parent:
        view["sub_technique_of"] = parent
    if brief:
        return view

    attack_ref = t.get("attack-reference") or {}
    view |= {
        "description": clean_text(t.get("description")),
        "tactics": [tactic_view(atlas, tid, brief=True) for tid in atlas.tactics_for_technique(technique_id)],
        "sub_techniques": [
            technique_view(atlas, sid, brief=True) for sid in atlas.subtechniques_of(technique_id)
        ],
        "mitigations": [
            mitigation_view(atlas, mid, brief=True)
            for mid in sorted(atlas.mitigations_for_technique(technique_id))
        ],
        "case_study_ids": atlas.case_studies_for_technique(technique_id),
        "attack_technique": {"id": attack_ref["id"], "url": attack_ref.get("url", "")}
        if attack_ref.get("id")
        else None,
        "references": references(t),
    }
    return view


def cosai_controls_view(mitigation_id: str) -> list[dict[str, Any]]:
    """CoSAI controls that implement an ATLAS mitigation.

    ATLAS says what to do; a CoSAI control also says who owns it and which
    components it applies to, which is what turns a threat model into
    assignable work. Returns an empty list when CoSAI maps nothing to this
    mitigation, which is the case for 31 of the 44 ATLAS mitigations.
    """
    cosai = get_cosai()
    out = []
    for cid in cosai.controls_for_mitigation(mitigation_id):
        c = cosai.controls[cid]
        out.append(
            {
                "id": cid,
                "title": c.get("title"),
                "category": c.get("category"),
                "owners": [
                    {"id": p, "name": cosai.persona_name(p)} for p in (c.get("personas") or [])
                ],
                "components": [
                    {"id": k, "name": cosai.component_name(k)}
                    for k in cosai.components_for_control(cid)
                    if k in cosai.components
                ],
                # A cross-cutting control declares `risks: all`. Listing all 28
                # risks would bury the signal, so say so instead.
                "applies_to_all_risks": cosai.applies_to_all_risks(cid),
                "addresses_risks": (
                    []
                    if cosai.applies_to_all_risks(cid)
                    else [
                        {"id": r, "title": (cosai.risks.get(r) or {}).get("title", r)}
                        for r in cosai.risks_for_control(cid)
                    ]
                ),
            }
        )
    return out


def mitigation_view(
    atlas: AtlasData,
    mitigation_id: str,
    *,
    brief: bool = False,
    include_controls: bool = True,
) -> dict[str, Any]:
    m = atlas.mitigations[mitigation_id]
    view: dict[str, Any] = {"id": mitigation_id, "name": m["name"]}
    if brief:
        if include_controls:
            # Even in brief form, carry the owners: a ranked mitigation list is
            # far more actionable when each line names who implements it.
            owners = sorted(
                {o["name"] for c in cosai_controls_view(mitigation_id) for o in c["owners"]}
            )
            if owners:
                view["owners"] = owners
        return view
    view |= {
        "description": clean_text(m.get("description")),
        "categories": list(m.get("categories") or []),
        "lifecycle_phases": list(m.get("lifecycle-phases") or []),
        "mitigates": [
            technique_view(atlas, tid, brief=True)
            for tid in sorted(atlas.techniques_for_mitigation(mitigation_id))
            if tid in atlas.techniques
        ],
        "references": references(m),
    }
    if include_controls:
        view["cosai_controls"] = cosai_controls_view(mitigation_id)
    return view


def case_study_view(
    atlas: AtlasData,
    case_study_id: str,
    *,
    brief: bool = False,
    include_steps: bool = True,
) -> dict[str, Any]:
    c = atlas.case_studies[case_study_id]
    view: dict[str, Any] = {
        "id": case_study_id,
        "name": c["name"],
        "type": c.get("type"),
        "actor": c.get("actor"),
        "target": c.get("target"),
    }
    if brief:
        return view

    view |= {
        "description": clean_text(c.get("description")),
        "start_date": c.get("start-date"),
        "end_date": c.get("end-date"),
        "attributed_to": [
            {"id": eid, "name": atlas.entities[eid]["name"]}
            for eid in atlas.entities_for_case_study(case_study_id)
            if eid in atlas.entities
        ],
        "references": references(c),
    }
    if include_steps:
        view["attack_flow"] = [
            {
                "step": e.get("step-id"),
                "leads_to": list(e.get("leads-to") or []),
                "tactic": tactic_view(atlas, e["tactic"], brief=True)
                if e.get("tactic") in atlas.tactics
                else None,
                "technique": technique_view(atlas, e["target"], brief=True)
                if e.get("target") in atlas.techniques
                else {"id": e.get("target")},
                "what_happened": clean_text(e.get("description")),
            }
            for e in atlas.steps_for_case_study(case_study_id)
        ]
    return view
