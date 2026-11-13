"""ATLAS to ATT&CK cross-mapping.

ATLAS techniques carry an ``attack-reference`` field pointing at the ATT&CK
technique they parallel, so this needs no STIX bundle and no network access.

Coverage is partial by design on MITRE's side: 48 of 221 techniques in the
pinned release carry a reference. Every response reports the coverage figure so
a caller never mistakes an empty result for "no ATT&CK equivalent exists".
"""

from __future__ import annotations

from typing import Any

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
