"""Loader and index over the vendored CoSAI Risk Map.

The CoSAI Risk Map (Coalition for Secure AI, an OASIS open project) describes
AI security risks and the engineering controls that address them. It is useful
here because of what ATLAS does not carry: an ATLAS mitigation says what to do,
while a CoSAI control also says **who owns it** and **which components it
touches**.

Two bridges exist between the datasets, and they are not equally reliable:

* ``controls[].mappings['mitre-atlas']`` cites ATLAS **mitigation** ids
  (``AML.M####``). Mitigation ids are stable, and every cited id resolves
  against the pinned ATLAS release. This is the bridge used to enrich
  mitigation output.
* ``risks[].mappings['mitre-atlas']`` cites ATLAS **technique** ids
  (``AML.T####``). CoSAI pins ATLAS 5.0.1, which predates the 2026.10 agentic
  expansion, so a few cited ids no longer exist and whole agentic surfaces have
  no technique-level coverage. Used only for the framework cross-mapping, which
  reports its own coverage.

Risks additionally map to STRIDE, the OWASP Top 10 for LLM Applications and
NIST AI RMF, which is what makes the cross-framework tool possible.
"""

from __future__ import annotations

import functools
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

DATA_DIR = Path(__file__).parent / "cosai"
COMMIT_FILE = DATA_DIR / "COMMIT"

#: Frameworks CoSAI maps to, besides ATLAS. Keys are CoSAI's framework ids.
OTHER_FRAMEWORKS = ("stride", "owasp-top10-llm", "nist-ai-rmf")


class CosaiData:
    """Parsed CoSAI Risk Map with indexes keyed for ATLAS lookups."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.risks: dict[str, dict] = {r["id"]: r for r in raw["risks"]["risks"]}
        self.controls: dict[str, dict] = {c["id"]: c for c in raw["controls"]["controls"]}
        self.personas: dict[str, dict] = {p["id"]: p for p in raw["personas"]["personas"]}
        self.components: dict[str, dict] = {c["id"]: c for c in raw["components"]["components"]}
        self.frameworks: dict[str, dict] = {
            f["id"]: f for f in raw["frameworks"]["frameworks"]
        }
        self.lifecycle_stages: dict[str, dict] = {
            s["id"]: s for s in raw["lifecycle-stage"]["lifecycleStages"]
        }

        # ATLAS mitigation id -> controls that implement it.
        self.controls_by_mitigation: dict[str, list[str]] = defaultdict(list)
        for cid, c in self.controls.items():
            for ref in self._atlas_refs(c):
                if ref.startswith("AML.M"):
                    self.controls_by_mitigation[ref].append(cid)

        # ATLAS technique id -> risks that cite it.
        self.risks_by_technique: dict[str, list[str]] = defaultdict(list)
        for rid, r in self.risks.items():
            for ref in self._atlas_refs(r):
                if ref.startswith("AML.T"):
                    self.risks_by_technique[ref].append(rid)

        # risk id -> controls addressing it. Cross-cutting controls declare
        # `risks: all` and apply to every risk.
        self.controls_by_risk: dict[str, list[str]] = defaultdict(list)
        for cid in self.controls:
            for rid in self.risks_for_control(cid):
                self.controls_by_risk[rid].append(cid)

    @staticmethod
    def _split_ref(ref: str) -> tuple[str, str | None]:
        """Split a mapping reference into its id and the ATLAS version it was authored against.

        Upstream writes references as ``AML.M0007@5.0.1``. The suffix records
        which ATLAS release the mapping was validated against, which is worth
        keeping rather than discarding: it is how a caller can tell a mapping
        checked against the release we serve from one carried over from an
        older one.
        """
        head, _, version = ref.partition("@")
        return head.strip(), (version.strip() or None)

    @classmethod
    def _atlas_refs(cls, obj: dict) -> list[str]:
        """ATLAS ids a CoSAI object maps to, with any version suffix removed."""
        raw = (obj.get("mappings") or {}).get("mitre-atlas") or ()
        return [cls._split_ref(r)[0] for r in raw]

    @classmethod
    def _atlas_refs_versioned(cls, obj: dict) -> list[tuple[str, str | None]]:
        raw = (obj.get("mappings") or {}).get("mitre-atlas") or ()
        return [cls._split_ref(r) for r in raw]

    def mapping_versions(self) -> dict[str, int]:
        """How many mappings were authored against each ATLAS version.

        A maintenance diagnostic, deliberately not returned by any tool: it
        describes upstream's labelling rather than anything a caller asked
        about. Used by the tests to detect a refresh that changes the mapping
        reference format.
        """
        counts: dict[str, int] = {}
        for obj in (*self.controls.values(), *self.risks.values()):
            for _, version in self._atlas_refs_versioned(obj):
                key = version or "unversioned"
                counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    @staticmethod
    def _expand_sentinel(value: Any, universe: list[str]) -> list[str]:
        """Resolve CoSAI's list-or-sentinel fields.

        `risks` and `components` on a control are usually a list of ids, but
        governance and testing controls use the bare strings ``all`` or
        ``none`` instead. Iterating those as sequences yields one entry per
        character, so they must be handled explicitly.
        """
        if value is None:
            return []
        if isinstance(value, str):
            lowered = value.strip().casefold()
            if lowered == "all":
                return list(universe)
            if lowered in {"none", ""}:
                return []
            return [value]
        return list(value)

    def risks_for_control(self, control_id: str) -> list[str]:
        """Risk ids a control addresses, expanding the ``all`` sentinel."""
        c = self.controls.get(control_id) or {}
        return self._expand_sentinel(c.get("risks"), list(self.risks))

    def components_for_control(self, control_id: str) -> list[str]:
        """Component ids a control applies to, expanding ``all`` and ``none``."""
        c = self.controls.get(control_id) or {}
        return self._expand_sentinel(c.get("components"), list(self.components))

    def applies_to_all_risks(self, control_id: str) -> bool:
        """Whether the control is cross-cutting rather than risk-specific."""
        value = (self.controls.get(control_id) or {}).get("risks")
        return isinstance(value, str) and value.strip().casefold() == "all"

    def dangling_component_refs(self) -> dict[str, list[str]]:
        """Component ids referenced by controls but absent from components.yaml.

        Upstream currently leaves a few of these behind after splitting generic
        handling components into per-layer ones. Reported rather than hidden so
        the tests can pin the count.
        """
        out: dict[str, list[str]] = {}
        for cid in self.controls:
            missing = [
                k for k in self.components_for_control(cid) if k not in self.components
            ]
            if missing:
                out[cid] = missing
        return out

    # -- lookups ----------------------------------------------------------

    def persona_name(self, persona_id: str) -> str:
        return (self.personas.get(persona_id) or {}).get("title", persona_id)

    def component_name(self, component_id: str) -> str:
        return (self.components.get(component_id) or {}).get("title", component_id)

    def controls_for_mitigation(self, mitigation_id: str) -> list[str]:
        return list(self.controls_by_mitigation.get(mitigation_id, ()))

    def frameworks_for_technique(self, technique_id: str) -> dict[str, list[str]]:
        """Non-ATLAS framework ids reachable from a technique, via its risks."""
        out: dict[str, set[str]] = defaultdict(set)
        for rid in self.risks_by_technique.get(technique_id, ()):
            for fw, ids in (self.risks[rid].get("mappings") or {}).items():
                if fw in OTHER_FRAMEWORKS:
                    out[fw].update(ids)
        return {fw: sorted(v) for fw, v in sorted(out.items())}

    def all_cited_atlas_ids(self) -> dict[str, list[str]]:
        """Every ATLAS id the dataset references, split by kind.

        Used by the tests to assert the vendored CoSAI release still lines up
        with the vendored ATLAS release.
        """
        mitigations: set[str] = set()
        techniques: set[str] = set()
        for obj in (*self.controls.values(), *self.risks.values()):
            for ref in self._atlas_refs(obj):
                (mitigations if ref.startswith("AML.M") else techniques).add(ref)
        return {"mitigations": sorted(mitigations), "techniques": sorted(techniques)}

    def stats(self) -> dict[str, Any]:
        """What is loaded, not how well it joins to ATLAS.

        Join coverage is reported by the tools that depend on it, where an
        empty result actually needs explaining. Returning it here made a
        question about which datasets are loaded come back with a paragraph
        about mapping staleness, which is not what was asked.
        """
        return {
            "cosai_commit": pinned_commit()[:12],
            "risks": len(self.risks),
            "controls": len(self.controls),
            "personas": len(self.personas),
            "components": len(self.components),
        }


@functools.lru_cache(maxsize=1)
def get_cosai() -> CosaiData:
    """Load and index the vendored CoSAI Risk Map. Cached for the process."""
    raw = {}
    for name in ("risks", "controls", "personas", "components", "frameworks", "lifecycle-stage"):
        path = DATA_DIR / f"{name}.yaml"
        if not path.exists():
            raise FileNotFoundError(
                f"CoSAI dataset missing at {path}. "
                "Run scripts/refresh_cosai.py to re-vendor it."
            )
        with path.open("r", encoding="utf-8") as fh:
            raw[name] = yaml.safe_load(fh)
    return CosaiData(raw)


def pinned_commit() -> str:
    """Upstream commit the vendored CoSAI data was taken from."""
    if COMMIT_FILE.exists():
        return COMMIT_FILE.read_text(encoding="utf-8").strip()
    return "unknown"
