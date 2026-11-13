"""Loader and index over the vendored MITRE ATLAS dataset.

ATLAS ships one authoritative YAML per release (format-version 6.1.0 here).
Its objects are dicts keyed by ATLAS id, and every link between objects lives
in a single top-level ``relationships`` block keyed by *source* id:

    relationships:
      AML.CS0000:
        employs:
          - source: AML.CS0000
            target: AML.T0000.001
            relationship-type: employs
            description: ...
            tactic: AML.TA0002
            step-id: S00
            leads-to: [S01]

Nothing is indexed by target, so this module builds the reverse index once and
exposes every traversal the tools need on top of it. Loading is lazy and
cached: the YAML is ~1.1MB and parses in well under a second, so there is no
download step and no network dependency at runtime.
"""

from __future__ import annotations

import functools
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

DATA_DIR = Path(__file__).parent / "atlas"
ATLAS_YAML = DATA_DIR / "ATLAS.yaml"
RELEASE_FILE = DATA_DIR / "RELEASE"

#: Object collections in the ATLAS YAML, mapped to the id prefix they use.
COLLECTIONS: dict[str, str] = {
    "tactics": "AML.TA",
    "techniques": "AML.T",
    "mitigations": "AML.M",
    "case-studies": "AML.CS",
    "entities": "AML.E",
    "software": "AML.S",
}

#: Values seen in ``technique.platforms``. "Agentic AI" is the one this server
#: is built around; ATLAS tags 148 of 221 techniques with it.
PLATFORMS = ("Agentic AI", "Generative AI", "Predictive AI", "Enterprise")

#: Values seen in ``technique.maturity``, ordered most to least substantiated.
MATURITY_ORDER = ("Realized", "Demonstrated", "Feasible")

_SUBTECHNIQUE_ID = re.compile(r"^(AML\.T\d{4})\.\d{3}$")


class AtlasData:
    """Parsed ATLAS release with forward and reverse relationship indexes."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw
        self.format_version: str = raw["format-version"]
        self.release_version: str = raw["collection"]["version"]

        self.tactics: dict[str, dict] = raw.get("tactics") or {}
        self.techniques: dict[str, dict] = raw.get("techniques") or {}
        self.mitigations: dict[str, dict] = raw.get("mitigations") or {}
        self.case_studies: dict[str, dict] = raw.get("case-studies") or {}
        self.entities: dict[str, dict] = raw.get("entities") or {}
        self.software: dict[str, dict] = raw.get("software") or {}

        # Unified id lookup across every collection.
        self.by_id: dict[str, dict] = {}
        for coll in (
            self.tactics,
            self.techniques,
            self.mitigations,
            self.case_studies,
            self.entities,
            self.software,
        ):
            self.by_id.update(coll)

        # edges_out[source][rel_type] -> [edge]; edges_in[target][rel_type] -> [edge]
        self.edges_out: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
        self.edges_in: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
        for source, by_type in (raw.get("relationships") or {}).items():
            for rel_type, edges in by_type.items():
                for edge in edges:
                    self.edges_out[source][rel_type].append(edge)
                    target = edge.get("target")
                    if target:
                        self.edges_in[target][rel_type].append(edge)

    # -- generic traversal ------------------------------------------------

    def out(self, source: str, rel_type: str) -> list[dict]:
        """Edges leaving ``source`` of type ``rel_type``."""
        return list(self.edges_out.get(source, {}).get(rel_type, ()))

    def inn(self, target: str, rel_type: str) -> list[dict]:
        """Edges arriving at ``target`` of type ``rel_type``."""
        return list(self.edges_in.get(target, {}).get(rel_type, ()))

    def targets(self, source: str, rel_type: str) -> list[str]:
        return [e["target"] for e in self.out(source, rel_type) if e.get("target")]

    def sources(self, target: str, rel_type: str) -> list[str]:
        return [e["source"] for e in self.inn(target, rel_type) if e.get("source")]

    # -- named traversals the tools use ----------------------------------

    def tactics_for_technique(self, technique_id: str) -> list[str]:
        """Tactic ids a technique achieves.

        Techniques carry no ``tactics`` field in 6.1.0; the linkage exists only
        as ``achieves`` edges. Sub-techniques inherit from their parent when
        they declare none of their own.
        """
        direct = self.targets(technique_id, "achieves")
        if direct:
            return direct
        parent = self.parent_of(technique_id)
        return self.targets(parent, "achieves") if parent else []

    def techniques_for_tactic(self, tactic_id: str) -> list[str]:
        return self.sources(tactic_id, "achieves")

    def mitigations_for_technique(self, technique_id: str) -> list[str]:
        return self.sources(technique_id, "mitigates")

    def techniques_for_mitigation(self, mitigation_id: str) -> list[str]:
        return self.targets(mitigation_id, "mitigates")

    def parent_of(self, technique_id: str) -> str | None:
        """Parent technique id, or None if this is not a sub-technique."""
        for parent in self.targets(technique_id, "specializes"):
            return parent
        # Fall back to the id form, which encodes the hierarchy.
        m = _SUBTECHNIQUE_ID.match(technique_id)
        return m.group(1) if m else None

    def subtechniques_of(self, technique_id: str) -> list[str]:
        return sorted(self.sources(technique_id, "specializes"))

    def case_studies_for_technique(self, technique_id: str) -> list[str]:
        return sorted({e["source"] for e in self.inn(technique_id, "employs")})

    def steps_for_case_study(self, case_study_id: str) -> list[dict]:
        """``employs`` edges for a case study, ordered into its attack flow.

        Each edge carries ``step-id`` and ``leads-to``, so the narrative order
        is recoverable without the separate attack-flow release assets.
        """
        steps = self.out(case_study_id, "employs")
        return sorted(steps, key=lambda e: str(e.get("step-id") or ""))

    def entities_for_case_study(self, case_study_id: str) -> list[str]:
        return self.targets(case_study_id, "attributed-to")

    # -- filtering --------------------------------------------------------

    def techniques_for_platform(self, platform: str) -> list[str]:
        """Technique ids tagged with ``platform``, case-insensitively."""
        want = platform.strip().casefold()
        return [
            tid
            for tid, t in self.techniques.items()
            if any(p.casefold() == want for p in (t.get("platforms") or ()))
        ]

    # -- metadata ---------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "atlas_release": self.release_version,
            "format_version": self.format_version,
            "tactics": len(self.tactics),
            "techniques": len(self.techniques),
            "sub_techniques": sum(1 for t in self.techniques if _SUBTECHNIQUE_ID.match(t)),
            "mitigations": len(self.mitigations),
            "case_studies": len(self.case_studies),
            "entities": len(self.entities),
            "software": len(self.software),
            "relationships": sum(
                len(edges)
                for by_type in self.edges_out.values()
                for edges in by_type.values()
            ),
            "techniques_by_platform": {
                p: len(self.techniques_for_platform(p)) for p in PLATFORMS
            },
        }


@functools.lru_cache(maxsize=1)
def get_atlas() -> AtlasData:
    """Load and index the vendored ATLAS release. Cached for the process."""
    if not ATLAS_YAML.exists():
        raise FileNotFoundError(
            f"ATLAS dataset missing at {ATLAS_YAML}. "
            "Run scripts/refresh_data.py to download a pinned release."
        )
    with ATLAS_YAML.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return AtlasData(raw)


def pinned_release() -> str:
    """Release tag of the vendored dataset, e.g. ``v2026.10``."""
    if RELEASE_FILE.exists():
        return RELEASE_FILE.read_text(encoding="utf-8").strip()
    return "unknown"
