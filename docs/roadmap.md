# Roadmap

Planned tools live here rather than as registered stubs, so a client never
sees a tool that fails when called. Everything registered in `server.py` is
implemented and tested.

## Built (v0.1.0)

16 tools across three layers, 2 resources, 2 prompts. 99 tests. See the README
table.

## Not yet built

**`assess_coverage(surfaces, controls_in_place)`** - take a list of controls
the team already has and return the in-scope techniques those controls do
*not* address. Needs a vocabulary for "control" that maps onto ATLAS
mitigation ids without forcing the caller to know them; the obvious approach
is fuzzy-matching free text against mitigation names and categories, which
needs care to avoid confidently wrong matches.

**`get_mitigation_plan(surfaces)`** - sequence the mitigations by ATLAS
`lifecycle-phases` (design / development / deployment / operation) so the
output is an ordered plan rather than a set. The data supports it;
`profile_ai_system` currently returns mitigations ranked by coverage only.

**`generate_navigator_layer(surfaces)`** - emit an ATLAS Navigator layer JSON
scoring in-scope techniques, for visual review. The release ships
`navigator-*.json` assets whose schema this should match.

**`get_entity(entity_id)`** - the 44 ATLAS entities (AI red teams, research
orgs) are loaded and indexed, and `get_case_study` resolves `attributed_to`
through them, but there is no direct lookup tool yet.

## Taxonomy coverage

The surface taxonomy reaches **94 of 221** techniques, asserted by
`test_taxonomy_coverage_of_atlas`. The gap is mostly deliberate: the remainder
are Predictive-AI, physical-access and Enterprise-only techniques that no
agentic architectural surface maps onto.

Worth reviewing for a future release:

- Techniques tagged `Agentic AI` that no surface currently seeds. There are
  148 agentic techniques and the taxonomy seeds a subset; some of the
  remainder likely deserve a surface, and a few may warrant new surfaces
  (sandbox/compute escape, human-in-the-loop approval bypass).
- A `physical_access` surface, if robotics or embodied agents become in scope.
- Per-surface severity weighting. Right now ordering is by ATLAS maturity,
  which is a property of the technique rather than of the system under review.

## Known data limitations

- ATLAS asserts an ATT&CK parallel for only **48 of 221** techniques. Both
  crossmap tools report this so an empty result is not misread.
- **26 of 92** sub-techniques carry no mitigations of their own;
  `get_mitigations_for_technique` falls back to the parent and flags it via
  `inherited_from`. For 8 of those the parent has none either.
- `tactics_for_technique` has a parent-inheritance fallback that v2026.10
  never exercises - every technique carries its own `achieves` edge. The
  branch is covered by a synthetic fixture in `test_loader.py` rather than
  real data.
