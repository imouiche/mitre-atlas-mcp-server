# MITRE ATLAS MCP Server

**Threat-model AI and agentic systems against [MITRE ATLAS](https://atlas.mitre.org/).**

Describe your system's architecture - an agent with tool access over a RAG
corpus, say - and get back the ATLAS techniques that apply, the mitigations
that cover them, the compounding risks your specific combination of surfaces
creates, and the real-world incidents that have already happened to systems
shaped like yours.

This is not a lookup wrapper around the ATLAS matrix. Lookup is included, but
the point is the mapping from *how you built it* to *what can be done to it*.

Pinned to **ATLAS v2026.10**: 16 tactics, 221 techniques, 44 mitigations, 77
case studies. No network access at runtime; the dataset is vendored.

## Install

```bash
# Preferred: isolated, nothing installed globally
uvx mitre-atlas-mcp-server

# Or from PyPI
pip install mitre-atlas-mcp-server

# Or from npm
npx -y @imouiche/mitre-atlas-mcp-server
```

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "mitre-atlas": {
      "command": "uvx",
      "args": ["mitre-atlas-mcp-server"]
    }
  }
}
```

## The idea

ATLAS is organised by adversary intent — tactics and techniques. Engineers
describe systems by architecture. That mismatch is why ATLAS is harder to apply
than it should be, and it is the gap this server closes.

It defines ten **surfaces**, each a yes/no question about your architecture,
each anchored to the ATLAS techniques that become reachable when the answer is
yes:

| Surface | Applies when |
|---|---|
| `untrusted_input` | Content from outside your trust boundary reaches the model |
| `tool_use` | The model's output drives function, shell, HTTP, or MCP calls |
| `rag` | Retrieved documents land in the context window |
| `agent_memory` | State persists across turns or sessions |
| `agent_config` | Config, system prompts, or tool manifests are reachable |
| `multi_agent` | Agents delegate to, spawn, or message other agents |
| `rendered_output` | Output is rendered as markdown, HTML, or links |
| `inference_api` | A model endpoint is reachable over the network |
| `model_supply_chain` | Weights, adapters, datasets, or MCP servers come from a registry |
| `training_pipeline` | You train or fine-tune on data you collect |

The surfaces that matter most are the ones that **combine**. `untrusted_input`
alone is a content-filtering problem. `untrusted_input` + `tool_use` is the
agentic equivalent of remote code execution: injected text becomes
attacker-chosen actions. `profile_ai_system` reports those compounds
explicitly rather than leaving you to infer them from two separate lists.

ATLAS v2026.10 tags 148 of its 221 techniques as applying to **Agentic AI**,
which is what makes this framing tractable - the agentic coverage is MITRE's,
not invented here.

## Tools

**Threat modelling**

| Tool | Does |
|---|---|
| `list_surfaces` | The ten surfaces, with the question that decides each. Start here |
| `profile_ai_system` | Surfaces in → techniques ranked by exposure, mitigations ranked by coverage, compound risks, and techniques ATLAS has no mitigation for |
| `map_surface_to_techniques` | One surface at a time, for drilling in |
| `find_analogous_incidents` | Case studies ranked by technique overlap, each naming the overlapping techniques so the relevance is checkable |

**Reference**

| Tool | Does |
|---|---|
| `get_atlas_info` | Release served and collection sizes |
| `list_tactics` | All 16 tactics with technique counts |
| `get_technique` | One technique: tactics, sub-techniques, mitigations, case studies, ATT&CK parallel |
| `search_techniques` | Text search, filterable by platform and maturity |
| `get_techniques_by_tactic` | By tactic id or name |
| `get_mitigation` | One mitigation, with everything it covers |
| `get_mitigations_for_technique` | Mitigations for a technique, inheriting from the parent when a sub-technique has none |
| `get_case_study` | One case study with its **ordered attack flow** — each step's tactic, technique, and what the operator actually did |
| `search_case_studies` | By text, by type (27 `Incident`, 50 `Exercise`), or by technique employed |
| `get_software` | Attacker tooling ATLAS catalogues |

**Cross-framework**

| Tool | Does |
|---|---|
| `map_atlas_to_attack` | The ATT&CK technique an ATLAS technique parallels |
| `map_attack_to_atlas` | The reverse, for teams already modelling against ATT&CK |

ATLAS asserts an ATT&CK parallel for 48 of 221 techniques. Both tools report
that coverage figure, so an empty result is never mistaken for "no parallel
exists".

**Resources:** `atlas://matrix` (the matrix as markdown), `atlas://surfaces`
(the taxonomy).

**Prompts:** `threat_model_this_agent`, `review_mcp_tool_surface`.

## Example

> Threat-model this: a customer-support agent that reads incoming email,
> retrieves from our knowledge base, and can issue refunds through our billing
> API. It remembers prior conversations per customer.

That is `untrusted_input` + `rag` + `tool_use` + `agent_memory`.
`profile_ai_system` returns the ranked techniques, and leads with the three
compounds - injection-to-tool-call, corpus-write-to-tool-call, and persistent
injection with delayed triggers - then the mitigations in coverage order, then
the real incidents that have already followed that shape.

## Data

The ATLAS dataset is vendored at
`src/mitre_atlas_mcp/data/atlas/ATLAS.yaml` (1.1MB), pinned to the release tag
in `RELEASE`. To move to a newer release:

```bash
python scripts/refresh_data.py --release v2026.10
uv run pytest        # the counts and taxonomy ids are asserted
```

The tests assert collection sizes and that every technique id in the surface
taxonomy resolves, so a renumbered or retired technique fails the suite instead
of silently shortening a threat model.

## Development

```bash
uv sync
uv run pytest
uv run python -m mitre_atlas_mcp.server    # stdio
```

## Licence

Apache-2.0. The ATLAS dataset is © 2021–2026 MITRE, redistributed under
Apache-2.0 — see [NOTICE](NOTICE). This project is not affiliated with or
endorsed by MITRE.

Issues and pull requests are welcome at
[github.com/imouiche/mitre-atlas-mcp-server](https://github.com/imouiche/mitre-atlas-mcp-server/issues).

## Author

**Inoussa Mouiche, Ph.D.** - University of Windsor, WASP Lab. Research in
threat intelligence automation, machine learning, agent AI security,
and LLM-powered security operations.

[GitHub](https://github.com/imouiche) ·
[LinkedIn](https://www.linkedin.com/in/inoussa-mouiche-ph-d-b5b5138b/) ·
[Google Scholar](https://scholar.google.com/citations?user=_d4cEVoAAAAJ&hl=en) ·
mouiche@uwindsor.ca

Also the author of the [MITRE ATT&CK MCP Server](https://github.com/imouiche/complete-mitre-attack-mcp-server),
which covers conventional adversary TTPs; this server covers the AI-specific
ones and cross-maps between the two.
