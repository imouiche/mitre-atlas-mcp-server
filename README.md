<div align="center">

# MITRE ATLAS MCP Server

**17 MCP tools that threat-model AI and agentic systems against [MITRE ATLAS](https://atlas.mitre.org/)**

[![MCP tools](https://img.shields.io/badge/MCP%20tools-17-0b7285)](#tools)
[![ATLAS](https://img.shields.io/badge/ATLAS-v2026.10-1864ab)](https://atlas.mitre.org/)
[![CoSAI Risk Map](https://img.shields.io/badge/CoSAI-Risk%20Map-5f3dc4)](https://github.com/cosai-oasis/secure-ai-tooling)
[![Cross-maps](https://img.shields.io/badge/cross--maps-ATT%26CK%20%7C%20OWASP%20%7C%20STRIDE%20%7C%20NIST-e8590c)](#cross-framework)
[![Data](https://img.shields.io/badge/data-vendored%20%7C%20offline-2f9e44)](#data-governance)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-published-success)](https://registry.modelcontextprotocol.io/?q=mitre-atlas-mcp-server)
[![npm](https://img.shields.io/npm/v/@imouiche/mitre-atlas-mcp-server.svg)](https://www.npmjs.com/package/@imouiche/mitre-atlas-mcp-server)
[![npm downloads](https://img.shields.io/npm/dm/@imouiche/mitre-atlas-mcp-server.svg)](https://www.npmjs.com/package/@imouiche/mitre-atlas-mcp-server)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Install](#install) · [The idea](#the-idea) · [Tools](#tools) · [Example prompts](#example-prompts) · [Data governance](#data-governance) · [Who owns the fix](#who-owns-the-fix)

</div>

---

Describe your system's architecture - an agent with tool access over a RAG
corpus, say - and get back the ATLAS techniques that apply, the mitigations
that cover them, the compounding risks your specific combination of surfaces
creates, and the real-world incidents that have already happened to systems
shaped like yours.

This is not a lookup wrapper around the ATLAS matrix. Lookup is included, but
the point is the mapping from *how you built it* to *what can be done to it*.

Pinned to **ATLAS v2026.10**: 16 tactics, 221 techniques, 44 mitigations, 77
case studies. Mitigations are enriched with control ownership from the **CoSAI
Risk Map**, and techniques cross-map to ATT&CK, STRIDE, OWASP Top 10 for LLM
and NIST AI RMF.

**Published in the official [MCP Registry](https://registry.modelcontextprotocol.io/?q=mitre-atlas-mcp-server)
as `io.github.imouiche/mitre-atlas-mcp-server`.**

## Install

```bash
npx -y @imouiche/mitre-atlas-mcp-server
```

Requires Node 18+ and Python 3.12+ on `PATH`. On first run it prepares a
private virtualenv under `~/.mitre-atlas-mcp-server/runtime`, which takes a few
seconds: both datasets are already in the package, so only `mcp` and `pyyaml`
are installed and nothing is downloaded. Nothing touches your system or active
Python environment.

| Variable | Effect |
|---|---|
| `MITRE_ATLAS_PYTHON` | Use this interpreter directly and skip virtualenv creation. It must already satisfy the dependencies in `pyproject.toml`. |
| `MITRE_ATLAS_RUNTIME_DIR` | Relocate the cached virtualenv. |

The PyPI release is not published yet, so these do not work today:

```bash
uvx mitre-atlas-mcp-server            # pending PyPI
pip install mitre-atlas-mcp-server    # pending PyPI
```

`uvx` will become the recommended path once the package is on PyPI, since it
needs no Node at all.

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "mitre-atlas": {
      "command": "npx",
      "args": ["-y", "@imouiche/mitre-atlas-mcp-server"]
    }
  }
}
```

## The idea

ATLAS is organised by adversary intent - tactics and techniques. Engineers
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

### Threat modelling

| Tool | Does |
|---|---|
| `list_surfaces` | The ten surfaces, with the question that decides each. Start here |
| `profile_ai_system` | Surfaces in → techniques ranked by exposure, mitigations ranked by coverage, compound risks, and techniques ATLAS has no mitigation for |
| `map_surface_to_techniques` | One surface at a time, for drilling in |
| `find_analogous_incidents` | Case studies ranked by technique overlap, each naming the overlapping techniques so the relevance is checkable |

### Reference

| Tool | Does |
|---|---|
| `get_atlas_info` | Release served and collection sizes |
| `list_tactics` | All 16 tactics with technique counts |
| `get_technique` | One technique: tactics, sub-techniques, mitigations, case studies, ATT&CK parallel |
| `search_techniques` | Text search, filterable by platform and maturity |
| `get_techniques_by_tactic` | By tactic id or name |
| `get_mitigation` | One mitigation, with everything it covers |
| `get_mitigations_for_technique` | Mitigations for a technique, inheriting from the parent when a sub-technique has none |
| `get_case_study` | One case study with its **ordered attack flow** - each step's tactic, technique, and what the operator actually did |
| `search_case_studies` | By text, by type (27 `Incident`, 50 `Exercise`), or by technique employed |
| `get_software` | Attacker tooling ATLAS catalogues |

### Cross-framework

| Tool | Does |
|---|---|
| `map_atlas_to_attack` | The ATT&CK technique an ATLAS technique parallels |
| `map_attack_to_atlas` | The reverse, for teams already modelling against ATT&CK |
| `map_technique_to_frameworks` | ATT&CK, **STRIDE**, **OWASP Top 10 for LLM** and **NIST AI RMF** for one technique, plus the CoSAI risks and controls behind them |

ATLAS asserts an ATT&CK parallel for 48 of 221 techniques. Every tool reports
its coverage figure, so an empty result is never mistaken for "no parallel
exists".

**Resources:** `atlas://matrix` (the matrix as markdown), `atlas://surfaces`
(the taxonomy).

**Prompts:** `threat_model_this_agent`, `review_mcp_tool_surface`.

## Who owns the fix

ATLAS tells you what to do about a technique. It does not tell you who does it.

So every mitigation this server returns is enriched from the
[CoSAI Risk Map](https://github.com/cosai-oasis/secure-ai-tooling) (Coalition
for Secure AI, an OASIS open project), which maps its engineering controls to
ATLAS mitigation ids. Where a mapping exists you also get the control, the
**personas who own it**, and the **components it applies to**:

```
AML.M0004  Limit AI Service Query Volume and Rate
  CoSAI control : Agent Execution Bounds
  owners        : Agentic Platform and Framework Providers, Application Developer,
                  AI Platform Provider
  components    : Agent Reasoning Core, Orchestration Input Handling,
                  Orchestration Output Handling
```

That turns a ranked mitigation list into assignable work, which is the point of
threat-modelling a system you are actually building.

**Coverage, stated plainly.** 13 of ATLAS's 44 mitigations have a CoSAI
control, and all 13 cited ids resolve against the pinned ATLAS release. Per
surface, roughly a quarter to a half of returned mitigations carry an owner;
`agent_config` currently has none. Where CoSAI maps nothing, the tools say so
rather than returning a silent blank.

## Example

> Threat-model this: a customer-support agent that reads incoming email,
> retrieves from our knowledge base, and can issue refunds through our billing
> API. It remembers prior conversations per customer.

That is four surfaces, so `profile_ai_system(["untrusted_input", "rag",
"tool_use", "agent_memory"])`. Actual output, abridged:

**27 techniques in scope, across 11 tactics. 18 mitigations. 5 techniques ATLAS
has no mitigation for.**

It leads with what the *combination* creates, not the individual techniques:

```
untrusted_input + tool_use
  Injected content becomes attacker-chosen tool calls, the agentic equivalent
  of remote code execution. Treat every tool the agent can reach as callable
  by whoever authors the untrusted content.

rag + tool_use
  Anyone who can write into the indexed corpus can steer tool calls without
  ever interacting with the system directly.

untrusted_input + agent_memory
  A single injection persists across sessions and can carry a delayed trigger,
  so the payload outlives the request that delivered it.
```

Then the mitigations, ranked by how much they cover, each naming who implements
it:

```
AML.M0020  covers 14  Generative AI Guardrails
           owners: AI Model Serving, AI Platform Provider,
                   Agentic Platform and Framework Providers
AML.M0035  covers 11  AI Red Team
AML.M0024  covers  7  AI Telemetry Logging and Monitoring
           owners: AI Model Serving, AI Platform Provider,
                   Agentic Platform and Framework Providers
```

Then `find_analogous_incidents` for the same surfaces, ranked by how many
in-scope techniques each case study actually employed:

```
AML.CS0063  overlap 10  Prompt-Based Attacks Against Gemini via Calendar Invitations
AML.CS0026  overlap  9  Financial Transaction Hijacking with M365 Copilot as an Insider
AML.CS0066  overlap  9  ZombieAgent: Data Exfiltration Attack on ChatGPT
AML.CS0024  overlap  7  Morris II Worm: RAG-Based Attack
```

A support agent that can move money, matched against a documented financial
transaction hijack with nine techniques in common. `get_case_study` returns any
of these as an ordered attack flow: each step's tactic, the technique used, and
what the operator actually did.

## Example prompts

Ask these as plain messages once the server is connected. Each one was run
against this release; the figures are what it actually returns.

### Threat-modelling a system you are building

```
What architectural surfaces can you threat-model against?
```
Returns the ten surfaces with the question that decides each. A good first
call, since the rest build on it.

```
Threat-model this: an internal assistant that answers questions from our
Confluence space and can file Jira tickets.
```
That is `untrusted_input` + `rag` + `tool_use`. Expect the compound risks to
lead, including corpus-write-to-tool-call.

```
We have agents that delegate to sub-agents, and each can call tools.
What is our exposure?
```
`multi_agent` + `tool_use`: 15 techniques in scope and the compound risk that
tool authority is transitive across delegation.

```
What does RAG specifically expose us to, and what mitigates it?
```
Five techniques and five mitigations for the `rag` surface alone, which is
useful when you want to drill into one decision rather than a whole system.

### Finding precedent

```
Show me real cases that overlap a system with a RAG corpus.
```
Four matches, led by *Financial Transaction Hijacking with M365 Copilot as an
Insider* and *Data Exfiltration from Slack AI via Indirect Prompt Injection*.

```
Which documented incidents involve poisoned models or MCP servers from a registry?
```
Eleven incidents for `model_supply_chain`, including *Poisoned Postmark MCP
Server Email Exfiltration* and *Malicious Models on Hugging Face*.

```
Walk me through the Morris II worm case study step by step.
```
`AML.CS0024` as an ordered attack flow: twelve steps, each with its tactic,
technique and what the operator actually did.

### Looking things up

```
Search ATLAS for techniques about memory that apply to agentic systems.
```
Eight hits, filtered to the Agentic AI platform.

```
Which ATLAS techniques achieve the Exfiltration tactic?
```

```
What mitigates RAG poisoning, and who implements it?
```
`AML.T0070`, its two mitigations, and the CoSAI control owners where they
exist.

```
Tell me about the attacker tool AML.S0001.
```

### Cross-framework, for compliance and review

```
Map AML.T0086 to OWASP, STRIDE and NIST.
```
Exfiltration via AI Agent Tool Invocation, returning ids from all three, with
each attributed to the CoSAI risk or control it came from.

```
We already threat-model against ATT&CK T1566. What AI-specific
techniques attach to it?
```

```
Here are the tools our agent exposes: [paste your tool list].
What could an attacker who controls its input make it do?
```
Uses the `review_mcp_tool_surface` prompt, mapping each tool to the technique
that covers its abuse.

Setup instructions for Claude Desktop, including the environment pitfalls that
stop a server from starting, are in [atlas_usage.md](atlas_usage.md).

## Data governance

Security tooling is only as trustworthy as the data under it, and most MCP
servers fetch theirs at call time from whatever the upstream API returns today.
This one does not. **Both datasets ship inside the package, pinned to an exact
release, and the server makes no network calls while serving.**

| Property | How it holds |
|---|---|
| **Reproducible** | Two identical calls return identical answers. The data cannot shift under a running assessment. |
| **Offline** | Runs air-gapped. Nothing is fetched at startup or per call; verified by there being no HTTP client anywhere in `src/`. |
| **Pinned and attributable** | ATLAS at `v2026.10` recorded in `RELEASE`; CoSAI at commit `622605a` recorded in `COMMIT`. Both Apache-2.0, attributed in [NOTICE](NOTICE). |
| **Integrity-checked** | 123 tests assert collection sizes, that every technique id in the surface taxonomy resolves, and that every ATLAS id CoSAI cites exists in the pinned release. |
| **No third-party reach** | No telemetry, no analytics, no credentials, no API keys. Nobody outside this repository can change what the server reports. |
| **Reviewed updates** | A weekly workflow pulls upstream, runs the suite and opens a pull request only when something changed. Refreshes are merged deliberately, never applied silently. |

That last row matters more than it sounds. Upstream renumbers things: a recent
CoSAI revision dropped a mapping the enrichment relied on, and a stale ATLAS id
would quietly shorten a threat model rather than erroring. The tests catch that
before a refresh lands.

### Updating the pinned data

```bash
python scripts/refresh_data.py --release v2026.10   # ATLAS, 1.1MB
python scripts/refresh_cosai.py --latest            # CoSAI Risk Map, 348KB
uv run pytest                                        # both pins are asserted
```

`get_atlas_info` reports both pins at runtime, so a caller can always see
exactly which releases produced an answer.

## Development

```bash
uv sync
uv run pytest
uv run python -m mitre_atlas_mcp.server    # stdio
```

## Licence

Apache-2.0. The ATLAS dataset is © 2021–2026 MITRE, redistributed under
Apache-2.0 - see [NOTICE](NOTICE). This project is not affiliated with or
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
