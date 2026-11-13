"""Attack-surface taxonomy for AI and agentic systems.

This is the keystone of the server. ATLAS is organised by adversary intent
(tactics and techniques); engineers describe their systems by *architecture*
("it's an agent with tool access over a RAG corpus"). This module is the
bridge: a small vocabulary of architectural surfaces, each anchored to the
ATLAS techniques that apply when that surface is present.

Seed technique ids are deliberately top-level only. The tools expand each seed
through the ATLAS relationship graph to pick up sub-techniques, mitigations and
case studies, so this table stays small and auditable. Every id here is
asserted to exist in the pinned dataset by ``tests/test_profile.py`` — when
ATLAS renumbers something, that test fails rather than the server silently
returning an empty result.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Surface:
    """One architectural property of a system, and what it exposes."""

    key: str
    label: str
    question: str
    """Plain-language test for whether a system has this surface."""
    techniques: tuple[str, ...]
    platforms: tuple[str, ...] = ("Agentic AI",)
    notes: str = ""


SURFACES: tuple[Surface, ...] = (
    Surface(
        key="untrusted_input",
        label="Untrusted input reaches the model",
        question=(
            "Can any content the model sees originate from outside your trust "
            "boundary — end users, scraped pages, email, uploaded files, "
            "third-party API responses?"
        ),
        techniques=(
            "AML.T0051",  # LLM Prompt Injection
            "AML.T0093",  # Prompt Infiltration via Public-Facing Application
            "AML.T0065",  # LLM Prompt Crafting
            "AML.T0068",  # LLM Prompt Obfuscation
            "AML.T0054",  # LLM Jailbreak
            "AML.T0129",  # Triggers in Multimodal Inputs
            "AML.T0143",  # LLM Prompt Propagation
        ),
        platforms=("Agentic AI", "Generative AI"),
        notes=(
            "Almost every agentic system has this surface. It is the root "
            "enabler for the tool-invocation and memory surfaces below."
        ),
    ),
    Surface(
        key="tool_use",
        label="Agent invokes tools",
        question=(
            "Does the model call functions, shell commands, HTTP APIs, or MCP "
            "servers, with its choice of call driven by model output?"
        ),
        techniques=(
            "AML.T0053",  # AI Agent Tool Invocation
            "AML.T0110",  # AI Agent Tool Poisoning
            "AML.T0086",  # Exfiltration via AI Agent Tool Invocation
            "AML.T0098",  # AI Agent Tool Credential Harvesting
            "AML.T0099",  # AI Agent Tool Data Poisoning
            "AML.T0101",  # Data Destruction via AI Agent Tool Invocation
            "AML.T0133",  # Discover AI Agent Runtime Capabilities
        ),
        notes=(
            "Combined with untrusted_input this is the highest-severity "
            "pairing in ATLAS: injected text becomes attacker-chosen actions."
        ),
    ),
    Surface(
        key="rag",
        label="Retrieval over a document corpus",
        question=(
            "Does the system retrieve from a vector store, search index, or "
            "document corpus and place the results in the context window?"
        ),
        techniques=(
            "AML.T0070",  # RAG Poisoning
            "AML.T0071",  # False RAG Entry Injection
            "AML.T0082",  # RAG Credential Harvesting
            "AML.T0064",  # Gather RAG-Indexed Targets
            "AML.T0066",  # Retrieval Content Crafting
        ),
        notes="Severity scales with who can write into the indexed corpus.",
    ),
    Surface(
        key="agent_memory",
        label="Persistent context or memory",
        question=(
            "Does the agent carry state across turns or sessions — chat "
            "history, scratchpad notes, a memory store, cached summaries?"
        ),
        techniques=(
            "AML.T0080",  # AI Agent Context Poisoning
            "AML.T0092",  # Manipulate User LLM Chat History
            "AML.T0094",  # Delay Execution of LLM Instructions
            "AML.T0061",  # LLM Prompt Self-Replication
        ),
        notes=(
            "Memory turns a one-shot injection into a persistent foothold, "
            "and enables delayed-trigger payloads."
        ),
    ),
    Surface(
        key="agent_config",
        label="Readable or writable agent configuration",
        question=(
            "Does the agent read configuration — system prompts, tool "
            "manifests, MCP server lists, credentials — from a file or "
            "service that something else can reach?"
        ),
        techniques=(
            "AML.T0081",  # Modify AI Agent Configuration
            "AML.T0083",  # Credentials from AI Agent Configuration
            "AML.T0084",  # Discover AI Agent Configuration
        ),
    ),
    Surface(
        key="multi_agent",
        label="Multiple agents communicating",
        question=(
            "Do agents delegate to, spawn, or exchange messages with other "
            "agents, including sub-agents of the same system?"
        ),
        techniques=(
            "AML.T0118",  # Autonomous AI Agent Communication
            "AML.T0124",  # Autonomous Attack Orchestration
            "AML.T0117",  # Autonomous Attack-Path Adaptation
            "AML.T0116",  # Autonomous Reconnaissance
            "AML.T0103",  # Deploy AI Agent
            "AML.T0108",  # AI Agent
        ),
        notes="Trust between agents is usually implicit and rarely authenticated.",
    ),
    Surface(
        key="rendered_output",
        label="Model output rendered in a UI",
        question=(
            "Is model output rendered as markdown, HTML, or links in a browser "
            "or chat client, rather than shown as plain text?"
        ),
        techniques=(
            "AML.T0077",  # LLM Response Rendering
            "AML.T0067",  # LLM Trusted Output Components Manipulation
            "AML.T0131",  # Crafted AI Assistant Links
            "AML.T0100",  # AI Agent Clickbait
            "AML.T0136",  # Exfiltration via AI User Interface
            "AML.T0130",  # AI Agent Response Biasing
        ),
        notes="Image and link rendering is a common zero-click exfiltration path.",
    ),
    Surface(
        key="inference_api",
        label="Hosted or exposed inference endpoint",
        question=(
            "Is there a model endpoint reachable over the network, whether "
            "yours or a third party's, that the system or its users call?"
        ),
        techniques=(
            "AML.T0040",  # AI Model Inference API Access
            "AML.T0024",  # Exfiltration via AI Inference API
            "AML.T0096",  # AI Service API
            "AML.T0132",  # Misconfigured or Publicly Exposed AI Services
            "AML.T0034",  # Cost Harvesting
            "AML.T0029",  # Denial of AI Service
        ),
        platforms=("Agentic AI", "Generative AI", "Predictive AI"),
    ),
    Surface(
        key="model_supply_chain",
        label="Third-party models, adapters, or tools",
        question=(
            "Do you pull model weights, adapters, datasets, prompts, or MCP "
            "servers from a registry or hub you do not control?"
        ),
        techniques=(
            "AML.T0010",  # Supply Chain Compromise
            "AML.T0109",  # AI Supply Chain Rug Pull
            "AML.T0111",  # AI Supply Chain Reputation Inflation
            "AML.T0115",  # Publish Poisoned AI Artifacts
            "AML.T0120",  # AI Artifact Repository
            "AML.T0002",  # Acquire Public AI Artifacts
        ),
        platforms=("Agentic AI", "Generative AI", "Predictive AI"),
    ),
    Surface(
        key="training_pipeline",
        label="Training or fine-tuning on collected data",
        question=(
            "Do you train, fine-tune, or continually learn from data you "
            "collect, including user feedback or agent traces?"
        ),
        techniques=(
            "AML.T0020",  # Training Data Poisoning
            "AML.T0018",  # Manipulate AI Model
            "AML.T0059",  # Erode Dataset Integrity
            "AML.T0076",  # Corrupt AI Model
            "AML.T0145",  # Poison AI Agent Learning Environment
            "AML.T0137",  # Training Data Information from AI Models
        ),
        platforms=("Agentic AI", "Generative AI", "Predictive AI"),
    ),
)

SURFACES_BY_KEY: dict[str, Surface] = {s.key: s for s in SURFACES}

#: Surface pairs whose combination is materially worse than either alone.
#: Reported by the threat-model tools so the compounding risk is explicit
#: rather than left for the reader to infer from two separate lists.
COMPOUND_RISKS: tuple[tuple[tuple[str, str], str], ...] = (
    (
        ("untrusted_input", "tool_use"),
        "Injected content becomes attacker-chosen tool calls — the agentic "
        "equivalent of remote code execution. Treat every tool the agent can "
        "reach as callable by whoever authors the untrusted content.",
    ),
    (
        ("untrusted_input", "agent_memory"),
        "A single injection persists across sessions and can carry a delayed "
        "trigger, so the payload outlives the request that delivered it.",
    ),
    (
        ("rag", "tool_use"),
        "Anyone who can write into the indexed corpus can steer tool calls "
        "without ever interacting with the system directly.",
    ),
    (
        ("tool_use", "multi_agent"),
        "Tool authority is transitive across delegation: a sub-agent inherits "
        "reach that the operator may never have granted it explicitly.",
    ),
    (
        ("untrusted_input", "rendered_output"),
        "Injection plus rich rendering yields zero-click exfiltration through "
        "image fetches and crafted links.",
    ),
    (
        ("agent_config", "model_supply_chain"),
        "An untrusted tool or MCP server that can rewrite agent configuration "
        "establishes persistence that survives redeployment.",
    ),
)


def unknown_surface_keys(keys: list[str]) -> list[str]:
    """Which of ``keys`` are not in the taxonomy."""
    return [k for k in keys if k not in SURFACES_BY_KEY]


def compound_risks_for(keys: list[str]) -> list[dict[str, object]]:
    """Compound risks whose both halves are present in ``keys``."""
    present = set(keys)
    return [
        {"surfaces": list(pair), "risk": text}
        for pair, text in COMPOUND_RISKS
        if set(pair) <= present
    ]
