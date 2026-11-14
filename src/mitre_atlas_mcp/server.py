"""MCP server entry point.

The MCPServer instance lives in app.py; the tool modules decorate their
functions with @mcp.tool() and register themselves on import. This module
imports them for that side effect, then adds the resources and prompts and
provides main().

Every tool registered is implemented and tested. Planned tools that are not
yet built are tracked in docs/roadmap.md, so a client never sees a tool that
fails when called.
"""

from __future__ import annotations

import logging

from . import __version__
from .app import mcp
from .data.loader import get_atlas, pinned_release
from .profile import SURFACES

# Imported for the registration side effect: each module applies @mcp.tool()
# to its own functions. Re-exported so `from .server import reference` keeps
# working and linters do not flag the imports as unused.
from .tools import crossmap, reference, threatmodel

__all__ = ["mcp", "main", "crossmap", "reference", "threatmodel"]

logger = logging.getLogger(__name__)


# -- resources ------------------------------------------------------------


@mcp.resource("atlas://matrix")
def atlas_matrix() -> str:
    """The ATLAS matrix as markdown: tactics in order, techniques beneath each."""
    atlas = get_atlas()
    lines = [
        f"# MITRE ATLAS {atlas.release_version}",
        "",
        f"{len(atlas.tactics)} tactics, {len(atlas.techniques)} techniques "
        f"(including sub-techniques), {len(atlas.mitigations)} mitigations, "
        f"{len(atlas.case_studies)} case studies.",
        "",
    ]
    for tid, tactic in atlas.tactics.items():
        technique_ids = sorted(atlas.techniques_for_tactic(tid))
        lines.append(f"## {tactic['name']} ({tid}) - {len(technique_ids)} techniques")
        for t in technique_ids:
            tech = atlas.techniques[t]
            platforms = ", ".join(tech.get("platforms") or [])
            lines.append(f"- **{t}** {tech['name']} - {tech.get('maturity')} [{platforms}]")
        lines.append("")
    return "\n".join(lines)


@mcp.resource("atlas://surfaces")
def atlas_surfaces() -> str:
    """The attack-surface taxonomy used by the threat-model tools."""
    lines = ["# AI/agentic attack surfaces", ""]
    for s in SURFACES:
        lines += [
            f"## {s.label} (`{s.key}`)",
            "",
            f"**Applies when:** {s.question}",
            "",
            f"**Platforms:** {', '.join(s.platforms)}",
            "",
            f"**Seed techniques:** {', '.join(s.techniques)}",
            "",
        ]
        if s.notes:
            lines += [f"**Note:** {s.notes}", ""]
    return "\n".join(lines)


# -- prompts --------------------------------------------------------------


@mcp.prompt()
def threat_model_this_agent(system_description: str) -> str:
    """Walk a described agentic system through an ATLAS threat model."""
    return (
        "Threat-model the following system against MITRE ATLAS.\n\n"
        f"SYSTEM:\n{system_description}\n\n"
        "Steps:\n"
        "1. Call list_surfaces and decide which surfaces this system has. "
        "State your reasoning for each one you include and each you rule out.\n"
        "2. Call profile_ai_system with those surface keys.\n"
        "3. Lead with the compound_risks, which matter more than any single "
        "technique.\n"
        "4. Call find_analogous_incidents with type=\"Incident\" and cite the "
        "real-world precedents by id.\n"
        "5. Recommend mitigations in coverage order, and call out explicitly "
        "any techniques ATLAS lists no mitigation for.\n\n"
        "Cite every ATLAS id you rely on. Do not invent technique ids."
    )


@mcp.prompt()
def review_mcp_tool_surface(tool_manifest: str) -> str:
    """Review an MCP server's tool surface for agentic attack exposure."""
    return (
        "Review this MCP server's tool surface for the exposure it creates in "
        "an agent that connects to it.\n\n"
        f"TOOLS:\n{tool_manifest}\n\n"
        "Use map_surface_to_techniques for tool_use and agent_config, then "
        "profile_ai_system with those plus untrusted_input, since an agent "
        "reaching these tools is nearly always also reading untrusted content.\n\n"
        "For each tool, state what an attacker who controls the agent's input "
        "could make it do, and name the ATLAS technique that covers it. "
        "Flag any tool that destroys data, moves credentials, or reaches the "
        "network, mapping to AML.T0101, AML.T0098 and AML.T0086 respectively."
    )


def main() -> None:
    """Run the server over stdio."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    atlas = get_atlas()
    logger.info(
        "mitre-atlas-mcp-server %s serving ATLAS %s (%s): "
        "%d techniques, %d mitigations, %d case studies",
        __version__,
        atlas.release_version,
        pinned_release(),
        len(atlas.techniques),
        len(atlas.mitigations),
        len(atlas.case_studies),
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
