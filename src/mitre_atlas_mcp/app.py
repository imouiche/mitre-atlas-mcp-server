"""The MCPServer instance, kept separate from the module that assembles it.

Tool modules decorate their functions with ``@mcp.tool()`` directly, which is
the idiomatic form and the only one a static reader can see. Importing the
instance from ``server`` would make that circular, since ``server`` imports the
tool modules. Holding it here breaks the cycle: tool modules import from
``app``, and ``server`` imports both.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from . import __version__

# mcp 2.x renamed FastMCP to MCPServer. The dependency is pinned to >=2.3,<3 in
# pyproject.toml rather than left open: the ATT&CK server declared `mcp>=1.1.0`,
# and when 2.0 landed its `mcp.server.fastmcp` import began failing on every
# fresh install.
mcp = MCPServer(
    name="mitre-atlas",
    version=__version__,
    instructions=(
        "MITRE ATLAS for AI and agentic system security.\n\n"
        "To threat-model a system: call list_surfaces, decide which surfaces "
        "the system has, then call profile_ai_system with those keys. It "
        "returns applicable techniques, mitigations ranked by coverage, and "
        "the compounding risks specific surface combinations create. Follow up "
        "with find_analogous_incidents for real precedents and get_case_study "
        "for a step-by-step attack flow.\n\n"
        "For direct lookup, use list_tactics, get_technique, search_techniques, "
        "get_techniques_by_tactic, get_mitigation and search_case_studies.\n\n"
        "ATLAS tags techniques by platform: Agentic AI, Generative AI, "
        "Predictive AI, Enterprise. Agentic AI is the default for the "
        "threat-model tools."
    ),
)

__all__ = ["mcp"]
