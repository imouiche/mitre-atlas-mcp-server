#!/usr/bin/env python3
"""End-to-end check that the MCP server registers and serves its tools.

The unit tests call the tool functions directly, which proves the logic but
not the MCP wiring. This drives the real FastMCP instance: enumerate tools,
resources and prompts, then call one tool from each layer through the server
rather than by import.

Run locally with `uv run python scripts/smoke_test.py`; CI runs it on every push.
"""

from __future__ import annotations

import asyncio
import json
import sys

from mitre_atlas_mcp.server import mcp

EXPECTED_TOOLS = {
    # reference
    "get_atlas_info",
    "list_tactics",
    "get_technique",
    "search_techniques",
    "get_techniques_by_tactic",
    "get_mitigation",
    "get_mitigations_for_technique",
    "get_case_study",
    "search_case_studies",
    "get_software",
    # threat modelling
    "list_surfaces",
    "map_surface_to_techniques",
    "profile_ai_system",
    "find_analogous_incidents",
    # cross-framework
    "map_atlas_to_attack",
    "map_attack_to_atlas",
    "map_technique_to_frameworks",
}


def payload(result) -> dict:
    """Pull the JSON body out of a FastMCP tool result."""
    content = result.content if hasattr(result, "content") else result
    first = content[0]
    return json.loads(first.text)


async def main() -> int:
    failures: list[str] = []

    tools = {t.name for t in await mcp.list_tools()}
    missing = EXPECTED_TOOLS - tools
    extra = tools - EXPECTED_TOOLS
    if missing:
        failures.append(f"tools not registered: {sorted(missing)}")
    if extra:
        failures.append(f"unexpected tools registered: {sorted(extra)}")
    print(f"tools:     {len(tools)} registered")

    resources = {str(r.uri) for r in await mcp.list_resources()}
    for uri in ("atlas://matrix", "atlas://surfaces"):
        if uri not in resources:
            failures.append(f"resource not registered: {uri}")
    print(f"resources: {sorted(resources)}")

    prompts = {p.name for p in await mcp.list_prompts()}
    for name in ("threat_model_this_agent", "review_mcp_tool_surface"):
        if name not in prompts:
            failures.append(f"prompt not registered: {name}")
    print(f"prompts:   {sorted(prompts)}")

    # Every tool must declare a description; an undocumented tool is unusable
    # to a model even when it works.
    for t in await mcp.list_tools():
        if not (t.description or "").strip():
            failures.append(f"tool has no description: {t.name}")

    # Call one tool per layer through the server.
    info = payload(await mcp.call_tool("get_atlas_info", {}))
    print(f"reference: ATLAS {info['atlas_release']}, {info['techniques']} techniques")
    if info["techniques"] != 221:
        failures.append(f"expected 221 techniques, got {info['techniques']}")

    profile = payload(
        await mcp.call_tool("profile_ai_system", {"surfaces": ["untrusted_input", "tool_use"]})
    )
    n = profile["summary"]["techniques_in_scope"]
    risks = len(profile["compound_risks"])
    print(f"threat:    {n} techniques in scope, {risks} compound risk(s)")
    if n == 0:
        failures.append("profile_ai_system returned no techniques")
    if risks == 0:
        failures.append("profile_ai_system reported no compound risk for a known-risky pair")

    crossmap = payload(await mcp.call_tool("map_atlas_to_attack", {"technique_id": "AML.T0000"}))
    print(f"crossmap:  AML.T0000 -> {crossmap['attack_technique']['id']}")
    if crossmap["attack_technique"]["id"] != "T1596":
        failures.append(f"unexpected ATT&CK mapping: {crossmap['attack_technique']}")

    # Resources must render without raising.
    for uri in ("atlas://matrix", "atlas://surfaces"):
        contents = await mcp.read_resource(uri)
        body = contents[0].content if hasattr(contents[0], "content") else contents[0]
        if not body or len(str(body)) < 200:
            failures.append(f"resource {uri} rendered suspiciously short")

    if failures:
        print("\nFAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
