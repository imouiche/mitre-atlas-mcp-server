"""MCP server for threat-modeling AI and agentic systems against MITRE ATLAS."""

# Single source of truth for the version. hatchling reads it from here, and
# scripts/sync_version.py propagates it into package.json and server.json.
__version__ = "0.1.1"

# The vendored ATLAS release this build is pinned to. Bumped by
# scripts/refresh_data.py, never by hand.
ATLAS_RELEASE = "v2026.10"

__all__ = ["__version__", "ATLAS_RELEASE"]
