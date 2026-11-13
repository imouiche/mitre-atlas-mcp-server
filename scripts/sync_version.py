#!/usr/bin/env python3
"""Propagate the version from __init__.py into package.json and server.json.

The ATT&CK server drifted to four different version numbers across
pyproject.toml, package.json, server.json and the two registries. Here
``mitre_atlas_mcp.__version__`` is the only place a version is written by hand;
hatchling reads it for the wheel, and this script pushes it everywhere else.

Run with --check in CI to fail on drift instead of fixing it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / "src" / "mitre_atlas_mcp" / "__init__.py"
PACKAGE_JSON = ROOT / "package.json"
SERVER_JSON = ROOT / "server.json"


def source_version() -> str:
    m = re.search(r'^__version__ = "([^"]+)"', INIT.read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit(f"Could not find __version__ in {INIT}")
    return m.group(1)


def sync_package_json(version: str, *, check: bool) -> list[str]:
    if not PACKAGE_JSON.exists():
        return []
    data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    if data.get("version") == version:
        return []
    if check:
        return [f"package.json version is {data.get('version')}, expected {version}"]
    data["version"] = version
    PACKAGE_JSON.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return [f"package.json -> {version}"]


def sync_server_json(version: str, *, check: bool) -> list[str]:
    """server.json carries a top-level version plus one per package entry."""
    if not SERVER_JSON.exists():
        return []
    data = json.loads(SERVER_JSON.read_text(encoding="utf-8"))
    drift: list[str] = []
    if data.get("version") != version:
        drift.append(f"server.json version is {data.get('version')}, expected {version}")
        data["version"] = version
    for pkg in data.get("packages", []):
        if pkg.get("version") != version:
            drift.append(
                f"server.json packages[{pkg.get('identifier')}] version is "
                f"{pkg.get('version')}, expected {version}"
            )
            pkg["version"] = version
    if drift and not check:
        SERVER_JSON.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return [f"server.json -> {version}"]
    return drift


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="report drift without writing")
    args = ap.parse_args()

    version = source_version()
    messages = sync_package_json(version, check=args.check) + sync_server_json(
        version, check=args.check
    )

    if not messages:
        print(f"All manifests at {version}.")
        return 0
    for m in messages:
        print(m)
    if args.check:
        print("\nRun scripts/sync_version.py to fix.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
