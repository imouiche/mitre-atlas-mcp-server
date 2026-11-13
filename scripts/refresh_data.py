#!/usr/bin/env python3
"""Re-vendor the ATLAS dataset from a pinned atlas-data release.

The dataset is committed to the repo so the server needs no network access at
runtime. This script is the only sanctioned way to change it: it downloads one
release asset, validates it parses and contains the collections the loader
expects, then writes the YAML, the RELEASE tag, and the ATLAS_RELEASE constant
in __init__.py together, so those three can never disagree.

    python scripts/refresh_data.py --release v2026.10
    python scripts/refresh_data.py --list

Re-run the test suite afterwards: tests/test_loader.py asserts collection
sizes and tests/test_profile.py asserts every technique id in the surface
taxonomy still resolves, so a renumbered technique surfaces as a failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "src" / "mitre_atlas_mcp" / "data" / "atlas"
ATLAS_YAML = DATA_DIR / "ATLAS.yaml"
RELEASE_FILE = DATA_DIR / "RELEASE"
INIT = ROOT / "src" / "mitre_atlas_mcp" / "__init__.py"

RELEASES_API = "https://api.github.com/repos/mitre-atlas/atlas-data/releases"
ASSET_URL = "https://github.com/mitre-atlas/atlas-data/releases/download/{tag}/ATLAS-{ver}.yaml"

REQUIRED_COLLECTIONS = ("tactics", "techniques", "mitigations", "case-studies", "relationships")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "mitre-atlas-mcp-server"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        sys.exit(f"HTTP {exc.code} fetching {url}")
    except urllib.error.URLError as exc:
        sys.exit(f"Could not reach {url}: {exc.reason}")


def list_releases() -> int:
    data = json.loads(fetch(RELEASES_API))
    current = RELEASE_FILE.read_text(encoding="utf-8").strip() if RELEASE_FILE.exists() else None
    for rel in data[:15]:
        tag = rel["tag_name"]
        marker = "  <- vendored" if tag == current else ""
        print(f"{tag:12} {rel.get('published_at', '')[:10]}{marker}")
    return 0


def validate(raw: dict) -> dict[str, int]:
    missing = [c for c in REQUIRED_COLLECTIONS if not raw.get(c)]
    if missing:
        sys.exit(f"Release is missing collections the loader needs: {missing}")
    fmt = str(raw.get("format-version", ""))
    if not fmt.startswith("6."):
        sys.exit(
            f"Unsupported format-version {fmt!r}. The loader targets 6.x; "
            "review src/mitre_atlas_mcp/data/loader.py before vendoring this."
        )
    return {c: len(raw[c]) for c in REQUIRED_COLLECTIONS}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--release", help="release tag, e.g. v2026.10")
    ap.add_argument("--list", action="store_true", help="list recent releases and exit")
    args = ap.parse_args()

    if args.list:
        return list_releases()
    if not args.release:
        ap.error("pass --release TAG (or --list to see available tags)")

    tag = args.release if args.release.startswith("v") else f"v{args.release}"
    version = tag.lstrip("v")

    url = ASSET_URL.format(tag=tag, ver=version)
    print(f"Fetching {url}")
    body = fetch(url)

    raw = yaml.safe_load(body)
    if not isinstance(raw, dict):
        sys.exit("Downloaded asset did not parse as a YAML mapping.")
    counts = validate(raw)

    declared = str((raw.get("collection") or {}).get("version", ""))
    if declared and declared != version:
        print(f"Warning: asset declares version {declared!r}, tag says {version!r}", file=sys.stderr)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ATLAS_YAML.write_bytes(body)
    RELEASE_FILE.write_text(f"{tag}\n", encoding="utf-8")

    text = INIT.read_text(encoding="utf-8")
    new_text = re.sub(r'^ATLAS_RELEASE = "[^"]*"', f'ATLAS_RELEASE = "{tag}"', text, flags=re.M)
    if new_text != text:
        INIT.write_text(new_text, encoding="utf-8")

    print(f"Vendored ATLAS {tag} ({len(body) / 1024:.0f}KB)")
    for name, n in counts.items():
        print(f"  {name:15} {n}")
    print("\nNow run: uv run pytest")
    print("Expect failures in test_loader.py (collection sizes) and test_profile.py")
    print("(taxonomy technique ids) if this release changed either — update both.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
