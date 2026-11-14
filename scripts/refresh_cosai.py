#!/usr/bin/env python3
"""Re-vendor the CoSAI Risk Map from a pinned upstream commit.

The CoSAI data is committed to this repository so the server needs no network
access at runtime. This script is the only sanctioned way to change it: it
downloads the six YAML files the loader needs at one commit, validates they
parse and contain the expected collections, then writes them together with the
commit id so the data and its provenance cannot disagree.

    python scripts/refresh_cosai.py --commit <sha>
    python scripts/refresh_cosai.py --latest

Re-run the tests afterwards. tests/test_cosai.py asserts that every ATLAS
mitigation id CoSAI cites resolves against the vendored ATLAS release, that the
`all` and `none` sentinels still behave, and that upstream's dangling component
references have not grown.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "src" / "mitre_atlas_mcp" / "data" / "cosai"
COMMIT_FILE = DATA_DIR / "COMMIT"

REPO = "cosai-oasis/secure-ai-tooling"
RAW = "https://raw.githubusercontent.com/{repo}/{sha}/risk-map/yaml/{name}.yaml"
HEAD_API = f"https://api.github.com/repos/{REPO}/commits/main"

FILES = ("risks", "controls", "personas", "components", "frameworks", "lifecycle-stage")

#: Collection each file must expose, so a reorganised upstream fails loudly.
REQUIRED_KEY = {
    "risks": "risks",
    "controls": "controls",
    "personas": "personas",
    "components": "components",
    "frameworks": "frameworks",
    "lifecycle-stage": "lifecycleStages",
}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "mitre-atlas-mcp-server"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        sys.exit(f"HTTP {exc.code} fetching {url}")
    except urllib.error.URLError as exc:
        sys.exit(f"Could not reach {url}: {exc.reason}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--commit", help="upstream commit sha to vendor")
    group.add_argument("--latest", action="store_true", help="vendor the current main")
    args = ap.parse_args()

    if args.latest:
        sha = json.loads(fetch(HEAD_API))["sha"]
        print(f"main is at {sha}")
    else:
        sha = args.commit.strip()
        if len(sha) != 40:
            sys.exit("--commit needs a full 40-character sha, for reproducibility")

    current = COMMIT_FILE.read_text(encoding="utf-8").strip() if COMMIT_FILE.exists() else None
    if current == sha:
        print(f"Already vendored at {sha[:12]}; nothing to do.")
        return 0

    downloaded: dict[str, bytes] = {}
    counts: dict[str, int] = {}
    for name in FILES:
        url = RAW.format(repo=REPO, sha=sha, name=name)
        print(f"fetching {name}.yaml")
        body = fetch(url)
        parsed = yaml.safe_load(body)
        key = REQUIRED_KEY[name]
        if not isinstance(parsed, dict) or key not in parsed:
            sys.exit(f"{name}.yaml has no {key!r} collection; upstream layout may have changed")
        counts[name] = len(parsed[key])
        downloaded[name] = body

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, body in downloaded.items():
        (DATA_DIR / f"{name}.yaml").write_bytes(body)
    COMMIT_FILE.write_text(f"{sha}\n", encoding="utf-8")

    print(f"\nVendored CoSAI Risk Map at {sha[:12]}")
    for name, n in counts.items():
        print(f"  {name:16} {n}")
    print("\nNow run: uv run pytest")
    print("tests/test_cosai.py pins the ATLAS id resolution and the known upstream")
    print("dangling component references; update it if this refresh changed either.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
