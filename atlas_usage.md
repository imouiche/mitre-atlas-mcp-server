# Using the MITRE ATLAS MCP server in Claude Desktop

Step by step, from a fresh Claude Desktop to a working threat model. Every
command and value here was run on macOS against the published package
`@imouiche/mitre-atlas-mcp-server@0.1.2`.

## Before you start

| Requirement | Why | Check |
|---|---|---|
| Claude Desktop | the client | `/Applications/Claude.app` |
| Node 18+ | runs `npx` and the launcher | `node -v` |
| Python 3.12+ | the server itself is Python | `python3 -V` |

The server needs no API key, no account and no network access once installed.

### The one thing that catches people out

Claude Desktop does not launch servers with your shell's `PATH`. It uses a
minimal environment, which on a typical Mac resolves to:

```
PATH=/usr/gnu/bin:/usr/local/bin:/bin:/usr/bin:.
```

In that environment `npx` is often **not found**, and `python3` may resolve to
an old build. On the machine this guide was written on, the minimal environment
produced `npx: NOT FOUND` and `Python 3.10.1`, which is below the 3.12 minimum.

The configuration below fixes both by giving an absolute path to `npx` and an
explicit `PATH`. If you skip that, the server fails to start with no obvious
reason.

## Step 1: find your absolute paths

```bash
command -v npx          # e.g. /opt/homebrew/bin/npx
ls /opt/homebrew/bin/python3.1*   # look for 3.12 or newer
```

Note the directory holding `npx`. On Apple Silicon with Homebrew that is
`/opt/homebrew/bin`; on Intel Macs it is usually `/usr/local/bin`.

## Step 2: warm the server once

The first launch creates a small private virtualenv and installs `mcp` and
`pyyaml`. It takes a few seconds, but Claude Desktop can time out waiting for a
server that is still setting up, so do it once from a terminal:

```bash
cd ~          # anywhere except the server's own git repo
npx -y @imouiche/mitre-atlas-mcp-server --setup
```

Expected final lines:

```
mitre-atlas-mcp-server:   installing: mcp>=2.3.0,<3, pyyaml>=6.0.0
mitre-atlas-mcp-server: environment ready. Subsequent runs start immediately.
mitre-atlas-mcp-server: setup complete.
```

Run it from your home directory, not from a clone of this repository. Inside
the repo, `npx` finds the local `package.json`, looks for a `node_modules/.bin`
that is not there, and fails with `command not found`.

Check it serves:

```bash
npx -y @imouiche/mitre-atlas-mcp-server < /dev/null
```

Expected:

```
mitre-atlas-mcp-server 0.1.2 serving ATLAS 2026.10 (v2026.10): 221 techniques, 44 mitigations, 77 case studies
```

## Step 3: add it to the Claude Desktop config

Open the config file:

```bash
open -e "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
```

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add a `mitre-atlas` entry inside `mcpServers`. **Merge it; do not replace the
file**, or you will lose any servers already configured:

```json
{
  "mcpServers": {
    "mitre-atlas": {
      "command": "/opt/homebrew/bin/npx",
      "args": ["-y", "@imouiche/mitre-atlas-mcp-server"],
      "env": {
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin"
      }
    }
  }
}
```

Replace `/opt/homebrew/bin` with the directory from step 1 if yours differs.

If you already run the ATT&CK server, the merged file holds both:

```json
{
  "mcpServers": {
    "mitre-attack": {
      "command": "/path/to/your/.venv/bin/python",
      "args": ["-m", "mitre_mcp_server.server"],
      "env": { "PYTHONPATH": "/path/to/your/src" }
    },
    "mitre-atlas": {
      "command": "/opt/homebrew/bin/npx",
      "args": ["-y", "@imouiche/mitre-atlas-mcp-server"],
      "env": { "PATH": "/opt/homebrew/bin:/usr/bin:/bin" }
    }
  }
}
```

Validate the JSON before restarting; a stray comma silently stops every server
from loading:

```bash
python3 -m json.tool "$HOME/Library/Application Support/Claude/claude_desktop_config.json" > /dev/null && echo OK
```

### Optional settings

| Variable | Use |
|---|---|
| `MITRE_ATLAS_PYTHON` | Point at a specific Python 3.12+ interpreter and skip virtualenv creation entirely. It must already have `mcp` and `pyyaml` installed. |
| `MITRE_ATLAS_RUNTIME_DIR` | Move the cached virtualenv somewhere other than `~/.mitre-atlas-mcp-server/runtime`. |

## Step 4: restart Claude Desktop

Quit completely with **Cmd+Q**. Closing the window is not enough; the server
process is only re-read on a full restart.

## Step 5: confirm it loaded

Reopen Claude Desktop and look for the tools or connector indicator in the
message composer. `mitre-atlas` should be listed with **17 tools**.

Then ask, as a plain message:

> What ATLAS release and datasets does the mitre-atlas server have loaded?

It should call `get_atlas_info` and come back with ATLAS **2026.10**, 221
techniques, 44 mitigations, 77 case studies, plus the CoSAI Risk Map with 37
controls. If you see those numbers, the server is working.

## Step 6: try it properly

These are worth running in order; each exercises a different layer.

**1. The core use case, threat-modelling a described system**

> Threat-model this against MITRE ATLAS: a customer-support agent that reads
> incoming email, retrieves from our knowledge base, and can issue refunds
> through our billing API. It remembers prior conversations per customer.

Expect it to call `list_surfaces`, then `profile_ai_system` with
`untrusted_input`, `rag`, `tool_use` and `agent_memory`, returning 27
techniques across 11 tactics and leading with three compound risks. The
important one is injection becoming attacker-chosen tool calls.

**2. Who implements the fix**

> For that system, which mitigations should we apply and who owns each one?

Expect mitigations ranked by coverage, with CoSAI control ownership attached.
`AML.M0020` (Generative AI Guardrails) covers the most and names AI Model
Serving, AI Platform Provider and Agentic Platform and Framework Providers.

**3. Real precedents**

> Show me real case studies that overlap this system's exposure.

Expect `find_analogous_incidents`, returning case studies ranked by how many
in-scope techniques each actually used, such as *Financial Transaction
Hijacking with M365 Copilot as an Insider*.

**4. Cross-framework, for compliance conversations**

> Map ATLAS technique AML.T0051 to OWASP, STRIDE and NIST.

Expect OWASP `LLM01:2025`, `LLM03:2025`, `LLM06:2025` and STRIDE
`Tampering`, `ElevationOfPrivilege`, plus the CoSAI risks behind them.

**5. An attack narrative**

> Walk me through case study AML.CS0000 step by step.

Expect an ordered attack flow: each step's tactic, the technique used, and what
the operator actually did.

**6. Reviewing another MCP server's exposure**

The server also ships a prompt, `review_mcp_tool_surface`. Paste a list of an
agent's tools and ask what an attacker controlling its input could make it do.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server not listed after restart | Config not valid JSON, or Claude not fully quit | Validate with `python3 -m json.tool`, then Cmd+Q and reopen |
| `npx: command not found` in the logs | Claude's minimal `PATH` | Use the absolute path to `npx` and set `env.PATH` as above |
| `requires Python 3.12 or newer` | Minimal `PATH` resolves to an older Python | Add the directory holding your 3.12+ build to `env.PATH`, or set `MITRE_ATLAS_PYTHON` |
| Starts, then disconnects | First-run setup exceeded the client's timeout | Run the `--setup` command from step 2, then restart |
| `command not found` when testing in a terminal | You ran `npx` inside a clone of this repo | Run it from your home directory instead |
| Tools listed but every call errors | Virtualenv half-built | `rm -rf ~/.mitre-atlas-mcp-server/runtime`, rerun `--setup` |

Logs are the fastest way to see what happened:

```bash
ls ~/Library/Logs/Claude/
tail -n 50 ~/Library/Logs/Claude/mcp-server-mitre-atlas.log
```

The server writes its own diagnostics to stderr, which is what lands there.

## What is actually running

Nothing is sent anywhere. Both datasets ship inside the package, pinned to
exact releases: MITRE ATLAS v2026.10 and the CoSAI Risk Map at commit
`622605a`. The server makes no network calls while serving, so two identical
questions return identical answers and it works offline.

The only network access is the one-time dependency install in step 2.

To remove it: delete the `mitre-atlas` block from the config, restart, and
optionally `rm -rf ~/.mitre-atlas-mcp-server`.
