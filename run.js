#!/usr/bin/env node
//
// npm entry point. The server itself is Python; this shim locates a suitable
// interpreter and execs the module with the bundled source on PYTHONPATH.
//
// Improvement over the ATT&CK server's shim: that one hardcoded `python`, which
// fails on the many systems where only `python3` is on PATH, and gave no
// actionable message when the Python dependencies were missing.

const { spawn, spawnSync } = require('child_process');
const path = require('path');

const MIN_PY = [3, 12];
const srcPath = path.join(__dirname, 'src');

function probe(cmd) {
  const r = spawnSync(cmd, ['-c', 'import sys; print("%d.%d" % sys.version_info[:2])'], {
    encoding: 'utf8',
  });
  if (r.error || r.status !== 0) return null;
  const [maj, min] = r.stdout.trim().split('.').map(Number);
  if (maj > MIN_PY[0] || (maj === MIN_PY[0] && min >= MIN_PY[1])) return { cmd, version: `${maj}.${min}` };
  return { cmd, version: `${maj}.${min}`, tooOld: true };
}

function resolvePython() {
  // Generic names first and deliberately: inside a virtualenv `python3` IS the
  // venv interpreter, the one with the dependencies installed. Probing
  // `python3.13` first would pick a bare system interpreter over it.
  // Version-specific names are only a fallback for hosts where the generic
  // ones are absent or too old.
  const candidates = ['python3', 'python', 'python3.14', 'python3.13', 'python3.12'];
  const seen = [];
  for (const c of candidates) {
    const r = probe(c);
    if (!r) continue;
    if (!r.tooOld) return r.cmd;
    seen.push(`${c} (${r.version})`);
  }
  const found = seen.length ? `Found only: ${seen.join(', ')}.` : 'No Python interpreter found on PATH.';
  console.error(
    `mitre-atlas-mcp-server requires Python ${MIN_PY.join('.')} or newer. ${found}\n` +
      `Install Python ${MIN_PY.join('.')}+, or run the server directly from PyPI:\n` +
      `  uvx mitre-atlas-mcp-server`
  );
  process.exit(1);
}

const python = resolvePython();

// Verify the Python dependencies are importable before handing over stdio,
// so a missing dep surfaces as a readable message rather than a traceback
// interleaved with the MCP handshake.
// Keep this list in step with [project.dependencies] in pyproject.toml.
const depCheck = spawnSync(python, ['-c', 'import mcp, yaml'], {
  encoding: 'utf8',
  env: { ...process.env, PYTHONPATH: srcPath },
});
if (depCheck.status !== 0) {
  console.error(
    `mitre-atlas-mcp-server: Python dependencies are not installed for ${python}.\n` +
      `Install them with one of:\n` +
      `  ${python} -m pip install "mcp>=2.3.0,<3" "pyyaml>=6"\n` +
      `  uvx mitre-atlas-mcp-server   # preferred: isolated, no global install\n`
  );
  process.exit(1);
}

const server = spawn(python, ['-m', 'mitre_atlas_mcp.server'], {
  stdio: 'inherit',
  cwd: __dirname,
  env: {
    ...process.env,
    PYTHONPATH: srcPath + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : ''),
  },
});

server.on('error', (err) => {
  console.error(`Failed to start server: ${err.message}`);
  process.exit(1);
});

server.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code === null ? 1 : code);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.kill(sig));
}
