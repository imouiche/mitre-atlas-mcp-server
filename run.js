#!/usr/bin/env node
//
// npm entry point for a Python MCP server.
//
// The npm package ships the Python source and the vendored datasets, but not
// the Python dependencies. Rather than requiring the user to have mcp and
// pyyaml already installed, this provisions a private virtualenv and installs
// the specifiers declared in the bundled pyproject.toml, so the pinned
// `mcp>=2.3.0,<3` bound reaches npm users too.
//
// The install is small and quick: the ATLAS and CoSAI datasets are already in
// the package, so nothing is downloaded at runtime.
//
// Escape hatches:
//   MITRE_ATLAS_PYTHON=/path/to/python   use this interpreter as-is, no venv
//   MITRE_ATLAS_RUNTIME_DIR=/path        where to keep the cached venv
//   --setup                              provision and exit

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const MIN_PY = [3, 12];
const PKG_DIR = __dirname;
const SRC_DIR = path.join(PKG_DIR, 'src');
const PYPROJECT = path.join(PKG_DIR, 'pyproject.toml');
const PKG_VERSION = require(path.join(PKG_DIR, 'package.json')).version;

const RUNTIME_ROOT =
  process.env.MITRE_ATLAS_RUNTIME_DIR ||
  path.join(os.homedir(), '.mitre-atlas-mcp-server', 'runtime');

const setupOnly = process.argv.includes('--setup');

// Progress goes to stderr only: stdout is the MCP stdio channel and must carry
// nothing but protocol traffic.
const log = (msg) => process.stderr.write(`mitre-atlas-mcp-server: ${msg}\n`);

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, { encoding: 'utf8', ...opts });
}

function pyVersion(cmd) {
  const r = run(cmd, ['-c', 'import sys; print("%d.%d" % sys.version_info[:2])']);
  if (r.error || r.status !== 0) return null;
  const [maj, min] = r.stdout.trim().split('.').map(Number);
  if (Number.isNaN(maj)) return null;
  return { maj, min, ok: maj > MIN_PY[0] || (maj === MIN_PY[0] && min >= MIN_PY[1]) };
}

// Generic names first and deliberately: inside an activated virtualenv
// `python3` IS that venv's interpreter. Version-specific names are a fallback
// for hosts where the generic ones are missing or too old.
function findPython() {
  const candidates = ['python3', 'python', 'python3.14', 'python3.13', 'python3.12'];
  const tooOld = [];
  for (const cmd of candidates) {
    const v = pyVersion(cmd);
    if (!v) continue;
    if (v.ok) return { cmd, label: `${v.maj}.${v.min}` };
    tooOld.push(`${cmd} (${v.maj}.${v.min})`);
  }
  const found = tooOld.length
    ? `Found only: ${tooOld.join(', ')}.`
    : 'No Python interpreter was found on PATH.';
  log(
    `requires Python ${MIN_PY.join('.')} or newer. ${found}\n` +
      `  Install Python ${MIN_PY.join('.')}+ and try again, or point\n` +
      `  MITRE_ATLAS_PYTHON at a suitable interpreter.`
  );
  process.exit(1);
}

// Read [project].dependencies out of the bundled pyproject.toml so the version
// bounds live in exactly one place. tomllib is stdlib from Python 3.11.
function readDependencies(python) {
  // Newline-joined, not ';'-joined: a `with` statement cannot follow a
  // semicolon in Python.
  const code = [
    'import tomllib, json, sys',
    'with open(sys.argv[1], "rb") as f:',
    '    d = tomllib.load(f)',
    'print(json.dumps(d["project"]["dependencies"]))',
  ].join('\n');
  const r = run(python, ['-c', code, PYPROJECT]);
  if (r.status !== 0) {
    log(`could not read dependencies from ${PYPROJECT}\n${r.stderr || ''}`);
    process.exit(1);
  }
  try {
    const deps = JSON.parse(r.stdout);
    if (!Array.isArray(deps) || deps.length === 0) throw new Error('empty');
    return deps;
  } catch {
    log('pyproject.toml declared no usable dependencies');
    process.exit(1);
  }
}

const venvPython = (dir) =>
  process.platform === 'win32'
    ? path.join(dir, 'Scripts', 'python.exe')
    : path.join(dir, 'bin', 'python');

// A venv is usable only if the dependencies actually import. Checking a marker
// file would leave a half-installed venv looking healthy.
function venvIsHealthy(dir) {
  const py = venvPython(dir);
  if (!fs.existsSync(py)) return false;
  return run(py, ['-c', 'import mcp.server.mcpserver, yaml'], {
    env: { ...process.env, PYTHONPATH: SRC_DIR },
  }).status === 0;
}

function provision(bootstrapPython, pyLabel) {
  const dir = path.join(RUNTIME_ROOT, `venv-${PKG_VERSION}-py${pyLabel}`);
  if (venvIsHealthy(dir)) return venvPython(dir);

  const deps = readDependencies(bootstrapPython);
  const hasUv = run('uv', ['--version']).status === 0;

  log('first run: preparing a private Python environment (one time).');
  log(`  location: ${dir}`);
  log(`  installing: ${deps.join(', ')}`);

  fs.mkdirSync(RUNTIME_ROOT, { recursive: true });

  if (hasUv) {
    if (run('uv', ['venv', '--python', bootstrapPython, dir], { stdio: 'inherit' }).status !== 0) {
      log('`uv venv` failed');
      process.exit(1);
    }
    if (
      run('uv', ['pip', 'install', '--python', venvPython(dir), ...deps], { stdio: 'inherit' })
        .status !== 0
    ) {
      log('`uv pip install` failed');
      process.exit(1);
    }
  } else {
    if (run(bootstrapPython, ['-m', 'venv', dir], { stdio: 'inherit' }).status !== 0) {
      log(`\`${bootstrapPython} -m venv\` failed. On Debian/Ubuntu you may need python3-venv.`);
      process.exit(1);
    }
    const py = venvPython(dir);
    run(py, ['-m', 'pip', 'install', '--quiet', '--upgrade', 'pip'], { stdio: 'inherit' });
    if (run(py, ['-m', 'pip', 'install', ...deps], { stdio: 'inherit' }).status !== 0) {
      log('pip install failed');
      process.exit(1);
    }
  }

  if (!venvIsHealthy(dir)) {
    log(
      'environment was created but its dependencies do not import.\n' +
        `  Remove ${dir} and try again, or set MITRE_ATLAS_PYTHON to an\n` +
        '  interpreter that already has them installed.'
    );
    process.exit(1);
  }

  log('environment ready. Subsequent runs start immediately.');
  return venvPython(dir);
}

function resolveInterpreter() {
  // Caller-supplied interpreter: trust it, but verify the imports so a wrong
  // one fails with a readable message instead of a traceback mid-handshake.
  const override = process.env.MITRE_ATLAS_PYTHON;
  if (override) {
    const v = pyVersion(override);
    if (!v) {
      log(`MITRE_ATLAS_PYTHON=${override} is not a working Python interpreter`);
      process.exit(1);
    }
    if (!v.ok) {
      log(`MITRE_ATLAS_PYTHON=${override} is Python ${v.maj}.${v.min}; need ${MIN_PY.join('.')}+`);
      process.exit(1);
    }
    const r = run(override, ['-c', 'import mcp.server.mcpserver, yaml'], {
      env: { ...process.env, PYTHONPATH: SRC_DIR },
    });
    if (r.status !== 0) {
      const detail = (r.stderr || '').trim().split('\n').slice(-1)[0];
      log(
        `MITRE_ATLAS_PYTHON=${override} is missing dependencies.\n` +
          `  ${detail}\n` +
          '  Install them there, or unset MITRE_ATLAS_PYTHON to let this package\n' +
          '  manage its own environment.'
      );
      process.exit(1);
    }
    return override;
  }

  const { cmd, label } = findPython();
  return provision(cmd, label);
}

const python = resolveInterpreter();

if (setupOnly) {
  log('setup complete.');
  process.exit(0);
}

const server = spawn(python, ['-m', 'mitre_atlas_mcp.server'], {
  stdio: 'inherit',
  cwd: PKG_DIR,
  env: {
    ...process.env,
    PYTHONPATH: SRC_DIR + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : ''),
  },
});

server.on('error', (err) => {
  log(`failed to start: ${err.message}`);
  process.exit(1);
});

server.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code === null ? 1 : code);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.kill(sig));
}
