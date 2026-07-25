import * as fs from 'fs';
import * as path from 'path';
import { parse as parseToml } from 'smol-toml';
import type { Detector, RuntimeFacts } from './types';

/**
 * Read package.json's "engines"."node" field, if present as a non-empty
 * string. Malformed/unreadable package.json yields undefined (UNKNOWN),
 * never a crash — mirrors readNpmDeclaredLicense in ./projectLicense.ts.
 */
function readNodeEngine(projectPath: string): string | undefined {
  const pkgJsonPath = path.join(projectPath, 'package.json');
  if (!fs.existsSync(pkgJsonPath)) return undefined;
  let manifest: { engines?: { node?: unknown } };
  try {
    manifest = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  } catch {
    return undefined; // malformed package.json — UNKNOWN, not a crash
  }
  const node = manifest.engines?.node;
  return typeof node === 'string' && node.length > 0 ? node : undefined;
}

/**
 * Read pyproject.toml's PEP 621 `[project]` `requires-python` field, if
 * present as a non-empty string. Malformed/unreadable/absent pyproject.toml
 * yields undefined (UNKNOWN), never a crash.
 */
function readPyprojectRequiresPython(projectPath: string): string | undefined {
  const pyprojectPath = path.join(projectPath, 'pyproject.toml');
  if (!fs.existsSync(pyprojectPath)) return undefined;
  let doc: Record<string, unknown>;
  try {
    doc = parseToml(fs.readFileSync(pyprojectPath, 'utf8')) as Record<string, unknown>;
  } catch {
    return undefined; // malformed pyproject.toml — UNKNOWN, not a crash
  }

  const project = doc.project as Record<string, unknown> | undefined;
  const requiresPython = project?.['requires-python'];
  return typeof requiresPython === 'string' && requiresPython.length > 0 ? requiresPython : undefined;
}

/**
 * Read setup.cfg's `[options]` section `python_requires` key, if present as
 * a non-empty value. setup.cfg is INI, not TOML — this is a minimal
 * line-based reader scoped to exactly the one section/key this detector
 * needs, not a general INI parser. Malformed/unreadable/absent setup.cfg
 * yields undefined (UNKNOWN), never a crash.
 */
function readSetupCfgPythonRequires(projectPath: string): string | undefined {
  const setupCfgPath = path.join(projectPath, 'setup.cfg');
  if (!fs.existsSync(setupCfgPath)) return undefined;
  let raw: string;
  try {
    raw = fs.readFileSync(setupCfgPath, 'utf8');
  } catch {
    return undefined; // unreadable setup.cfg — UNKNOWN, not a crash
  }

  const lines = raw.split(/\r\n|\n|\r/);
  let inOptionsSection = false;
  for (const line of lines) {
    const sectionMatch = line.match(/^\s*\[([^\]]+)]\s*(?:[;#].*)?$/);
    if (sectionMatch) {
      inOptionsSection = sectionMatch[1].trim() === 'options';
      continue;
    }
    if (!inOptionsSection) continue;

    // A continuation line (indented, no "key = value") belongs to a
    // multi-line value of the previous key — python_requires is always a
    // single-line value in practice, so continuation lines are irrelevant
    // here and simply skipped rather than mis-parsed as a new key.
    const kvMatch = line.match(/^([A-Za-z0-9_.-]+)\s*[:=]\s*(.*)$/);
    if (!kvMatch) continue;
    if (kvMatch[1].trim() !== 'python_requires') continue;

    const value = kvMatch[2].trim();
    return value.length > 0 ? value : undefined;
  }
  return undefined;
}

function run(projectPath: string): RuntimeFacts {
  const node = readNodeEngine(projectPath);
  // pyproject.toml's PEP 621 requires-python takes precedence over the
  // setup.cfg fallback per the task's stated ordering (pyproject.toml wins
  // when it declares the field at all).
  const python = readPyprojectRequiresPython(projectPath) ?? readSetupCfgPythonRequires(projectPath);

  return {
    ...(node !== undefined ? { node } : {}),
    ...(python !== undefined ? { python } : {}),
  };
}

export const runtimesDetector: Detector<RuntimeFacts> = { id: 'runtimes', run };
