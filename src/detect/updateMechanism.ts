/**
 * Detects presence of automated dependency-update tooling configuration at
 * a project root: Dependabot (.github/dependabot.yml or
 * .github/dependabot.yaml) and Renovate (renovate.json, renovate.json5,
 * .renovaterc, .renovaterc.json, or a "renovate" key inside package.json).
 *
 * Facts-only: this detector makes no judgment about whether a found config
 * is well-formed or effective — it only reports presence.
 *
 * The package.json "renovate" key is only checked when package.json exists
 * and parses as valid JSON; a malformed package.json is treated as "no
 * embedded renovate config found" rather than thrown as an error (per the
 * "run() must not throw for the nothing-found case" doctrine in ./types).
 */
import * as fs from 'fs';
import * as path from 'path';
import type { Detector, UpdateMechanismFacts } from './types';

const DEPENDABOT_CANDIDATES = [path.join('.github', 'dependabot.yml'), path.join('.github', 'dependabot.yaml')];
const RENOVATE_FILE_CANDIDATES = ['renovate.json', 'renovate.json5', '.renovaterc', '.renovaterc.json'];

function anyExists(projectPath: string, candidates: string[]): boolean {
  return candidates.some((candidate) => fs.existsSync(path.join(projectPath, candidate)));
}

/** Returns true only if package.json exists, parses as valid JSON, and has a "renovate" key. */
function hasEmbeddedRenovateConfig(projectPath: string): boolean {
  const pkgPath = path.join(projectPath, 'package.json');
  if (!fs.existsSync(pkgPath)) return false;

  let raw: string;
  try {
    raw = fs.readFileSync(pkgPath, 'utf8');
  } catch {
    return false;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return false;
  }

  return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) && 'renovate' in parsed;
}

function run(projectPath: string): UpdateMechanismFacts {
  const dependabotPresent = anyExists(projectPath, DEPENDABOT_CANDIDATES);
  const renovatePresent = anyExists(projectPath, RENOVATE_FILE_CANDIDATES) || hasEmbeddedRenovateConfig(projectPath);

  return {
    dependabotPresent,
    renovatePresent,
  };
}

export const updateMechanismDetector: Detector<UpdateMechanismFacts> = { id: 'update-mechanism', run };
