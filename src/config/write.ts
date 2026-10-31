import * as fs from 'fs';
import * as nodePath from 'path';
import type { CeproofConfig } from './types';

export type ReadConfigFileResult =
  | { present: false }
  | { present: true; raw: unknown }
  | { present: true; parseError: string };

/**
 * Reads and JSON.parses `path`, if it exists.
 *
 * - Missing file: `{ present: false }` — not a throw. Only ENOENT is treated
 *   this way; a genuinely unexpected fs error (e.g. EACCES) propagates as a
 *   thrown exception rather than being silently swallowed into "not present",
 *   since that would misreport a real permissions problem as a simple
 *   first-run case.
 * - Present but invalid JSON: `{ present: true, parseError }` — not a throw,
 *   so callers can present a clear, actionable message instead of an
 *   unhandled exception.
 * - Present and valid JSON: `{ present: true, raw }` — the caller is
 *   responsible for shape-validating `raw` (see validateConfig).
 */
export function readConfigFile(path: string): ReadConfigFileResult {
  let text: string;
  try {
    text = fs.readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { present: false };
    }
    throw err;
  }

  try {
    return { present: true, raw: JSON.parse(text) };
  } catch (err) {
    return { present: true, parseError: `Invalid JSON in ${path}: ${(err as Error).message}` };
  }
}

/**
 * Writes `config` to `path` as pretty-printed (2-space indent) JSON with a
 * trailing newline.
 */
export function writeConfigFile(path: string, config: CeproofConfig): void {
  fs.writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
}

/** The conventional config filename, looked for under the scanned project path. */
export const CONFIG_FILENAME = 'ceproof.config.json';

/**
 * Thrown when `--config <path>` names a file that isn't there. Distinct type so
 * callers can map it to a usage exit code rather than guessing from the message.
 */
export class ConfigFileNotFoundError extends Error {
  constructor(configPath: string) {
    super(`config file not found: ${configPath}`);
    this.name = 'ConfigFileNotFoundError';
  }
}

/**
 * Resolves which config file a command should read: the explicitly-passed
 * `--config` value if there is one, else `<projectPath>/ceproof.config.json`.
 *
 * An explicitly-passed path that doesn't exist is a usage error, NOT a
 * first-run case. Treating it as "no config present" (what this used to do by
 * falling straight through to readConfigFile) silently discards every answer
 * the user wrote and then fails their build on the very items that config was
 * answering, with nothing on screen explaining why — a single typo in a CI
 * workflow looked exactly like a genuine wall of open CRA items. The DEFAULT
 * path is still allowed to be absent: that one genuinely is the first run.
 */
export function resolveConfigPath(projectPath: string, explicitPath?: string): string {
  if (explicitPath === undefined) return nodePath.join(projectPath, CONFIG_FILENAME);
  if (!fs.existsSync(explicitPath)) throw new ConfigFileNotFoundError(explicitPath);
  return explicitPath;
}
