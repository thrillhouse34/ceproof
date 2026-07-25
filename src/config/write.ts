import * as fs from 'fs';
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
