import * as fs from 'fs';
import { licenseKeyPath } from '../license/discovery';
import { PRODUCT_NAME } from '../branding';

export interface RunDeactivateOptions {
  /** Key-file path override for hermetic tests. Defaults to `licenseKeyPath()`. */
  keyFilePath?: string;
}

export interface RunDeactivateResult {
  exitCode: number;
  output: string;
}

/**
 * `ceproof deactivate` — remove the stored license key at
 * `~/.config/ceproof/license.key`. Idempotent: no error if the file is
 * already absent. Prints a confirmation either way, exit code 0.
 *
 * NOT registered in the CLI as of M1 (see cli/index.ts) — kept compiling and
 * unit-tested so a later milestone can wire it back in alongside `activate`
 * and a paid `report` command.
 */
export function runDeactivate(opts: RunDeactivateOptions = {}): RunDeactivateResult {
  const target = opts.keyFilePath ?? licenseKeyPath();
  try {
    if (fs.existsSync(target)) {
      fs.rmSync(target);
      return {
        exitCode: 0,
        output:
          `${PRODUCT_NAME}: deactivated. The stored license key was removed; the ` +
          'report command’s paid formats will need a key again.',
      };
    }
  } catch (err) {
    // Exceptional (e.g. a permissions problem on the user's own config file).
    // Still exit 0 — deactivate is a "make sure it's gone" operation — but say so.
    return {
      exitCode: 0,
      output: `${PRODUCT_NAME}: could not remove ${target}: ${(err as Error).message}`,
    };
  }
  return {
    exitCode: 0,
    output: `${PRODUCT_NAME}: no active license key was found. Nothing to remove.`,
  };
}
