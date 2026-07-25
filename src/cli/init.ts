import * as fs from 'fs';
import * as path from 'path';
import { getCraStructure } from '../cra/loader';
import type { CeproofConfig } from '../config/types';
import { validateConfig } from '../config/validate';
import { readConfigFile, writeConfigFile } from '../config/write';
import { PRODUCT_NAME } from '../branding';

export interface RunInitOptions {
  /** Project directory init runs against. */
  path: string;
  /** Config-file path override for hermetic tests. Defaults to `ceproof.config.json` under opts.path. */
  configPath?: string;
  /** Overwrite an existing config file instead of refusing. Defaults to false. */
  force?: boolean;
}

export interface RunInitResult {
  exitCode: number;
  output: string;
}

const DEFAULT_CONFIG_FILENAME = 'ceproof.config.json';

/**
 * `ceproof init` — generate `ceproof.config.json`.
 *
 * SCOPING DECISION (M1): a real interview flow would prompt interactively,
 * one question per `human-required` CraStructureItem (src/cra/types.ts), and
 * write the operator's actual answers. There's no interactive-prompt library
 * in this repo's dependency set, and picking one (inquirer, prompts, enquirer,
 * or hand-rolled readline) is a decision this milestone deliberately leaves
 * for later — M1's deliverable is "generate + validate the config shape",
 * not "build a TUI". So instead this generates a config file with honest,
 * visibly-empty placeholder values (manufacturer.name: '', product.name: '',
 * and one empty-string `answers` entry per human-required item id) and prints
 * exactly what still needs to be filled in by hand. This is consistent with
 * the never-silent-assumptions doctrine: nothing here is guessed or defaulted
 * to a plausible-looking value — every unanswered field is left visibly
 * blank and named in the output. A later milestone can swap the placeholder
 * generation for a real interactive interview without changing this
 * function's contract (opts in, { exitCode, output } out).
 *
 * Behavior:
 * - Default configPath is `ceproof.config.json` under opts.path.
 * - If that file already exists and !opts.force: refuses (exit 2), one-line
 *   message pointing at --force. Nothing is read from, or written to, the
 *   existing file.
 * - Otherwise: writes a freshly generated config, then runs validateConfig
 *   on what was actually written back off disk, and reports exactly which
 *   fields/answers still need human input before the file will validate.
 *   The freshly generated file is EXPECTED to fail validateConfig (empty
 *   manufacturer.name/product.name) — that's correct, not a bug: `init`
 *   never claims success it hasn't earned.
 */
export function runInit(opts: RunInitOptions): RunInitResult {
  const configPath = opts.configPath ?? path.join(opts.path, DEFAULT_CONFIG_FILENAME);

  if (fs.existsSync(configPath) && !opts.force) {
    return {
      exitCode: 2,
      output: `${PRODUCT_NAME} init: ${configPath} already exists. Re-run with --force to overwrite it.`,
    };
  }

  const humanRequiredItems = getCraStructure().items.filter((item) => item.derivability === 'human-required');

  const answers: Record<string, string> = {};
  for (const item of humanRequiredItems) {
    answers[item.id] = '';
  }

  const config: CeproofConfig = {
    manufacturer: { name: '' },
    product: { name: '' },
    supportPeriod: {},
    answers,
  };

  writeConfigFile(configPath, config);

  // Validate what actually landed on disk (not just the in-memory object) —
  // this is what a user would see if they hand-inspected the file, and
  // guards against writeConfigFile/readConfigFile drifting apart later.
  const readBack = readConfigFile(configPath);
  const validationErrors: string[] =
    readBack.present && 'raw' in readBack
      ? (() => {
          const result = validateConfig(readBack.raw);
          return result.valid ? [] : result.errors;
        })()
      : [`could not re-read ${configPath} after writing it`];

  // Beyond what validateConfig strictly requires (non-empty manufacturer.name
  // / product.name; answers values merely need to be strings, so an empty
  // string is technically well-typed), every answers entry generated above is
  // a placeholder that still needs a real human answer. List those
  // separately so nothing is silently left blank without being called out.
  const emptyAnswerItems = humanRequiredItems.filter((item) => answers[item.id] === '');

  const lines: string[] = [];
  lines.push(`${PRODUCT_NAME} init: wrote ${configPath}`);
  lines.push('');
  lines.push(
    'This file was generated with placeholder values only — nothing was assumed on your behalf. ' +
      'It will not pass validation until you fill in the fields below by hand:'
  );
  lines.push('');

  if (validationErrors.length > 0) {
    lines.push('Required fields:');
    for (const err of validationErrors) {
      lines.push(`  - ${err}`);
    }
    lines.push('');
  }

  if (emptyAnswerItems.length > 0) {
    lines.push(`Answers needed (${emptyAnswerItems.length} human-required CRA item(s)):`);
    for (const item of emptyAnswerItems) {
      lines.push(`  - answers.${item.id}: ${item.requirementSummary} (${item.citation})`);
    }
    lines.push('');
  }

  const totalNeeded = validationErrors.length + emptyAnswerItems.length;
  lines.push(`${totalNeeded} field(s) still need your input.`);

  return { exitCode: 0, output: lines.join('\n') };
}
