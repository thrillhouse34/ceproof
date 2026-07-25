import * as path from 'path';
import { buildReportData } from '../report/reportData';
import { renderSummary } from '../report/summary';
import { buildJsonReport } from '../report/json';
import type { JsonReportConfigStatus } from '../report/json';
import { collectRepoFacts } from '../detect';
import { getCraStructure, getCraSourceVersion } from '../cra/loader';
import { readConfigFile } from '../config/write';
import { validateConfig } from '../config/validate';
import type { CeproofConfig } from '../config/types';
import { computeGapChecklist } from '../gap/gapEngine';
import type { GapChecklistItem } from '../gap/types';
import { PRODUCT_NAME } from '../branding';

export type FailOnMode = 'human-required' | 'partial' | 'never';

export interface RunScanOptions {
  path: string;
  productionOnly: boolean;
  format: 'summary' | 'json';
  projectLicenseOverride: string | undefined;
  failOn?: FailOnMode; // default 'human-required'
  configPath?: string; // default ./ceproof.config.json under opts.path
  colorEnabled?: boolean; // defaults to computed TTY detection if omitted; explicit param mainly for tests
}

export interface RunScanResult {
  exitCode: number;
  output: string;
}

function resolveConfigStatus(configPath: string): {
  status: JsonReportConfigStatus;
  config: CeproofConfig | null;
} {
  const read = readConfigFile(configPath);

  if (!read.present) {
    return { status: { present: false, valid: null, missingAnswers: [] }, config: null };
  }
  if ('parseError' in read) {
    return { status: { present: true, valid: false, errors: [read.parseError], missingAnswers: [] }, config: null };
  }

  const result = validateConfig(read.raw);
  if (result.valid) {
    return { status: { present: true, valid: true, missingAnswers: [] }, config: result.config };
  }
  // An invalid config's fields aren't trustworthy as a whole — we don't cherry-pick
  // .answers out of a shape validateConfig rejected. Treated as "no config" for the
  // gap engine, but the JSON/summary output still honestly reports it as present+invalid.
  return { status: { present: true, valid: false, errors: result.errors, missingAnswers: [] }, config: null };
}

export async function runScan(opts: RunScanOptions): Promise<RunScanResult> {
  try {
    const data = await buildReportData(opts.path, {
      productionOnly: opts.productionOnly,
      projectLicenseOverride: opts.projectLicenseOverride,
    });

    const facts = collectRepoFacts(opts.path);
    const craStructure = getCraStructure();
    const dataVersion = getCraSourceVersion();

    const configPath = opts.configPath ?? path.join(opts.path, 'ceproof.config.json');
    const { status: configStatusBase, config } = resolveConfigStatus(configPath);

    const gapChecklist: GapChecklistItem[] = computeGapChecklist(facts, data.packages, config, craStructure.items);

    // Fill in missingAnswers from the computed checklist now that we have it —
    // this is the single source of truth for "which human-required items still
    // need an answer", never recomputed a second, possibly-divergent way.
    const configStatus: JsonReportConfigStatus = {
      ...configStatusBase,
      missingAnswers: gapChecklist.filter((i) => i.status === 'NEEDS-HUMAN-INPUT').map((i) => i.id),
    };

    const output =
      opts.format === 'json'
        ? JSON.stringify(
            buildJsonReport({
              projectName: data.projectName,
              toolVersion: data.toolVersion,
              dataVersion,
              scanTimestamp: data.scanTimestamp,
              facts,
              gapChecklist,
              configStatus,
              warnings: data.warnings,
            }),
            null,
            2,
          )
        : renderSummary({
            projectName: data.projectName,
            toolVersion: data.toolVersion,
            dataVersion,
            scanTimestamp: data.scanTimestamp,
            gapChecklist,
            configPresent: configStatus.present,
            colorEnabled: opts.colorEnabled ?? (process.stdout.isTTY === true && process.env.NO_COLOR === undefined),
          });

    const exitCode = computeExitCode(gapChecklist, opts.failOn ?? 'human-required');
    return { exitCode, output };
  } catch (err) {
    return { exitCode: 2, output: `${PRODUCT_NAME}: ${(err as Error).message}` };
  }
}

export function computeExitCode(gapChecklist: GapChecklistItem[], failOn: FailOnMode): number {
  if (failOn === 'never') return 0;
  const hasNeedsHuman = gapChecklist.some((i) => i.status === 'NEEDS-HUMAN-INPUT');
  const hasPartial = gapChecklist.some((i) => i.status === 'PARTIAL');
  if (failOn === 'human-required' && hasNeedsHuman) return 1;
  if (failOn === 'partial' && (hasNeedsHuman || hasPartial)) return 1;
  return 0;
}
