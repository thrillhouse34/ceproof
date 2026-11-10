import { buildReportData } from '../report/reportData';
import { renderSummary } from '../report/summary';
import { buildJsonReport } from '../report/json';
import type { JsonReportConfigStatus } from '../report/json';
import { collectRepoFacts } from '../detect';
import { getCraStructure, getCraSourceVersion } from '../cra/loader';
import { readConfigFile, resolveConfigPath } from '../config/write';
import { validateConfig } from '../config/validate';
import type { CeproofConfig } from '../config/types';
import { computeGapChecklist } from '../gap/gapEngine';
import type { GapChecklistItem, GapStatus } from '../gap/types';
import { runFda, NoComponentsError, SbomImportError } from '../fda/run';
import { computeFdaProfile } from '../fda/gap';
import { buildFdaProfileJson, renderFdaProfileSummary, type FdaProfileRenderInput } from '../fda/profile';
import { PRODUCT_NAME } from '../branding';

export type FailOnMode = 'human-required' | 'partial' | 'never';

/**
 * `scan`'s two profiles. `cra` is the original behaviour and the default —
 * nothing about an existing invocation changes. `fda` is the free FDA-profile
 * gap view (src/fda/gap.ts): the same DERIVED/PARTIAL/NEEDS-HUMAN-INPUT
 * vocabulary, the same `--format` and `--fail-on` flags and the same exit
 * codes, resolved against `data/fda-structure.json` instead of
 * `data/cra-structure.json`.
 */
export const SCAN_PROFILES = ['cra', 'fda'] as const;
export type ScanProfile = (typeof SCAN_PROFILES)[number];

/**
 * `--fail-on`'s default, per profile. Not one constant, because the two
 * profiles have different arithmetic underneath them.
 *
 *  - `cra` keeps `human-required`, exactly as it always has. Every existing
 *    invocation, workflow and action input behaves identically.
 *  - `fda` is REPORT-ONLY by default (`never`, exit 0). Three of its thirteen
 *    items are permanently NEEDS-HUMAN-INPUT by design — the risk assessment,
 *    the risk controls and the cyber-device determination are the things no
 *    tool can answer — so `human-required` would fail every run of this
 *    profile forever, no matter how complete the SBOM. An exit code that is
 *    red on a perfect run is not a signal; it teaches people to stop reading
 *    the exit code. Failing the build on this profile is opt-in: pass
 *    `--fail-on partial` or `--fail-on human-required` deliberately.
 *
 * The findings themselves are unaffected — report-only changes the exit code
 * and nothing else. The summary and the JSON report say exactly what they said
 * before.
 */
export const DEFAULT_FAIL_ON: Record<ScanProfile, FailOnMode> = {
  cra: 'human-required',
  fda: 'never',
};

export interface RunScanOptions {
  path: string;
  productionOnly: boolean;
  format: 'summary' | 'json';
  projectLicenseOverride: string | undefined;
  failOn?: FailOnMode; // default: DEFAULT_FAIL_ON[profile] — 'human-required' for cra, 'never' (report-only) for fda
  configPath?: string; // default ./ceproof.config.json under opts.path
  colorEnabled?: boolean; // defaults to computed TTY detection if omitted; explicit param mainly for tests
  /** Default 'cra' — the original behaviour, unchanged. */
  profile?: ScanProfile;
  /** `--sbom <file>`, repeatable. Read by the fda profile only; passing it to the cra profile is a usage error rather than a silent no-op. */
  sbomPaths?: string[];
  /** The run date, YYYY-MM-DD. Injected by tests; defaults to today. */
  asOf?: string;
  /** Full ISO timestamp of the run. Injected by tests; defaults to now. */
  generatedAt?: string;
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

/**
 * The free FDA-profile view. Same flags, same statuses, same exit codes as the
 * CRA profile — a user who knows one knows the other.
 *
 * Nothing here is gated and nothing here writes a file. The paid pack is
 * `report --format fda-pack`, and the one difference in substance between the
 * two is that this view reports the counts and the gaps while that one
 * produces the documents.
 */
async function runFdaProfile(opts: RunScanOptions): Promise<RunScanResult> {
  const run = await runFda({
    path: opts.path,
    sbomPaths: opts.sbomPaths ?? [],
    productionOnly: opts.productionOnly,
    ...(opts.configPath ? { configPath: opts.configPath } : {}),
    ...(opts.asOf ? { asOf: opts.asOf } : {}),
    ...(opts.generatedAt ? { generatedAt: opts.generatedAt } : {}),
  });
  const profile = computeFdaProfile(run.input, run.rows);
  const { input } = run;

  const renderInput: FdaProfileRenderInput = {
    profile,
    toolVersion: input.toolVersion,
    generatedAt: input.generatedAt,
    asOf: input.asOf,
    ...(input.subject
      ? {
          device: {
            name: input.subject.name,
            ...(input.subject.version ? { version: input.subject.version } : {}),
            ...(input.subject.supplier ? { supplier: input.subject.supplier } : {}),
          },
        }
      : {}),
    ...(input.sbomAuthor ? { sbomAuthor: input.sbomAuthor } : {}),
    ...(input.scanPath ? { repoScan: input.scanPath } : {}),
    sboms: input.sbomInputs.map((sbom) => ({
      sourceLabel: sbom.sourceLabel,
      specVersion: sbom.specVersion,
      ...(sbom.sha256 ? { sha256: sbom.sha256 } : {}),
      componentCount: sbom.componentCount,
    })),
    fdaData: {
      eolSnapshotGeneratedAt: input.support.snapshotSource.upstreamGeneratedAt,
      eolSnapshotSha256: input.support.snapshotSource.upstreamSha256,
      kevCatalogVersion: input.kev.snapshotSource.catalogVersion,
      kevSnapshotReleased: input.kev.snapshotSource.dateReleased,
      osvQueriedAt: input.kev.indexBuiltFrom.osvQueriedAt,
    },
    limits: input.kev.limits,
  };

  const output =
    opts.format === 'json'
      ? JSON.stringify(buildFdaProfileJson(renderInput), null, 2)
      : renderFdaProfileSummary(renderInput, opts.colorEnabled ?? (process.stdout.isTTY === true && process.env.NO_COLOR === undefined));

  // The same thresholds `--fail-on` already means for the CRA profile, over
  // the FDA items. `computeExitCode` takes the status list, so it needs no
  // change to serve both. Only the DEFAULT differs — see DEFAULT_FAIL_ON.
  return { exitCode: computeExitCode(profile.items, opts.failOn ?? DEFAULT_FAIL_ON.fda), output };
}

export async function runScan(opts: RunScanOptions): Promise<RunScanResult> {
  const profile = opts.profile ?? 'cra';
  if ((opts.sbomPaths?.length ?? 0) > 0 && profile !== 'fda') {
    return {
      exitCode: 2,
      output:
        `${PRODUCT_NAME} scan: --sbom is only read by the FDA profile, so the file would have been ignored. ` +
        `Run \`${PRODUCT_NAME} scan --profile fda --sbom <file>\`, or drop --sbom.`,
    };
  }
  if (profile === 'fda') {
    try {
      return await runFdaProfile(opts);
    } catch (err) {
      // An unreadable or unsupported --sbom file and an empty component list
      // are usage errors about what the user supplied; both messages already
      // name the real problem.
      if (err instanceof SbomImportError || err instanceof NoComponentsError) {
        return { exitCode: 2, output: `${PRODUCT_NAME} scan: ${err.message}` };
      }
      return { exitCode: 2, output: `${PRODUCT_NAME} scan: ${(err as Error).message}` };
    }
  }
  try {
    // Resolved FIRST, before any scan work: a `--config` path that doesn't
    // exist is a usage error, and there's no reason to make the user wait
    // through a full dependency scan to be told about a typo.
    const configPath = resolveConfigPath(opts.path, opts.configPath);

    const data = await buildReportData(opts.path, {
      productionOnly: opts.productionOnly,
      projectLicenseOverride: opts.projectLicenseOverride,
    });

    const facts = collectRepoFacts(opts.path);
    const craStructure = getCraStructure();
    const dataVersion = getCraSourceVersion();

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

    const exitCode = computeExitCode(gapChecklist, opts.failOn ?? DEFAULT_FAIL_ON.cra);
    return { exitCode, output };
  } catch (err) {
    return { exitCode: 2, output: `${PRODUCT_NAME}: ${(err as Error).message}` };
  }
}

/**
 * `--fail-on` over any list of resolved items. Typed on `{ status }` rather
 * than `GapChecklistItem` so the FDA profile's items (which carry a `measure`
 * instead of an `instrument`) go through the same thresholds — the exit-code
 * contract is about statuses and nothing else.
 */
export function computeExitCode(gapChecklist: { status: GapStatus }[], failOn: FailOnMode): number {
  if (failOn === 'never') return 0;
  const hasNeedsHuman = gapChecklist.some((i) => i.status === 'NEEDS-HUMAN-INPUT');
  const hasPartial = gapChecklist.some((i) => i.status === 'PARTIAL');
  if (failOn === 'human-required' && hasNeedsHuman) return 1;
  if (failOn === 'partial' && (hasNeedsHuman || hasPartial)) return 1;
  return 0;
}
