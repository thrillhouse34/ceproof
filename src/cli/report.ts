import * as fs from 'fs';
import * as path from 'path';
import { buildReportData, NoProjectFoundError, type ReportData } from '../report/reportData';
import { renderAnnexHtml } from '../report/html';
import { renderAnnexPdf } from '../report/pdf';
import { renderCycloneDx } from '../report/sbom/cyclonedx';
import { renderSpdx } from '../report/sbom/spdx';
import { computeAnnexViiPackContent, computeAnnexVDocContent } from '../report/annexContent';
import { computeProvenance } from '../report/provenance';
import { collectRepoFacts } from '../detect';
import { getCraStructure, getCraSourceVersion } from '../cra/loader';
import { readConfigFile } from '../config/write';
import { validateConfig } from '../config/validate';
import type { CeproofConfig } from '../config/types';
import { computeGapChecklist } from '../gap/gapEngine';
import { discoverLicenseKey } from '../license/discovery';
import { verifyLicenseKey, type LicenseInfo } from '../license/verify';
import { dataCurrencyNote } from '../license/dataCurrency';
import { PRODUCT_NAME, PRODUCT_URL, PRICE_INDIVIDUAL, PRICE_AGENCY } from '../branding';

// `report` renders the paid Annex VII technical documentation pack and
// Annex V Declaration of Conformity draft (both driven by the same
// data/cra-structure.json + gap-checklist engine `scan` uses), plus the free
// standalone SBOM formats. See milestone2_brief.md for the M2 content model
// and milestone3_brief.md (M3) for the gating below.

export const REPORT_FORMATS = ['annex7', 'annex7-pdf', 'doc', 'doc-pdf', 'sbom-cyclonedx', 'sbom-spdx'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

/**
 * The four narrative formats — the actual paid product — require a valid
 * license key. `sbom-cyclonedx`/`sbom-spdx` stay free: per the M1 plan's
 * SBOM-placement decision, the SBOM isn't the differentiated paid product —
 * it's largely mechanical output of the already-free `scan` engine, and
 * CRA's Annex VII SBOM requirement is closer to required plumbing than
 * compiled deliverable. The paid product is the compiled, cited, per-release
 * narrative pack + DoC.
 */
const GATED_FORMATS: ReadonlySet<ReportFormat> = new Set<ReportFormat>(['annex7', 'annex7-pdf', 'doc', 'doc-pdf']);

/** Request refused for lack of a key. */
export const EXIT_UNLICENSED = 3;

/**
 * The friendly, non-naggy refusal shown when a gated format is requested
 * without a valid key. States what the paid report includes, the price, and
 * where to buy.
 */
const UNLICENSED_MESSAGE = [
  `This report format needs a ${PRODUCT_NAME} license.`,
  '',
  'The paid report gives you an audit-ready Annex VII technical documentation',
  `pack and Annex V Declaration of Conformity draft. It is a perpetual license:`,
  `${PRICE_INDIVIDUAL} individual, ${PRICE_AGENCY} agency. See samples and buy a key at ${PRODUCT_URL}`,
  '',
  `Already have a key? Run:  ${PRODUCT_NAME} activate <key>`,
  'The free scan, JSON output, and SBOM formats never need a key.',
].join('\n');

/** Default per-format filenames used whenever `--out` names a directory (or is omitted). */
const DEFAULT_FILENAMES: Record<ReportFormat, string> = {
  annex7: 'annex7.html',
  'annex7-pdf': 'annex7.pdf',
  doc: 'doc.html',
  'doc-pdf': 'doc.pdf',
  'sbom-cyclonedx': 'sbom.cyclonedx.json',
  'sbom-spdx': 'sbom.spdx.json',
};

/** Default output directory when `--out` is omitted. */
const DEFAULT_OUT_DIR = `./${PRODUCT_NAME}-report`;

const VALID_LIST = REPORT_FORMATS.join(', ');

export interface RunReportOptions {
  path: string;
  productionOnly: boolean;
  /** Raw requested formats (comma-list already expanded by the CLI collector). Validated here. */
  formats: string[];
  /** `--out` value: a single file path (one format) or a directory (multiple/omitted). */
  out?: string;
  projectLicenseOverride?: string;
  configPath?: string; // default <path>/ceproof.config.json, same convention as `scan`
  /** The `--key <string>` value, if the user passed one on `report` (highest-priority key source). */
  key?: string;
  /** Environment to resolve the `CEPROOF_KEY` var from. Defaults to `process.env`; injectable for hermetic tests. */
  env?: NodeJS.ProcessEnv;
  /** License-key-file path override. Defaults to `~/.config/ceproof/license.key`; injectable for hermetic tests. */
  keyFilePath?: string;
}

export interface RunReportResult {
  exitCode: number;
  output: string;
}

/**
 * Resolves the on-disk config (if any) into a `CeproofConfig | null` for the
 * content builders. An absent or invalid config degrades to `null` — every
 * item that would have needed it just renders as an honest open item; this
 * never throws.
 */
function resolveConfig(configPath: string): CeproofConfig | null {
  const read = readConfigFile(configPath);
  if (!read.present || 'parseError' in read) return null;
  const result = validateConfig(read.raw);
  return result.valid ? result.config : null;
}

interface AnnexContext {
  data: ReportData;
  provenance: ReturnType<typeof computeProvenance>;
  craItems: ReturnType<typeof getCraStructure>['items'];
  config: CeproofConfig | null;
  gapChecklist: ReturnType<typeof computeGapChecklist>;
}

/**
 * The shared scan+facts+gap-checklist+provenance assembly both annex7 and doc
 * formats need. Computed at most once per `runReport` call regardless of how
 * many of the two formats are requested together (see the memoized call site
 * in `renderFormat`'s caller).
 */
async function buildAnnexContext(opts: RunReportOptions): Promise<AnnexContext> {
  const data = await buildReportData(opts.path, {
    productionOnly: opts.productionOnly,
    projectLicenseOverride: opts.projectLicenseOverride,
  });
  const facts = collectRepoFacts(opts.path);
  const craStructure = getCraStructure();
  const dataVersion = getCraSourceVersion();
  const configPath = opts.configPath ?? path.join(opts.path, 'ceproof.config.json');
  const config = resolveConfig(configPath);
  const gapChecklist = computeGapChecklist(facts, data.packages, config, craStructure.items);
  const provenance = computeProvenance({
    toolVersion: data.toolVersion,
    dataVersion,
    scanTimestamp: data.scanTimestamp,
    vcs: facts.vcs,
  });
  return { data, provenance, craItems: craStructure.items, config, gapChecklist };
}

/** Produce the artifact bytes for one format. String artifacts and the binary PDFs are both handled. */
async function renderFormat(
  fmt: ReportFormat,
  sbomData: ReportData,
  annexCtx: AnnexContext | undefined
): Promise<string | Buffer> {
  switch (fmt) {
    case 'annex7': {
      const ctx = annexCtx!;
      const content = computeAnnexViiPackContent(ctx.craItems, ctx.gapChecklist, ctx.config, ctx.provenance, ctx.data.projectName);
      return renderAnnexHtml(content);
    }
    case 'annex7-pdf': {
      const ctx = annexCtx!;
      const content = computeAnnexViiPackContent(ctx.craItems, ctx.gapChecklist, ctx.config, ctx.provenance, ctx.data.projectName);
      return renderAnnexPdf(renderAnnexHtml(content), content);
    }
    case 'doc': {
      const ctx = annexCtx!;
      const content = computeAnnexVDocContent(ctx.craItems, ctx.gapChecklist, ctx.config, ctx.provenance, ctx.data.projectName);
      return renderAnnexHtml(content);
    }
    case 'doc-pdf': {
      const ctx = annexCtx!;
      const content = computeAnnexVDocContent(ctx.craItems, ctx.gapChecklist, ctx.config, ctx.provenance, ctx.data.projectName);
      return renderAnnexPdf(renderAnnexHtml(content), content);
    }
    case 'sbom-cyclonedx':
      return renderCycloneDx(sbomData);
    case 'sbom-spdx':
      return renderSpdx(sbomData);
  }
}

const ANNEX_FORMATS: ReadonlySet<ReportFormat> = new Set<ReportFormat>(['annex7', 'annex7-pdf', 'doc', 'doc-pdf']);

/**
 * Validate + de-duplicate the requested formats. Returns the ordered unique
 * format list on success, or an error message string on failure (unknown value
 * or empty request) — never silently drops a typo'd format.
 */
function validateFormats(requested: string[]): { formats: ReportFormat[] } | { error: string } {
  if (requested.length === 0) {
    return { error: `${PRODUCT_NAME} report: at least one --format is required (${VALID_LIST}).` };
  }
  const seen = new Set<string>();
  const formats: ReportFormat[] = [];
  for (const raw of requested) {
    const value = raw.trim();
    if (!(REPORT_FORMATS as readonly string[]).includes(value)) {
      return { error: `${PRODUCT_NAME} report: unknown format "${raw}". Valid formats: ${VALID_LIST}.` };
    }
    if (!seen.has(value)) {
      seen.add(value);
      formats.push(value as ReportFormat);
    }
  }
  return { formats };
}

/**
 * `--out` reconciliation (documented in the CLI --help and README): honor `--out`
 * as a literal file path ONLY when exactly one format was requested; otherwise
 * (multiple formats, or `--out` omitted) treat it as an output DIRECTORY and
 * write each artifact under it with its default filename. When `--out` is omitted
 * entirely, default to the product's default report dir regardless of format count. Returns
 * the absolute target path for each requested format.
 */
function resolveOutputTargets(formats: ReportFormat[], out: string | undefined): { format: ReportFormat; target: string }[] {
  if (out !== undefined && formats.length === 1) {
    return [{ format: formats[0], target: path.resolve(out) }];
  }
  const dir = path.resolve(out ?? DEFAULT_OUT_DIR);
  return formats.map((format) => ({ format, target: path.join(dir, DEFAULT_FILENAMES[format]) }));
}

export async function runReport(opts: RunReportOptions): Promise<RunReportResult> {
  // Validate formats FIRST, before any scan work or filesystem writes, so an
  // unknown/typo'd format fails cleanly with nothing written.
  const validated = validateFormats(opts.formats);
  if ('error' in validated) {
    return { exitCode: 2, output: validated.error };
  }
  const formats = validated.formats;

  // GATING — WHOLE-REQUEST, NOT PER-ARTIFACT (deliberate design decision).
  //
  // If ANY requested format in this single invocation is gated, the request
  // needs a valid key; without one we refuse the ENTIRE request (write
  // nothing, exit 3) even if a free `sbom-cyclonedx` was also requested
  // alongside. A request for ONLY free formats needs no key and proceeds
  // exactly as before.
  //
  // Rationale: gating per-artifact-within-one-invocation would mean
  // partially fulfilling a request (writing the free SBOM, skipping the
  // paid pack) and then having to pick a mixed exit code — a confusing
  // "some of what you asked for" outcome. Whole-request gating is
  // unambiguous: the invocation either fully succeeds or writes nothing.
  const needsKey = formats.some((f) => GATED_FORMATS.has(f));
  let license: LicenseInfo | null = null;
  if (needsKey) {
    const keyString = discoverLicenseKey({
      cliKey: opts.key,
      env: opts.env,
      keyFilePath: opts.keyFilePath,
    });
    license = keyString ? verifyLicenseKey(keyString) : null;
    if (!license) {
      // Refuse the whole request. Nothing is scanned, nothing is written.
      return { exitCode: EXIT_UNLICENSED, output: UNLICENSED_MESSAGE };
    }
  }

  let sbomData: ReportData;
  let annexCtx: AnnexContext | undefined;
  try {
    // annex7/annex7-pdf/doc/doc-pdf all need the fuller AnnexContext (facts,
    // gap checklist, provenance) — computed once and reused across however
    // many of those four formats were requested together, never per-format.
    // sbom-cyclonedx/sbom-spdx only need the base ReportData; if any annex
    // format is ALSO requested, annexCtx.data is the identical ReportData
    // and is reused directly rather than scanning twice.
    if (formats.some((f) => ANNEX_FORMATS.has(f))) {
      annexCtx = await buildAnnexContext(opts);
      sbomData = annexCtx.data;
    } else {
      sbomData = await buildReportData(opts.path, {
        productionOnly: opts.productionOnly,
        projectLicenseOverride: opts.projectLicenseOverride,
      });
    }
  } catch (err) {
    if (err instanceof NoProjectFoundError) {
      // Match the `scan` command's exit-2 "no project" style, extended to name
      // the `report` command. Nothing is written.
      return { exitCode: 2, output: `${PRODUCT_NAME} report: ${err.message}. No artifacts were generated.` };
    }
    return { exitCode: 2, output: `${PRODUCT_NAME} report: ${(err as Error).message}` };
  }

  const targets = resolveOutputTargets(formats, opts.out);
  const written: string[] = [];
  try {
    for (const { format, target } of targets) {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const content = await renderFormat(format, sbomData, annexCtx);
      fs.writeFileSync(target, content);
      written.push(target);
    }
  } catch (err) {
    // Covers, among other things, a PDF format requested with no installed
    // browser (renderAnnexPdf throws NO_BROWSER_MESSAGE) — exit 2, per
    // addendum D ("tool/runtime error"), same bucket as every other render
    // failure. An open item in the rendered CONTENT is never an error here —
    // only a genuine failure to produce the artifact is.
    return { exitCode: 2, output: `${PRODUCT_NAME} report: ${(err as Error).message}` };
  }

  const lines = [
    `${PRODUCT_NAME}: wrote ${written.length} report artifact${written.length === 1 ? '' : 's'}:`,
    ...written.map((w) => `  ${w}`),
  ];

  // Data-currency FYI: when a gated format was generated with a valid key AND
  // the installed reference data postdates the key's update window, append
  // ONE purely informational line. Report generation is perpetual and
  // completely unaffected — this never nags, degrades, or blocks.
  if (license) {
    const note = dataCurrencyNote(license.updatesUntil, sbomData.dataVersion);
    if (note) lines.push('', note);
  }

  return { exitCode: 0, output: lines.join('\n') };
}
