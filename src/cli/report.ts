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
import { readConfigFile, resolveConfigPath, ConfigFileNotFoundError } from '../config/write';
import { validateConfig } from '../config/validate';
import type { CeproofConfig } from '../config/types';
import { computeGapChecklist } from '../gap/gapEngine';
import { discoverLicenseKey } from '../license/discovery';
import { verifyLicenseKey, type LicenseInfo } from '../license/verify';
import { dataCurrencyNote } from '../license/dataCurrency';
import { licenseExpiry, licenseExpiryNote } from '../license/expiry';
import { runFda, NoComponentsError, SbomImportError } from '../fda/run';
import { renderFdaArtifacts, FDA_ARTIFACT_FILES } from '../fda/render/artifacts';
import { PRODUCT_NAME, PRODUCT_URL, PRICE_INDIVIDUAL, PRICE_AGENCY, SUPPORT_EMAIL } from '../branding';

// `report` renders the paid Annex VII technical documentation pack and
// Annex V Declaration of Conformity draft (both driven by the same
// data/cra-structure.json + gap-checklist engine `scan` uses), plus the free
// standalone SBOM formats. See milestone2_brief.md for the M2 content model
// and milestone3_brief.md (M3) for the gating below.

export const REPORT_FORMATS = ['annex7', 'annex7-pdf', 'doc', 'doc-pdf', 'sbom-cyclonedx', 'sbom-spdx', 'fda-pack'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

/**
 * `fda-pack` is ONE format that writes a DIRECTORY, which is the only format
 * here that does. The alternative was five formats — an enriched SBOM, two
 * tables, a summary, an open-items list — and that was rejected: the pack's
 * whole design is that the gaps travel with the SBOM, and a format list lets a
 * customer request the SBOM alone and ship it as if it were the deliverable.
 * One atomic pack, split into per-artifact formats if a customer ever asks for
 * one on its own.
 */
const FDA_FORMATS: ReadonlySet<ReportFormat> = new Set<ReportFormat>(['fda-pack']);

/**
 * The four narrative formats — the actual paid product — require a valid
 * license key. `sbom-cyclonedx`/`sbom-spdx` stay free: per the M1 plan's
 * SBOM-placement decision, the SBOM isn't the differentiated paid product —
 * it's largely mechanical output of the already-free `scan` engine, and
 * CRA's Annex VII SBOM requirement is closer to required plumbing than
 * compiled deliverable. The paid product is the compiled, cited, per-release
 * narrative pack + DoC.
 */
const GATED_FORMATS: ReadonlySet<ReportFormat> = new Set<ReportFormat>(['annex7', 'annex7-pdf', 'doc', 'doc-pdf', 'fda-pack']);

/** Request refused for lack of a key. */
export const EXIT_UNLICENSED = 3;

/**
 * Which gated formats each tier unlocks. The CRA tiers and the FDA tiers are
 * different products at different prices, so neither unlocks the other: a $99
 * `individual` key does not generate FDA artifacts, and an FDA key does not
 * generate the Annex VII pack.
 *
 * `fda-company` and `fda-consultant` map to the SAME formats on purpose. The
 * difference between them is a licence TERM — a consultant generates packs for
 * several clients — not a feature. Gating a consultant out of an artifact a
 * company gets would be a worse product and would not make anyone buy the
 * higher tier.
 *
 * FAILS CLOSED, and that is the point of the lookup rather than a default: a
 * tier string this build does not recognise unlocks NOTHING. A key is
 * cryptographically genuine or it is not (that is verify.ts's job and it
 * involves no tiers); what a genuine key ENTITLES you to is this table, and a
 * tier it has never heard of — a future product's tier, a typo at issuance —
 * must not fall through to "probably fine". `tests/cli/fdaGating.test.ts`
 * covers that direction specifically.
 */
const TIER_FORMATS: Record<string, readonly ReportFormat[]> = {
  individual: ['annex7', 'annex7-pdf', 'doc', 'doc-pdf'],
  agency: ['annex7', 'annex7-pdf', 'doc', 'doc-pdf'],
  'fda-company': ['fda-pack'],
  'fda-consultant': ['fda-pack'],
};

/** The tiers that unlock a given format, for the refusal message. Derived from the table above so the two cannot disagree. */
function tiersFor(format: ReportFormat): string[] {
  return Object.keys(TIER_FORMATS).filter((tier) => TIER_FORMATS[tier].includes(format));
}

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

/**
 * The FDA pack's own refusal. Separate from the CRA one because it is a
 * different product at a different price with a different free tier to point
 * at — and because telling someone who asked for FDA artifacts about Annex VII
 * pricing reads as a tool that did not understand the question.
 *
 * No price here: the FDA tiers are annual, the CRA constants in branding.ts
 * are perpetual, and a stale price in a CLI someone installed eight months ago
 * is worse than a link to the page that is current.
 */
const FDA_UNLICENSED_MESSAGE = [
  `The FDA premarket SBOM pack needs an FDA-tier ${PRODUCT_NAME} license.`,
  '',
  'It generates the enriched CycloneDX SBOM, the level-of-support and',
  'end-of-support addendum, the known-vulnerability table with the two columns',
  'you fill in, the open-items list and the provenance record.',
  '',
  `Annual, sold per company and per consultant. See ${PRODUCT_URL}`,
  '',
  `The free diagnosis never needs a key:  ${PRODUCT_NAME} scan --profile fda --sbom <file.json>`,
  `Already have a key? Run:  ${PRODUCT_NAME} activate <key>`,
].join('\n');

/** The refusal when the key is genuine but is for a tier that does not include what was asked for. Names the tier needed rather than being vague about it. */
function wrongTierMessage(license: LicenseInfo, formats: ReportFormat[]): string {
  const unlocked = TIER_FORMATS[license.tier] ?? [];
  const refused = formats.filter((f) => GATED_FORMATS.has(f) && !unlocked.includes(f));
  const needed = [...new Set(refused.flatMap(tiersFor))];
  return [
    `Your license key is valid, but its tier ("${license.tier}") does not include ${refused.join(', ')}.`,
    '',
    needed.length > 0
      ? `${refused.length === 1 ? 'That format needs' : 'Those formats need'} one of these tiers: ${needed.join(', ')}.`
      : // A tier the table does not list unlocks nothing, and saying which tier
        // would unlock it is not possible from this build. Fail closed and say so.
        `${refused.length === 1 ? 'That format is' : 'Those formats are'} not unlocked by any tier this version of ${PRODUCT_NAME} knows about. Upgrade ${PRODUCT_NAME} and try again, or get in touch.`,
    '',
    `Your key unlocks: ${unlocked.length > 0 ? unlocked.join(', ') : 'no paid formats in this version'}.`,
    `Buy the tier you need at ${PRODUCT_URL}`,
  ].join('\n');
}

/**
 * The lapsed sentence for an FDA key, worded to match the renewal emails the
 * fulfillment Worker sends (`licenseproof-fulfillment/docs/fda-email-copy.md`)
 * so a customer reading both is told the same thing twice, not two things.
 *
 * Separate from `licenseExpiryNote`'s generic sentence for the same reason
 * FDA_UNLICENSED_MESSAGE is separate from UNLICENSED_MESSAGE: the FDA tiers are
 * a Stripe subscription, so the action is "update payment" before it is "buy
 * again", and the renewal link a customer actually possesses is the one in their
 * receipt email — there is no self-serve renewal page on the site to send them
 * to, and the portal's plan switch is deliberately off.
 *
 * Pinned verbatim by tests/cli/fdaGating.test.ts. Do not re-word it here alone:
 * the email copy says the same words.
 */
function fdaLapsedNote(expiresAt: string): string {
  return (
    `Your ${PRODUCT_NAME} FDA license expired on ${expiresAt.slice(0, 10)}. ` +
    `Update payment or renew from the link in your receipt email, or write to ${SUPPORT_EMAIL}.`
  );
}

/** The refusal when the subscription has lapsed. Never worded as an invalid key — see src/license/expiry.ts. */
function lapsedMessage(note: string, formats: ReportFormat[]): string {
  const fda = formats.some((f) => FDA_FORMATS.has(f));
  return [
    note,
    '',
    `Nothing was written. The format${formats.length === 1 ? '' : 's'} you asked for (${formats.join(', ')}) ${formats.length === 1 ? 'is' : 'are'} part of the paid subscription.`,
    // The FDA sentence already carries its own two routes (payment, support@),
    // so adding a third one here would be the tool contradicting itself.
    ...(fda ? [] : [`Renew at ${PRODUCT_URL} and run the same command again; your existing config and declarations are untouched.`]),
    '',
    `Still free, with no key and no subscription:  ${PRODUCT_NAME} scan,  ${PRODUCT_NAME} scan --profile fda,  --format sbom-cyclonedx,  --format sbom-spdx`,
  ].join('\n');
}

/** Default per-format filenames used whenever `--out` names a directory (or is omitted). */
const DEFAULT_FILENAMES: Record<ReportFormat, string> = {
  annex7: 'annex7.html',
  'annex7-pdf': 'annex7.pdf',
  doc: 'doc.html',
  'doc-pdf': 'doc.pdf',
  'sbom-cyclonedx': 'sbom.cyclonedx.json',
  'sbom-spdx': 'sbom.spdx.json',
  // Never used: fda-pack writes a directory of files, not one file, and is
  // handled on its own path. Present because the record type is exhaustive and
  // a missing key would be a compile error the day a format is added.
  'fda-pack': '',
};

/** Default output directory when `--out` is omitted. */
const DEFAULT_OUT_DIR = `./${PRODUCT_NAME}-report`;

/** Default output directory for the FDA pack. Separate from the CRA one so the two packs never land on top of each other. */
const DEFAULT_FDA_OUT_DIR = `./${PRODUCT_NAME}-fda`;

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
  /** `--sbom <file>`, repeatable. Only meaningful with `fda-pack`; passing it without one is a usage error rather than a silent no-op. */
  sbomPaths?: string[];
  /** The run date, YYYY-MM-DD. Injected by tests so a pack can be regenerated for a fixed date; defaults to today. */
  asOf?: string;
  /** Full ISO timestamp of the run. Injected by tests for the same reason; defaults to now. */
  generatedAt?: string;
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
  const config = resolveConfig(resolveConfigPath(opts.path, opts.configPath));
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
    case 'fda-pack':
      // Unreachable: runReport returns on the FDA path before it ever builds
      // targets or calls this. Thrown rather than silently returning '' so a
      // future refactor that routes fda-pack through here fails loudly instead
      // of writing an empty file called "".
      throw new Error('fda-pack is written as a directory of artifacts on its own path in runReport, not through renderFormat.');
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
  // fda-pack is the only format that writes a DIRECTORY of artifacts rather
  // than one file, so `--out` means something different for it than for every
  // other format, and no single licence tier unlocks it alongside the CRA
  // formats. Combining them is refused here rather than half-supported.
  if (formats.some((f) => FDA_FORMATS.has(f)) && formats.length > 1) {
    return {
      error:
        `${PRODUCT_NAME} report: fda-pack must be requested on its own. It writes a directory of artifacts rather than a single file, ` +
        'and no license tier includes it alongside the CRA formats. Run it as a separate command.',
    };
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

/**
 * The three licence decisions, as one pure function of a verified key and the
 * requested formats.
 *
 * Extracted from `runReport` because the three are genuinely separate
 * questions that get confused when they share a body, and because this is the
 * only way they can be tested exhaustively WITHOUT the signing key: the
 * decisions take a `LicenseInfo`, which is the already-verified contents of a
 * key, so every branch — unknown tier, wrong tier, lapsed, unreadable expiry,
 * perpetual — can be exercised from a hand-built object with no key material
 * anywhere near the test. Whether a key is GENUINE is verify.ts's job and
 * needs real cryptography; what a genuine key ENTITLES you to is this, and it
 * needs none.
 *
 * Order is load-bearing:
 *  1. no key at all             -> the product-appropriate purchase message;
 *  2. genuine key, wrong tier   -> names the tier needed. A valid key for the
 *     wrong product is not an expiry problem and must not be reported as one;
 *  3. genuine key, right tier, lapsed subscription -> the lapsed message, by
 *     that name, never "invalid license key".
 *
 * Returns a `refusal` to refuse the whole request (nothing written, exit 3),
 * or an `expiryNote` to print alongside a successful run — or neither.
 */
export function gateRequest(
  license: LicenseInfo | null,
  formats: ReportFormat[],
  now: Date = new Date(),
): { refusal?: string; expiryNote?: string } {
  const gated = formats.filter((f) => GATED_FORMATS.has(f));
  if (gated.length === 0) return {};
  if (!license) {
    return { refusal: formats.some((f) => FDA_FORMATS.has(f)) ? FDA_UNLICENSED_MESSAGE : UNLICENSED_MESSAGE };
  }
  // FAILS CLOSED on an unrecognised tier: the lookup misses, `unlocked` is
  // empty, and every gated format is refused.
  const unlocked = TIER_FORMATS[license.tier] ?? [];
  if (gated.some((f) => !unlocked.includes(f))) return { refusal: wrongTierMessage(license, formats) };

  const expiry = licenseExpiry(license, now);
  const expiryNote = licenseExpiryNote(expiry);
  if (expiry.expired) {
    // The FDA tiers get their own sentence; expiry.expiresAt is always present
    // on this branch (expired can only be true when a readable date was there).
    const note =
      gated.some((f) => FDA_FORMATS.has(f)) && expiry.expiresAt !== undefined
        ? fdaLapsedNote(expiry.expiresAt)
        : (expiryNote ?? '');
    return { refusal: lapsedMessage(note, gated) };
  }
  return expiryNote !== undefined ? { expiryNote } : {};
}

/**
 * Generate and write the FDA pack.
 *
 * Shares the gating above (whole-request, exit 3, nothing written) and the
 * exit-code vocabulary with the CRA formats, and nothing else: it does not use
 * `ReportData`, the CRA gap checklist, the Annex content model or the
 * per-format filename table, because the FDA mode has its own component model
 * and its own three engines.
 *
 * Exported, and takes no licence, on purpose. The licence decision is
 * `gateRequest`'s and is already made by the time this runs — so this function
 * can be tested against the real filesystem, writing the real seven artifacts,
 * with no key material involved. Calling it directly does NOT bypass a gate;
 * there is no gate in here to bypass.
 */
export async function writeFdaPack(opts: RunReportOptions, expiryNote?: string): Promise<RunReportResult> {
  const dir = path.resolve(opts.out ?? DEFAULT_FDA_OUT_DIR);
  let artifacts: ReturnType<typeof renderFdaArtifacts>;
  try {
    const run = await runFda({
      path: opts.path,
      sbomPaths: opts.sbomPaths ?? [],
      productionOnly: opts.productionOnly,
      ...(opts.configPath ? { configPath: opts.configPath } : {}),
      ...(opts.asOf ? { asOf: opts.asOf } : {}),
      ...(opts.generatedAt ? { generatedAt: opts.generatedAt } : {}),
    });
    artifacts = renderFdaArtifacts(run.input);
  } catch (err) {
    // An unreadable or unsupported --sbom file and an empty component list are
    // both usage errors about what the user supplied — exit 2, nothing
    // written — and both already carry a message naming the real problem.
    if (err instanceof SbomImportError || err instanceof NoComponentsError) {
      return { exitCode: 2, output: `${PRODUCT_NAME} report: ${err.message}` };
    }
    return { exitCode: 2, output: `${PRODUCT_NAME} report: ${(err as Error).message}` };
  }

  const written: string[] = [];
  try {
    // Created only once the artifacts exist, so a failed run leaves no empty
    // directory behind suggesting something was produced.
    fs.mkdirSync(dir, { recursive: true });
    for (const artifact of artifacts) {
      const target = path.join(dir, artifact.file);
      fs.writeFileSync(target, artifact.contents);
      written.push(target);
    }
  } catch (err) {
    return { exitCode: 2, output: `${PRODUCT_NAME} report: ${(err as Error).message}` };
  }

  const lines = [
    `${PRODUCT_NAME}: wrote ${written.length} FDA premarket SBOM artifacts:`,
    ...written.map((w) => `  ${w}`),
    '',
    `Read ${path.join(dir, FDA_ARTIFACT_FILES.openItems)} before you rely on any of it: it lists what still needs a human.`,
  ];
  if (expiryNote) lines.push('', expiryNote);
  return { exitCode: 0, output: lines.join('\n') };
}

export async function runReport(opts: RunReportOptions): Promise<RunReportResult> {
  // Validate formats FIRST, before any scan work or filesystem writes, so an
  // unknown/typo'd format fails cleanly with nothing written.
  const validated = validateFormats(opts.formats);
  if ('error' in validated) {
    return { exitCode: 2, output: validated.error };
  }
  const formats = validated.formats;

  // A `--sbom` that reaches no importer is a silent no-op, which this repo's
  // never-silent-assumptions rule forbids: the user believes they supplied
  // component data and the artifact would come out without it.
  if ((opts.sbomPaths?.length ?? 0) > 0 && !formats.some((f) => FDA_FORMATS.has(f))) {
    return {
      exitCode: 2,
      output:
        `${PRODUCT_NAME} report: --sbom is only read by the FDA formats (fda-pack), and none was requested, so the file would have been ignored. ` +
        `Run \`${PRODUCT_NAME} report --format fda-pack --sbom <file>\`, or drop --sbom.`,
    };
  }

  // A `--config` path that doesn't exist is a usage error, checked here with
  // the other usage errors rather than inside buildAnnexContext: the SBOM-only
  // formats never read the config at all, so leaving the check downstream
  // would silently accept a typo'd path for half the format list.
  try {
    resolveConfigPath(opts.path, opts.configPath);
  } catch (err) {
    if (err instanceof ConfigFileNotFoundError) {
      return { exitCode: 2, output: `${PRODUCT_NAME} report: ${err.message}` };
    }
    throw err;
  }

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
  let expiryNote: string | undefined;
  if (needsKey) {
    const keyString = discoverLicenseKey({
      cliKey: opts.key,
      env: opts.env,
      keyFilePath: opts.keyFilePath,
    });
    license = keyString ? verifyLicenseKey(keyString) : null;
    // Genuineness happened above (verifyLicenseKey, cryptography); entitlement
    // and expiry are gateRequest's, in that order. Nothing is scanned and
    // nothing is written on a refusal.
    const gate = gateRequest(license, formats);
    if (gate.refusal !== undefined) return { exitCode: EXIT_UNLICENSED, output: gate.refusal };
    expiryNote = gate.expiryNote;
  }

  // THE FDA PACK, on its own path from here down. See writeFdaPack.
  if (formats.some((f) => FDA_FORMATS.has(f))) return writeFdaPack(opts, expiryNote);

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
  // A running subscription says when it runs until; a perpetual key says
  // nothing, which is the overwhelmingly common case here and must stay silent.
  if (expiryNote) lines.push('', expiryNote);

  return { exitCode: 0, output: lines.join('\n') };
}
