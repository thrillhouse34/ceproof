import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR } from '../paths';
import type { FdaConfig, FdaSupportDeclaration } from '../config/types';
import { normalizePurl } from './importSbom';
import type { FdaComponent } from './types';

/**
 * The support-level and end-of-support engine.
 *
 * FDA's premarket cybersecurity guidance (section V.A.4(b)) asks, for each
 * software component in the SBOM, for two things beyond the NTIA minimum
 * elements — quoting the vendored source text in data/sources/:
 *
 *   "The software level of support provided through monitoring and maintenance
 *    from the software component manufacturer (e.g., the software is actively
 *    maintained, no longer maintained, abandoned); and
 *    The software component's end-of-support date."
 *
 * Those three parenthesised examples are where SupportLevel's three non-unknown
 * values come from verbatim; they are not invented categories. The guidance also
 * says that where a manufacturer cannot supply the information, it "should
 * provide a justification for why the information cannot be included" — which is
 * what the `note` on a declaration carries, and why an undeclared component
 * resolves to `unknown` with a stated reason rather than to a plausible guess.
 *
 * Two things this module will not do, both deliberate:
 *
 *  - It never asserts `abandoned` on its own. No free public dataset
 *    distinguishes "the vendor published an end-of-support date" from "the
 *    project was abandoned with no announcement at all"; endoflife.date models
 *    announced lifecycles only. `abandoned` is a judgement about a supplier, so
 *    only the manufacturer can declare it.
 *  - It never fabricates an end-of-support date. A component whose cycle isn't
 *    in the snapshot comes back `unknown` with the reason stated, per the
 *    repo's honest-UNKNOWN doctrine. An FDA artifact with a confident wrong date
 *    in it is worse than one with a visible gap.
 *
 * No network access: everything is resolved against the vendored
 * data/eol-snapshot.json. See scripts/fetch-eol-snapshot.ts for how it is built.
 */

/**
 * The exact passages of the guidance this module implements, kept as data
 * rather than only as prose in the comment above so they can be checked
 * verbatim against the vendored primary-source text — the same standard
 * data/cra-structure.json is held to by tests/cra/traceability.test.ts — and so
 * the milestone-4 renderers cite one agreed wording instead of each
 * paraphrasing the guidance their own way.
 *
 * Every excerpt is a single line of the pdftotext extract, because the PDF's
 * own line wrapping means a sentence spanning two lines has no verbatim form.
 */
export const FDA_SOURCE = {
  citation: 'FDA, "Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions", issued February 3, 2026, section V.A.4(b), pp. 17-18',
  sourceFile: 'data/sources/fda-premarket-cybersecurity-2026-02-03-extract.md',
  excerpts: {
    /** Why SupportLevel exists at all, and where its three non-unknown values come from. */
    supportLevel: 'The software level of support provided through monitoring and maintenance from the',
    supportLevelExamples: 'software component manufacturer (e.g., the software is actively maintained, no longer',
    /** Why endOfSupportDate exists. */
    endOfSupportDate: 'The software component\u2019s end-of-support date.',
    /** Why a declaration carries a `note`, and why the engine warns when an "unknown" has none. */
    justification: 'provide a justification for why the information cannot be included in the premarket submission.',
  },
} as const;

/** Bumped only when the snapshot's own shape changes incompatibly, so an old vendored file fails loudly instead of being half-read. */
export const EOL_SNAPSHOT_SCHEMA = 1;

/**
 * How old a vendored snapshot may get before every FDA output carries a
 * staleness warning. Deliberately the same 30 days as the KEV snapshot
 * (milestone 3) rather than a looser EOL-specific number: the failure mode is
 * a component reported "actively maintained" whose vendor announced an
 * end-of-support date after this snapshot was taken, and in a premarket
 * submission that is a material error, not a cosmetic one. One threshold, one
 * rule, one constant for both datasets.
 */
export const SNAPSHOT_STALE_AFTER_DAYS = 30;

export interface EolRelease {
  /** Upstream's release-cycle name, e.g. "3.0", "1.1.1", "20.04". */
  cycle: string;
  /** End of standard support. Absent means upstream publishes no date, NOT that there is none. */
  eolFrom?: string;
  /** End of active (feature) support — after this, security fixes only. Reported in the evidence string, never used as the end-of-support date. */
  eoasFrom?: string;
  /** End of extended/paid support, where the vendor sells one. Reported in the evidence only — never used as the end-of-support date, since it normally needs a separate contract. */
  eoesFrom?: string;
  /** Upstream's own end-of-life boolean, computed when the snapshot was taken. Used only for cycles that carry no date at all, and always labelled "as of the snapshot date". */
  isEolAtSnapshot?: boolean;
}

export interface EolProduct {
  /** endoflife.date product id, e.g. "openssl". */
  id: string;
  label?: string;
  aliases?: string[];
  /** Versionless, normalized purl keys (see normalizePurlKey). */
  purls?: string[];
  /** Normalized `vendor:product` CPE keys (see normalizeCpeKey). */
  cpes?: string[];
  /** The component manufacturer's own published support policy, cited as evidence. */
  releasePolicyUrl?: string;
  pageUrl?: string;
  releases: EolRelease[];
}

export interface EolSnapshotSource {
  name: string;
  url: string;
  license: string;
  licenseUrl: string;
  copyright: string;
  upstreamSchemaVersion: string;
  upstreamGeneratedAt: string;
  upstreamSha256: string;
}

export interface EolSnapshot {
  schema: number;
  source: EolSnapshotSource;
  fetchedAt: string;
  products: EolProduct[];
}

/** FDA's three examples, verbatim, plus the honest fourth. */
export type SupportLevel = 'actively-maintained' | 'no-longer-maintained' | 'abandoned' | 'unknown';

export const SUPPORT_LEVELS: readonly SupportLevel[] = [
  'actively-maintained',
  'no-longer-maintained',
  'abandoned',
  'unknown',
];

export function isSupportLevel(v: unknown): v is SupportLevel {
  return typeof v === 'string' && (SUPPORT_LEVELS as readonly string[]).includes(v);
}

export type SupportBasis =
  /** The manufacturer declared it in ceproof.config.json. Authoritative — they are the ones FDA is asking. */
  | 'manufacturer-declared'
  /** The imported SBOM already carried a ceproof:fda:* property saying so. */
  | 'sbom-declared'
  /** Derived from the vendored endoflife.date snapshot. */
  | 'eol-snapshot'
  | 'unknown';

export type MatchedBy = 'purl' | 'cpe' | 'name';

export interface SupportRecord {
  supportLevel: SupportLevel;
  /** ISO yyyy-mm-dd. Absent means no date is known — never a guess, never a placeholder. */
  endOfSupportDate?: string;
  basis: SupportBasis;
  /**
   * One auditable sentence naming what was matched, how, against which snapshot,
   * and as of when. Always present, including for `unknown` — a reviewer should
   * never have to ask why a row says what it says.
   */
  evidence: string;
  matchedBy?: MatchedBy;
  matchedProductId?: string;
  matchedCycle?: string;
  /** The manufacturer's justification/comment, carried through verbatim. */
  note?: string;
  releasePolicyUrl?: string;
}

/** CycloneDX 1.6 has no field for either value (checked against the vendored schema in tests/schemas), so these namespaced properties are the carrier. */
export const SUPPORT_LEVEL_PROPERTY = 'ceproof:fda:supportLevel';
export const END_OF_SUPPORT_PROPERTY = 'ceproof:fda:endOfSupportDate';
export const SUPPORT_NOTE_PROPERTY = 'ceproof:fda:supportNote';
/** Which of the four bases produced the two values above — a reviewer must never have to guess whether a row was declared or derived. */
export const SUPPORT_SOURCE_PROPERTY = 'ceproof:fda:supportSource';
/** The one auditable sentence behind the row, carried into the machine-readable SBOM as well as the human-readable addendum. */
export const SUPPORT_EVIDENCE_PROPERTY = 'ceproof:fda:supportEvidence';
/** Where the component itself came from: `scan`, `sbom:<file>`, `override` — comma-separated when more than one source contributed. */
export const ORIGIN_PROPERTY = 'ceproof:fda:origin';

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Reduce a purl to a versionless lookup key: qualifiers and subpath stripped
 * (reusing the importer's rule), then the `@version`, then percent-decoded and
 * lowercased.
 *
 * Lowercasing the whole key is deliberate and slightly lossy — purl name case
 * sensitivity varies by type — but the keys here are only ever compared against
 * endoflife.date product identifiers, which are lowercase. Two spellings that
 * differ only in case are far more likely to be the same component than not.
 */
export function normalizePurlKey(purl: string): string | undefined {
  const base = normalizePurl(purl);
  if (!base.toLowerCase().startsWith('pkg:')) return undefined;
  // The version is whatever follows the LAST "@" that appears after the final
  // "/", which is what keeps `pkg:npm/@angular/core` (a namespace containing an
  // "@", unencoded as real generators emit it) from being truncated.
  const lastSlash = base.lastIndexOf('/');
  const atIndex = base.indexOf('@', lastSlash + 1);
  const versionless = atIndex === -1 ? base : base.slice(0, atIndex);
  let decoded = versionless;
  try {
    decoded = decodeURIComponent(versionless);
  } catch {
    // A malformed percent-escape is not worth failing a whole run over; the
    // undecoded form is still a usable (just narrower) key.
  }
  const key = decoded.trim().toLowerCase();
  return key.length > 'pkg:'.length ? key : undefined;
}

/**
 * Reduce a CPE to a `vendor:product` lookup key, collapsing the 2.3 formatted
 * form (`cpe:2.3:a:openssl:openssl:...`) and the legacy URI form
 * (`cpe:/a:openssl:openssl`) onto the same key. Wildcard or empty
 * vendor/product parts yield undefined — `*:*` would match everything.
 *
 * This is the only identifier most C/C++ components carry, which is exactly the
 * case this whole mode exists for.
 */
export function normalizeCpeKey(cpe: string): string | undefined {
  const parts = cpe.trim().toLowerCase().split(':');
  if (parts[0] !== 'cpe') return undefined;
  // cpe:2.3:<part>:<vendor>:<product>  vs  cpe:/<part>:<vendor>:<product>
  const offset = parts[1] === '2.3' ? 3 : 2;
  const vendor = parts[offset];
  const product = parts[offset + 1];
  if (!vendor || !product || vendor === '*' || product === '*' || vendor === '-' || product === '-') return undefined;
  return `${vendor}:${product}`;
}

/**
 * Strip the decorations real-world version strings carry before cycle matching:
 * a leading "v" (`v18.1.0`) and a Debian/RPM epoch (`1:1.1.1n-0+deb11u5`).
 * Distro revision suffixes need no stripping — the prefix rule in matchCycle
 * handles them.
 */
function normalizeVersion(version: string): string {
  return version.trim().replace(/^v(?=\d)/i, '').replace(/^\d+:/, '');
}

export interface EolIndex {
  snapshot: EolSnapshot;
  byPurl: Map<string, EolProduct[]>;
  byCpe: Map<string, EolProduct[]>;
  byName: Map<string, EolProduct[]>;
}

function push(map: Map<string, EolProduct[]>, key: string, product: EolProduct): void {
  const existing = map.get(key);
  if (existing) existing.push(product);
  else map.set(key, [product]);
}

export function buildEolIndex(snapshot: EolSnapshot): EolIndex {
  const index: EolIndex = { snapshot, byPurl: new Map(), byCpe: new Map(), byName: new Map() };
  for (const product of snapshot.products) {
    for (const purl of product.purls ?? []) push(index.byPurl, purl, product);
    for (const cpe of product.cpes ?? []) push(index.byCpe, cpe, product);
    push(index.byName, product.id.toLowerCase(), product);
    for (const alias of product.aliases ?? []) push(index.byName, alias.toLowerCase(), product);
  }
  return index;
}

let cachedSnapshot: EolSnapshot | undefined;

/**
 * Load and structurally check the vendored snapshot. Throws rather than
 * returning a default: a missing or wrong-schema snapshot in an installed
 * package is a broken install, and silently resolving every component to
 * "unknown" would hide that behind an artifact that looks complete.
 */
export function loadEolSnapshot(dataDir: string = DATA_DIR): EolSnapshot {
  if (dataDir === DATA_DIR && cachedSnapshot) return cachedSnapshot;
  const file = path.join(dataDir, 'eol-snapshot.json');
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`Cannot read the end-of-support snapshot at ${file} (${(err as Error).message}). Reinstall the package — data/ did not ship or is corrupt.`);
  }
  const snapshot = parsed as EolSnapshot;
  if (!snapshot || typeof snapshot !== 'object' || !Array.isArray(snapshot.products) || !snapshot.source) {
    throw new Error(`The end-of-support snapshot at ${file} is not in the expected shape.`);
  }
  if (snapshot.schema !== EOL_SNAPSHOT_SCHEMA) {
    throw new Error(`The end-of-support snapshot at ${file} declares schema ${String(snapshot.schema)}, but this version of the tool reads schema ${EOL_SNAPSHOT_SCHEMA}. Re-run scripts/fetch-eol-snapshot.ts.`);
  }
  if (dataDir === DATA_DIR) cachedSnapshot = snapshot;
  return snapshot;
}

/** Whole days between two ISO dates, floor. Negative when `later` precedes `earlier`. */
function daysBetween(earlier: string, later: string): number {
  const a = Date.parse(earlier);
  const b = Date.parse(later);
  if (Number.isNaN(a) || Number.isNaN(b)) return 0;
  return Math.floor((b - a) / 86_400_000);
}

export interface StalenessCheck {
  /** What dataset this is, named as it should read in the warning. */
  label: string;
  /** Upstream's own generated-at for the vendored snapshot. */
  generatedAt: string;
  /** The run's date. */
  asOf: string;
  /** The ONE sentence naming what being stale actually costs for this dataset. Each dataset has a different real consequence; the sentence shape around it does not change. */
  consequence: string;
  /** The command that refreshes it. */
  refreshCommand: string;
}

/**
 * The staleness warning, or undefined when the snapshot is fresh enough.
 *
 * One threshold (SNAPSHOT_STALE_AFTER_DAYS), one sentence shape, for every
 * vendored dataset in the FDA mode — the end-of-support snapshot and the KEV
 * catalogue both come through here. Only the dataset's name, its real
 * consequence and its refresh command differ, because a shared wording that
 * named the wrong consequence would be worse than two wordings.
 */
/** The staleness decision on its own, for callers that need the fact rather than the sentence (the open-items list derives an item from it). One threshold, used by both. */
export function isSnapshotStale(generatedAt: string, asOf: string): boolean {
  return daysBetween(generatedAt, asOf) > SNAPSHOT_STALE_AFTER_DAYS;
}

export function snapshotStalenessWarning(check: StalenessCheck): string | undefined {
  if (!isSnapshotStale(check.generatedAt, check.asOf)) return undefined;
  const age = daysBetween(check.generatedAt, check.asOf);
  return (
    `The bundled ${check.label} is ${age} days old (generated ${check.generatedAt}, this run is dated ${check.asOf}), past the ` +
    `${SNAPSHOT_STALE_AFTER_DAYS}-day freshness threshold. Anything published upstream since then is not reflected here — ` +
    `${check.consequence} ` +
    `Refresh the data (${check.refreshCommand}) or re-check the affected components against their sources before relying on this output.`
  );
}

/**
 * Pick the release cycle a version belongs to. Exact cycle name first, then the
 * LONGEST cycle that prefixes the version on a non-digit boundary — so `3.0.11`
 * resolves to cycle `3.0` rather than `3`, `1.1.1w` resolves to `1.1.1` (the
 * OpenSSL letter-suffix case), and `30` never resolves to cycle `3`.
 *
 * Returns undefined rather than the nearest cycle when nothing matches. A
 * version that isn't in the snapshot gets an honest unknown; guessing the
 * closest cycle would put a wrong end-of-support date in a submission document.
 */
export function matchCycle(product: EolProduct, version: string): EolRelease | undefined {
  const v = normalizeVersion(version).toLowerCase();
  if (!v) return undefined;
  let best: EolRelease | undefined;
  for (const release of product.releases) {
    const cycle = release.cycle.toLowerCase();
    if (v === cycle) return release;
    if (!v.startsWith(cycle)) continue;
    const next = v.charAt(cycle.length);
    if (next >= '0' && next <= '9') continue; // "30" is not in cycle "3"
    if (!best || cycle.length > best.cycle.length) best = release;
  }
  return best;
}

interface ProductMatch {
  product: EolProduct;
  matchedBy: MatchedBy;
}

/**
 * Match a component to a snapshot product: purl, then CPE, then name/alias.
 *
 * A key that resolves to more than one product is treated as NO match, with the
 * candidates named in the returned reason. Picking one of two products that both
 * claim the same identifier would be a coin flip attached to a regulatory date.
 */
function matchProduct(index: EolIndex, component: FdaComponent): { match?: ProductMatch; reason?: string } {
  const attempts: { key: string | undefined; map: Map<string, EolProduct[]>; matchedBy: MatchedBy }[] = [
    { key: component.purl ? normalizePurlKey(component.purl) : undefined, map: index.byPurl, matchedBy: 'purl' },
    { key: component.cpe ? normalizeCpeKey(component.cpe) : undefined, map: index.byCpe, matchedBy: 'cpe' },
    { key: component.name.trim().toLowerCase(), map: index.byName, matchedBy: 'name' },
  ];
  for (const attempt of attempts) {
    if (!attempt.key) continue;
    const candidates = attempt.map.get(attempt.key);
    if (!candidates || candidates.length === 0) continue;
    if (candidates.length > 1) {
      return {
        reason:
          `${attempt.matchedBy} "${attempt.key}" is claimed by more than one product in the end-of-support data ` +
          `(${candidates.map((c) => c.id).join(', ')}), so no match was made rather than guessing one`,
      };
    }
    return { match: { product: candidates[0], matchedBy: attempt.matchedBy } };
  }
  return {};
}

function productLabel(product: EolProduct): string {
  return product.label && product.label.toLowerCase() !== product.id.toLowerCase()
    ? `"${product.id}" (${product.label})`
    : `"${product.id}"`;
}

/**
 * Derive a support record from the snapshot alone. Dates are compared against
 * `asOf` rather than trusting upstream's own `isEol`/`isMaintained` booleans,
 * which were computed when the snapshot was taken — recomputing is what keeps a
 * month-old snapshot from reporting a cycle as supported after its published
 * end-of-support date has passed. The booleans are the fallback only for cycles
 * upstream publishes no date for at all, and the evidence string says so.
 */
function fromSnapshot(index: EolIndex, component: FdaComponent, asOf: string): SupportRecord {
  const sourceName = index.snapshot.source.name;
  const generated = index.snapshot.source.upstreamGeneratedAt;
  const unknown = (why: string): SupportRecord => ({
    supportLevel: 'unknown',
    basis: 'unknown',
    evidence: `No support level or end-of-support date could be determined: ${why}. Declare it in ceproof.config.json under fda.componentSupport to supply the value, or record why it cannot be supplied.`,
  });

  const { match, reason } = matchProduct(index, component);
  if (!match) {
    return unknown(
      reason ??
        `"${component.name}"${component.version ? ` ${component.version}` : ''} was not found in the bundled ${sourceName} data by purl, CPE or name`,
    );
  }

  const { product, matchedBy } = match;
  if (!component.version) {
    return unknown(
      `${component.name} matched ${sourceName} product ${productLabel(product)} by ${matchedBy}, but the component has no version, and support status is per release cycle`,
    );
  }

  const release = matchCycle(product, component.version);
  if (!release) {
    return unknown(
      `${component.name} matched ${sourceName} product ${productLabel(product)} by ${matchedBy}, but version ${component.version} does not fall in any release cycle that snapshot knows about (${product.releases.map((r) => r.cycle).join(', ')})`,
    );
  }

  const base = {
    basis: 'eol-snapshot' as const,
    matchedBy,
    matchedProductId: product.id,
    matchedCycle: release.cycle,
    ...(product.releasePolicyUrl ? { releasePolicyUrl: product.releasePolicyUrl } : {}),
  };
  const matchedVia = `Matched by ${matchedBy} to ${sourceName} product ${productLabel(product)}, release cycle ${release.cycle} (snapshot generated ${generated}).`;
  const activeSupportNote = release.eoasFrom
    ? ` Active (feature) support ended ${release.eoasFrom}; maintenance after that date is security fixes only.`
    : '';

  // STANDARD support end, not the extended one, even when the vendor sells
  // extended support that runs years longer (Debian 11: standard support to
  // 2026-08-31, paid ELTS to 2031-06-30). Extended support is normally a
  // separate paid contract, so reporting its date by default would tell FDA a
  // component is supported until 2031 for a manufacturer who never bought it —
  // overstating support means understating cybersecurity risk, which is the
  // dangerous direction to be wrong in. The extended window is reported in the
  // evidence instead, with the pointer to declare it if the contract is held.
  const supportEnd = release.eolFrom ?? release.eoesFrom;
  if (supportEnd) {
    const stillSupported = supportEnd > asOf;
    const extendedNote =
      release.eoesFrom && release.eoesFrom !== supportEnd
        ? ` The vendor also offers extended/paid support for this cycle to ${release.eoesFrom}; that is NOT the date reported, because it generally requires a separate support contract. If you hold one, declare the component in ceproof.config.json under fda.componentSupport.`
        : '';
    return {
      ...base,
      supportLevel: stillSupported ? 'actively-maintained' : 'no-longer-maintained',
      endOfSupportDate: supportEnd,
      evidence:
        `${matchedVia} End-of-support date ${supportEnd}, which is ${stillSupported ? 'after' : 'on or before'} this run's date ${asOf}, ` +
        `so the cycle is reported as ${stillSupported ? 'actively maintained' : 'no longer maintained'}. Recomputed against ${asOf}, not taken from the snapshot's own status flag.` +
        activeSupportNote +
        extendedNote,
    };
  }

  // No published date. Upstream's boolean is the only signal left, and it is
  // only true as of the snapshot date — stated as such.
  if (release.isEolAtSnapshot !== undefined) {
    const eol = release.isEolAtSnapshot;
    return {
      ...base,
      supportLevel: eol ? 'no-longer-maintained' : 'actively-maintained',
      evidence:
        `${matchedVia} ${sourceName} publishes no end-of-support date for this cycle, only a status of ` +
        `"${eol ? 'end of life' : 'supported'}" as of ${generated}, so the end-of-support date is reported as not available rather than estimated.` +
        activeSupportNote,
    };
  }

  return unknown(`${component.name} matched ${sourceName} product ${productLabel(product)} release cycle ${release.cycle}, but that cycle carries neither a date nor a support status`);
}

/** Read a support declaration a previous run (or the user, by hand) left on the component as CycloneDX properties. */
function fromSbomProperties(component: FdaComponent, warnings: string[]): SupportRecord | undefined {
  const rawLevel = component.properties[SUPPORT_LEVEL_PROPERTY];
  const rawDate = component.properties[END_OF_SUPPORT_PROPERTY];
  const note = component.properties[SUPPORT_NOTE_PROPERTY];
  if (!rawLevel && !rawDate) return undefined;

  let level: SupportLevel = 'unknown';
  if (rawLevel) {
    if (isSupportLevel(rawLevel)) {
      level = rawLevel;
    } else {
      warnings.push(
        `${component.name}: the imported SBOM carries ${SUPPORT_LEVEL_PROPERTY}="${rawLevel}", which is not one of ${SUPPORT_LEVELS.join(', ')}. ` +
          'It was treated as unknown rather than accepted — an unrecognised value must not become a confident claim in a submission artifact.',
      );
    }
  }
  let date: string | undefined;
  if (rawDate) {
    if (ISO_DATE.test(rawDate)) {
      date = rawDate;
    } else {
      warnings.push(
        `${component.name}: the imported SBOM carries ${END_OF_SUPPORT_PROPERTY}="${rawDate}", which is not a YYYY-MM-DD date. It was dropped rather than reformatted by guesswork.`,
      );
    }
  }
  return {
    supportLevel: level,
    ...(date ? { endOfSupportDate: date } : {}),
    basis: 'sbom-declared',
    evidence: `Declared in the imported SBOM as CycloneDX properties (${SUPPORT_LEVEL_PROPERTY}/${END_OF_SUPPORT_PROPERTY}). Not verified against any other source.`,
    ...(note ? { note } : {}),
  };
}

/**
 * Which declaration key, if any, applies to a component. Most specific first:
 * purl, then `name@version`, then bare name. The bare-name form is kept because
 * firmware components routinely arrive with no version at all and no purl, and
 * without it those components could not be declared.
 */
function declarationKeysFor(component: FdaComponent): string[] {
  const keys: string[] = [];
  if (component.purl) {
    const key = normalizePurlKey(component.purl);
    if (key) keys.push(key);
    keys.push(component.purl.toLowerCase());
  }
  if (component.version) keys.push(`${component.name}@${component.version}`.toLowerCase());
  keys.push(component.name.toLowerCase());
  return keys;
}

export interface ResolveSupportOptions {
  /** The run's date, YYYY-MM-DD. Defaults to today. Every date comparison and the staleness check use it, so an artifact can be regenerated for a past date deterministically. */
  asOf?: string;
  /** Manufacturer declarations from ceproof.config.json. */
  fda?: FdaConfig;
  /** Pre-built index, for callers resolving many components. Built from the bundled snapshot when omitted. */
  index?: EolIndex;
}

export interface ComponentSupport {
  component: FdaComponent;
  support: SupportRecord;
}

export interface SupportResolution {
  results: ComponentSupport[];
  warnings: string[];
  /** The snapshot the run resolved against, for the provenance artifact. */
  snapshotSource: EolSnapshotSource;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function declarationToRecord(key: string, declaration: FdaSupportDeclaration): SupportRecord {
  return {
    supportLevel: declaration.supportLevel,
    ...(declaration.endOfSupportDate ? { endOfSupportDate: declaration.endOfSupportDate } : {}),
    basis: 'manufacturer-declared',
    evidence: `Declared by the manufacturer in ceproof.config.json under fda.componentSupport["${key}"].`,
    ...(declaration.note ? { note: declaration.note } : {}),
  };
}

/**
 * Resolve a support level and end-of-support date for every component.
 *
 * Precedence, highest first:
 *  1. the manufacturer's declaration in ceproof.config.json — FDA is asking the
 *     manufacturer, who may hold a support contract no public dataset knows
 *     about, and who is the only party that can say "abandoned";
 *  2. a declaration already present on the imported SBOM's component properties;
 *  3. the bundled end-of-support snapshot;
 *  4. unknown, with the reason stated.
 *
 * The snapshot is consulted even when a declaration wins, purely so a
 * declaration that CONTRADICTS the public data is visible: the declaration still
 * stands (it is authoritative), but the disagreement is appended to the evidence
 * so a reviewer sees it instead of the tool quietly taking a side.
 */
export function resolveSupport(components: FdaComponent[], options: ResolveSupportOptions = {}): SupportResolution {
  const asOf = options.asOf ?? today();
  const index = options.index ?? buildEolIndex(loadEolSnapshot());
  const declarations = options.fda?.componentSupport ?? {};
  const warnings: string[] = [];
  const usedKeys = new Set<string>();
  const results: ComponentSupport[] = [];

  const stale = snapshotStalenessWarning({
    label: `end-of-support data (${index.snapshot.source.name})`,
    generatedAt: index.snapshot.source.upstreamGeneratedAt,
    asOf,
    consequence: 'a component shown as actively maintained may have had an end-of-support date announced after this snapshot was taken.',
    refreshCommand: 'npm run fetch-eol-snapshot',
  });
  if (stale) warnings.push(stale);

  for (const component of components) {
    const derived = fromSnapshot(index, component, asOf);

    let support = derived;
    let declaredKey: string | undefined;
    for (const key of declarationKeysFor(component)) {
      if (declarations[key]) {
        declaredKey = key;
        break;
      }
    }

    if (declaredKey) {
      usedKeys.add(declaredKey);
      const declaration = declarations[declaredKey];
      support = declarationToRecord(declaredKey, declaration);
      if (derived.basis === 'eol-snapshot') {
        support.matchedProductId = derived.matchedProductId;
        support.matchedCycle = derived.matchedCycle;
        if (derived.releasePolicyUrl) support.releasePolicyUrl = derived.releasePolicyUrl;
        const levelDiffers = derived.supportLevel !== support.supportLevel;
        const dateDiffers = derived.endOfSupportDate !== undefined && derived.endOfSupportDate !== support.endOfSupportDate;
        if (levelDiffers || dateDiffers) {
          support.evidence +=
            ` The manufacturer's declaration was used. Note that the bundled ${index.snapshot.source.name} data says` +
            (levelDiffers ? ` the support level is "${derived.supportLevel}"` : '') +
            (levelDiffers && dateDiffers ? ' and' : '') +
            (dateDiffers ? ` the end-of-support date is ${derived.endOfSupportDate}` : '') +
            ` for product "${derived.matchedProductId}" cycle ${derived.matchedCycle}; the declaration takes precedence but the disagreement is recorded here.`;
        }
      }
      if (support.supportLevel === 'unknown' && !support.note) {
        warnings.push(
          `${component.name}: declared as support level "unknown" in ceproof.config.json with no note. FDA's guidance asks for a justification where the ` +
            'information cannot be provided — add a "note" explaining why (for example, the supplier was asked and did not answer).',
        );
      }
    } else {
      const sbomDeclared = fromSbomProperties(component, warnings);
      if (sbomDeclared) support = sbomDeclared;
    }

    results.push({ component, support });
  }

  for (const key of Object.keys(declarations)) {
    if (!usedKeys.has(key)) {
      warnings.push(
        `ceproof.config.json declares fda.componentSupport["${key}"], but no component in this run matched that key, so the declaration had no effect. ` +
          'Check the spelling — the key must be a purl, "name@version", or a bare component name as it appears in the SBOM.',
      );
    }
  }

  const unresolved = results.filter((r) => r.support.supportLevel === 'unknown').length;
  if (unresolved > 0) {
    warnings.push(
      `${unresolved} of ${results.length} component${results.length === 1 ? '' : 's'} have no support level or end-of-support date. ` +
        'FDA asks for both for every software component in the SBOM, so each one is either declared in ceproof.config.json ' +
        '(fda.componentSupport) or carried into the submission with a justification for why it cannot be supplied. Each row states why it is unresolved.',
    );
  }

  return { results, warnings, snapshotSource: index.snapshot.source };
}
