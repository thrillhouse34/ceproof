import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR } from '../paths';
import { normalizePurlKey, normalizeCpeKey, snapshotStalenessWarning } from './support';
import type { FdaComponent } from './types';

/**
 * The known-vulnerability screen, centred on CISA's Known Exploited
 * Vulnerabilities Catalog.
 *
 * FDA's premarket cybersecurity guidance (section V.A.4(b)) asks for this
 * alongside the SBOM itself — quoting the vendored source text in data/sources/:
 *
 *   "As part of the premarket submission, manufacturers should also identify all
 *    known vulnerabilities associated with the device and the software
 *    components, including those identified in CISA's Known Exploited
 *    Vulnerabilities Catalog. For each known vulnerability, manufacturers should
 *    describe how the vulnerabilities were discovered ..."
 *
 * and then, for components with known vulnerabilities:
 *
 *   "A safety and security risk assessment of each known vulnerability
 *    (including device and system impacts); and
 *    Details of applicable safety and security risk controls to address the
 *    vulnerability."
 *
 * The division of labour this module is built around, and will not cross: it
 * SCREENS, the manufacturer ASSESSES. Those two bullets are the manufacturer's
 * to write — they require device and system impact knowledge no scanner has —
 * so what this produces is a candidate list with a stated basis and confidence
 * for every row, plus (via MANUFACTURER_SUPPLIED_COLUMNS) the names of the two
 * columns the manufacturer has to fill in. Nothing here ever claims a risk
 * assessment was performed.
 *
 * What the screen can and cannot be precise about, and why:
 *
 *  - The KEV catalogue identifies a vulnerability by free-text vendor and
 *    product ("OpenSSL"/"OpenSSL", "Linux"/"Kernel") and carries NO version
 *    information at all. So a match against the catalogue alone can only ever be
 *    `possible` — it says "a known-exploited vulnerability exists in this
 *    product", never "in your version of it". This is the normal case for the
 *    C/C++ firmware components this whole mode exists for, and every such row
 *    says so in its own evidence string rather than leaving the customer to
 *    discover the limit.
 *  - `confirmed` requires version-range evidence, which only an ecosystem
 *    advisory can supply. data/kev-index.json is the build-time join of the KEV
 *    CVE list against OSV, carrying the affected version ranges for the npm and
 *    PyPI packages involved — the ecosystems ceproof's own scanner can produce.
 *    That is deliberately NOT an NVD/CPE layer (excluded from this version): it
 *    maps advisories to package versions, so it cannot confirm anything for a
 *    component that has no npm or PyPI identity.
 *  - `not-affected` is only ever reported when an advisory names the exact
 *    package AND the component's version is provably outside every affected
 *    range. Those rows are kept and reported, not dropped, so a reviewer can see
 *    the CVE was considered and why it was set aside.
 *
 * Fully offline, like the rest of the tool: both datasets are vendored under
 * data/ and nothing here makes a network call. See scripts/fetch-kev-snapshot.ts
 * and scripts/build-kev-index.ts for how they are built, and NOTICE for the
 * licence attribution each one requires.
 */

/**
 * The exact passages of the guidance this module implements, kept as data so
 * they can be checked verbatim against the vendored primary-source text — the
 * same standard data/cra-structure.json is held to by
 * tests/cra/traceability.test.ts, and the same arrangement src/fda/support.ts
 * uses for the support-level fields.
 *
 * Every excerpt is a single line of the pdftotext extract, with the PDF's own
 * line-wrapping left intact, because a sentence spanning two lines has no
 * verbatim form.
 */
export const FDA_VULN_SOURCE = {
  citation:
    'FDA, "Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions", issued February 3, 2026, sections V.A.2 (p. 14) and V.A.4(b) (pp. 17-18)',
  sourceFile: 'data/sources/fda-premarket-cybersecurity-2026-02-03-extract.md',
  excerpts: {
    /** Why this screen exists at all, and why KEV specifically is named. */
    identifyAll: 'vulnerabilities associated with the device and the software components, including those',
    kevCatalog: 'identified in CISA’s Known Exploited Vulnerabilities Catalog. For each known vulnerability,',
    /** Why every finding carries an `evidence` sentence naming how it was found. */
    howDiscovered: 'manufacturers should describe how the vulnerabilities were discovered to demonstrate whether',
    /** The two columns this module deliberately leaves to the manufacturer. */
    riskAssessment: 'A safety and security risk assessment of each known vulnerability (including device and',
    riskControls: 'Details of applicable safety and security risk controls to address the vulnerability. If risk',
    /** Why a KEV hit is more than informational: V.A.2, p. 14. */
    designedOut: 'in CISA’s Known Exploited Vulnerabilities Catalog should be designed out of the device, as',
  },
} as const;

/**
 * The two things FDA asks the MANUFACTURER to provide for each known
 * vulnerability. Exported as the single agreed wording so the milestone-4
 * renderers emit these as blank columns for the manufacturer to complete
 * instead of each paraphrasing the guidance, and so no surface can imply the
 * tool filled them in.
 */
export const MANUFACTURER_SUPPLIED_COLUMNS = [
  'Safety and security risk assessment (including device and system impacts)',
  'Details of applicable safety and security risk controls',
] as const;

/**
 * What this screen does NOT cover, stated as fixed text so it travels with
 * every artifact that carries the findings. A screen whose limits are only in
 * the README is a screen whose limits a reviewer will discover at the worst
 * possible moment.
 */
export const KEV_SCREEN_LIMITS = [
  'This screen covers the CISA Known Exploited Vulnerabilities Catalog only. FDA asks for ALL known vulnerabilities associated with the device and its software components; vulnerabilities that are not in the KEV catalogue are not searched for here and must be identified by other means.',
  'The KEV catalogue identifies vulnerabilities by vendor and product name and carries no version information, so a match against it alone cannot establish that the specific version in this device is affected. Such rows are reported as "possible".',
  'A "confirmed" row means an ecosystem advisory (npm or PyPI, via OSV) names this exact package and the component version falls inside an affected range. No equivalent version-precise data is bundled for C/C++ or other non-npm/PyPI components, so those components can never reach "confirmed" in this version.',
  'The safety and security risk assessment of each vulnerability, and the risk controls applied, are the manufacturer’s to provide. This screen identifies candidates and records how each was found; it does not assess them.',
] as const;

/** Bumped only when the snapshot's own shape changes incompatibly, so an old vendored file fails loudly instead of being half-read. */
export const KEV_SNAPSHOT_SCHEMA = 1;
/** Likewise for the OSV-derived index. Separate from the snapshot's, because the two files are built by separate scripts on separate cadences. */
export const KEV_INDEX_SCHEMA = 1;

export interface KevSnapshotSource {
  name: string;
  url: string;
  license: string;
  licenseUrl: string;
  /** CISA's own one-line statement of the terms, quoted so the artifact can cite it without a network call. */
  licenseStatement: string;
  /** CISA's catalogue version, e.g. "2026.10.30". */
  catalogVersion: string;
  /** CISA's own dateReleased for the catalogue this snapshot was distilled from — the date the staleness check measures from. */
  dateReleased: string;
  /** The catalogue's own `count`, kept so a silently truncated distillation is detectable. */
  upstreamCount: number;
  upstreamSha256: string;
}

export interface KevCatalogEntry {
  /** CVE id, e.g. "CVE-2021-44228". */
  cve: string;
  /** CISA's `vendorProject`, verbatim. */
  vendor: string;
  /** CISA's `product`, verbatim. */
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate?: string;
  /** True only where CISA says "Known". Their "Unknown" is absence of evidence, not evidence of absence, so it is recorded as absent rather than as false. */
  ransomware?: boolean;
  cwes?: string[];
}

export interface KevSnapshot {
  schema: number;
  source: KevSnapshotSource;
  fetchedAt: string;
  entries: KevCatalogEntry[];
}

export interface KevIndexSource {
  name: string;
  url: string;
  license: string;
  licenseUrl: string;
  /** The attribution the licence requires, in the form it has to appear in NOTICE. */
  attribution: string;
}

/** One OSV range event set, field-renamed to camelCase. OSV's `limit` is kept because it bounds a range the same way `fixed` does. */
export interface KevIndexRange {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
  limit?: string;
}

export interface KevIndexEntry {
  cve: string;
  /** The advisory that supplied the version ranges, e.g. "GHSA-35jh-r3h4-6jhm" or "PYSEC-2021-76". */
  advisory: string;
  /** Which upstream database the advisory came from, by `name` in KevIndex.sources. */
  advisorySource: string;
  ecosystem: 'npm' | 'PyPI';
  /** The package name as the advisory spells it. */
  package: string;
  /** Versionless purl, normalized through normalizePurlKey so both sides of a lookup go through one function. */
  purlKey: string;
  /** OSV range type — "SEMVER" for npm, "ECOSYSTEM" for PyPI. Recorded because it is what the version comparison has to be honest about. */
  rangeType: string;
  ranges: KevIndexRange[];
}

export interface KevIndex {
  schema: number;
  sources: KevIndexSource[];
  builtFrom: {
    kevCatalogVersion: string;
    kevSha256: string;
    kevEntryCount: number;
    /** When OSV was queried. The index is a point-in-time join; a CVE that gained an npm advisory later is not in it. */
    osvQueriedAt: string;
    /** How many KEV CVEs were looked up, and how many had any OSV record, so a near-empty index is visibly near-empty. */
    cvesQueried: number;
    cvesWithOsvRecord: number;
  };
  entries: KevIndexEntry[];
}

/**
 * `confirmed` — an ecosystem advisory names this exact package and the
 * component's version falls in an affected range.
 * `possible`  — the product was identified but no version-precise evidence
 * applies (the normal case for C/C++ components, and for any range this tool
 * declines to evaluate). The reason is in the evidence string.
 * `not-affected` — an advisory names the package and the version is provably
 * outside every affected range. Reported, not dropped.
 */
export type KevConfidence = 'confirmed' | 'possible' | 'not-affected';

export type KevBasis =
  /** data/kev-index.json: an npm/PyPI advisory names this package, with version ranges. */
  | 'ecosystem-advisory'
  /** The component's CPE vendor:product equals the KEV entry's vendor:product. */
  | 'cpe'
  /** The component's supplier AND name match the KEV entry's vendor and product. */
  | 'vendor-product'
  /** Only the product name matched; the vendor could not be corroborated. The weakest basis, and the one most likely to be a different product with the same name. */
  | 'product-name';

/** Strongest first. Used to pick one row when the same CVE matches a component more than one way. */
const BASIS_STRENGTH: readonly KevBasis[] = ['ecosystem-advisory', 'cpe', 'vendor-product', 'product-name'];

export interface KevFinding {
  cve: string;
  vulnerabilityName: string;
  /** CISA's vendor and product for this CVE, carried verbatim so a reviewer can rule out a wrong-product match at a glance. */
  kevVendor: string;
  kevProduct: string;
  /** The date CISA added it to the catalogue, and the remediation due date they set for federal agencies. The due date is not a requirement on a device manufacturer; it is included because it is CISA's own urgency signal. */
  dateAdded: string;
  dueDate?: string;
  ransomware?: boolean;
  cwes?: string[];
  confidence: KevConfidence;
  basis: KevBasis;
  /**
   * One auditable sentence: how this vulnerability was discovered, what was
   * matched, and why the confidence is what it is. FDA asks manufacturers to
   * describe how vulnerabilities were discovered, so this is submission content,
   * not a debug string — including for `possible` and `not-affected` rows.
   */
  evidence: string;
  advisory?: string;
  advisorySource?: string;
}

export interface ComponentKevFindings {
  component: FdaComponent;
  /** `confirmed` and `possible` rows, strongest basis first then by CVE. */
  findings: KevFinding[];
  /** `not-affected` rows: considered and set aside, with the comparison stated. */
  notAffected: KevFinding[];
}

export interface KevLookup {
  snapshot: KevSnapshot;
  index: KevIndex;
  /** `vendorkey:productkey` -> KEV entries. */
  byVendorProduct: Map<string, KevCatalogEntry[]>;
  /** `productkey` -> KEV entries. */
  byProduct: Map<string, KevCatalogEntry[]>;
  /** versionless purl key -> index entries. */
  byPurlKey: Map<string, KevIndexEntry[]>;
  byCve: Map<string, KevCatalogEntry>;
}

export interface KevScreenOptions {
  /** The run's date, YYYY-MM-DD. Defaults to today. Used by the staleness check only; KEV itself carries no dates to compare against. */
  asOf?: string;
  /** Pre-built lookup, for callers screening many components. Built from the bundled data when omitted. */
  lookup?: KevLookup;
}

export interface KevScreenResult {
  results: ComponentKevFindings[];
  warnings: string[];
  /** KEV_SCREEN_LIMITS, carried on the result so a renderer cannot emit findings without them. */
  limits: readonly string[];
  snapshotSource: KevSnapshotSource;
  indexSources: KevIndexSource[];
  /**
   * The advisory index's own build record. Carried on the result because the
   * artifacts have to state when the advisory data was captured (`osvQueriedAt`)
   * separately from the KEV catalogue version — the index is a point-in-time
   * join, so a CVE that gained an npm advisory after that date is screened
   * against the catalogue but not against any version range.
   */
  indexBuiltFrom: KevIndex['builtFrom'];
  totals: {
    components: number;
    componentsWithFindings: number;
    confirmed: number;
    possible: number;
    notAffected: number;
    /** How many findings CISA flags as used in a known ransomware campaign. */
    ransomware: number;
    /** How many findings rest on a product name alone, with no vendor corroboration — the ones most likely to be a different product with the same name. */
    productNameOnly: number;
  };
}

/**
 * Reduce a vendor or product string to a comparison key: lowercased with every
 * non-alphanumeric character removed, so "Connect Secure", "connect-secure" and
 * "ConnectSecure" land on one key.
 *
 * Stripping separators rather than normalising them to a single dash is
 * deliberate: CISA's product strings are prose ("Internet Explorer", "Smart
 * Install"), SBOM component names are package identifiers ("internet_explorer",
 * "smart-install"), and the separator convention between the two is arbitrary.
 * Returns undefined for a string with no alphanumeric content, which must never
 * become a key that matches everything.
 */
export function normalizeKevKey(value: string): string | undefined {
  const key = value.toLowerCase().replace(/[^a-z0-9]+/g, '');
  return key.length > 0 ? key : undefined;
}

let cachedSnapshot: KevSnapshot | undefined;
let cachedIndex: KevIndex | undefined;

function readJson(file: string, what: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`Cannot read the ${what} at ${file} (${(err as Error).message}). Reinstall the package — data/ did not ship or is corrupt.`);
  }
}

/**
 * Load and structurally check the vendored KEV snapshot. Throws rather than
 * returning an empty catalogue: a missing or wrong-schema file in an installed
 * package is a broken install, and screening every component against nothing
 * would produce a clean-looking "no known exploited vulnerabilities" result
 * that is the most dangerous possible output of this tool.
 */
export function loadKevSnapshot(dataDir: string = DATA_DIR): KevSnapshot {
  if (dataDir === DATA_DIR && cachedSnapshot) return cachedSnapshot;
  const file = path.join(dataDir, 'kev-snapshot.json');
  const snapshot = readJson(file, 'KEV catalogue snapshot') as KevSnapshot;
  if (!snapshot || typeof snapshot !== 'object' || !Array.isArray(snapshot.entries) || !snapshot.source) {
    throw new Error(`The KEV catalogue snapshot at ${file} is not in the expected shape.`);
  }
  if (snapshot.schema !== KEV_SNAPSHOT_SCHEMA) {
    throw new Error(`The KEV catalogue snapshot at ${file} declares schema ${String(snapshot.schema)}, but this version of the tool reads schema ${KEV_SNAPSHOT_SCHEMA}. Re-run scripts/fetch-kev-snapshot.ts.`);
  }
  if (snapshot.entries.length === 0) {
    throw new Error(`The KEV catalogue snapshot at ${file} contains no entries. Screening against an empty catalogue would report every component as having no known exploited vulnerabilities, which is worse than failing. Re-run scripts/fetch-kev-snapshot.ts.`);
  }
  if (dataDir === DATA_DIR) cachedSnapshot = snapshot;
  return snapshot;
}

/**
 * Load the OSV-derived version-range index. An EMPTY index is legitimate here,
 * unlike an empty snapshot — it only means no KEV CVE currently has an npm or
 * PyPI advisory — so the floor check is on shape, not on size. Losing the index
 * costs `confirmed` rows, never whole findings: without it every match falls
 * back to `possible`.
 */
export function loadKevIndex(dataDir: string = DATA_DIR): KevIndex {
  if (dataDir === DATA_DIR && cachedIndex) return cachedIndex;
  const file = path.join(dataDir, 'kev-index.json');
  const index = readJson(file, 'KEV ecosystem-advisory index') as KevIndex;
  if (!index || typeof index !== 'object' || !Array.isArray(index.entries) || !Array.isArray(index.sources) || !index.builtFrom) {
    throw new Error(`The KEV ecosystem-advisory index at ${file} is not in the expected shape.`);
  }
  if (index.schema !== KEV_INDEX_SCHEMA) {
    throw new Error(`The KEV ecosystem-advisory index at ${file} declares schema ${String(index.schema)}, but this version of the tool reads schema ${KEV_INDEX_SCHEMA}. Re-run scripts/build-kev-index.ts.`);
  }
  if (dataDir === DATA_DIR) cachedIndex = index;
  return index;
}

function push<T>(map: Map<string, T[]>, key: string, value: T): void {
  const existing = map.get(key);
  if (existing) existing.push(value);
  else map.set(key, [value]);
}

export function buildKevLookup(snapshot: KevSnapshot, index: KevIndex): KevLookup {
  const lookup: KevLookup = {
    snapshot,
    index,
    byVendorProduct: new Map(),
    byProduct: new Map(),
    byPurlKey: new Map(),
    byCve: new Map(),
  };
  for (const entry of snapshot.entries) {
    lookup.byCve.set(entry.cve, entry);
    const vendor = normalizeKevKey(entry.vendor);
    const product = normalizeKevKey(entry.product);
    if (!product) continue;
    push(lookup.byProduct, product, entry);
    if (vendor) push(lookup.byVendorProduct, `${vendor}:${product}`, entry);
  }
  for (const entry of index.entries) {
    push(lookup.byPurlKey, entry.purlKey, entry);
  }
  return lookup;
}

/** Build the lookup from the two bundled files. */
export function loadKevLookup(dataDir: string = DATA_DIR): KevLookup {
  return buildKevLookup(loadKevSnapshot(dataDir), loadKevIndex(dataDir));
}

const PLAIN_NUMERIC = /^\d+(\.\d+)*$/;

/**
 * Compare two version strings, or REFUSE by returning undefined.
 *
 * Deliberately narrow: it compares plain dotted-numeric versions ("0", "1.2",
 * "4.17.21") and nothing else. Anything carrying a pre-release, post-release,
 * dev, epoch, build-metadata or distro suffix — "1.0.0-rc.1", "2.0.0rc1",
 * "1.0.post1", "1:1.1.1n-0+deb11u5" — is refused outright.
 *
 * Refusing is the whole point. npm ranges are SEMVER-ordered and PyPI ranges
 * are PEP 440-ordered, and those two orderings disagree about exactly the
 * suffixed versions above. Implementing both correctly is a large amount of
 * code; implementing one of them approximately and applying it to both would
 * put a wrong "not affected" next to a known-exploited CVE in a premarket
 * submission. A refusal degrades the finding to `possible` with the reason
 * stated, which is the safe direction: the row still appears, it just isn't
 * version-precise.
 *
 * ponytail: plain-numeric comparison only; add a real SEMVER/PEP 440 comparator
 * if pre-release component versions turn out to be common in real device SBOMs.
 */
export function compareVersions(a: string, b: string): number | undefined {
  if (!PLAIN_NUMERIC.test(a) || !PLAIN_NUMERIC.test(b)) return undefined;
  const left = a.split('.').map(Number);
  const right = b.split('.').map(Number);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    // A missing trailing segment is zero: "1.2" and "1.2.0" are the same
    // version in both SEMVER and PEP 440.
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * Does `version` fall inside this range? `undefined` means the comparison was
 * refused (see compareVersions) and the caller must not conclude anything.
 *
 * OSV's own event semantics: a version is affected once it is at or after an
 * `introduced` bound, and stops being affected at or after a `fixed` or `limit`
 * bound, or after a `last_affected` one. Events are applied in version order
 * rather than file order, because OSV does not guarantee the array is sorted.
 */
export function evaluateRange(version: string, range: KevIndexRange): boolean | undefined {
  const bounds: { at: string; affectedFromHere: boolean; inclusive: boolean }[] = [];
  if (range.introduced !== undefined) bounds.push({ at: range.introduced, affectedFromHere: true, inclusive: true });
  if (range.fixed !== undefined) bounds.push({ at: range.fixed, affectedFromHere: false, inclusive: true });
  if (range.limit !== undefined) bounds.push({ at: range.limit, affectedFromHere: false, inclusive: true });
  // last_affected is the final affected version, so the flip happens strictly
  // AFTER it — one off-by-one away from fixed, and the difference matters.
  if (range.lastAffected !== undefined) bounds.push({ at: range.lastAffected, affectedFromHere: false, inclusive: false });
  if (bounds.length === 0) return undefined;

  // Sort the bounds themselves, refusing the whole range if any pair is
  // incomparable rather than falling back to file order.
  for (const bound of bounds) {
    if (compareVersions(version, bound.at) === undefined) return undefined;
  }
  const sorted = [...bounds].sort((x, y) => compareVersions(x.at, y.at) ?? 0);

  let affected = false;
  for (const bound of sorted) {
    const cmp = compareVersions(version, bound.at);
    if (cmp === undefined) return undefined;
    const reached = bound.inclusive ? cmp >= 0 : cmp > 0;
    if (reached) affected = bound.affectedFromHere;
  }
  return affected;
}

/** `true` if any range covers the version, `false` if all evaluable ranges exclude it, `undefined` if the comparison was refused. */
export function evaluateRanges(version: string, ranges: KevIndexRange[]): boolean | undefined {
  let sawRefusal = false;
  let sawEvaluable = false;
  for (const range of ranges) {
    const result = evaluateRange(version, range);
    if (result === undefined) sawRefusal = true;
    else if (result) return true;
    else sawEvaluable = true;
  }
  if (sawRefusal || !sawEvaluable) return undefined;
  return false;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

/** Candidate `vendor:product` and `product` keys a component offers, cheapest identity signal last. */
function componentKeys(component: FdaComponent): {
  cpeKey?: string;
  supplierKey?: string;
  nameKeys: string[];
} {
  const cpeKey = component.cpe ? normalizeCpeKey(component.cpe) : undefined;
  const supplierKey = component.supplier ? normalizeKevKey(component.supplier) : undefined;
  const nameKeys: string[] = [];
  const fromName = normalizeKevKey(component.name);
  if (fromName) nameKeys.push(fromName);
  // The product half of a CPE is frequently a better product name than the
  // component's own name (a Yocto SBOM may call it "openssl-bin" while the CPE
  // says "openssl").
  if (cpeKey) {
    const product = normalizeKevKey(cpeKey.slice(cpeKey.indexOf(':') + 1));
    if (product && !nameKeys.includes(product)) nameKeys.push(product);
  }
  return { ...(cpeKey ? { cpeKey } : {}), ...(supplierKey ? { supplierKey } : {}), nameKeys };
}

function baseFinding(entry: KevCatalogEntry): Omit<KevFinding, 'confidence' | 'basis' | 'evidence'> {
  return {
    cve: entry.cve,
    vulnerabilityName: entry.vulnerabilityName,
    kevVendor: entry.vendor,
    kevProduct: entry.product,
    dateAdded: entry.dateAdded,
    ...(entry.dueDate ? { dueDate: entry.dueDate } : {}),
    ...(entry.ransomware ? { ransomware: true } : {}),
    ...(entry.cwes && entry.cwes.length > 0 ? { cwes: [...entry.cwes] } : {}),
  };
}

/** The sentence every finding opens with — FDA asks how the vulnerability was discovered, and the answer is the same for all of them. */
function discoveredBy(catalogVersion: string): string {
  return `Discovered by screening the component list against the bundled CISA Known Exploited Vulnerabilities Catalog (catalogue version ${catalogVersion}), offline.`;
}

/**
 * The ecosystem-advisory pass: npm/PyPI components matched by purl against
 * data/kev-index.json, which carries real affected version ranges. This is the
 * only path that can produce `confirmed` or `not-affected`.
 */
function advisoryFindings(
  component: FdaComponent,
  lookup: KevLookup,
  discovery: string,
): { byCve: Map<string, KevFinding>; warnings: string[] } {
  const byCve = new Map<string, KevFinding>();
  const warnings: string[] = [];
  const purlKey = component.purl ? normalizePurlKey(component.purl) : undefined;
  if (!purlKey) return { byCve, warnings };
  const matches = lookup.byPurlKey.get(purlKey);
  if (!matches) return { byCve, warnings };

  for (const match of matches) {
    const entry = lookup.byCve.get(match.cve);
    // An index entry whose CVE is not in the snapshot means the two files were
    // built from different catalogue versions. Say so rather than dropping the
    // row: the index exists only to refine KEV findings.
    if (!entry) {
      warnings.push(
        `data/kev-index.json references ${match.cve} (via ${match.advisory}) but data/kev-snapshot.json does not contain it, so the finding for ${component.name} was skipped. ` +
          'The two files were built from different catalogue versions — re-run "npm run fetch-kev-snapshot" then "npm run build-kev-index".',
      );
      continue;
    }
    const where = `${match.advisorySource} advisory ${match.advisory} names ${match.ecosystem} package "${match.package}" as affected by ${match.cve}`;
    const ranges = match.ranges
      .map((r) =>
        [
          r.introduced !== undefined ? `>= ${r.introduced}` : undefined,
          r.fixed !== undefined ? `< ${r.fixed} (fixed)` : undefined,
          r.lastAffected !== undefined ? `<= ${r.lastAffected} (last affected)` : undefined,
          r.limit !== undefined ? `< ${r.limit} (limit)` : undefined,
        ]
          .filter(Boolean)
          .join(' and '),
      )
      .filter((s) => s.length > 0)
      .join('; ');

    const common = { ...baseFinding(entry), basis: 'ecosystem-advisory' as const, advisory: match.advisory, advisorySource: match.advisorySource };
    let finding: KevFinding;
    if (!component.version) {
      finding = {
        ...common,
        confidence: 'possible',
        evidence: `${discovery} ${where}, with affected ranges ${ranges}. The component carries no version, so whether this device's copy is inside an affected range could not be determined.`,
      };
    } else {
      const affected = evaluateRanges(component.version, match.ranges);
      if (affected === true) {
        finding = {
          ...common,
          confidence: 'confirmed',
          evidence: `${discovery} ${where}. Version ${component.version} falls inside the affected range ${ranges} (${match.rangeType} ordering).`,
        };
      } else if (affected === false) {
        finding = {
          ...common,
          confidence: 'not-affected',
          evidence: `${discovery} ${where}, but version ${component.version} is outside every affected range (${ranges}, ${match.rangeType} ordering). Recorded so the CVE is visibly considered rather than silently omitted.`,
        };
      } else {
        finding = {
          ...common,
          confidence: 'possible',
          evidence:
            `${discovery} ${where}, with affected ranges ${ranges}. This tool declined to compare version "${component.version}" against those bounds — ` +
            'it only compares plain dotted-numeric versions, because SEMVER and PEP 440 order pre-release and post-release versions differently and a wrong comparison here would mean a wrong "not affected" next to a known-exploited vulnerability. Check this one by hand.',
        };
      }
    }
    const existing = byCve.get(entry.cve);
    // The same CVE can name two packages that both match (e.g. a scoped and an
    // unscoped alias). Keep the most severe verdict.
    if (!existing || rank(finding.confidence) < rank(existing.confidence)) byCve.set(entry.cve, finding);
  }
  return { byCve, warnings };
}

function rank(confidence: KevConfidence): number {
  return confidence === 'confirmed' ? 0 : confidence === 'possible' ? 1 : 2;
}

/**
 * The identity pass over the KEV catalogue itself. Produces `possible` rows
 * only, always — the catalogue has no version data, so no amount of identity
 * confidence can make a row version-precise.
 */
function identityFindings(component: FdaComponent, lookup: KevLookup, discovery: string): Map<string, KevFinding> {
  const byCve = new Map<string, KevFinding>();
  const { cpeKey, supplierKey, nameKeys } = componentKeys(component);
  const noVersions =
    'The KEV catalogue records no version information, so this identifies a known-exploited vulnerability in the product, not in this specific version of it; the match is reported as possible and needs confirmation against the component version by hand.';

  const consider = (entry: KevCatalogEntry, basis: KevBasis, how: string): void => {
    const existing = byCve.get(entry.cve);
    if (existing && BASIS_STRENGTH.indexOf(existing.basis) <= BASIS_STRENGTH.indexOf(basis)) return;
    byCve.set(entry.cve, {
      ...baseFinding(entry),
      confidence: 'possible',
      basis,
      evidence: `${discovery} ${how} ${noVersions}`,
    });
  };

  if (cpeKey) {
    for (const entry of lookup.byVendorProduct.get(cpeKey) ?? []) {
      consider(
        entry,
        'cpe',
        `The component's CPE resolves to vendor:product "${cpeKey}", which equals CISA's listed vendor "${entry.vendor}" and product "${entry.product}".`,
      );
    }
  }

  for (const nameKey of nameKeys) {
    if (supplierKey) {
      for (const entry of lookup.byVendorProduct.get(`${supplierKey}:${nameKey}`) ?? []) {
        consider(
          entry,
          'vendor-product',
          `The SBOM's supplier "${component.supplier}" and component name "${component.name}" match CISA's listed vendor "${entry.vendor}" and product "${entry.product}".`,
        );
      }
    }
    for (const entry of lookup.byProduct.get(nameKey) ?? []) {
      const supplierMismatch =
        supplierKey && normalizeKevKey(entry.vendor) !== supplierKey
          ? ` The SBOM names supplier "${component.supplier}" while CISA lists vendor "${entry.vendor}", so this may well be a different product that shares a name — check before carrying it forward.`
          : ' The vendor could not be corroborated (the component declares no supplier), so this may be a different product that shares a name — check before carrying it forward.';
      consider(
        entry,
        'product-name',
        `Component name "${component.name}" matches CISA's listed product "${entry.product}" (vendor "${entry.vendor}").${supplierMismatch}`,
      );
    }
  }
  return byCve;
}

/**
 * Screen every component against the bundled KEV catalogue, refined by the
 * bundled ecosystem-advisory index where it applies.
 *
 * Ordering of the two passes is deliberate: the advisory pass runs first and its
 * verdict for a CVE wins, because a version-range comparison is strictly better
 * evidence than a product-name match for the same CVE. A CVE the advisory pass
 * ruled `not-affected` is therefore NOT re-raised as `possible` by the identity
 * pass — that would be the tool arguing with its own better evidence — but it
 * still appears in `notAffected` with the comparison written out.
 */
export function screenKev(components: FdaComponent[], options: KevScreenOptions = {}): KevScreenResult {
  const asOf = options.asOf ?? today();
  const lookup = options.lookup ?? loadKevLookup();
  const { snapshot, index } = lookup;
  const warnings: string[] = [];
  const seenIndexWarnings = new Set<string>();

  const stale = snapshotStalenessWarning({
    label: `CISA Known Exploited Vulnerabilities Catalog (catalogue version ${snapshot.source.catalogVersion})`,
    generatedAt: snapshot.source.dateReleased,
    asOf,
    consequence:
      'CISA adds newly-exploited vulnerabilities to the catalogue continuously, so a component shown here as having no known exploited vulnerability may have had one catalogued since this snapshot was taken.',
    refreshCommand: 'npm run fetch-kev-snapshot, then npm run build-kev-index',
  });
  if (stale) warnings.push(stale);

  const results: ComponentKevFindings[] = [];
  const totals = {
    components: components.length,
    componentsWithFindings: 0,
    confirmed: 0,
    possible: 0,
    notAffected: 0,
    ransomware: 0,
    productNameOnly: 0,
  };

  for (const component of components) {
    const discovery = discoveredBy(snapshot.source.catalogVersion);
    const advisory = advisoryFindings(component, lookup, discovery);
    for (const warning of advisory.warnings) {
      if (!seenIndexWarnings.has(warning)) {
        seenIndexWarnings.add(warning);
        warnings.push(warning);
      }
    }
    const byCve = advisory.byCve;
    for (const [cve, finding] of identityFindings(component, lookup, discovery)) {
      if (!byCve.has(cve)) byCve.set(cve, finding);
    }

    const all = [...byCve.values()].sort(
      (a, b) => rank(a.confidence) - rank(b.confidence) || BASIS_STRENGTH.indexOf(a.basis) - BASIS_STRENGTH.indexOf(b.basis) || a.cve.localeCompare(b.cve),
    );
    const findings = all.filter((f) => f.confidence !== 'not-affected');
    const notAffected = all.filter((f) => f.confidence === 'not-affected');
    if (findings.length > 0) totals.componentsWithFindings += 1;
    for (const finding of findings) {
      if (finding.confidence === 'confirmed') totals.confirmed += 1;
      else totals.possible += 1;
      if (finding.ransomware) totals.ransomware += 1;
      if (finding.basis === 'product-name') totals.productNameOnly += 1;
    }
    totals.notAffected += notAffected.length;
    results.push({ component, findings, notAffected });
  }

  if (totals.confirmed > 0) {
    warnings.push(
      `${totals.confirmed} known-exploited ${totals.confirmed === 1 ? 'vulnerability is' : 'vulnerabilities are'} confirmed against a component version in this device. ` +
        'FDA’s guidance states that vulnerabilities in CISA’s catalogue should be designed out of the device, so each one needs a safety and security risk assessment and the risk controls applied, written by the manufacturer.',
    );
  }
  if (totals.productNameOnly > 0) {
    warnings.push(
      `${totals.productNameOnly} of the ${totals.confirmed + totals.possible} findings rest on a product-name match with no corroborating vendor, and some of those will be a different product that happens to share a name. ` +
        'They are listed rather than filtered because missing a real known-exploited vulnerability is the worse error; each row names CISA’s vendor so it can be ruled out quickly.',
    );
  }
  if (index.entries.length === 0) {
    warnings.push(
      'data/kev-index.json is empty, so no finding in this run can be version-precise and everything is reported as "possible". Re-run "npm run build-kev-index".',
    );
  }

  return {
    results,
    warnings,
    limits: KEV_SCREEN_LIMITS,
    snapshotSource: snapshot.source,
    indexSources: index.sources,
    indexBuiltFrom: index.builtFrom,
    totals,
  };
}
