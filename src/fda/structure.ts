import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR } from '../paths';

/**
 * `data/fda-structure.json`: the content items FDA's premarket cybersecurity
 * guidance asks for around the SBOM, extracted from the vendored primary text
 * and held to the same traceability standard as `data/cra-structure.json` —
 * every item's `sourceExcerpt` must appear verbatim in the file it cites
 * (`tests/fda/structure.test.ts`).
 *
 * Why this is a separate file and a separate loader from `src/cra/loader.ts`
 * rather than a second instrument on the CRA one: a `CraStructureItem` carries
 * an `instrument` of `annexVII | annexV` and `evidenceKeys` that are dot-paths
 * into `RepoFacts`. Neither means anything here. The FDA items resolve against
 * the FDA mode's own three engine results (the merged component list, the
 * support resolution, the KEV screen), not against repo facts, so they carry a
 * `measure` naming which of those metrics answers the item instead. Widening
 * the CRA types to cover both would make `instrument` and `evidenceKeys`
 * optional for every CRA item in order to serve a mode that does not use them.
 *
 * The resolution vocabulary IS shared — `GapStatus`, and the
 * DERIVED/PARTIAL/NEEDS-HUMAN-INPUT meanings — because a user reading both
 * views should not have to learn two scales. See `src/fda/gap.ts`.
 */

/**
 * Which run metric answers an item. A closed set: `src/fda/gap.ts` owns one
 * resolver per value, and `tests/fda/structure.test.ts` asserts the set in the
 * data file and the set the resolver handles are the SAME set, in both
 * directions — an item with a measure nothing resolves would silently render
 * as an unexplained gap, and a resolver for a measure no item names is dead
 * code that looks like coverage.
 */
export const FDA_MEASURES = [
  'sbom-provided',
  'ntia-minimum-elements',
  'support-placement',
  'support-level',
  'end-of-support-date',
  'unknown-justification',
  'all-known-vulnerabilities',
  'kev-screen',
  'how-discovered',
  'risk-assessment',
  'risk-controls',
  'kev-designed-out',
  'cyber-device-determination',
] as const;

export type FdaMeasure = (typeof FDA_MEASURES)[number];

export function isFdaMeasure(value: unknown): value is FdaMeasure {
  return typeof value === 'string' && (FDA_MEASURES as readonly string[]).includes(value);
}

export interface FdaStructureItem {
  id: string;
  requirementSummary: string;
  citation: string;
  /** Relative path under data/sources/ — the vendored primary text. */
  sourceFile: string;
  /** Verbatim excerpt anchoring the citation. One line of the pdftotext extract, because the PDF's own wrapping means a sentence spanning two lines has no verbatim form. */
  sourceExcerpt: string;
  measure: FdaMeasure;
}

export interface FdaStructureFile {
  sourceVersion: string;
  /**
   * The same guidance, short enough for a terminal header line. The full
   * `sourceVersion` runs to ~650 characters (docket number, superseded
   * edition, the two NTIA documents) and would dwarf every other field in
   * the header; it is stated in full exactly once, below it. The CRA summary
   * solves the same problem with `shortDataVersion`, by regex; here it is a
   * field, because a hand-written short form cannot drift out of a regex's
   * reach the way the CRA one did.
   */
  shortVersion: string;
  generatedAt: string;
  /**
   * What this extraction could NOT trace to vendored text, stated in the data
   * file rather than only in a comment. FDA incorporates the NTIA 2021 minimum
   * elements by reference instead of listing them, and that NTIA document is
   * not vendored here.
   */
  notVendored: string;
  items: FdaStructureItem[];
}

function assertString(value: unknown, field: string, where: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Malformed FDA structure data: ${where} field "${field}" must be a non-empty string`);
  }
  return value;
}

export function parseFdaStructure(raw: unknown): FdaStructureFile {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Malformed FDA structure data: expected a top-level object');
  }
  const data = raw as Record<string, unknown>;
  if (!Array.isArray(data.items)) {
    throw new Error('Malformed FDA structure data: field "items" must be an array');
  }
  const seen = new Set<string>();
  const items = data.items.map((raw, index) => {
    const where = `items[${index}]`;
    if (typeof raw !== 'object' || raw === null) throw new Error(`Malformed FDA structure data: ${where} must be an object`);
    const item = raw as Record<string, unknown>;
    const id = assertString(item.id, 'id', where);
    // A duplicate id would make one of the two items unreachable by id in the
    // JSON output, which is the surface a CI pipeline keys off.
    if (seen.has(id)) throw new Error(`Malformed FDA structure data: duplicate item id "${id}"`);
    seen.add(id);
    if (!isFdaMeasure(item.measure)) {
      throw new Error(`Malformed FDA structure data: ${where} field "measure" must be one of ${FDA_MEASURES.join(', ')}`);
    }
    return {
      id,
      requirementSummary: assertString(item.requirementSummary, 'requirementSummary', where),
      citation: assertString(item.citation, 'citation', where),
      sourceFile: assertString(item.sourceFile, 'sourceFile', where),
      sourceExcerpt: assertString(item.sourceExcerpt, 'sourceExcerpt', where),
      measure: item.measure,
    };
  });
  return {
    sourceVersion: assertString(data.sourceVersion, 'sourceVersion', 'root'),
    shortVersion: assertString(data.shortVersion, 'shortVersion', 'root'),
    generatedAt: assertString(data.generatedAt, 'generatedAt', 'root'),
    notVendored: assertString(data.notVendored, 'notVendored', 'root'),
    items,
  };
}

let cached: FdaStructureFile | undefined;

export function getFdaStructure(dataDir: string = DATA_DIR): FdaStructureFile {
  if (cached) return cached;
  const filePath = path.join(dataDir, 'fda-structure.json');
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    throw new Error(`Failed to read/parse FDA structure data at ${filePath}: ${(err as Error).message}`);
  }
  cached = parseFdaStructure(raw);
  return cached;
}

export function getFdaStructureVersion(dataDir?: string): string {
  return getFdaStructure(dataDir).sourceVersion;
}
