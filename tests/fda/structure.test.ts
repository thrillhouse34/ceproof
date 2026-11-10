import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR, REPO_ROOT } from '../../src/paths';
import { FDA_MEASURES, getFdaStructure, parseFdaStructure } from '../../src/fda/structure';
import { computeFdaProfile } from '../../src/fda/gap';
import { fixtureInput } from './renderFixture';

/**
 * The same traceability standard `tests/cra/traceability.test.ts` holds
 * `data/cra-structure.json` to, applied to the FDA extraction: every item's
 * `sourceExcerpt` must appear VERBATIM in the vendored primary-source file it
 * cites. That is what makes the free profile's output auditable back to the
 * guidance text rather than to a paraphrase someone wrote from memory.
 */
describe('FDA structure data — traceability to the vendored guidance text', () => {
  const structure = getFdaStructure();

  it('is the real extraction, not a placeholder', () => {
    expect(structure.sourceVersion.toLowerCase()).not.toContain('placeholder');
    expect(structure.items.length).toBeGreaterThan(0);
    expect(structure.sourceVersion).toContain('February 3, 2026');
  });

  it('every item cites a sourceFile that exists under data/sources/', () => {
    for (const item of structure.items) {
      const resolved = path.join(REPO_ROOT, item.sourceFile);
      expect(fs.existsSync(resolved), `${item.id}: ${item.sourceFile} does not exist`).toBe(true);
      expect(path.resolve(resolved).startsWith(path.resolve(DATA_DIR, 'sources'))).toBe(true);
    }
  });

  it('every sourceExcerpt appears verbatim in its cited sourceFile', () => {
    const cache = new Map<string, string>();
    const failures: string[] = [];
    for (const item of structure.items) {
      const resolved = path.join(REPO_ROOT, item.sourceFile);
      if (!cache.has(resolved)) cache.set(resolved, fs.readFileSync(resolved, 'utf8'));
      if (!cache.get(resolved)!.includes(item.sourceExcerpt)) {
        failures.push(`${item.id}: sourceExcerpt not found verbatim in ${item.sourceFile}`);
      }
    }
    expect(failures, failures.join('\n')).toEqual([]);
  });

  it('every sourceExcerpt is substantial enough to prove anything', () => {
    for (const item of structure.items) {
      expect(item.sourceExcerpt.trim().length, `${item.id}: sourceExcerpt too short to be meaningful`).toBeGreaterThan(15);
    }
  });

  it('every citation names the guidance and a section', () => {
    for (const item of structure.items) {
      expect(item.citation, item.id).toContain('February 3, 2026');
      expect(item.citation, `${item.id}: no section in the citation`).toMatch(/section\s+V/);
    }
  });

  it('discloses in the data file what it could NOT trace: the NTIA document is not vendored', () => {
    // FDA incorporates the NTIA 2021 minimum elements by reference instead of
    // listing them, so the seven element NAMES come from a document that is not
    // under data/sources/. That limit belongs in the data, not only in a
    // comment, because the data is what ships.
    expect(structure.notVendored).toContain('NTIA');
    expect(structure.notVendored).toContain('not vendored');
    expect(structure.sourceVersion).toContain('NOT vendored in this repo');
  });

  it('dates the minimum-elements report July 12, 2021, and names it by title and URL', () => {
    // TWO different NTIA documents are in play and they are a year apart in
    // nothing but confusion:
    //  - the minimum elements themselves are "The Minimum Elements For a
    //    Software Bill of Materials (SBOM)", July 12, 2021;
    //  - FDA's sentence cites "Framing Software Component Transparency" and
    //    dates it October 2021.
    // Naming only the second (which this file used to do) attributes the
    // elements to a document that does not contain them. Naming only the
    // first silently corrects a verbatim FDA citation. Both are stated, so
    // neither error can come back.
    const ntia = `${structure.sourceVersion} ${structure.notVendored}`;
    expect(ntia).toContain('July 12, 2021');
    expect(ntia).toContain('The Minimum Elements For a Software Bill of Materials (SBOM)');
    expect(ntia).toContain('https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf');
    expect(ntia).toContain('Framing Software Component Transparency'); // FDA's own words, kept
    const item = structure.items.find((i) => i.measure === 'ntia-minimum-elements');
    expect(item?.citation).toContain('July 12, 2021');
    // And nowhere does anything still attribute the ELEMENTS to October 2021.
    expect(structure.sourceVersion).not.toMatch(/minimum elements[^.]*October 2021/);
  });

  it('carries a short guidance identifier as well as the full one, because the full one is 650 characters', () => {
    expect(structure.shortVersion.length).toBeLessThan(80);
    expect(structure.sourceVersion.length).toBeGreaterThan(200);
  });
});

/**
 * The drift guard. An item whose measure nothing resolves would render as an
 * unexplained gap; a resolver for a measure no item names is dead code that
 * reads as coverage. Both directions are checked.
 */
describe('FDA structure data — measures and resolvers agree', () => {
  const structure = getFdaStructure();

  it('every item names a measure the resolver knows', () => {
    for (const item of structure.items) {
      expect(FDA_MEASURES, `${item.id}: unknown measure`).toContain(item.measure);
    }
  });

  it('every known measure is used by exactly one item — no orphan resolver, no duplicate', () => {
    const used = structure.items.map((i) => i.measure);
    expect([...used].sort()).toEqual([...FDA_MEASURES].sort());
  });

  it('resolves every item to a real status, with evidence, on a real run', () => {
    const profile = computeFdaProfile(fixtureInput());
    expect(profile.items).toHaveLength(structure.items.length);
    for (const item of profile.items) {
      expect(['DERIVED', 'PARTIAL', 'NEEDS-HUMAN-INPUT']).toContain(item.status);
      // A status with no evidence is indistinguishable from a bug.
      expect(item.evidence.length, `${item.id}: resolved with no evidence`).toBeGreaterThan(0);
      for (const line of item.evidence) expect(line.trim().length).toBeGreaterThan(0);
    }
  });
});

describe('the FDA structure loader refuses malformed data loudly', () => {
  const valid = {
    sourceVersion: 'v',
    shortVersion: 's',
    generatedAt: 'now',
    notVendored: 'n',
    items: [
      {
        id: 'a',
        requirementSummary: 'r',
        citation: 'c',
        sourceFile: 'data/sources/x.md',
        sourceExcerpt: 'e',
        measure: 'sbom-provided',
      },
    ],
  };

  it('accepts a well-formed file', () => {
    expect(parseFdaStructure(valid).items[0].measure).toBe('sbom-provided');
  });

  it('rejects an unknown measure rather than carrying an item nothing can resolve', () => {
    expect(() => parseFdaStructure({ ...valid, items: [{ ...valid.items[0], measure: 'vibes' }] })).toThrow(/measure/);
  });

  it('rejects a duplicate item id', () => {
    expect(() => parseFdaStructure({ ...valid, items: [valid.items[0], valid.items[0]] })).toThrow(/duplicate item id/);
  });

  it('rejects a missing required field', () => {
    expect(() => parseFdaStructure({ ...valid, shortVersion: undefined })).toThrow(/shortVersion/);
    expect(() => parseFdaStructure({ ...valid, items: [{ ...valid.items[0], citation: '' }] })).toThrow(/citation/);
  });

  it('rejects a non-object root and a non-array items', () => {
    expect(() => parseFdaStructure(null)).toThrow(/top-level object/);
    expect(() => parseFdaStructure({ ...valid, items: 'nope' })).toThrow(/must be an array/);
  });
});
