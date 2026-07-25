import { describe, it, expect } from 'vitest';
import { getCraStructure, getCraSourceVersion, parseCraStructure } from '../../src/cra/loader';

describe('cra structure loader', () => {
  it('loads sourceVersion, generatedAt, and items from data/cra-structure.json', () => {
    // Deliberately not hardcoding the exact real sourceVersion/item-count
    // here — this is the real, non-placeholder CRA structure data now, and
    // asserting an exact string/count would make this test brittle against
    // legitimate future re-extractions (e.g. once a corrigendum touches
    // Annex V/VII, or the source is re-verified against a newer
    // consolidation). tests/cra/traceability.test.ts is the test that
    // actually enforces content correctness (every excerpt verified
    // verbatim against the vendored source).
    const structure = getCraStructure();
    expect(structure.sourceVersion.length).toBeGreaterThan(0);
    expect(structure.sourceVersion.toLowerCase()).not.toContain('placeholder');
    expect(structure.generatedAt.length).toBeGreaterThan(0);
    expect(Array.isArray(structure.items)).toBe(true);
    expect(structure.items.length).toBeGreaterThan(0);
  });

  it('getCraSourceVersion returns the same non-empty string as structure.sourceVersion', () => {
    expect(getCraSourceVersion()).toBe(getCraStructure().sourceVersion);
    expect(getCraSourceVersion().length).toBeGreaterThan(0);
  });

  it('includes a mix of instruments and derivability levels', () => {
    const { items } = getCraStructure();
    const instruments = new Set(items.map((i) => i.instrument));
    const derivabilities = new Set(items.map((i) => i.derivability));

    expect(instruments.has('annexVII')).toBe(true);
    expect(instruments.has('annexV')).toBe(true);
    expect(derivabilities.has('derivable')).toBe(true);
    expect(derivabilities.has('partial')).toBe(true);
    expect(derivabilities.has('human-required')).toBe(true);
  });

  it('every item has all required string fields populated and a valid evidenceKeys array', () => {
    const { items } = getCraStructure();
    for (const item of items) {
      expect(item.id.length).toBeGreaterThan(0);
      expect(item.requirementSummary.length).toBeGreaterThan(0);
      expect(item.citation.length).toBeGreaterThan(0);
      expect(item.sourceFile.length).toBeGreaterThan(0);
      expect(item.sourceExcerpt.length).toBeGreaterThan(0);
      expect(['annexVII', 'annexV']).toContain(item.instrument);
      expect(['derivable', 'partial', 'human-required', 'boilerplate']).toContain(item.derivability);
      expect(Array.isArray(item.evidenceKeys)).toBe(true);
      for (const key of item.evidenceKeys) {
        expect(typeof key).toBe('string');
      }
      if (item.derivability === 'boilerplate') {
        expect(item.boilerplateText, `${item.id}: boilerplate item missing boilerplateText`).toBeTruthy();
      } else {
        expect(item.boilerplateText, `${item.id}: non-boilerplate item should not have boilerplateText`).toBeUndefined();
      }
    }
  });

  it('allows human-required items to have an empty evidenceKeys array', () => {
    const { items } = getCraStructure();
    const humanRequired = items.filter((i) => i.derivability === 'human-required');
    expect(humanRequired.length).toBeGreaterThan(0);
    for (const item of humanRequired) {
      expect(item.evidenceKeys).toEqual([]);
    }
  });

  it('caches the loaded structure across calls (same object identity)', () => {
    const first = getCraStructure();
    const second = getCraStructure();
    expect(first).toBe(second);
  });

  it('returns the same result from parseCraStructure directly on valid input', () => {
    const valid = {
      sourceVersion: 'v-test',
      generatedAt: '2026-01-01T00:00:00Z',
      items: [
        {
          id: 'annex7.1.a',
          instrument: 'annexVII',
          requirementSummary: 'summary',
          citation: 'citation text',
          sourceFile: 'data/sources/PLACEHOLDER-not-yet-vendored.txt',
          sourceExcerpt: 'excerpt',
          derivability: 'derivable',
          evidenceKeys: ['repo.manifest.name'],
        },
      ],
    };
    const parsed = parseCraStructure(valid);
    expect(parsed.items).toHaveLength(1);
    expect(parsed.items[0].id).toBe('annex7.1.a');
  });

  it('throws a clear error when the top-level object is missing required fields', () => {
    expect(() => parseCraStructure({ items: [] })).toThrow(/sourceVersion/);
    expect(() => parseCraStructure({ sourceVersion: 'v1', items: [] })).toThrow(/generatedAt/);
  });

  it('throws a clear error when items is not an array', () => {
    expect(() =>
      parseCraStructure({ sourceVersion: 'v1', generatedAt: '2026-01-01T00:00:00Z', items: 'nope' })
    ).toThrow(/items/);
  });

  it('throws a clear error when an item is missing a required string field', () => {
    const malformed = {
      sourceVersion: 'v1',
      generatedAt: '2026-01-01T00:00:00Z',
      items: [
        {
          id: 'annex7.1.a',
          instrument: 'annexVII',
          // requirementSummary missing
          citation: 'citation text',
          sourceFile: 'data/sources/PLACEHOLDER-not-yet-vendored.txt',
          sourceExcerpt: 'excerpt',
          derivability: 'derivable',
          evidenceKeys: [],
        },
      ],
    };
    expect(() => parseCraStructure(malformed)).toThrow(/requirementSummary/);
  });

  it('throws a clear error when instrument has an invalid value', () => {
    const malformed = {
      sourceVersion: 'v1',
      generatedAt: '2026-01-01T00:00:00Z',
      items: [
        {
          id: 'annex7.1.a',
          instrument: 'annexIX',
          requirementSummary: 'summary',
          citation: 'citation text',
          sourceFile: 'data/sources/PLACEHOLDER-not-yet-vendored.txt',
          sourceExcerpt: 'excerpt',
          derivability: 'derivable',
          evidenceKeys: [],
        },
      ],
    };
    expect(() => parseCraStructure(malformed)).toThrow(/instrument/);
  });

  it('throws a clear error when derivability has an invalid value', () => {
    const malformed = {
      sourceVersion: 'v1',
      generatedAt: '2026-01-01T00:00:00Z',
      items: [
        {
          id: 'annex7.1.a',
          instrument: 'annexVII',
          requirementSummary: 'summary',
          citation: 'citation text',
          sourceFile: 'data/sources/PLACEHOLDER-not-yet-vendored.txt',
          sourceExcerpt: 'excerpt',
          derivability: 'maybe',
          evidenceKeys: [],
        },
      ],
    };
    expect(() => parseCraStructure(malformed)).toThrow(/derivability/);
  });

  it('throws a clear error when evidenceKeys is not an array of strings', () => {
    const malformed = {
      sourceVersion: 'v1',
      generatedAt: '2026-01-01T00:00:00Z',
      items: [
        {
          id: 'annex7.1.a',
          instrument: 'annexVII',
          requirementSummary: 'summary',
          citation: 'citation text',
          sourceFile: 'data/sources/PLACEHOLDER-not-yet-vendored.txt',
          sourceExcerpt: 'excerpt',
          derivability: 'derivable',
          evidenceKeys: [42],
        },
      ],
    };
    expect(() => parseCraStructure(malformed)).toThrow(/evidenceKeys/);
  });

  it('throws a clear error when the top-level input is not an object', () => {
    expect(() => parseCraStructure(null)).toThrow(/top-level object/);
    expect(() => parseCraStructure('not an object')).toThrow(/top-level object/);
  });
});
