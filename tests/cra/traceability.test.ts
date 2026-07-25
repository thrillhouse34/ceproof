import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR, REPO_ROOT } from '../../src/paths';
import { getCraStructure } from '../../src/cra/loader';

// Doctrine, non-negotiable: every CraStructureItem's sourceExcerpt must appear
// verbatim in the vendored primary-text file it cites. This is what makes the
// gap-checklist engine's output auditable back to the actual regulation text
// rather than a paraphrase or a hallucination. Every item, not a sample.

describe('CRA structure data — traceability to vendored primary sources', () => {
  const structure = getCraStructure();

  it('the real (non-placeholder) cra-structure.json is loaded', () => {
    // A guard against silently regressing to synthetic placeholder data —
    // this test only means something once real sourceVersion/citations exist.
    expect(structure.sourceVersion.toLowerCase()).not.toContain('placeholder');
    expect(structure.items.length).toBeGreaterThan(0);
    for (const item of structure.items) {
      expect(item.citation.toLowerCase()).not.toContain('synthetic placeholder citation');
      expect(item.requirementSummary.toLowerCase()).not.toContain('[synthetic placeholder]');
    }
  });

  it('every item cites a sourceFile that actually exists under data/sources/', () => {
    for (const item of structure.items) {
      const resolved = path.join(REPO_ROOT, item.sourceFile);
      expect(fs.existsSync(resolved), `${item.id}: sourceFile ${item.sourceFile} does not exist`).toBe(true);
      // sourceFile must live under data/sources/, not point elsewhere.
      expect(path.resolve(resolved).startsWith(path.resolve(DATA_DIR, 'sources'))).toBe(true);
    }
  });

  it('every item sourceExcerpt appears verbatim in its cited sourceFile', () => {
    const fileCache = new Map<string, string>();
    const failures: string[] = [];

    for (const item of structure.items) {
      const resolved = path.join(REPO_ROOT, item.sourceFile);
      if (!fileCache.has(resolved)) {
        fileCache.set(resolved, fs.readFileSync(resolved, 'utf8'));
      }
      const content = fileCache.get(resolved)!;
      if (!content.includes(item.sourceExcerpt)) {
        failures.push(`${item.id}: sourceExcerpt not found verbatim in ${item.sourceFile}`);
      }
    }

    expect(failures, failures.join('\n')).toEqual([]);
  });

  it('every sourceExcerpt is non-trivial (not empty, not a single common word)', () => {
    // A traceability test that could be satisfied by an excerpt like "the" or
    // "a" would prove nothing. Require a real minimum length.
    for (const item of structure.items) {
      expect(item.sourceExcerpt.trim().length, `${item.id}: sourceExcerpt too short to be meaningful`).toBeGreaterThan(15);
    }
  });

  it('Annex VII items cite Annex VII, Annex V items cite Annex V (citation/instrument consistency)', () => {
    for (const item of structure.items) {
      const label = item.instrument === 'annexVII' ? 'Annex VII' : 'Annex V';
      expect(item.citation, `${item.id}: citation should reference ${label}`).toContain(label);
    }
  });

  it('every derivable/partial item has at least one evidenceKey; human-required/boilerplate items may have none', () => {
    for (const item of structure.items) {
      if (item.derivability === 'human-required' || item.derivability === 'boilerplate') continue;
      expect(
        item.evidenceKeys.length,
        `${item.id}: derivability "${item.derivability}" but evidenceKeys is empty`,
      ).toBeGreaterThan(0);
    }
  });

  it('every boilerplate item has a non-empty boilerplateText, and no other item does', () => {
    for (const item of structure.items) {
      if (item.derivability === 'boilerplate') {
        expect(item.boilerplateText, `${item.id}: boilerplate item missing boilerplateText`).toBeTruthy();
        expect(item.boilerplateText!.trim().length).toBeGreaterThan(0);
      } else {
        expect(item.boilerplateText, `${item.id}: non-boilerplate item should not have boilerplateText`).toBeUndefined();
      }
    }
  });
});
