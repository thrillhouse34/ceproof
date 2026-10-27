import { describe, it, expect } from 'vitest';
import {
  computeReleaseIdentifier,
  computeProvenance,
  shortDataVersion,
  citationTail,
} from '../../src/report/provenance';
import { getCraStructure } from '../../src/cra/loader';
import type { VcsFacts } from '../../src/detect/types';

describe('shortDataVersion', () => {
  it('extracts the short consolidation id out of the full CRA source-version sentence', () => {
    const full =
      '32024R2847 consolidated as 02024R2847-20241120 (EN), incorporating Corrigenda 1-3 (OJ L 90780 5.12.2024; ' +
      'OJ L 90555 2.7.2025; OJ L 90828 17.10.2025) -- verified none of the three corrigenda touch Annex V, Annex ' +
      'VII, or Articles 13/31/33. Supplementary source: BSI TR-03183-2 v2.1.0 (2025-08-20).';
    expect(shortDataVersion(full)).toBe('02024R2847-20241120');
  });

  it('falls back to the input unchanged when the "consolidated as X" shape is not found', () => {
    expect(shortDataVersion('2026.07.24')).toBe('2026.07.24');
    expect(shortDataVersion('')).toBe('');
  });
});

// citationTail() is the shared per-item counterpart to shortDataVersion()
// above — both extract a short, item/consolidation-specific token out of a
// long shared sentence, and both live here so summary.ts (terminal) and
// html.ts (HTML/PDF pack) render the same trimmed text instead of two
// independently-drifting regexes. See the doc comment above citationTail()
// in src/report/provenance.ts for the full rationale.
describe('citationTail', () => {
  const REAL_SHAPED_PREAMBLE =
    'Regulation (EU) 2024/2847 (Cyber Resilience Act), consolidated text 02024R2847-20241120 ' +
    '(base act + Corrigenda 1-3, none of which touch Annex V, Annex VII, or Articles 13/31/33), ';

  it('drops the shared preamble but keeps the item-specific instrument/point', () => {
    const citation = `${REAL_SHAPED_PREAMBLE}Annex VII, point 3.`;
    expect(citationTail(citation)).toBe('Annex VII, point 3.');
  });

  it('handles an Annex V citation the same way', () => {
    const citation = `${REAL_SHAPED_PREAMBLE}Annex V, point 5.`;
    expect(citationTail(citation)).toBe('Annex V, point 5.');
  });

  it('preserves a genuinely item-specific "See also" BSI cross-reference verbatim (annex7.8 shape)', () => {
    const citation =
      `${REAL_SHAPED_PREAMBLE}Annex VII, point 8. See also BSI TR-03183-2 v2.1.0 section 4 ` +
      '(SBOM format: CycloneDX >=1.6 or SPDX >=3.0.1 required) and section 5.2.2 (required component fields, ' +
      'including licence information).';
    expect(citationTail(citation)).toBe(
      'Annex VII, point 8. See also BSI TR-03183-2 v2.1.0 section 4 ' +
        '(SBOM format: CycloneDX >=1.6 or SPDX >=3.0.1 required) and section 5.2.2 (required component fields, ' +
        'including licence information).',
    );
  });

  it('preserves the annex7.2.b-shape "See also" cross-reference, including the "(b)" that follows the point number', () => {
    const citation =
      `${REAL_SHAPED_PREAMBLE}Annex VII, point 2(b). See also BSI TR-03183-2 v2.1.0 section 5.2.2 ` +
      "(component-level required SBOM data fields, including 'Distribution licences') for what counts as " +
      'SBOM-readiness evidence.';
    expect(citationTail(citation)).toBe(
      "Annex VII, point 2(b). See also BSI TR-03183-2 v2.1.0 section 5.2.2 (component-level required SBOM data " +
        "fields, including 'Distribution licences') for what counts as SBOM-readiness evidence.",
    );
  });

  it('does not match the preamble\'s own "...Annex V, Annex VII, or Articles..." aside, which is never followed by "point"', () => {
    // If the regex were too loose it would match inside the preamble itself
    // and truncate to something starting mid-preamble instead of at the real
    // item-specific point.
    const citation = `${REAL_SHAPED_PREAMBLE}Annex VII, point 1(a).`;
    expect(citationTail(citation)).not.toContain('Articles 13/31/33), Annex VII, point 1(a)');
    expect(citationTail(citation)).toBe('Annex VII, point 1(a).');
  });

  it('falls back to the full citation unchanged when the expected "Annex X, point N" shape is absent', () => {
    expect(citationTail('An unusually shaped citation with no point number.')).toBe(
      'An unusually shaped citation with no point number.',
    );
    expect(citationTail('')).toBe('');
  });

  it('matches every real citation in data/cra-structure.json exactly once (regression guard for both renderers)', () => {
    // Mirrors the manual verification this function's doc comment claims —
    // re-checked here so a future edit to the CRA data or the regex can't
    // silently break that claim without a test failing. Deliberately not
    // hardcoding the exact item count as a magic 21 beyond this one
    // assertion — see tests/cra/loader.test.ts's precedent for why the real
    // data's shape (mix of instruments) is checked without over-asserting
    // its exact size elsewhere.
    const { items } = getCraStructure();
    const withCitations = items.filter((i) => typeof i.citation === 'string' && i.citation.length > 0);
    expect(withCitations.length).toBeGreaterThan(0);
    for (const item of withCitations) {
      const matches = item.citation.match(/Annex (?:VII|V), point \d/g);
      expect(matches, `item ${item.id} citation should match the tail pattern exactly once`).not.toBeNull();
      expect(matches!.length, `item ${item.id} citation matched ${matches!.length} times, expected 1`).toBe(1);
      // The trimmed result must actually be shorter (real work done) and end
      // exactly where the full citation ends (nothing dropped off the end).
      const trimmed = citationTail(item.citation);
      expect(item.citation.endsWith(trimmed)).toBe(true);
      expect(trimmed.length).toBeLessThan(item.citation.length);
    }
  });
});

describe('computeReleaseIdentifier', () => {
  it('labels a real tag as itself, never as a commit', () => {
    const vcs: VcsFacts = { isGitRepo: true, tag: 'v1.2.3', tagIsRealTag: true, commit: 'abc123' };
    const result = computeReleaseIdentifier(vcs);
    expect(result.kind).toBe('tag');
    expect(result.value).toBe('v1.2.3');
    expect(result.label).toBe('v1.2.3');
  });

  it('explicitly labels a bare commit-hash fallback as a commit, never as a version', () => {
    const vcs: VcsFacts = { isGitRepo: true, tag: 'bf5e50e', tagIsRealTag: false, commit: 'bf5e50e1234567890abcdef' };
    const result = computeReleaseIdentifier(vcs);
    expect(result.kind).toBe('commit');
    expect(result.label).toMatch(/^commit /);
    expect(result.label).not.toBe('bf5e50e1234567890abcdef');
  });

  it('falls back to labeling the tag fallback value as a commit when the strict commit lookup is absent', () => {
    const vcs: VcsFacts = { isGitRepo: true, tag: 'bf5e50e', tagIsRealTag: false };
    const result = computeReleaseIdentifier(vcs);
    expect(result.kind).toBe('commit');
    expect(result.value).toBe('bf5e50e');
    expect(result.label).toBe('commit bf5e50e');
  });

  it('reports an honest "no VCS identity detected" when not a git repo', () => {
    const vcs: VcsFacts = { isGitRepo: false };
    const result = computeReleaseIdentifier(vcs);
    expect(result.kind).toBe('none');
    expect(result.value).toBeUndefined();
    expect(result.label).toBe('no VCS identity detected');
  });

  it('reports "no VCS identity detected" for an inside-git-repo state with no tag or commit resolved', () => {
    const vcs: VcsFacts = { isGitRepo: true };
    const result = computeReleaseIdentifier(vcs);
    expect(result.kind).toBe('none');
  });
});

describe('computeProvenance', () => {
  it('carries toolVersion, dataVersion, scanTimestamp, and the computed release identifier', () => {
    const provenance = computeProvenance({
      toolVersion: '0.1.0',
      dataVersion: 'test-data-version',
      scanTimestamp: '2026-01-01T00:00:00.000Z',
      vcs: { isGitRepo: true, tag: 'v2.0.0', tagIsRealTag: true },
    });
    expect(provenance.toolVersion).toBe('0.1.0');
    expect(provenance.dataVersion).toBe('test-data-version');
    expect(provenance.scanTimestamp).toBe('2026-01-01T00:00:00.000Z');
    expect(provenance.release).toEqual({ kind: 'tag', value: 'v2.0.0', label: 'v2.0.0' });
  });
});
