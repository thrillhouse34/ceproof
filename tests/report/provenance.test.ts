import { describe, it, expect } from 'vitest';
import { computeReleaseIdentifier, computeProvenance, shortDataVersion } from '../../src/report/provenance';
import type { VcsFacts } from '../../src/detect/types';

describe('shortDataVersion', () => {
  it('extracts the short consolidation id out of the full CRA source-version sentence', () => {
    const full =
      '32024R2847 consolidated as 02024R2847-20241120 (EN), incorporating Corrigenda 1-3 (OJ L 90780 5.12.2024; ' +
      'OJ L 90555 2.7.2025; OJ L 90828 17.10.2025) -- verified none of the three corrigenda touch Annex V, Annex ' +
      'VII, or Articles 13/31/33 (see completion report). Supplementary source: BSI TR-03183-2 v2.1.0 (2025-08-20).';
    expect(shortDataVersion(full)).toBe('02024R2847-20241120');
  });

  it('falls back to the input unchanged when the "consolidated as X" shape is not found', () => {
    expect(shortDataVersion('2026.07.24')).toBe('2026.07.24');
    expect(shortDataVersion('')).toBe('');
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
