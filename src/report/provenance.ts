/**
 * Provenance/release-stamping shared by every M2 document renderer (Annex VII
 * pack, Annex V DoC draft) — the audit-artifact header every rendered pack
 * carries, per foundations_addendum.md §3 and the M2 brief's addendum C.
 *
 * The release-identifier logic is deliberately honest about what it found:
 *  - a real git tag is labeled as a version;
 *  - a bare commit hash (the `git describe --always` fallback with no
 *    reachable tag) is labeled explicitly as a commit, never dressed up as a
 *    version — this mirrors the same honesty distinction M1's
 *    VcsFacts.tagIsRealTag fix established for the scan gap checklist. A
 *    rendered artifact must not quietly regress that.
 *  - no git repo at all is stated plainly, never silently omitted.
 */
import type { VcsFacts } from '../detect/types';

export type ReleaseIdentifierKind = 'tag' | 'commit' | 'none';

export interface ReleaseIdentifier {
  kind: ReleaseIdentifierKind;
  /** Present iff kind !== 'none'. The tag name or commit hash itself. */
  value?: string;
  /** Human-readable label for rendering, e.g. "v1.2.3" or "commit bf5e50e" or "no VCS identity detected". */
  label: string;
}

export interface ProvenanceInfo {
  toolVersion: string;
  /** The CRA source-consolidation identifier (getCraSourceVersion()), not a generic "data version". */
  dataVersion: string;
  scanTimestamp: string;
  release: ReleaseIdentifier;
}

export function computeReleaseIdentifier(vcs: VcsFacts): ReleaseIdentifier {
  if (!vcs.isGitRepo) {
    return { kind: 'none', label: 'no VCS identity detected' };
  }
  if (vcs.tag !== undefined && vcs.tagIsRealTag === true) {
    return { kind: 'tag', value: vcs.tag, label: vcs.tag };
  }
  if (vcs.commit !== undefined) {
    // Prefer the full commit over the possibly-abbreviated `tag` fallback
    // value when both are available — it's the more precise identifier.
    const commit = vcs.commit;
    return { kind: 'commit', value: commit, label: `commit ${commit.slice(0, 12)}` };
  }
  if (vcs.tag !== undefined) {
    // isGitRepo is true and `tag` resolved (the --always commit-hash
    // fallback) but the strict `commit` lookup itself failed for some
    // reason — fall back to labeling `tag`'s value as a commit rather than
    // silently treating it as a version.
    return { kind: 'commit', value: vcs.tag, label: `commit ${vcs.tag}` };
  }
  return { kind: 'none', label: 'no VCS identity detected' };
}

/**
 * Extracts the short consolidation identifier (e.g. "02024R2847-20241120")
 * out of the full CRA source-version sentence that getCraSourceVersion()
 * (and every gap-checklist item's `citation`) embeds. That full sentence
 * carries real, non-redundant information — corrigenda verification, the
 * BSI supplementary source — which must still be stated in full exactly
 * once (see summary.ts's renderSummary), but repeating all ~300 characters
 * of it on every header line, or once per rendered item, buries the part
 * that's actually distinguishing. Falls back to returning the input
 * unchanged when the expected "consolidated as X" shape isn't found —
 * never silently drops information into an empty or wrong string.
 */
export function shortDataVersion(dataVersion: string): string {
  const m = dataVersion.match(/consolidated as (\S+)/);
  return m ? m[1] : dataVersion;
}

export function computeProvenance(params: {
  toolVersion: string;
  dataVersion: string;
  scanTimestamp: string;
  vcs: VcsFacts;
}): ProvenanceInfo {
  return {
    toolVersion: params.toolVersion,
    dataVersion: params.dataVersion,
    scanTimestamp: params.scanTimestamp,
    release: computeReleaseIdentifier(params.vcs),
  };
}
