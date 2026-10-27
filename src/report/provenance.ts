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

// Every item's `citation` (data/cra-structure.json, traceability-tested —
// never edit that field) is dominated by a shared regulation/consolidation
// preamble ("Regulation (EU) 2024/2847 (Cyber Resilience Act), consolidated
// text 02024R2847-20241120 (base act + Corrigenda 1-3, ...), ") that is
// byte-identical across all 21 items. That preamble is stated once, in full,
// elsewhere instead (the terminal header/provenance line in summary.ts, the
// cover header's `cover__data-version` line in html.ts) — printing it once
// per item buries the part that's actually item-specific: which
// instrument/point (and, for annex7.8 / annex7.2.b, a genuinely item-specific
// "See also" BSI cross-reference) under a wall of repeated text.
//
// This finds where the item-specific part starts and keeps everything from
// there to the end of the string (so any trailing "See also ..." content is
// preserved verbatim, not stripped along with the preamble). The regex
// requires "point" immediately after "Annex VII,"/"Annex V," specifically so
// it does NOT match the preamble's own "...touch Annex V, Annex VII, or
// Articles..." aside, which is never followed by "point". Falls back to the
// full citation, unchanged, if that shape isn't found — this must never
// silently drop information, only shorten it when it safely can.
//
// Verified against all 21 real citations in data/cra-structure.json (each
// matches exactly once, including annex7.8 and annex7.2.b's BSI TR-03183-2
// cross-references, which are preserved intact after the matched point).
// Shared by both the terminal renderer (summary.ts) and the HTML/PDF pack
// renderer (html.ts) so the two never drift onto independent regexes.
const CITATION_TAIL_START_RE = /Annex (?:VII|V), point \d/;

export function citationTail(citation: string): string {
  const m = citation.match(CITATION_TAIL_START_RE);
  return m && m.index !== undefined ? citation.slice(m.index) : citation;
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
