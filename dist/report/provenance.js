"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeReleaseIdentifier = computeReleaseIdentifier;
exports.shortDataVersion = shortDataVersion;
exports.computeProvenance = computeProvenance;
function computeReleaseIdentifier(vcs) {
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
function shortDataVersion(dataVersion) {
    const m = dataVersion.match(/consolidated as (\S+)/);
    return m ? m[1] : dataVersion;
}
function computeProvenance(params) {
    return {
        toolVersion: params.toolVersion,
        dataVersion: params.dataVersion,
        scanTimestamp: params.scanTimestamp,
        release: computeReleaseIdentifier(params.vcs),
    };
}
//# sourceMappingURL=provenance.js.map