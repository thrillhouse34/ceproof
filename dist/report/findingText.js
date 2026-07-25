"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatChain = formatChain;
// ─────────────────────────────────────────────────────────────────────────────
// Shared package-rendering text helpers, reused by every renderer that
// describes a resolved package (the terminal summary and the HTML report).
// Kept in exactly one place so the terminal and HTML output can never
// silently say different things about the same package's dependency chain.
//
// licenseproof also kept a `conflict-explanations.json`-backed `explanationFor`
// and an `agplAlternativeNote` here — both were specific to conflict-severity
// findings (a vendored explanation string per conflict reason code, and an
// AGPL-as-non-chosen-branch note). ceproof has no conflict concept, so both
// were removed along with `data/conflict-explanations.json`. `formatChain` has
// no such dependency and is unchanged.
// ─────────────────────────────────────────────────────────────────────────────
/**
 * The single canonical dependency-chain phrasing. Shows the primary chain and,
 * when the enumeration cap was hit, the "at least N other paths" floor.
 *
 * `pathCountAtLeast` is a floor established by the path-enumeration cap
 * (Milestone 1), never an exact count once the cap is hit — "at least N"
 * phrasing is mandatory so the number is never misread as a precise total.
 */
function formatChain(pkg) {
    const chain = (pkg.paths[0] ?? [pkg.name]).join(' → ');
    const extra = pkg.pathCountAtLeast - 1;
    if (extra <= 0)
        return `via ${chain}`;
    return `via ${chain} (+at least ${extra.toLocaleString()} other path${extra === 1 ? '' : 's'})`;
}
//# sourceMappingURL=findingText.js.map