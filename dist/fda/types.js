"use strict";
/**
 * The component model the FDA mode works in, and why it isn't `ResolvedPackage`.
 *
 * `ResolvedPackage` (src/resolve/types.ts) is an npm/PyPI package: it requires
 * an `ecosystem` of `'npm' | 'pypi'`, an `installPath`, dependency `paths`, and
 * a resolved license category. None of that is true of a component imported
 * from a device-firmware SBOM — `openssl 1.1.1` out of a Yocto build has no
 * ecosystem in that enum, no lockfile path, and no node_modules directory. The
 * options were to widen `EcosystemId` (which ripples through every switch in
 * src/ecosystems, src/resolve and src/report for no benefit to the CRA product)
 * or to give the FDA mode its own narrow type and adapt into it. This is the
 * second option: `componentsFromScan` in ./merge.ts is the only bridge, and
 * nothing in the existing scan pipeline changes shape.
 *
 * Every field is optional except `name` on purpose. A real imported SBOM is
 * frequently thin — no purl, no supplier, a fuzzy version like "1.1.1" with no
 * patch letter — and the repo's honest-UNKNOWN doctrine means an absent value
 * stays absent all the way to the rendered artifact, never gets filled with a
 * plausible guess.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.qualifyRef = qualifyRef;
/**
 * Prefix a document-local `bom-ref` with the origin that declared it, so refs
 * from two different SBOMs can never collide. "|" is the separator because no
 * purl, no CPE and no origin label contains one.
 */
function qualifyRef(origin, ref) {
    return `${origin}|${ref}`;
}
//# sourceMappingURL=types.js.map