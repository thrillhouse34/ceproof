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

/**
 * Where a component's data came from. Carried through to the output so a
 * reviewer can always see whether a row was scanned, imported, or declared.
 * `sbom:<basename>` names the imported file; `override` is the manufacturer's
 * declaration from `ceproof.config.json` (milestone 2).
 */
export type ComponentOrigin = 'scan' | 'override' | `sbom:${string}`;

export interface ComponentHash {
  /** CycloneDX hash algorithm name, e.g. "SHA-256". Carried through verbatim. */
  alg: string;
  content: string;
}

export interface FdaComponent {
  name: string;
  version?: string;
  /** Package URL, with any `?qualifiers` / `#subpath` stripped (see normalizePurl). */
  purl?: string;
  /** CPE 2.3 string when the source SBOM carried one — the only usable identifier for most C/C++ components. */
  cpe?: string;
  supplier?: string;
  /** CycloneDX component type (library, firmware, operating-system, application, ...), carried through so the enriched SBOM can re-emit it. */
  type?: string;
  /** License expressions, SPDX ids, or non-SPDX license names, as strings. Empty means "not resolved" — never "no license". */
  licenses: string[];
  hashes: ComponentHash[];
  /** CycloneDX `properties` as a flat map, kept so an SBOM that already carries `ceproof:fda:*` values (support level, end-of-support) isn't silently dropped on import. */
  properties: Record<string, string>;
  /** Every source that contributed to this component, in contribution order. */
  origins: ComponentOrigin[];
  /**
   * Set when two sources had the same component name but could not be matched
   * on purl or on name@version (a missing or differing version). Such entries
   * are deliberately NOT merged — guessing that two same-named components are
   * the same thing is exactly the kind of silent assumption this repo bans.
   */
  possibleDuplicate?: boolean;
  /**
   * Human-readable record of a field where two sources disagreed. The first
   * value encountered is kept and the loser is recorded here rather than being
   * dropped silently; the milestone-4 open-items artifact surfaces these.
   */
  conflicts?: string[];
  /**
   * Every QUALIFIED source `bom-ref` that resolved to this component (see
   * `qualifyRef`). Absent for a scan-derived component, which has no source
   * document and therefore no ref. This is the only thing that lets an
   * imported SBOM's `dependencies[]` edges survive the merge: the refs in that
   * array point at the SOURCE document's identifiers, and the enriched
   * document re-derives its own `bom-ref`s, so an edge can only be carried
   * through by mapping one to the other.
   */
  sourceRefs?: string[];
}

/**
 * One edge set from an imported SBOM's `dependencies[]` array, carried through
 * VERBATIM. Nothing in this mode ever infers an edge: a dependency graph that
 * was guessed at is worse than a stated gap, because a reviewer has no way to
 * see which edges the producer asserted and which this tool invented.
 *
 * Both `ref` and the entries of `dependsOn` are QUALIFIED source refs, not raw
 * `bom-ref` strings. A `bom-ref` is unique only inside its own document, and
 * this mode merges several documents plus a repo scan, so two imported SBOMs
 * can legitimately both call their root component "1". Qualifying at import
 * time is what stops one SBOM's edges from landing on another's components.
 */
export interface FdaDependency {
  ref: string;
  dependsOn: string[];
}

/**
 * Prefix a document-local `bom-ref` with the origin that declared it, so refs
 * from two different SBOMs can never collide. "|" is the separator because no
 * purl, no CPE and no origin label contains one.
 */
export function qualifyRef(origin: ComponentOrigin, ref: string): string {
  return `${origin}|${ref}`;
}
