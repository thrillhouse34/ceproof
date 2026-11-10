import type { SupportLevel } from '../fda/support';

/**
 * The `ceproof.config.json` interview-file shape. Generated and validated by
 * `ceproof init` (src/cli/init.ts + validate.ts); consumed by the gap-checklist
 * engine (src/gap/gapEngine.ts) now, and by M2's document renderers later.
 *
 * `answers` is the only field the gap engine actually reads: one entry per
 * `human-required` CraStructureItem id (src/cra/types.ts) that the user has
 * supplied a value for. An item with no entry here stays NEEDS-HUMAN-INPUT —
 * never silently defaulted, never inferred.
 *
 * The other top-level fields (manufacturer/product/supportPeriod) are
 * scaffolding for M2's Annex VII pack + Annex V DoC — M1 only generates and
 * validates this shape, it doesn't render from it yet.
 */
/**
 * One manufacturer declaration of a component's support position, for the FDA
 * premarket-SBOM mode. FDA's guidance (section V.A.4(b)) asks the manufacturer
 * for a level of support and an end-of-support date per software component;
 * this is where the manufacturer supplies the ones no public dataset can
 * answer, and it outranks every derived value (see resolveSupport's precedence
 * in src/fda/support.ts).
 */
export interface FdaSupportDeclaration {
  /** One of the four SupportLevel values. `abandoned` can ONLY arrive this way — nothing derives it. */
  supportLevel: SupportLevel;
  /** ISO YYYY-MM-DD. Omit when genuinely unknown; never fill it with a placeholder. */
  endOfSupportDate?: string;
  /**
   * Free text carried verbatim into the output. For a `supportLevel` of
   * `unknown` this is the justification FDA asks for where the information
   * cannot be provided, so the engine warns when it is missing there.
   */
  note?: string;
}

export interface FdaConfig {
  /**
   * Keyed by purl, `name@version`, or a bare component name (matched in that
   * order of specificity, case-insensitively). A key matching no component in a
   * run produces a warning rather than being silently ignored — a declaration
   * the manufacturer believes they made but which never applied is exactly the
   * kind of invisible gap this repo's doctrine forbids.
   */
  componentSupport?: Record<string, FdaSupportDeclaration>;
}

export interface CeproofConfig {
  manufacturer: {
    name: string;
    address?: string;
    contact?: string;
  };
  product: {
    name: string;
    /** Classification per CRA Annex III (e.g. "default" | "important" | "critical") — free-form string in M1, not yet enum-validated against the real annex text. */
    classification?: string;
  };
  supportPeriod: {
    years?: number;
    endDate?: string; // ISO date
  };
  /** Keyed by CraStructureItem id (e.g. "annex7.3.b") for every human-required item the user has answered. */
  answers: Record<string, string>;
  /** FDA premarket-SBOM mode settings. Absent for every CRA-only user; `ceproof init` does not generate it. */
  fda?: FdaConfig;
}
