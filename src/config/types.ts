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
}
