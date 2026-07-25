export type CraInstrument = 'annexVII' | 'annexV';
/**
 * 'boilerplate': fixed regulatory text that never varies by product (e.g. Annex V
 * point 3's "issued under the sole responsibility of the provider" statement) —
 * always DERIVED, with no per-repo evidence and no human-input interview needed.
 * Distinct from 'derivable'/'partial' (which resolve from evidenceKeys) and
 * 'human-required' (which needs a ceproof.config answer).
 */
export type CraDerivability = 'derivable' | 'partial' | 'human-required' | 'boilerplate';

export interface CraStructureItem {
  id: string; // e.g. "annex7.1.a"
  instrument: CraInstrument;
  requirementSummary: string;
  citation: string; // exact source citation, e.g. "Regulation (EU) 2024/2847, Annex VII, point 1(a)"
  sourceFile: string; // relative path under data/sources/, e.g. "data/sources/celex-32024r2847-en.html"
  sourceExcerpt: string; // verbatim short excerpt anchoring the citation, for traceability testing
  derivability: CraDerivability;
  evidenceKeys: string[]; // dot-paths into RepoFacts/scan output the gap engine looks up; empty array valid for pure human-required/boilerplate items
  /** Required if and only if derivability === 'boilerplate': the fixed text rendered as this item's DERIVED content. Absent for every other derivability. */
  boilerplateText?: string;
}

export interface CraStructureFile {
  sourceVersion: string;
  generatedAt: string; // ISO date
  items: CraStructureItem[];
}
