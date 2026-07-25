/**
 * The gap-checklist engine's output shape.
 *
 * Doctrine (binding, see src/gap/gapEngine.ts for the full resolution
 * semantics): every status is derived honestly from evidence that was
 * actually checked — never a silent guess, never a silent omission.
 */
export type GapStatus = 'DERIVED' | 'PARTIAL' | 'NEEDS-HUMAN-INPUT';

export interface GapChecklistItem {
  id: string;
  instrument: 'annexVII' | 'annexV';
  status: GapStatus;
  requirementSummary: string;
  citation: string;
  /** Human-readable evidence, e.g. "git tag v1.2.3 detected", "SECURITY.md present at repo root", "supplied via ceproof.config". */
  evidence: string[];
}
