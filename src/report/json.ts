import type { RepoFacts } from '../detect/types';
import type { GapChecklistItem } from '../gap/types';

// ─────────────────────────────────────────────────────────────────────────────
// Machine-readable JSON renderer for `ceproof scan --format json`.
// Stable schema, versioned (schemaVersion: 1) — a breaking change bumps it,
// additive changes don't need to.
// ─────────────────────────────────────────────────────────────────────────────

export interface JsonReportConfigStatus {
  present: boolean;
  /** null when no config file is present at all (nothing to validate). */
  valid: boolean | null;
  errors?: string[];
  /** ids of human-required CRA items with no answer yet (mirrors gapChecklist's NEEDS-HUMAN-INPUT items). */
  missingAnswers: string[];
}

export interface JsonReport {
  schemaVersion: 1;
  toolVersion: string;
  dataVersion: string;
  scanTimestamp: string;
  projectName: string;
  facts: RepoFacts;
  gapChecklist: GapChecklistItem[];
  summary: {
    totalItems: number;
    derived: number;
    partial: number;
    needsHumanInput: number;
  };
  configStatus: JsonReportConfigStatus;
  warnings: string[];
}

export interface BuildJsonReportInput {
  projectName: string;
  toolVersion: string;
  dataVersion: string;
  scanTimestamp: string;
  facts: RepoFacts;
  gapChecklist: GapChecklistItem[];
  configStatus: JsonReportConfigStatus;
  warnings: string[];
}

export function buildJsonReport(input: BuildJsonReportInput): JsonReport {
  const summary = {
    totalItems: input.gapChecklist.length,
    derived: input.gapChecklist.filter((i) => i.status === 'DERIVED').length,
    partial: input.gapChecklist.filter((i) => i.status === 'PARTIAL').length,
    needsHumanInput: input.gapChecklist.filter((i) => i.status === 'NEEDS-HUMAN-INPUT').length,
  };

  return {
    schemaVersion: 1,
    toolVersion: input.toolVersion,
    dataVersion: input.dataVersion,
    scanTimestamp: input.scanTimestamp,
    projectName: input.projectName,
    facts: input.facts,
    gapChecklist: input.gapChecklist,
    summary,
    configStatus: input.configStatus,
    warnings: input.warnings,
  };
}
