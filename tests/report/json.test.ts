import { describe, it, expect } from 'vitest';
import { buildJsonReport } from '../../src/report/json';
import type { GapChecklistItem } from '../../src/gap/types';
import type { RepoFacts } from '../../src/detect/types';

function item(overrides: Partial<GapChecklistItem>): GapChecklistItem {
  return {
    id: 'annex7.1.a',
    instrument: 'annexVII',
    status: 'DERIVED',
    requirementSummary: 'A synthetic test requirement.',
    citation: 'Regulation (EU) 2024/2847, Annex VII, point 1(a)',
    evidence: ['some evidence line'],
    ...overrides,
  };
}

function emptyFacts(): RepoFacts {
  return {
    security: { securityMdPresent: false, securityTxtPresent: false, vulnDisclosurePolicyPresent: false, paths: [] },
    projectLicense: { rootLicenseFilePresent: false },
    ecosystems: { detected: [] },
    runtimes: {},
    vcs: { isGitRepo: false },
    updateMechanism: { dependabotPresent: false, renovatePresent: false },
  };
}

function baseInput(overrides: Partial<Parameters<typeof buildJsonReport>[0]> = {}) {
  return {
    projectName: 'my-app',
    toolVersion: '0.1.0',
    dataVersion: '2026.07.24',
    scanTimestamp: '2026-07-24T00:00:00.000Z',
    facts: emptyFacts(),
    gapChecklist: [] as GapChecklistItem[],
    configStatus: { present: false, valid: null, missingAnswers: [] },
    warnings: [] as string[],
    ...overrides,
  };
}

describe('buildJsonReport', () => {
  it('includes schemaVersion 1 and all required metadata fields', () => {
    const report = buildJsonReport(baseInput());
    expect(report.schemaVersion).toBe(1);
    expect(report.toolVersion).toBe('0.1.0');
    expect(report.dataVersion).toBe('2026.07.24');
    expect(report.scanTimestamp).toBe('2026-07-24T00:00:00.000Z');
    expect(report.projectName).toBe('my-app');
  });

  it('passes facts and gapChecklist through unchanged', () => {
    const facts = emptyFacts();
    facts.vcs = { isGitRepo: true, commit: 'abc123', branch: 'main', dirty: false };
    const checklist = [item({ id: 'x' }), item({ id: 'y', status: 'PARTIAL' })];
    const report = buildJsonReport(baseInput({ facts, gapChecklist: checklist }));
    expect(report.facts).toEqual(facts);
    expect(report.gapChecklist).toEqual(checklist);
  });

  it('computes summary counts correctly', () => {
    const report = buildJsonReport(
      baseInput({
        gapChecklist: [
          item({ id: 'a', status: 'DERIVED' }),
          item({ id: 'b', status: 'DERIVED' }),
          item({ id: 'c', status: 'PARTIAL' }),
          item({ id: 'd', status: 'NEEDS-HUMAN-INPUT' }),
        ],
      }),
    );
    expect(report.summary).toEqual({ totalItems: 4, derived: 2, partial: 1, needsHumanInput: 1 });
  });

  it('summary counts are all zero for an empty checklist', () => {
    const report = buildJsonReport(baseInput({ gapChecklist: [] }));
    expect(report.summary).toEqual({ totalItems: 0, derived: 0, partial: 0, needsHumanInput: 0 });
  });

  it('passes configStatus through, including missingAnswers', () => {
    const configStatus = { present: true, valid: false, errors: ['manufacturer.name is required and is missing'], missingAnswers: ['annex7.2'] };
    const report = buildJsonReport(baseInput({ configStatus }));
    expect(report.configStatus).toEqual(configStatus);
  });

  it('configStatus.valid is null when no config is present at all', () => {
    const report = buildJsonReport(baseInput({ configStatus: { present: false, valid: null, missingAnswers: [] } }));
    expect(report.configStatus.present).toBe(false);
    expect(report.configStatus.valid).toBeNull();
  });

  it('passes warnings through unchanged', () => {
    const report = buildJsonReport(baseInput({ warnings: ['a warning'] }));
    expect(report.warnings).toEqual(['a warning']);
  });

  it('citation field is the full, untouched string in JSON output — the terminal renderer trims its own display copy (src/report/summary.ts), but --format json is a machine contract and must never be shortened', () => {
    const fullCitation =
      'Regulation (EU) 2024/2847 (Cyber Resilience Act), consolidated text 02024R2847-20241120 (base act + ' +
      'Corrigenda 1-3, none of which touch Annex V, Annex VII, or Articles 13/31/33), Annex VII, point 8. See ' +
      'also BSI TR-03183-2 v2.1.0 section 4 (SBOM format: CycloneDX >=1.6 or SPDX >=3.0.1 required) and section ' +
      "5.2.2 (required component fields, including licence information).";
    const report = buildJsonReport(baseInput({ gapChecklist: [item({ id: 'annex7.8', citation: fullCitation })] }));
    expect(report.gapChecklist[0].citation).toBe(fullCitation);
    // Byte-identical to the exact same shape rendered by JSON.stringify — no
    // trimming, truncation, or preamble-stripping anywhere in the JSON path.
    const serialized = JSON.stringify(report, null, 2);
    expect(serialized).toContain(fullCitation);
  });
});
