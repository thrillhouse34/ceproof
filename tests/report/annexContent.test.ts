import { describe, it, expect } from 'vitest';
import { computeAnnexViiPackContent, computeAnnexVDocContent } from '../../src/report/annexContent';
import type { CraStructureItem } from '../../src/cra/types';
import type { GapChecklistItem } from '../../src/gap/types';
import type { CeproofConfig } from '../../src/config/types';
import type { ProvenanceInfo } from '../../src/report/provenance';

function makeProvenance(): ProvenanceInfo {
  return {
    toolVersion: '0.1.0',
    dataVersion: 'test-data-version',
    scanTimestamp: '2026-01-01T00:00:00.000Z',
    release: { kind: 'tag', value: 'v1.0.0', label: 'v1.0.0' },
  };
}

function craItem(overrides: Partial<CraStructureItem>): CraStructureItem {
  return {
    id: 'annex7.x',
    instrument: 'annexVII',
    requirementSummary: 'Synthetic requirement.',
    citation: 'Synthetic citation.',
    sourceFile: 'data/sources/test.txt',
    sourceExcerpt: 'synthetic excerpt',
    derivability: 'derivable',
    evidenceKeys: [],
    ...overrides,
  };
}

function gapItem(overrides: Partial<GapChecklistItem>): GapChecklistItem {
  return {
    id: 'annex7.x',
    instrument: 'annexVII',
    status: 'DERIVED',
    requirementSummary: 'Synthetic requirement.',
    citation: 'Synthetic citation.',
    evidence: [],
    ...overrides,
  };
}

function makeConfig(answers: Record<string, string>): CeproofConfig {
  return {
    manufacturer: { name: 'Acme Corp' },
    product: { name: 'Widget' },
    supportPeriod: {},
    answers,
  };
}

describe('annexContent — derivable/partial items', () => {
  it('renders scan evidence as body for a DERIVED derivable item', () => {
    const structure = [craItem({ id: 'annex7.1.b', derivability: 'derivable', evidenceKeys: ['vcs.tag'] })];
    const gap = [gapItem({ id: 'annex7.1.b', status: 'DERIVED', evidence: ['vcs.tag: "v1.0.0"'] })];
    const content = computeAnnexViiPackContent(structure, gap, null, makeProvenance(), 'proj');
    expect(content.sections).toHaveLength(1);
    expect(content.sections[0].isOpenItem).toBe(false);
    expect(content.sections[0].body).toEqual(['Scan evidence: vcs.tag: "v1.0.0"']);
    expect(content.openItemCount).toBe(0);
  });

  it('appends a caveat line for a PARTIAL item', () => {
    const structure = [craItem({ id: 'annex7.2.b', derivability: 'partial', evidenceKeys: ['a', 'b'] })];
    const gap = [gapItem({ id: 'annex7.2.b', status: 'PARTIAL', evidence: ['a: true', 'b: false'] })];
    const content = computeAnnexViiPackContent(structure, gap, null, makeProvenance(), 'proj');
    expect(content.sections[0].body).toEqual([
      'Scan evidence: a: true',
      'Scan evidence: b: false',
      'This item is only partially supported by automated scan evidence — review and supplement before submission.',
    ]);
    expect(content.sections[0].isOpenItem).toBe(false);
  });
});

describe('annexContent — human-required items', () => {
  it('renders an open item (empty body) when NEEDS-HUMAN-INPUT with no config', () => {
    const structure = [craItem({ id: 'annex7.1.a', derivability: 'human-required' })];
    const gap = [gapItem({ id: 'annex7.1.a', status: 'NEEDS-HUMAN-INPUT', evidence: [] })];
    const content = computeAnnexViiPackContent(structure, gap, null, makeProvenance(), 'proj');
    expect(content.sections[0].isOpenItem).toBe(true);
    expect(content.sections[0].body).toEqual([]);
    expect(content.openItemCount).toBe(1);
  });

  it('renders the config answer verbatim when DERIVED via config', () => {
    const structure = [craItem({ id: 'annex7.1.a', derivability: 'human-required' })];
    const gap = [gapItem({ id: 'annex7.1.a', status: 'DERIVED', evidence: ['Supplied via ceproof.config'] })];
    const config = makeConfig({ 'annex7.1.a': 'This product is a widget.' });
    const content = computeAnnexViiPackContent(structure, gap, config, makeProvenance(), 'proj');
    expect(content.sections[0].isOpenItem).toBe(false);
    expect(content.sections[0].body).toEqual(['This product is a widget.']);
  });
});

describe('annexContent — boilerplate items', () => {
  it('renders boilerplateText as body, always DERIVED, regardless of config', () => {
    const structure = [
      craItem({
        id: 'annex5.3',
        instrument: 'annexV',
        derivability: 'boilerplate',
        boilerplateText: 'Fixed statement text.',
      }),
    ];
    const gap = [
      gapItem({ id: 'annex5.3', instrument: 'annexV', status: 'DERIVED', evidence: ['Fixed regulatory boilerplate'] }),
    ];
    const content = computeAnnexVDocContent(structure, gap, null, makeProvenance(), 'proj');
    expect(content.sections[0].body).toEqual(['Fixed statement text.']);
    expect(content.sections[0].isOpenItem).toBe(false);
  });
});

describe('annexContent — annex7.7 composition from Annex V', () => {
  function fullStructure(): CraStructureItem[] {
    return [
      craItem({ id: 'annex7.7', derivability: 'human-required' }),
      craItem({
        id: 'annex5.1',
        instrument: 'annexV',
        requirementSummary: 'Name and type.',
        derivability: 'human-required',
      }),
      craItem({
        id: 'annex5.2',
        instrument: 'annexV',
        requirementSummary: 'Manufacturer name and address.',
        derivability: 'human-required',
      }),
      craItem({
        id: 'annex5.3',
        instrument: 'annexV',
        requirementSummary: 'Sole-responsibility statement.',
        derivability: 'boilerplate',
        boilerplateText: 'Issued under sole responsibility.',
      }),
    ];
  }

  it('composes from Annex V when every Annex V item is DERIVED, and never asks for annex7.7 directly', () => {
    const structure = fullStructure();
    const gap = [
      gapItem({ id: 'annex7.7', status: 'NEEDS-HUMAN-INPUT', evidence: [] }),
      gapItem({ id: 'annex5.1', instrument: 'annexV', status: 'DERIVED', evidence: [] }),
      gapItem({ id: 'annex5.2', instrument: 'annexV', status: 'DERIVED', evidence: [] }),
      gapItem({ id: 'annex5.3', instrument: 'annexV', status: 'DERIVED', evidence: [] }),
    ];
    const config = makeConfig({
      'annex5.1': 'Widget, type X.',
      'annex5.2': 'Acme Corp, 1 Main St.',
      // annex7.7 deliberately NOT answered directly — proves composition, not a direct answer, produced the content.
    });
    const content = computeAnnexViiPackContent(structure, gap, config, makeProvenance(), 'proj');
    const section77 = content.sections.find((s) => s.id === 'annex7.7')!;
    expect(section77.isOpenItem).toBe(false);
    expect(section77.status).toBe('DERIVED');
    expect(section77.composedFromAnnexV).toBe(true);
    expect(section77.body.some((line) => line.includes('Widget, type X.'))).toBe(true);
    expect(section77.body.some((line) => line.includes('Acme Corp, 1 Main St.'))).toBe(true);
    expect(section77.body.some((line) => line.includes('Issued under sole responsibility.'))).toBe(true);
    expect(content.openItemCount).toBe(0);
  });

  it('falls back to a direct config answer when not every Annex V item is DERIVED', () => {
    const structure = fullStructure();
    const gap = [
      gapItem({ id: 'annex7.7', status: 'NEEDS-HUMAN-INPUT', evidence: [] }),
      gapItem({ id: 'annex5.1', instrument: 'annexV', status: 'NEEDS-HUMAN-INPUT', evidence: [] }),
      gapItem({ id: 'annex5.2', instrument: 'annexV', status: 'DERIVED', evidence: [] }),
      gapItem({ id: 'annex5.3', instrument: 'annexV', status: 'DERIVED', evidence: [] }),
    ];
    const config = makeConfig({
      'annex5.2': 'Acme Corp, 1 Main St.',
      'annex7.7': 'Directly supplied DoC copy text.',
    });
    const content = computeAnnexViiPackContent(structure, gap, config, makeProvenance(), 'proj');
    const section77 = content.sections.find((s) => s.id === 'annex7.7')!;
    expect(section77.isOpenItem).toBe(false);
    expect(section77.composedFromAnnexV).toBeFalsy();
    expect(section77.body).toEqual(['Directly supplied DoC copy text.']);
  });

  it('renders an honest open item when neither composition nor a direct answer is available', () => {
    const structure = fullStructure();
    const gap = [
      gapItem({ id: 'annex7.7', status: 'NEEDS-HUMAN-INPUT', evidence: [] }),
      gapItem({ id: 'annex5.1', instrument: 'annexV', status: 'NEEDS-HUMAN-INPUT', evidence: [] }),
      gapItem({ id: 'annex5.2', instrument: 'annexV', status: 'NEEDS-HUMAN-INPUT', evidence: [] }),
      gapItem({ id: 'annex5.3', instrument: 'annexV', status: 'DERIVED', evidence: [] }),
    ];
    const content = computeAnnexViiPackContent(structure, gap, null, makeProvenance(), 'proj');
    const section77 = content.sections.find((s) => s.id === 'annex7.7')!;
    expect(section77.isOpenItem).toBe(true);
    expect(section77.body).toEqual([]);
  });
});

describe('annexContent — defensive checks', () => {
  it('throws a clear error if the gap checklist is missing an entry for a structure item', () => {
    const structure = [craItem({ id: 'annex7.1.a', derivability: 'human-required' })];
    expect(() => computeAnnexViiPackContent(structure, [], null, makeProvenance(), 'proj')).toThrow(/annex7\.1\.a/);
  });
});
