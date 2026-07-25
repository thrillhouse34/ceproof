import { describe, it, expect } from 'vitest';
import { computeGapChecklist } from '../../src/gap/gapEngine';
import type { CraStructureItem } from '../../src/cra/types';
import type { RepoFacts } from '../../src/detect/types';
import type { CeproofConfig } from '../../src/config/types';
import type { ResolvedPackage } from '../../src/resolve/types';

function makeItem(overrides: Partial<CraStructureItem>): CraStructureItem {
  return {
    id: 'test.item',
    instrument: 'annexVII',
    requirementSummary: 'Synthetic test requirement.',
    citation: 'Synthetic test citation.',
    sourceFile: 'data/sources/test-fixture.txt',
    sourceExcerpt: 'Synthetic test excerpt.',
    derivability: 'derivable',
    evidenceKeys: [],
    ...overrides,
  };
}

function makeFacts(overrides: Partial<RepoFacts> = {}): RepoFacts {
  return {
    security: {
      securityMdPresent: false,
      securityTxtPresent: false,
      vulnDisclosurePolicyPresent: false,
      paths: [],
    },
    projectLicense: {
      rootLicenseFilePresent: false,
    },
    ecosystems: {
      detected: [],
    },
    runtimes: {},
    vcs: {
      isGitRepo: false,
    },
    updateMechanism: {
      dependabotPresent: false,
      renovatePresent: false,
    },
    ...overrides,
  };
}

function makePackage(overrides: Partial<ResolvedPackage> = {}): ResolvedPackage {
  return {
    name: 'left-pad',
    version: '1.0.0',
    ecosystem: 'npm',
    direct: true,
    dev: false,
    paths: [['left-pad']],
    pathCountAtLeast: 1,
    installPath: 'node_modules/left-pad',
    license: 'MIT',
    licenseIds: ['MIT'],
    category: 'permissive',
    confidence: 'high',
    source: 'metadata',
    ...overrides,
  };
}

describe('computeGapChecklist', () => {
  it('marks a boilerplate item DERIVED with the fixed boilerplateText as evidence, regardless of config', () => {
    const item = makeItem({
      id: 'boilerplate.1',
      derivability: 'boilerplate',
      evidenceKeys: [],
      boilerplateText: 'This statement never varies by product.',
    });
    const [resultNoConfig] = computeGapChecklist(makeFacts(), [], null, [item]);
    expect(resultNoConfig.status).toBe('DERIVED');
    expect(resultNoConfig.evidence[0]).toContain('This statement never varies by product.');

    const config: CeproofConfig = {
      manufacturer: { name: 'Acme Corp' },
      product: { name: 'Widget' },
      supportPeriod: {},
      answers: {},
    };
    const [resultWithConfig] = computeGapChecklist(makeFacts(), [], config, [item]);
    expect(resultWithConfig.status).toBe('DERIVED');
  });

  it('marks a human-required item with no config answer as NEEDS-HUMAN-INPUT', () => {
    const item = makeItem({ id: 'human.1', derivability: 'human-required', evidenceKeys: [] });
    const [result] = computeGapChecklist(makeFacts(), [], null, [item]);
    expect(result.status).toBe('NEEDS-HUMAN-INPUT');
    expect(result.evidence).toEqual([]);
  });

  it('marks the same human-required item DERIVED when config supplies an answer', () => {
    const item = makeItem({ id: 'human.1', derivability: 'human-required', evidenceKeys: [] });
    const config: CeproofConfig = {
      manufacturer: { name: 'Acme Corp' },
      product: { name: 'Widget' },
      supportPeriod: {},
      answers: { 'human.1': 'Jane Doe, VP Engineering' },
    };
    const [result] = computeGapChecklist(makeFacts(), [], config, [item]);
    expect(result.status).toBe('DERIVED');
    expect(result.evidence.length).toBeGreaterThan(0);
    expect(result.evidence.some((e) => /ceproof\.config/.test(e))).toBe(true);
  });

  it('treats an empty-string config answer as not answered (still NEEDS-HUMAN-INPUT)', () => {
    const item = makeItem({ id: 'human.1', derivability: 'human-required', evidenceKeys: [] });
    const config: CeproofConfig = {
      manufacturer: { name: 'Acme Corp' },
      product: { name: 'Widget' },
      supportPeriod: {},
      answers: { 'human.1': '' },
    };
    const [result] = computeGapChecklist(makeFacts(), [], config, [item]);
    expect(result.status).toBe('NEEDS-HUMAN-INPUT');
  });

  it('marks a derivable item DERIVED when its single evidenceKey resolves', () => {
    const item = makeItem({
      id: 'derivable.1',
      derivability: 'derivable',
      evidenceKeys: ['vcs.isGitRepo'],
    });
    const facts = makeFacts({ vcs: { isGitRepo: true, tag: 'v1.2.3' } });
    const [result] = computeGapChecklist(facts, [], null, [item]);
    expect(result.status).toBe('DERIVED');
    expect(result.evidence).toEqual(['vcs.isGitRepo: true']);
  });

  it('marks a derivable item PARTIAL (not silently DERIVED) when its evidenceKey does not resolve', () => {
    const item = makeItem({
      id: 'derivable.2',
      derivability: 'derivable',
      evidenceKeys: ['vcs.isGitRepo'],
    });
    const facts = makeFacts({ vcs: { isGitRepo: false } });
    const [result] = computeGapChecklist(facts, [], null, [item]);
    expect(result.status).toBe('PARTIAL');
    expect(result.evidence).toEqual(['vcs.isGitRepo: false']);
  });

  it('marks a partial item PARTIAL when only 1 of 2 evidenceKeys resolves', () => {
    const item = makeItem({
      id: 'partial.1',
      derivability: 'partial',
      evidenceKeys: ['security.securityMdPresent', 'security.securityTxtPresent'],
    });
    const facts = makeFacts({
      security: {
        securityMdPresent: true,
        securityTxtPresent: false,
        vulnDisclosurePolicyPresent: false,
        paths: ['SECURITY.md'],
      },
    });
    const [result] = computeGapChecklist(facts, [], null, [item]);
    expect(result.status).toBe('PARTIAL');
    expect(result.evidence).toHaveLength(2);
    expect(result.evidence).toContain('security.securityMdPresent: true');
    expect(result.evidence).toContain('security.securityTxtPresent: false');
  });

  it('marks an item with empty evidenceKeys and derivability "partial" as PARTIAL without crashing', () => {
    const item = makeItem({ id: 'empty.1', derivability: 'partial', evidenceKeys: [] });
    const [result] = computeGapChecklist(makeFacts(), [], null, [item]);
    expect(result.status).toBe('PARTIAL');
    expect(result.evidence[0]).toMatch(/data-authoring inconsistency/);
  });

  it('resolves packages.count and packages.allLicensesKnown from resolvedPackages', () => {
    const item = makeItem({
      id: 'sbom.1',
      instrument: 'annexV',
      derivability: 'partial',
      evidenceKeys: ['packages.count', 'packages.allLicensesKnown'],
    });
    const resolvedPackages: ResolvedPackage[] = [
      makePackage({ name: 'left-pad', category: 'permissive' }),
      makePackage({ name: 'mystery-pkg', category: 'unknown' }),
    ];
    const [result] = computeGapChecklist(makeFacts(), resolvedPackages, null, [item]);
    // packages.count resolves (>=1 package), packages.allLicensesKnown does not (one unknown) -> PARTIAL
    expect(result.status).toBe('PARTIAL');
    expect(result.evidence.some((e) => /packages\.count: 2 package/.test(e))).toBe(true);
    expect(result.evidence.some((e) => /packages\.allLicensesKnown: 1 of 2/.test(e))).toBe(true);
  });

  it('marks packages evidence DERIVED when all resolved packages have a known license category', () => {
    const item = makeItem({
      id: 'sbom.2',
      instrument: 'annexV',
      derivability: 'partial',
      evidenceKeys: ['packages.count', 'packages.allLicensesKnown'],
    });
    const resolvedPackages: ResolvedPackage[] = [
      makePackage({ name: 'left-pad', category: 'permissive' }),
      makePackage({ name: 'other-pkg', category: 'weak-copyleft' }),
    ];
    const [result] = computeGapChecklist(makeFacts(), resolvedPackages, null, [item]);
    expect(result.status).toBe('DERIVED');
  });

  it('does not crash and treats missing config the same as no answers (null and undefined)', () => {
    const item = makeItem({ id: 'human.2', derivability: 'human-required', evidenceKeys: [] });
    const resultsNull = computeGapChecklist(makeFacts(), [], null, [item]);
    const resultsUndefined = computeGapChecklist(makeFacts(), [], undefined, [item]);
    expect(resultsNull[0].status).toBe('NEEDS-HUMAN-INPUT');
    expect(resultsUndefined[0].status).toBe('NEEDS-HUMAN-INPUT');
  });

  it('never throws on an unrecognized packages.* key and treats it as not resolved', () => {
    const item = makeItem({
      id: 'sbom.3',
      instrument: 'annexV',
      derivability: 'partial',
      evidenceKeys: ['packages.mysteryField'],
    });
    const [result] = computeGapChecklist(makeFacts(), [makePackage()], null, [item]);
    expect(result.status).toBe('PARTIAL');
    expect(result.evidence[0]).toMatch(/unrecognized SBOM evidence key/);
  });

  it('resolves an item with all evidenceKeys present across multiple items in one call', () => {
    const items: CraStructureItem[] = [
      makeItem({ id: 'a', derivability: 'human-required', evidenceKeys: [] }),
      makeItem({ id: 'b', derivability: 'derivable', evidenceKeys: ['vcs.isGitRepo'] }),
    ];
    const facts = makeFacts({ vcs: { isGitRepo: true } });
    const results = computeGapChecklist(facts, [], null, items);
    expect(results).toHaveLength(2);
    expect(results[0].id).toBe('a');
    expect(results[0].status).toBe('NEEDS-HUMAN-INPUT');
    expect(results[1].id).toBe('b');
    expect(results[1].status).toBe('DERIVED');
  });
});
