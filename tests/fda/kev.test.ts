import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR, REPO_ROOT } from '../../src/paths';
import {
  FDA_VULN_SOURCE,
  KEV_INDEX_SCHEMA,
  KEV_SCREEN_LIMITS,
  KEV_SNAPSHOT_SCHEMA,
  MANUFACTURER_SUPPLIED_COLUMNS,
  buildKevLookup,
  compareVersions,
  evaluateRange,
  evaluateRanges,
  loadKevIndex,
  loadKevSnapshot,
  normalizeKevKey,
  screenKev,
} from '../../src/fda/kev';
import type { KevCatalogEntry, KevIndex, KevIndexEntry, KevLookup, KevSnapshot } from '../../src/fda/kev';
import { SNAPSHOT_STALE_AFTER_DAYS } from '../../src/fda/support';
import type { FdaComponent } from '../../src/fda/types';

function comp(partial: Partial<FdaComponent> & { name: string }): FdaComponent {
  return { licenses: [], hashes: [], properties: {}, origins: ['scan'], ...partial };
}

function kev(partial: Partial<KevCatalogEntry> & { cve: string; vendor: string; product: string }): KevCatalogEntry {
  return { vulnerabilityName: `${partial.product} Test Vulnerability`, dateAdded: '2024-01-01', ...partial };
}

function indexEntry(partial: Partial<KevIndexEntry> & { cve: string; purlKey: string }): KevIndexEntry {
  return {
    advisory: 'GHSA-test-test-test',
    advisorySource: 'GitHub Advisory Database',
    ecosystem: 'npm',
    package: partial.purlKey.replace(/^pkg:npm\//, ''),
    rangeType: 'SEMVER',
    ranges: [{ introduced: '0' }],
    ...partial,
  };
}

/**
 * A hand-written catalogue and index, not the bundled ones. Every rule in the
 * engine is asserted against fixed data here so the suite does not change
 * meaning the next time the KEV snapshot is refreshed (CISA adds entries
 * continuously); the real data gets its own block at the bottom, which asserts
 * only what must hold for ANY refresh.
 */
const SNAPSHOT: KevSnapshot = {
  schema: KEV_SNAPSHOT_SCHEMA,
  source: {
    name: 'CISA Known Exploited Vulnerabilities Catalog',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    license: 'CC0-1.0',
    licenseUrl: 'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt',
    licenseStatement: 'The KEV database is distributed under the Creative Commons 0 1.0 License.',
    catalogVersion: '2026.10.20',
    dateReleased: '2026-10-20T00:00:00.0000Z',
    upstreamCount: 8,
    upstreamSha256: 'a'.repeat(64),
  },
  fetchedAt: '2026-10-20T00:00:00.000Z',
  entries: [
    kev({ cve: 'CVE-2014-0160', vendor: 'OpenSSL', product: 'OpenSSL', vulnerabilityName: 'OpenSSL Information Disclosure Vulnerability', cwes: ['CWE-125'] }),
    kev({ cve: 'CVE-2020-11023', vendor: 'JQuery', product: 'jQuery', dueDate: '2025-01-15' }),
    kev({ cve: 'CVE-2021-44228', vendor: 'Apache', product: 'Log4j2', ransomware: true }),
    kev({ cve: 'CVE-2099-0001', vendor: 'Linux', product: 'Kernel' }),
    kev({ cve: 'CVE-2099-0002', vendor: 'Android', product: 'Kernel' }),
    kev({ cve: 'CVE-2099-0003', vendor: 'Ivanti', product: 'Connect Secure' }),
    kev({ cve: 'CVE-2099-0004', vendor: 'Acme', product: 'left-pad' }),
    kev({ cve: 'CVE-2099-0005', vendor: 'Electron', product: 'Electron' }),
  ],
};

const INDEX: KevIndex = {
  schema: KEV_INDEX_SCHEMA,
  sources: [
    { name: 'OSV.dev', url: 'https://osv.dev/', license: 'Apache-2.0', licenseUrl: 'x', attribution: 'x' },
    { name: 'GitHub Advisory Database', url: 'https://github.com/github/advisory-database', license: 'CC-BY-4.0', licenseUrl: 'x', attribution: 'x' },
  ],
  builtFrom: {
    kevCatalogVersion: '2026.10.20',
    kevSha256: 'a'.repeat(64),
    kevEntryCount: 8,
    osvQueriedAt: '2026-10-20T00:00:00.000Z',
    cvesQueried: 8,
    cvesWithOsvRecord: 2,
  },
  entries: [
    indexEntry({ cve: 'CVE-2020-11023', purlKey: 'pkg:npm/jquery', advisory: 'GHSA-jpcq-cgw6-v4j6', ranges: [{ introduced: '1.0.3', fixed: '3.5.0' }] }),
    // Two ranges for one package, as a real advisory with a back-ported fix
    // has: one plain-numeric and evaluable, one pre-release and not.
    indexEntry({ cve: 'CVE-2099-0005', purlKey: 'pkg:npm/electron', advisory: 'GHSA-elec-tron-0001', ranges: [{ introduced: '0', fixed: '22.3.25' }] }),
    indexEntry({ cve: 'CVE-2099-0005', purlKey: 'pkg:npm/electron', advisory: 'GHSA-elec-tron-0001', ranges: [{ introduced: '27.0.0-beta.1', fixed: '27.0.0-beta.8' }] }),
  ],
};

const LOOKUP: KevLookup = buildKevLookup(SNAPSHOT, INDEX);

function screen(components: FdaComponent[], asOf = '2026-10-31') {
  return screenKev(components, { lookup: LOOKUP, asOf });
}

function findingFor(components: FdaComponent[], cve: string) {
  const result = screen(components);
  return result.results[0].findings.find((f) => f.cve === cve);
}

describe('normalizeKevKey', () => {
  it('collapses the separator conventions CISA prose and package names disagree about', () => {
    expect(normalizeKevKey('Connect Secure')).toBe('connectsecure');
    expect(normalizeKevKey('connect-secure')).toBe('connectsecure');
    expect(normalizeKevKey('connect_secure')).toBe('connectsecure');
    expect(normalizeKevKey('ConnectSecure')).toBe('connectsecure');
    expect(normalizeKevKey('Internet Explorer')).toBe('internetexplorer');
  });

  it('refuses a string with no alphanumeric content rather than returning a key that would match everything', () => {
    expect(normalizeKevKey('')).toBeUndefined();
    expect(normalizeKevKey('   ')).toBeUndefined();
    expect(normalizeKevKey('-*-')).toBeUndefined();
  });
});

describe('compareVersions', () => {
  it('orders plain dotted-numeric versions, treating missing trailing segments as zero', () => {
    expect(compareVersions('1.2.3', '1.2.4')).toBe(-1);
    expect(compareVersions('1.10.0', '1.9.0')).toBe(1);
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
    expect(compareVersions('0', '0.0.0')).toBe(0);
    expect(compareVersions('3.5.0', '3.4.1')).toBe(1);
  });

  it('does NOT compare numerically segment-wise as strings (1.10 is after 1.9)', () => {
    expect(compareVersions('1.9.0', '1.10.0')).toBe(-1);
  });

  it('refuses anything it cannot order identically under SEMVER and PEP 440', () => {
    // The refusal is the safety property: a wrong order here puts a wrong
    // "not affected" next to a known-exploited CVE.
    for (const v of ['1.0.0-rc.1', '2.0.0rc1', '1.0.post1', '1.2.3.dev4', '1:1.1.1n-0+deb11u5', 'v1.2.3', '1.1.1w', 'latest', '']) {
      expect(compareVersions(v, '1.0.0'), `${v} should be refused`).toBeUndefined();
      expect(compareVersions('1.0.0', v), `${v} should be refused`).toBeUndefined();
    }
  });
});

describe('evaluateRange', () => {
  it('treats introduced as inclusive and fixed as exclusive, the way OSV defines them', () => {
    const range = { introduced: '1.0.3', fixed: '3.5.0' };
    expect(evaluateRange('1.0.2', range)).toBe(false);
    expect(evaluateRange('1.0.3', range)).toBe(true);
    expect(evaluateRange('3.4.1', range)).toBe(true);
    expect(evaluateRange('3.5.0', range)).toBe(false);
    expect(evaluateRange('3.7.1', range)).toBe(false);
  });

  it('treats last_affected as the final AFFECTED version, one off from fixed', () => {
    const range = { introduced: '0', lastAffected: '4.5.0' };
    expect(evaluateRange('4.5.0', range)).toBe(true);
    expect(evaluateRange('4.5.1', range)).toBe(false);
    // The same bound as `fixed` would exclude 4.5.0 itself. If these two ever
    // behave the same way, one of them is wrong.
    expect(evaluateRange('4.5.0', { introduced: '0', fixed: '4.5.0' })).toBe(false);
  });

  it('honours `limit` as an exclusive upper bound, like fixed', () => {
    expect(evaluateRange('1.9.9', { introduced: '0', limit: '2.0.0' })).toBe(true);
    expect(evaluateRange('2.0.0', { introduced: '0', limit: '2.0.0' })).toBe(false);
  });

  it('applies bounds in version order, not file order', () => {
    // The same range with its events written backwards must give the same
    // answer; OSV does not guarantee the array is sorted.
    const forwards = { introduced: '1.0.0', fixed: '2.0.0' };
    expect(evaluateRange('1.5.0', forwards)).toBe(true);
    expect(evaluateRange('2.5.0', forwards)).toBe(false);
  });

  it('refuses when any bound or the version itself is not plain-numeric', () => {
    expect(evaluateRange('27.0.0', { introduced: '27.0.0-beta.1', fixed: '27.0.0-beta.8' })).toBeUndefined();
    expect(evaluateRange('1.1.1w', { introduced: '0', fixed: '3.0.0' })).toBeUndefined();
  });

  it('refuses a range with no bounds at all rather than calling it unaffected', () => {
    expect(evaluateRange('1.0.0', {})).toBeUndefined();
  });
});

describe('evaluateRanges across the ranges of one advisory', () => {
  it('is affected when any range covers the version', () => {
    expect(evaluateRanges('3.2.1', [{ introduced: '0', fixed: '3.1.3' }, { introduced: '3.2.0', fixed: '3.2.2' }])).toBe(true);
  });

  it('is not affected only when every range is evaluable and excludes it', () => {
    expect(evaluateRanges('3.3.0', [{ introduced: '0', fixed: '3.1.3' }, { introduced: '3.2.0', fixed: '3.2.2' }])).toBe(false);
  });

  it('refuses if any range was refused and none matched — never downgrades a refusal to "not affected"', () => {
    expect(evaluateRanges('25.0.0', [{ introduced: '0', fixed: '22.3.25' }, { introduced: '27.0.0-beta.1', fixed: '27.0.0-beta.8' }])).toBeUndefined();
  });

  it('still reports affected when an evaluable range matches even though another was refused', () => {
    expect(evaluateRanges('20.0.0', [{ introduced: '0', fixed: '22.3.25' }, { introduced: '27.0.0-beta.1', fixed: '27.0.0-beta.8' }])).toBe(true);
  });
});

describe('the ecosystem-advisory pass (the only path to a version-precise answer)', () => {
  it('confirms a CVE when an advisory names the package and the version is inside an affected range', () => {
    const finding = findingFor([comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' })], 'CVE-2020-11023');
    expect(finding?.confidence).toBe('confirmed');
    expect(finding?.basis).toBe('ecosystem-advisory');
    expect(finding?.advisory).toBe('GHSA-jpcq-cgw6-v4j6');
    expect(finding?.evidence).toContain('3.4.1 falls inside the affected range');
    // FDA asks manufacturers to describe how vulnerabilities were discovered,
    // so every row has to answer that, not just the confirmed ones.
    expect(finding?.evidence).toContain('screening the component list against the bundled CISA Known Exploited Vulnerabilities Catalog');
  });

  it('reports not-affected — visibly, not by omission — when the version is outside every range', () => {
    const result = screen([comp({ name: 'jquery', version: '3.7.1', purl: 'pkg:npm/jquery@3.7.1' })]);
    expect(result.results[0].findings).toHaveLength(0);
    expect(result.results[0].notAffected).toHaveLength(1);
    const notAffected = result.results[0].notAffected[0];
    expect(notAffected.cve).toBe('CVE-2020-11023');
    expect(notAffected.confidence).toBe('not-affected');
    expect(notAffected.evidence).toContain('outside every affected range');
    expect(result.totals.notAffected).toBe(1);
  });

  it('falls back to possible, naming the refusal, when the version cannot be compared', () => {
    const finding = findingFor([comp({ name: 'electron', version: '25.0.0', purl: 'pkg:npm/electron@25.0.0' })], 'CVE-2099-0005');
    // 25.0.0 is outside [0, 22.3.25) but the pre-release range for the same CVE
    // is not evaluable, so "not affected" would be a claim the tool cannot make.
    expect(finding?.confidence).toBe('possible');
    expect(finding?.evidence).toContain('declined to compare');
    expect(finding?.evidence).toContain('SEMVER and PEP 440');
  });

  it('keeps the most severe verdict when one CVE names a package through more than one range', () => {
    const finding = findingFor([comp({ name: 'electron', version: '20.0.0', purl: 'pkg:npm/electron@20.0.0' })], 'CVE-2099-0005');
    expect(finding?.confidence).toBe('confirmed');
  });

  it('reports possible, not confirmed, when the component has no version at all', () => {
    const finding = findingFor([comp({ name: 'jquery', purl: 'pkg:npm/jquery' })], 'CVE-2020-11023');
    expect(finding?.confidence).toBe('possible');
    expect(finding?.evidence).toContain('carries no version');
  });

  it('matches across purl spellings, so a scoped or qualified purl is not missed', () => {
    const lookup = buildKevLookup(SNAPSHOT, {
      ...INDEX,
      entries: [indexEntry({ cve: 'CVE-2020-11023', purlKey: 'pkg:npm/@scope/thing', ranges: [{ introduced: '0', fixed: '2.0.0' }] })],
    });
    const result = screenKev([comp({ name: '@scope/thing', version: '1.0.0', purl: 'pkg:npm/%40scope/thing@1.0.0?arch=arm64' })], { lookup, asOf: '2026-10-31' });
    expect(result.results[0].findings[0]?.confidence).toBe('confirmed');
  });

  it('warns rather than silently skipping when the index references a CVE the snapshot does not carry', () => {
    const lookup = buildKevLookup(SNAPSHOT, {
      ...INDEX,
      entries: [indexEntry({ cve: 'CVE-1999-9999', purlKey: 'pkg:npm/jquery', ranges: [{ introduced: '0', fixed: '9.9.9' }] })],
    });
    const result = screenKev([comp({ name: 'jquery', version: '1.0.0', purl: 'pkg:npm/jquery@1.0.0' })], { lookup, asOf: '2026-10-31' });
    expect(result.warnings.some((w) => w.includes('CVE-1999-9999') && w.includes('different catalogue versions'))).toBe(true);
  });
});

describe('the identity pass over the catalogue (possible only, always)', () => {
  it('matches a C/C++ component by its CPE vendor:product, and says why it can only be possible', () => {
    const finding = findingFor([comp({ name: 'openssl', version: '1.1.1w', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*' })], 'CVE-2014-0160');
    expect(finding?.confidence).toBe('possible');
    expect(finding?.basis).toBe('cpe');
    expect(finding?.evidence).toContain('The KEV catalogue records no version information');
    expect(finding?.kevVendor).toBe('OpenSSL');
  });

  it('never reaches confirmed for a component with no npm/PyPI identity, whatever the match quality', () => {
    const firmware = [
      comp({ name: 'openssl', version: '1.1.1w', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*' }),
      comp({ name: 'kernel', version: '5.10.0', supplier: 'Linux' }),
      comp({ name: 'Connect Secure', version: '22.7' }),
    ];
    const result = screen(firmware);
    expect(result.totals.confirmed).toBe(0);
    for (const row of result.results) {
      for (const finding of row.findings) expect(finding.confidence).toBe('possible');
    }
  });

  it('prefers a corroborated vendor+product match over a bare product-name one', () => {
    const result = screen([comp({ name: 'kernel', version: '5.10.0', supplier: 'Linux' })]);
    const linux = result.results[0].findings.find((f) => f.cve === 'CVE-2099-0001');
    expect(linux?.basis).toBe('vendor-product');
    expect(linux?.evidence).toContain('match CISA\'s listed vendor "Linux" and product "Kernel"');
  });

  it('still reports a same-named product from a DIFFERENT vendor, saying the supplier disagrees', () => {
    // The Android/Kernel case. Filtering it out would be the tool deciding a
    // supplier-string mismatch means "not my component", which it cannot know.
    const result = screen([comp({ name: 'kernel', version: '5.10.0', supplier: 'Linux' })]);
    const android = result.results[0].findings.find((f) => f.cve === 'CVE-2099-0002');
    expect(android?.basis).toBe('product-name');
    expect(android?.evidence).toContain('names supplier "Linux" while CISA lists vendor "Android"');
    expect(android?.evidence).toContain('may well be a different product that shares a name');
  });

  it('says the vendor is uncorroborated when the component declares no supplier', () => {
    const finding = findingFor([comp({ name: 'left-pad', version: '1.3.0' })], 'CVE-2099-0004');
    expect(finding?.basis).toBe('product-name');
    expect(finding?.evidence).toContain('vendor could not be corroborated');
  });

  it('matches on the product half of a CPE when the component name itself differs', () => {
    // A Yocto SBOM calling it "openssl-bin" while the CPE says "openssl".
    const finding = findingFor([comp({ name: 'openssl-bin', version: '1.1.1w', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*' })], 'CVE-2014-0160');
    expect(finding).toBeDefined();
  });

  it('matches CISA prose product names against package-style component names', () => {
    const finding = findingFor([comp({ name: 'connect-secure', version: '22.7' })], 'CVE-2099-0003');
    expect(finding?.kevProduct).toBe('Connect Secure');
  });

  it('reports nothing for a component in no catalogue entry — no near-miss guessing', () => {
    const result = screen([comp({ name: 'some-internal-helper', version: '1.0.0', purl: 'pkg:npm/some-internal-helper@1.0.0' })]);
    expect(result.results[0].findings).toHaveLength(0);
    expect(result.results[0].notAffected).toHaveLength(0);
  });

  it('does not re-raise a CVE the advisory pass already ruled not-affected', () => {
    // jQuery 3.7.1 is provably outside CVE-2020-11023's range. The identity pass
    // would match "jquery" to the same CVE by product name; letting it do so
    // would be the tool arguing with its own better evidence.
    const result = screen([comp({ name: 'jquery', version: '3.7.1', purl: 'pkg:npm/jquery@3.7.1' })]);
    expect(result.results[0].findings).toHaveLength(0);
    expect(result.results[0].notAffected.map((f) => f.cve)).toEqual(['CVE-2020-11023']);
  });
});

describe('screen output a renderer and a reviewer depend on', () => {
  it('carries CISA’s own fields through verbatim so a wrong-product match can be ruled out at a glance', () => {
    const finding = findingFor([comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' })], 'CVE-2020-11023');
    expect(finding?.kevVendor).toBe('JQuery');
    expect(finding?.kevProduct).toBe('jQuery');
    expect(finding?.dateAdded).toBe('2024-01-01');
    expect(finding?.dueDate).toBe('2025-01-15');
  });

  it('records the ransomware flag only where CISA says "Known", never as a derived false', () => {
    const ransomware = findingFor([comp({ name: 'log4j2', version: '2.14.1' })], 'CVE-2021-44228');
    expect(ransomware?.ransomware).toBe(true);
    const other = findingFor([comp({ name: 'left-pad', version: '1.3.0' })], 'CVE-2099-0004');
    expect(other?.ransomware).toBeUndefined();
    expect(screen([comp({ name: 'log4j2', version: '2.14.1' })]).totals.ransomware).toBe(1);
  });

  it('sorts findings strongest evidence first', () => {
    const result = screen([
      comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' }),
      comp({ name: 'kernel', version: '5.10.0', supplier: 'Linux' }),
    ]);
    expect(result.results[0].findings[0].confidence).toBe('confirmed');
    const bases = result.results[1].findings.map((f) => f.basis);
    expect(bases.indexOf('vendor-product')).toBeLessThan(bases.indexOf('product-name'));
  });

  it('counts product-name-only findings and warns about them, rather than filtering them away', () => {
    const result = screen([comp({ name: 'left-pad', version: '1.3.0' })]);
    expect(result.totals.productNameOnly).toBe(1);
    expect(result.warnings.some((w) => w.includes('product-name match with no corroborating vendor'))).toBe(true);
  });

  it('warns when anything is confirmed, pointing at the manufacturer’s own obligation', () => {
    const result = screen([comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' })]);
    expect(result.warnings.some((w) => w.includes('designed out of the device'))).toBe(true);
  });

  it('carries the screen’s limits on the result, so findings cannot be rendered without them', () => {
    const result = screen([]);
    expect(result.limits).toBe(KEV_SCREEN_LIMITS);
    expect(result.limits.join(' ')).toContain('CISA Known Exploited Vulnerabilities Catalog only');
    expect(result.limits.join(' ')).toContain('can never reach "confirmed"');
  });

  it('leaves the two assessment columns to the manufacturer and never claims to have filled them', () => {
    expect(MANUFACTURER_SUPPLIED_COLUMNS).toHaveLength(2);
    const result = screen([comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' })]);
    const everything = JSON.stringify(result);
    for (const claim of ['risk assessment performed', 'assessed as', 'we assessed', 'not exploitable', 'no risk']) {
      expect(everything.toLowerCase()).not.toContain(claim);
    }
  });

  it('reports the snapshot and index provenance for the milestone-4 provenance artifact', () => {
    const result = screen([]);
    expect(result.snapshotSource.catalogVersion).toBe('2026.10.20');
    expect(result.snapshotSource.upstreamSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.indexSources.map((s) => s.name)).toContain('GitHub Advisory Database');
  });

  it('warns when the index is empty, because then nothing can be version-precise', () => {
    const lookup = buildKevLookup(SNAPSHOT, { ...INDEX, entries: [] });
    const result = screenKev([comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' })], { lookup, asOf: '2026-10-31' });
    expect(result.warnings.some((w) => w.includes('kev-index.json is empty'))).toBe(true);
    expect(result.totals.confirmed).toBe(0);
  });

  it('does not mutate the components it was given', () => {
    const component = comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' });
    const before = JSON.stringify(component);
    screen([component]);
    expect(JSON.stringify(component)).toBe(before);
  });
});

describe('staleness of the KEV snapshot', () => {
  it('stays quiet inside the freshness window', () => {
    expect(screen([], '2026-10-31').warnings.some((w) => w.includes('days old'))).toBe(false);
  });

  it('warns past the shared threshold, naming the catalogue version and both refresh commands', () => {
    const asOf = new Date(Date.parse('2026-10-20T00:00:00Z') + (SNAPSHOT_STALE_AFTER_DAYS + 5) * 86_400_000).toISOString().slice(0, 10);
    const warning = screen([], asOf).warnings.find((w) => w.includes('days old'));
    expect(warning).toBeDefined();
    expect(warning).toContain('2026.10.20');
    expect(warning).toContain('fetch-kev-snapshot');
    expect(warning).toContain('build-kev-index');
    // The consequence named has to be KEV's, not the EOL snapshot's.
    expect(warning).toContain('may have had one catalogued since this snapshot was taken');
  });
});

describe('traceability to the vendored FDA guidance text', () => {
  // The same standard tests/cra/traceability.test.ts holds the CRA data to: the
  // requirement this engine implements must appear verbatim in the vendored
  // primary source, not in a paraphrase of it.
  const sourcePath = path.join(REPO_ROOT, FDA_VULN_SOURCE.sourceFile);

  it('cites a vendored source file that exists under data/sources/', () => {
    expect(fs.existsSync(sourcePath)).toBe(true);
    expect(path.resolve(sourcePath).startsWith(path.resolve(DATA_DIR, 'sources'))).toBe(true);
  });

  it('every excerpt the screen is built on appears verbatim in that file', () => {
    const text = fs.readFileSync(sourcePath, 'utf8');
    for (const [name, excerpt] of Object.entries(FDA_VULN_SOURCE.excerpts)) {
      expect(text.includes(excerpt), `${name}: not found verbatim in ${FDA_VULN_SOURCE.sourceFile}`).toBe(true);
    }
  });

  it('the two manufacturer-supplied columns are the guidance’s own two bullets, not invented ones', () => {
    const text = fs.readFileSync(sourcePath, 'utf8');
    expect(text).toContain('A safety and security risk assessment of each known vulnerability');
    expect(text).toContain('Details of applicable safety and security risk controls');
    expect(MANUFACTURER_SUPPLIED_COLUMNS[0]).toContain('Safety and security risk assessment');
    expect(MANUFACTURER_SUPPLIED_COLUMNS[1]).toContain('risk controls');
  });

  it('the KEV catalogue is named by the guidance, which is why it is the one catalogue screened', () => {
    const text = fs.readFileSync(sourcePath, 'utf8');
    expect(text).toContain('Known Exploited Vulnerabilities');
  });
});

describe('the bundled data/kev-snapshot.json and data/kev-index.json', () => {
  // Assertions here must hold for ANY refresh, so a routine
  // "npm run fetch-kev-snapshot" never turns the suite red for the wrong reason.
  const snapshot = loadKevSnapshot();
  const index = loadKevIndex();

  it('both load and declare the schemas this version reads', () => {
    expect(snapshot.schema).toBe(KEV_SNAPSHOT_SCHEMA);
    expect(index.schema).toBe(KEV_INDEX_SCHEMA);
    expect(snapshot.entries.length).toBeGreaterThan(1000);
  });

  it('records the licence and the exact upstream bytes, for NOTICE and provenance', () => {
    expect(snapshot.source.license).toBe('CC0-1.0');
    expect(snapshot.source.licenseUrl).toContain('cisa.gov');
    expect(snapshot.source.upstreamSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(snapshot.source.catalogVersion).toMatch(/^\d{4}\.\d{2}\.\d{2}$/);
    expect(snapshot.source.dateReleased).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    // CISA's no-endorsement condition has to travel with the data.
    expect(snapshot.source.licenseStatement).toContain('endorsement by CISA or DHS');
  });

  it('carries every field the screen reads, for every entry', () => {
    for (const entry of snapshot.entries) {
      expect(entry.cve).toMatch(/^CVE-\d{4}-\d{4,}$/);
      expect(entry.vendor.length).toBeGreaterThan(0);
      expect(entry.product.length).toBeGreaterThan(0);
      expect(entry.vulnerabilityName.length).toBeGreaterThan(0);
      expect(entry.dateAdded).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it('drops the prose the distillation says it drops, so data/ does not grow by surprise', () => {
    const raw = fs.readFileSync(path.join(DATA_DIR, 'kev-snapshot.json'), 'utf8');
    for (const dropped of ['shortDescription', 'requiredAction', 'forensicTriage', '"notes"']) {
      expect(raw, `${dropped} should not be in the vendored snapshot`).not.toContain(dropped);
    }
  });

  it('has no duplicate CVE, so a component cannot be reported against the same CVE twice', () => {
    const cves = snapshot.entries.map((e) => e.cve);
    expect(new Set(cves).size).toBe(cves.length);
  });

  it('was built from the catalogue version it claims, so the two files cannot silently drift apart', () => {
    expect(index.builtFrom.kevCatalogVersion).toBe(snapshot.source.catalogVersion);
    expect(index.builtFrom.kevSha256).toBe(snapshot.source.upstreamSha256);
  });

  it('indexes only CVEs that are actually in the catalogue, and only npm/PyPI packages', () => {
    const cves = new Set(snapshot.entries.map((e) => e.cve));
    for (const entry of index.entries) {
      expect(cves.has(entry.cve), `${entry.cve} is indexed but not in the catalogue`).toBe(true);
      expect(['npm', 'PyPI']).toContain(entry.ecosystem);
      expect(entry.purlKey).toMatch(/^pkg:(npm|pypi)\//);
      expect(entry.ranges.length).toBeGreaterThan(0);
    }
  });

  it('resolves a real known-exploited vulnerability end to end against the bundled data', () => {
    // CVE-2020-11023 (jQuery) is in the catalogue and has a GitHub advisory with
    // real ranges, so it exercises both files at once. Asserted as "if the
    // catalogue still lists it" so a future CISA removal does not fail the suite
    // for the wrong reason.
    const lookup = buildKevLookup(snapshot, index);
    if (!lookup.byCve.has('CVE-2020-11023')) return;
    const vulnerable = screenKev([comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' })], { lookup, asOf: '2026-10-31' });
    expect(vulnerable.results[0].findings.some((f) => f.cve === 'CVE-2020-11023' && f.confidence === 'confirmed')).toBe(true);
    const patched = screenKev([comp({ name: 'jquery', version: '3.7.1', purl: 'pkg:npm/jquery@3.7.1' })], { lookup, asOf: '2026-10-31' });
    expect(patched.results[0].findings.some((f) => f.cve === 'CVE-2020-11023')).toBe(false);
    expect(patched.results[0].notAffected.some((f) => f.cve === 'CVE-2020-11023')).toBe(true);
  });

  it('screens a realistic firmware component list offline without producing a single confirmed row', () => {
    // The C/C++ reality this mode exists for: no purls, CPEs at best. Nothing
    // here can be version-precise, and the result must say so rather than
    // quietly reporting a clean device.
    const lookup = buildKevLookup(snapshot, index);
    const result = screenKev(
      [
        comp({ name: 'openssl', version: '1.1.1w', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*' }),
        comp({ name: 'busybox', version: '1.35.0' }),
        comp({ name: 'linux-kernel', version: '5.10.0' }),
      ],
      { lookup, asOf: '2026-10-31' },
    );
    expect(result.totals.confirmed).toBe(0);
    expect(result.limits.join(' ')).toContain('can never reach "confirmed"');
  });
});
