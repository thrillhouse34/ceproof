import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR, REPO_ROOT } from '../../src/paths';
import {
  FDA_SOURCE,
  EOL_SNAPSHOT_SCHEMA,
  SNAPSHOT_STALE_AFTER_DAYS,
  buildEolIndex,
  loadEolSnapshot,
  matchCycle,
  normalizeCpeKey,
  normalizePurlKey,
  resolveSupport,
  snapshotStalenessWarning,
  SUPPORT_LEVEL_PROPERTY,
  END_OF_SUPPORT_PROPERTY,
  SUPPORT_LEVELS,
  SUPPORT_NOTE_PROPERTY,
} from '../../src/fda/support';
import type { EolProduct, EolSnapshot } from '../../src/fda/support';
import type { FdaComponent } from '../../src/fda/types';

function comp(partial: Partial<FdaComponent> & { name: string }): FdaComponent {
  return { licenses: [], hashes: [], properties: {}, origins: ['scan'], ...partial };
}

/**
 * A hand-written snapshot, not the bundled one. Every rule in the engine is
 * asserted against fixed data here so the tests don't change meaning the next
 * time data/eol-snapshot.json is refreshed; the real snapshot gets its own
 * separate block at the bottom, which asserts only things that must stay true
 * of ANY refresh.
 */
const SNAPSHOT: EolSnapshot = {
  schema: EOL_SNAPSHOT_SCHEMA,
  source: {
    name: 'endoflife.date',
    url: 'https://endoflife.date/api/v1/products/full/',
    license: 'MIT',
    licenseUrl: 'https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE',
    copyright: 'Copyright 2020 endoflife.date contributors',
    upstreamSchemaVersion: '1.2.1',
    upstreamGeneratedAt: '2026-10-20T00:00:00+00:00',
    upstreamSha256: 'f'.repeat(64),
  },
  fetchedAt: '2026-10-20T00:00:00.000Z',
  products: [
    {
      id: 'openssl',
      label: 'OpenSSL',
      cpes: ['openssl:openssl'],
      releasePolicyUrl: 'https://openssl-library.org/policies/releasestrat/',
      releases: [
        { cycle: '3.2', eolFrom: '2027-11-23' },
        { cycle: '3.0', eolFrom: '2026-09-07' },
        { cycle: '1.1.1', eolFrom: '2023-09-11' },
        { cycle: '1', eolFrom: '2019-12-31' },
      ],
    },
    {
      id: 'nodejs',
      label: 'Node.js',
      aliases: ['node'],
      purls: ['pkg:npm/node'],
      releases: [
        { cycle: '24', eolFrom: '2028-04-30' },
        { cycle: '18', eolFrom: '2025-04-30', eoasFrom: '2023-10-18' },
      ],
    },
    {
      id: 'debian',
      cpes: ['debian:debian_linux'],
      releases: [{ cycle: '11', eolFrom: '2026-08-31', eoasFrom: '2024-08-14', eoesFrom: '2031-06-30' }],
    },
    {
      id: 'express',
      purls: ['pkg:npm/express'],
      // Supported, but upstream publishes no end-of-support date for it.
      releases: [{ cycle: '4', isEolAtSnapshot: false }],
    },
    {
      id: 'angular',
      purls: ['pkg:npm/@angular/core'],
      releases: [{ cycle: '15', isEolAtSnapshot: true }],
    },
    // Two products both claiming the name "ambiguous" via an alias.
    { id: 'ambiguous-one', aliases: ['ambiguous'], releases: [{ cycle: '1', eolFrom: '2020-01-01' }] },
    { id: 'ambiguous-two', aliases: ['ambiguous'], releases: [{ cycle: '1', eolFrom: '2030-01-01' }] },
  ],
};

const INDEX = buildEolIndex(SNAPSHOT);
const ASOF = '2026-10-31';
const resolve = (components: FdaComponent[], extra: Parameters<typeof resolveSupport>[1] = {}) =>
  resolveSupport(components, { asOf: ASOF, index: INDEX, ...extra });
const one = (component: FdaComponent, extra: Parameters<typeof resolveSupport>[1] = {}) => resolve([component], extra).results[0].support;

describe('normalizePurlKey', () => {
  it('drops the version, qualifiers and subpath', () => {
    expect(normalizePurlKey('pkg:npm/express@4.18.2')).toBe('pkg:npm/express');
    expect(normalizePurlKey('pkg:deb/debian/openssl@1.1.1n-0+deb11u5?arch=arm64&distro=debian-11')).toBe('pkg:deb/debian/openssl');
  });

  it('keeps a namespace that itself contains an "@", encoded or not', () => {
    // Both spellings are emitted by real generators and must land on one key.
    expect(normalizePurlKey('pkg:npm/%40angular/core@15.0.0')).toBe('pkg:npm/@angular/core');
    expect(normalizePurlKey('pkg:npm/@angular/core@15.0.0')).toBe('pkg:npm/@angular/core');
  });

  it('lowercases, and rejects anything that is not a purl', () => {
    expect(normalizePurlKey('pkg:Maven/Org.Apache/Commons@1.0')).toBe('pkg:maven/org.apache/commons');
    expect(normalizePurlKey('openssl')).toBeUndefined();
    expect(normalizePurlKey('pkg:')).toBeUndefined();
  });

  it('survives a malformed percent-escape rather than throwing', () => {
    expect(normalizePurlKey('pkg:generic/bad%zz@1.0')).toBe('pkg:generic/bad%zz');
  });
});

describe('normalizeCpeKey', () => {
  it('collapses the 2.3 formatted form and the legacy URI form onto one key', () => {
    expect(normalizeCpeKey('cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*')).toBe('openssl:openssl');
    expect(normalizeCpeKey('cpe:/a:openssl:openssl')).toBe('openssl:openssl');
  });

  it('refuses wildcard or missing vendor/product — a "*:*" key would match everything', () => {
    expect(normalizeCpeKey('cpe:2.3:a:*:*:1.0:*:*:*:*:*:*:*')).toBeUndefined();
    expect(normalizeCpeKey('cpe:2.3:a:openssl')).toBeUndefined();
    expect(normalizeCpeKey('not-a-cpe')).toBeUndefined();
  });
});

describe('matchCycle', () => {
  const openssl = SNAPSHOT.products.find((p) => p.id === 'openssl') as EolProduct;

  it('prefers the longest prefixing cycle, not the first or shortest', () => {
    expect(matchCycle(openssl, '3.0.11')?.cycle).toBe('3.0');
    expect(matchCycle(openssl, '3.0')?.cycle).toBe('3.0');
  });

  it('matches a letter-suffixed version to its numeric cycle (the OpenSSL 1.1.1w case)', () => {
    expect(matchCycle(openssl, '1.1.1w')?.cycle).toBe('1.1.1');
  });

  it('does not treat a digit boundary as a cycle match', () => {
    // "30" must not land in cycle "3" just because the string starts with it.
    expect(matchCycle(openssl, '30.0')).toBeUndefined();
  });

  it('strips a leading "v" and a Debian/RPM epoch before matching', () => {
    expect(matchCycle(openssl, 'v3.0.11')?.cycle).toBe('3.0');
    expect(matchCycle(openssl, '1:1.1.1n-0+deb11u5')?.cycle).toBe('1.1.1');
  });

  it('returns undefined rather than the nearest cycle for a version it does not know', () => {
    expect(matchCycle(openssl, '9.9.9')).toBeUndefined();
    expect(matchCycle(openssl, '')).toBeUndefined();
  });
});

describe('resolveSupport — derivation from the snapshot', () => {
  it('reports a past end-of-support date as no-longer-maintained, with the date', () => {
    const support = one(comp({ name: 'openssl', version: '1.1.1w' }));
    expect(support.supportLevel).toBe('no-longer-maintained');
    expect(support.endOfSupportDate).toBe('2023-09-11');
    expect(support.basis).toBe('eol-snapshot');
    expect(support.matchedCycle).toBe('1.1.1');
  });

  it('reports a future end-of-support date as actively-maintained', () => {
    const support = one(comp({ name: 'openssl', version: '3.2.1' }));
    expect(support.supportLevel).toBe('actively-maintained');
    expect(support.endOfSupportDate).toBe('2027-11-23');
  });

  it('recomputes status against the run date instead of trusting the snapshot — the same cycle flips as the date moves', () => {
    const before = resolveSupport([comp({ name: 'openssl', version: '3.0.11' })], { asOf: '2026-09-06', index: INDEX }).results[0].support;
    const after = resolveSupport([comp({ name: 'openssl', version: '3.0.11' })], { asOf: '2026-09-07', index: INDEX }).results[0].support;
    expect(before.supportLevel).toBe('actively-maintained');
    // On the end-of-support date itself, support has ended.
    expect(after.supportLevel).toBe('no-longer-maintained');
    expect(after.evidence).toContain('Recomputed against 2026-09-07');
  });

  it('reports the STANDARD end-of-support date, not a longer paid-extended one', () => {
    // Debian 11: standard support to 2026-08-31, paid ELTS to 2031-06-30.
    // Reporting 2031 by default would tell FDA a component is supported for five
    // more years than the manufacturer has actually paid for.
    const support = one(comp({ name: 'debian', version: '11', cpe: 'cpe:2.3:o:debian:debian_linux:11:*:*:*:*:*:*:*' }));
    expect(support.supportLevel).toBe('no-longer-maintained');
    expect(support.endOfSupportDate).toBe('2026-08-31');
    expect(support.matchedBy).toBe('cpe');
    expect(support.evidence).toContain('extended/paid support for this cycle to 2031-06-30');
    expect(support.evidence).toContain('NOT the date reported');
  });

  it('notes a security-fixes-only phase in the evidence without changing the reported date', () => {
    const support = one(comp({ name: 'node', version: '18.19.0' }));
    expect(support.endOfSupportDate).toBe('2025-04-30');
    expect(support.matchedProductId).toBe('nodejs');
    expect(support.evidence).toContain('Active (feature) support ended 2023-10-18');
    expect(support.evidence).toContain('security fixes only');
  });

  it('matches by purl, including a scoped npm name, in preference to name', () => {
    expect(one(comp({ name: 'core', version: '15.0.0', purl: 'pkg:npm/%40angular/core@15.0.0' })).matchedProductId).toBe('angular');
    expect(one(comp({ name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2' })).matchedBy).toBe('purl');
  });

  it('leaves the end-of-support date ABSENT when upstream publishes none, rather than estimating one', () => {
    const support = one(comp({ name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2' }));
    expect(support.supportLevel).toBe('actively-maintained');
    expect(support.endOfSupportDate).toBeUndefined();
    expect(support.evidence).toContain('publishes no end-of-support date');
    expect(support.evidence).toContain('not available rather than estimated');
  });

  it('carries the component vendor’s own support policy URL through as evidence', () => {
    expect(one(comp({ name: 'openssl', version: '3.0.11' })).releasePolicyUrl).toBe('https://openssl-library.org/policies/releasestrat/');
  });

  it('never derives "abandoned" — only a manufacturer can say that', () => {
    const { results } = resolve(
      SNAPSHOT.products.flatMap((p) => p.releases.map((r) => comp({ name: p.id, version: r.cycle }))),
    );
    expect(results.some((r) => r.support.supportLevel === 'abandoned')).toBe(false);
  });
});

describe('resolveSupport — honest unknowns', () => {
  it('says unknown, with the reason, for a component not in the data at all', () => {
    const support = one(comp({ name: 'mbedtls', version: '2.28.5' }));
    expect(support.supportLevel).toBe('unknown');
    expect(support.endOfSupportDate).toBeUndefined();
    expect(support.evidence).toContain('was not found in the bundled endoflife.date data');
    expect(support.evidence).toContain('fda.componentSupport');
  });

  it('says unknown when the product matched but the component has no version', () => {
    const support = one(comp({ name: 'openssl' }));
    expect(support.supportLevel).toBe('unknown');
    expect(support.evidence).toContain('has no version');
  });

  it('says unknown, listing the known cycles, when the version matches no cycle', () => {
    const support = one(comp({ name: 'openssl', version: '9.9.9' }));
    expect(support.supportLevel).toBe('unknown');
    expect(support.evidence).toContain('does not fall in any release cycle');
    expect(support.evidence).toContain('3.2, 3.0, 1.1.1, 1');
  });

  it('refuses to pick between two products claiming the same name, and names both', () => {
    const support = one(comp({ name: 'ambiguous', version: '1.0' }));
    expect(support.supportLevel).toBe('unknown');
    expect(support.evidence).toContain('ambiguous-one, ambiguous-two');
    expect(support.evidence).toContain('rather than guessing one');
  });

  it('warns with a count when any component is unresolved', () => {
    const { warnings } = resolve([comp({ name: 'mbedtls', version: '2.28.5' }), comp({ name: 'openssl', version: '3.0.11' })]);
    expect(warnings.some((w) => w.startsWith('1 of 2 components have no support level'))).toBe(true);
  });
});

describe('resolveSupport — manufacturer declarations', () => {
  const fda = (componentSupport: Record<string, { supportLevel: 'actively-maintained' | 'no-longer-maintained' | 'abandoned' | 'unknown'; endOfSupportDate?: string; note?: string }>) => ({ componentSupport });

  it('lets a declaration outrank the snapshot, and records the disagreement rather than hiding it', () => {
    const support = one(comp({ name: 'openssl', version: '1.1.1w' }), {
      fda: fda({ 'openssl@1.1.1w': { supportLevel: 'actively-maintained', endOfSupportDate: '2028-01-01', note: 'Vendor support contract in place.' } }),
    });
    expect(support.supportLevel).toBe('actively-maintained');
    expect(support.endOfSupportDate).toBe('2028-01-01');
    expect(support.basis).toBe('manufacturer-declared');
    expect(support.note).toBe('Vendor support contract in place.');
    expect(support.evidence).toContain('the support level is "no-longer-maintained"');
    expect(support.evidence).toContain('the end-of-support date is 2023-09-11');
    expect(support.evidence).toContain('the declaration takes precedence');
  });

  it('does not bolt a disagreement note on when the declaration agrees with the data', () => {
    const support = one(comp({ name: 'openssl', version: '1.1.1w' }), {
      fda: fda({ 'openssl@1.1.1w': { supportLevel: 'no-longer-maintained', endOfSupportDate: '2023-09-11' } }),
    });
    expect(support.evidence).not.toContain('disagreement');
  });

  it('accepts "abandoned", which nothing else can produce', () => {
    const support = one(comp({ name: 'libfoo' }), { fda: fda({ libfoo: { supportLevel: 'abandoned', note: 'Upstream repository archived in 2021.' } }) });
    expect(support.supportLevel).toBe('abandoned');
    expect(support.basis).toBe('manufacturer-declared');
  });

  it('prefers the most specific key: purl, then name@version, then bare name', () => {
    const component = comp({ name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2' });
    const all = fda({
      'pkg:npm/express': { supportLevel: 'abandoned' },
      'express@4.18.2': { supportLevel: 'no-longer-maintained' },
      express: { supportLevel: 'actively-maintained' },
    });
    expect(one(component, { fda: all }).supportLevel).toBe('abandoned');
    expect(one(comp({ name: 'express', version: '4.18.2' }), { fda: all }).supportLevel).toBe('no-longer-maintained');
    expect(one(comp({ name: 'express' }), { fda: all }).supportLevel).toBe('actively-maintained');
  });

  it('warns when a declared "unknown" carries no justification, which FDA asks for', () => {
    const { warnings } = resolve([comp({ name: 'libfoo' })], { fda: fda({ libfoo: { supportLevel: 'unknown' } }) });
    expect(warnings.some((w) => w.includes('with no note') && w.includes('justification'))).toBe(true);
  });

  it('accepts a declared "unknown" with a justification silently', () => {
    const { warnings } = resolve([comp({ name: 'libfoo' })], { fda: fda({ libfoo: { supportLevel: 'unknown', note: 'Supplier asked 2026-09-01, no answer.' } }) });
    expect(warnings.some((w) => w.includes('with no note'))).toBe(false);
  });

  it('warns about a declaration that matched nothing, instead of ignoring it silently', () => {
    const { warnings } = resolve([comp({ name: 'openssl', version: '3.0.11' })], { fda: fda({ opensl: { supportLevel: 'abandoned' } }) });
    expect(warnings.some((w) => w.includes('fda.componentSupport["opensl"]') && w.includes('had no effect'))).toBe(true);
  });
});

describe('resolveSupport — declarations already on an imported SBOM', () => {
  it('reads the ceproof:fda:* properties the renderer writes, so an enriched SBOM round-trips', () => {
    const support = one(
      comp({
        name: 'libfoo',
        version: '1.0.0',
        properties: {
          [SUPPORT_LEVEL_PROPERTY]: 'abandoned',
          [END_OF_SUPPORT_PROPERTY]: '2021-06-30',
          [SUPPORT_NOTE_PROPERTY]: 'Upstream archived.',
        },
      }),
    );
    expect(support.supportLevel).toBe('abandoned');
    expect(support.endOfSupportDate).toBe('2021-06-30');
    expect(support.basis).toBe('sbom-declared');
    expect(support.note).toBe('Upstream archived.');
  });

  it('is outranked by the manufacturer’s own config declaration', () => {
    const support = one(comp({ name: 'libfoo', properties: { [SUPPORT_LEVEL_PROPERTY]: 'abandoned' } }), {
      fda: { componentSupport: { libfoo: { supportLevel: 'actively-maintained' as const } } },
    });
    expect(support.basis).toBe('manufacturer-declared');
  });

  it('treats an unrecognised support level as unknown and warns, rather than passing it through', () => {
    const { results, warnings } = resolve([comp({ name: 'libfoo', properties: { [SUPPORT_LEVEL_PROPERTY]: 'activelyMaintained' } })]);
    expect(results[0].support.supportLevel).toBe('unknown');
    expect(warnings.some((w) => w.includes('not one of') && w.includes('activelyMaintained'))).toBe(true);
  });

  it('drops a malformed date and warns, rather than reformatting it by guesswork', () => {
    const { results, warnings } = resolve([
      comp({ name: 'libfoo', properties: { [SUPPORT_LEVEL_PROPERTY]: 'no-longer-maintained', [END_OF_SUPPORT_PROPERTY]: '06/2021' } }),
    ]);
    expect(results[0].support.endOfSupportDate).toBeUndefined();
    expect(warnings.some((w) => w.includes('not a YYYY-MM-DD date'))).toBe(true);
  });
});

describe('snapshot staleness', () => {
  it('stays quiet inside the freshness window', () => {
    expect(
      snapshotStalenessWarning({
        label: 'end-of-support data',
        generatedAt: '2026-10-20T00:00:00+00:00',
        asOf: '2026-10-31',
      consequence: 'a component shown as actively maintained may have had an end-of-support date announced after this snapshot was taken.',
      refreshCommand: 'npm run fetch-eol-snapshot',
      }),
    ).toBeUndefined();
    expect(resolve([comp({ name: 'openssl', version: '3.0.11' })]).warnings.some((w) => w.includes('days old'))).toBe(false);
  });

  it('warns, naming the age and both dates, once past the threshold', () => {
    const warning = snapshotStalenessWarning({
      label: 'end-of-support data',
      generatedAt: '2026-01-01T00:00:00+00:00',
      asOf: '2026-10-31',
      consequence: 'a component shown as actively maintained may have had an end-of-support date announced after this snapshot was taken.',
      refreshCommand: 'npm run fetch-eol-snapshot',
    });
    expect(warning).toContain('303 days old');
    expect(warning).toContain('this run is dated 2026-10-31');
    expect(warning).toContain('fetch-eol-snapshot');
  });

  it('fires at exactly one day past the threshold, not before', () => {
    const asOf = '2026-10-31';
    const fresh = new Date(Date.parse(`${asOf}T00:00:00Z`) - SNAPSHOT_STALE_AFTER_DAYS * 86_400_000).toISOString();
    const stale = new Date(Date.parse(`${asOf}T00:00:00Z`) - (SNAPSHOT_STALE_AFTER_DAYS + 1) * 86_400_000).toISOString();
    const check = { label: 'd', consequence: 'something is out of date.', refreshCommand: 'npm run x' };
    expect(snapshotStalenessWarning({ ...check, generatedAt: fresh, asOf })).toBeUndefined();
    expect(snapshotStalenessWarning({ ...check, generatedAt: stale, asOf })).toBeDefined();
  });
});

describe('the bundled data/eol-snapshot.json', () => {
  // Assertions here must hold for ANY refresh of the snapshot, so a routine
  // "npm run fetch-eol-snapshot" never turns the suite red for the wrong reason.
  const snapshot = loadEolSnapshot();

  it('is present, loads, and declares the schema this version reads', () => {
    expect(snapshot.schema).toBe(EOL_SNAPSHOT_SCHEMA);
    expect(snapshot.products.length).toBeGreaterThan(300);
  });

  it('records the licence and the exact upstream bytes it was distilled from, for NOTICE and provenance', () => {
    expect(snapshot.source.license).toBe('MIT');
    expect(snapshot.source.copyright).toContain('endoflife.date contributors');
    expect(snapshot.source.upstreamSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(snapshot.source.upstreamGeneratedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('carries no product without release cycles, which could never answer a version question', () => {
    expect(snapshot.products.filter((p) => p.releases.length === 0)).toEqual([]);
  });

  it('has no purl claimed by two products — a purl is precise, so a collision there would be an upstream bug', () => {
    const index = buildEolIndex(snapshot);
    expect([...index.byPurl.entries()].filter(([, v]) => v.length > 1).map(([k]) => k)).toEqual([]);
  });

  it('handles every CPE key that two products do share, instead of picking one', () => {
    // These collisions are real and expected: `redhat:ansible` is claimed by
    // both "ansible" and "ansible-core" upstream, and more will appear as the
    // data grows. The invariant is not that there are none, it is that each one
    // resolves to a stated unknown naming both candidates — asserted against
    // whatever the current refresh contains rather than against a pinned list.
    const index = buildEolIndex(snapshot);
    const collided = [...index.byCpe.entries()].filter(([, v]) => v.length > 1);
    for (const [key, candidates] of collided) {
      const support = resolveSupport([comp({ name: 'irrelevant-name', version: '1.0', cpe: `cpe:2.3:a:${key}:1.0:*:*:*:*:*:*:*` })], {
        asOf: '2026-10-31',
        index,
      }).results[0].support;
      expect(support.supportLevel).toBe('unknown');
      for (const candidate of candidates) expect(support.evidence).toContain(candidate.id);
    }
  });

  it('resolves real firmware-shaped components end to end', () => {
    const { results } = resolveSupport(
      [
        comp({ name: 'openssl', version: '1.1.1w', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*' }),
        comp({ name: 'node', version: '18.19.0' }),
      ],
      { asOf: '2026-10-31' },
    );
    // OpenSSL 1.1.1 reached end of support on 2023-09-11 — a date in the real
    // vendored data, not in the fixture above.
    expect(results[0].support.endOfSupportDate).toBe('2023-09-11');
    expect(results[0].support.supportLevel).toBe('no-longer-maintained');
    expect(results[1].support.matchedProductId).toBe('nodejs');
  });
});

describe('traceability to the FDA guidance text', () => {
  // Same standard tests/cra/traceability.test.ts holds the CRA data to: the
  // requirement this engine implements must appear verbatim in the vendored
  // primary source, not in a paraphrase. An FDA artifact whose field list came
  // from a remembered summary of the guidance is exactly the failure this
  // catches.
  const sourcePath = path.join(REPO_ROOT, FDA_SOURCE.sourceFile);

  it('cites a vendored source file that exists under data/sources/', () => {
    expect(fs.existsSync(sourcePath)).toBe(true);
    expect(path.resolve(sourcePath).startsWith(path.resolve(DATA_DIR, 'sources'))).toBe(true);
  });

  it('every excerpt the engine is built on appears verbatim in that file', () => {
    const text = fs.readFileSync(sourcePath, 'utf8');
    for (const [name, excerpt] of Object.entries(FDA_SOURCE.excerpts)) {
      expect(text.includes(excerpt), `${name}: not found verbatim in ${FDA_SOURCE.sourceFile}`).toBe(true);
    }
  });

  it('the support levels are the guidance’s own three examples, not invented categories', () => {
    const text = fs.readFileSync(sourcePath, 'utf8');
    // The guidance's example list wraps across two lines in the PDF, so the
    // phrases are checked individually; these are what the three non-unknown
    // SUPPORT_LEVELS values are kebab-cased from.
    for (const phrase of ['actively maintained', 'no longer', 'maintained, abandoned']) {
      expect(text, `"${phrase}" not found in the vendored guidance text`).toContain(phrase);
    }
    expect(SUPPORT_LEVELS).toEqual(['actively-maintained', 'no-longer-maintained', 'abandoned', 'unknown']);
  });
});
