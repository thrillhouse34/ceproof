/**
 * One realistic FDA render input, built from hand-written datasets.
 *
 * Hand-written rather than bundled, for the same reason milestones 2 and 3
 * wrote their own: data/eol-snapshot.json and data/kev-snapshot.json are
 * refreshed on their own cadence, and a renderer test asserting "3 confirmed
 * findings" against live CISA data would change meaning every time someone
 * runs the fetch script. The real bundled data gets its own end-to-end block
 * in render.test.ts, which asserts only what must hold for any refresh.
 *
 * The component list is deliberately awkward in every way a real device SBOM
 * is awkward: a C library identified only by a CPE, a component with no
 * version at all, a component whose type CycloneDX has no name for, a hash in
 * an algorithm CycloneDX cannot express, an unresolved possible duplicate, a
 * field two sources disagreed about, and a pre-release version the KEV screen
 * refuses to compare. Every one of those drives a different branch in the
 * renderers.
 */
import {
  EOL_SNAPSHOT_SCHEMA,
  buildEolIndex,
  resolveSupport,
  SUPPORT_LEVEL_PROPERTY,
  type EolSnapshot,
} from '../../src/fda/support';
import {
  KEV_INDEX_SCHEMA,
  KEV_SNAPSHOT_SCHEMA,
  buildKevLookup,
  screenKev,
  type KevCatalogEntry,
  type KevIndex,
  type KevIndexEntry,
  type KevSnapshot,
} from '../../src/fda/kev';
import { qualifyRef, type FdaComponent, type FdaDependency } from '../../src/fda/types';
import type { FdaRenderInput } from '../../src/fda/render/input';

export const ASOF = '2026-10-31';
export const GENERATED_AT = '2026-10-31T09:15:00.000Z';

export function comp(partial: Partial<FdaComponent> & { name: string }): FdaComponent {
  return { licenses: [], hashes: [], properties: {}, origins: ['scan'], ...partial };
}

const EOL_SNAPSHOT: EolSnapshot = {
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
        { cycle: '3.0', eolFrom: '2026-09-07' },
        { cycle: '1.1.1', eolFrom: '2023-09-11' },
      ],
    },
    {
      id: 'nodejs',
      label: 'Node.js',
      aliases: ['node'],
      purls: ['pkg:npm/node'],
      releases: [{ cycle: '24', eolFrom: '2028-04-30' }],
    },
  ],
};

function kev(partial: Partial<KevCatalogEntry> & { cve: string; vendor: string; product: string }): KevCatalogEntry {
  return { vulnerabilityName: `${partial.product} Test Vulnerability`, dateAdded: '2024-01-01', ...partial };
}

const KEV_SNAPSHOT: KevSnapshot = {
  schema: KEV_SNAPSHOT_SCHEMA,
  source: {
    name: 'CISA Known Exploited Vulnerabilities Catalog',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    license: 'CC0-1.0',
    licenseUrl: 'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt',
    licenseStatement:
      'Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS.',
    catalogVersion: '2026.10.20',
    dateReleased: '2026-10-20T00:00:00.0000Z',
    upstreamCount: 5,
    upstreamSha256: 'a'.repeat(64),
  },
  fetchedAt: '2026-10-20T00:00:00.000Z',
  entries: [
    kev({ cve: 'CVE-2014-0160', vendor: 'OpenSSL', product: 'OpenSSL', vulnerabilityName: 'OpenSSL Information Disclosure Vulnerability', cwes: ['CWE-125'] }),
    kev({ cve: 'CVE-2020-11023', vendor: 'JQuery', product: 'jQuery', dueDate: '2025-01-15' }),
    kev({ cve: 'CVE-2099-0004', vendor: 'Acme', product: 'left-pad' }),
    kev({ cve: 'CVE-2099-0005', vendor: 'Electron', product: 'Electron', ransomware: true }),
    kev({ cve: 'CVE-2099-0009', vendor: 'Acme', product: 'lwip' }),
  ],
};

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

const KEV_INDEX: KevIndex = {
  schema: KEV_INDEX_SCHEMA,
  sources: [
    { name: 'OSV.dev', url: 'https://osv.dev/', license: 'Apache-2.0', licenseUrl: 'https://github.com/google/osv.dev/blob/master/LICENSE', attribution: 'OSV.dev, Google LLC, Apache-2.0.' },
    {
      name: 'GitHub Advisory Database',
      url: 'https://github.com/github/advisory-database',
      license: 'CC-BY-4.0',
      licenseUrl: 'https://github.com/github/advisory-database/blob/main/LICENSE.md',
      attribution: 'GitHub Advisory Database, CC-BY-4.0. Modified: only affected package names and version ranges are retained.',
    },
  ],
  builtFrom: {
    kevCatalogVersion: '2026.10.20',
    kevSha256: 'a'.repeat(64),
    kevEntryCount: 5,
    osvQueriedAt: '2026-10-21T04:05:06.000Z',
    cvesQueried: 5,
    cvesWithOsvRecord: 3,
  },
  entries: [
    // jquery 3.4.1 is inside this range -> confirmed.
    indexEntry({ cve: 'CVE-2020-11023', purlKey: 'pkg:npm/jquery', advisory: 'GHSA-jpcq-cgw6-v4j6', ranges: [{ introduced: '1.0.3', fixed: '3.5.0' }] }),
    // left-pad 1.3.0 is outside this range -> not-affected, and it goes in Appendix B.
    indexEntry({ cve: 'CVE-2099-0004', purlKey: 'pkg:npm/left-pad', advisory: 'GHSA-left-pad-0001', ranges: [{ introduced: '0', fixed: '1.0.0' }] }),
    // electron 27.0.0-beta.3 is a version compareVersions refuses -> possible,
    // with "check this one by hand".
    indexEntry({ cve: 'CVE-2099-0005', purlKey: 'pkg:npm/electron', advisory: 'GHSA-elec-tron-0001', ranges: [{ introduced: '0', fixed: '28.0.0' }] }),
  ],
};

/** The origin every imported component and every dependency ref in this fixture is qualified with. */
const SBOM_ORIGIN = 'sbom:firmware.json' as const;

/** Shorthand for a ref as it looks after import, so the fixture reads like the real qualified form. */
function ref(raw: string): string {
  return qualifyRef(SBOM_ORIGIN, raw);
}

export const SUBJECT = comp({
  name: 'acme-glucose-monitor',
  version: '2.0',
  type: 'device',
  supplier: 'Acme Medical',
  origins: [SBOM_ORIGIN],
  sourceRefs: [ref('device-root')],
});

/**
 * The imported SBOM's dependency graph, in the state a real firmware SBOM's
 * graph is in: rooted at `metadata.component`, naming the components that have
 * edges, and silent about the rest. `missing-from-this-sbom` is here on
 * purpose — a source graph referencing something the component list does not
 * carry is common (a dropped nameless component, a service, an external BOM
 * link) and the renderer has to report it rather than resolve it.
 */
export function fixtureDependencies(): FdaDependency[] {
  return [
    { ref: ref('device-root'), dependsOn: [ref('c-openssl'), ref('c-freertos'), ref('c-yocto')] },
    { ref: ref('c-openssl'), dependsOn: [ref('c-lwip')] },
    { ref: ref('c-freertos'), dependsOn: [] },
    { ref: ref('c-lwip'), dependsOn: [ref('missing-from-this-sbom')] },
    { ref: ref('c-yocto'), dependsOn: [] },
  ];
}

export function fixtureComponents(): FdaComponent[] {
  return [
    comp({
      name: 'openssl',
      version: '1.1.1',
      cpe: 'cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*',
      type: 'library',
      licenses: ['Apache-2.0'],
      hashes: [
        { alg: 'SHA-256', content: 'b'.repeat(64) },
        // Not a CycloneDX algorithm name: omitted from the document, reported
        // as an open item.
        { alg: 'SHA256', content: 'c'.repeat(64) },
      ],
      origins: [SBOM_ORIGIN],
      properties: { 'syft:package:type': 'binary' },
      sourceRefs: [ref('c-openssl')],
    }),
    comp({ name: 'FreeRTOS', version: '10.4.6', supplier: 'Amazon Web Services', type: 'library', origins: [SBOM_ORIGIN], sourceRefs: [ref('c-freertos')] }),
    // No version, no purl, no CPE, and a type CycloneDX has no name for.
    comp({ name: 'lwip', type: 'yocto-recipe', origins: [SBOM_ORIGIN], possibleDuplicate: true, sourceRefs: [ref('c-lwip')] }),
    comp({
      name: 'Yocto',
      version: 'kirkstone',
      type: 'operating-system',
      origins: [SBOM_ORIGIN, 'scan'],
      sourceRefs: [ref('c-yocto')],
      conflicts: ['supplier: kept "Yocto Project" from sbom:firmware.json, dropped "Linux Foundation" from scan'],
      supplier: 'Yocto Project',
    }),
    comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1', licenses: ['MIT'], type: 'library', origins: ['scan'] }),
    comp({ name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0', licenses: ['WTFPL OR MIT'], origins: ['scan'] }),
    comp({ name: 'electron', version: '27.0.0-beta.3', purl: 'pkg:npm/electron@27.0.0-beta.3', licenses: ['MIT'], origins: ['scan'] }),
    // Already carries a support declaration from a previous enrichment pass.
    comp({
      name: 'node',
      version: '24.1.0',
      purl: 'pkg:npm/node@24.1.0',
      origins: ['sbom:firmware.json'],
      properties: { [SUPPORT_LEVEL_PROPERTY]: 'actively-maintained' },
    }),
  ];
}

export interface FixtureOptions {
  asOf?: string;
  components?: FdaComponent[];
  sbomAuthor?: string;
  subject?: FdaComponent;
  /** Pass `[]` for the no-graph case — the shape a source SBOM with no `dependencies` array produces. */
  dependencies?: FdaDependency[];
}

export function fixtureInput(options: FixtureOptions = {}): FdaRenderInput {
  const asOf = options.asOf ?? ASOF;
  const components = options.components ?? fixtureComponents();
  const support = resolveSupport(components, {
    asOf,
    index: buildEolIndex(EOL_SNAPSHOT),
    fda: {
      componentSupport: {
        'pkg:npm/jquery@3.4.1': { supportLevel: 'actively-maintained', endOfSupportDate: '2029-01-01', note: 'Covered by our maintenance contract.' },
        // Lower-cased, as src/config/validate.ts normalises every declaration
        // key on load — the engine matches case-insensitively by comparing
        // against already-lowercased keys.
        freertos: { supportLevel: 'unknown', note: 'Vendor publishes no support policy; asked and awaiting an answer.' },
      },
    },
  });
  const kev = screenKev(components, { asOf, lookup: buildKevLookup(KEV_SNAPSHOT, KEV_INDEX) });
  return {
    asOf,
    generatedAt: GENERATED_AT,
    toolVersion: '0.3.5',
    subject: 'subject' in options ? options.subject : SUBJECT,
    ...(options.sbomAuthor ? { sbomAuthor: options.sbomAuthor } : {}),
    support,
    kev,
    mergeWarnings: ['1 component could not be matched across sources on a purl or on name@version and is listed twice; see the possible-duplicate rows.'],
    sbomInputs: [{ sourceLabel: 'firmware.json', specVersion: '1.6', sha256: 'd'.repeat(64), componentCount: 5 }],
    scanPath: '/repo/companion-app',
    // Only meaningful alongside the default component list, whose sourceRefs
    // these edges name. A caller passing its own `components` gets no graph
    // unless it passes matching edges too.
    dependencies: options.dependencies ?? (options.components ? [] : fixtureDependencies()),
  };
}
