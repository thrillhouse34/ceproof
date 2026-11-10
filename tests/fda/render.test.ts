import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { buildEolIndex, loadEolSnapshot, SNAPSHOT_STALE_AFTER_DAYS, resolveSupport } from '../../src/fda/support';
import { loadKevLookup, screenKev, MANUFACTURER_SUPPLIED_COLUMNS } from '../../src/fda/kev';
import { renderFdaCycloneDx } from '../../src/fda/render/cyclonedx';
import { renderFdaArtifacts, FDA_ARTIFACT_FILES } from '../../src/fda/render/artifacts';
import { renderFdaSummary, renderFdaOpenItems } from '../../src/fda/render/summary';
import { buildFdaProvenance } from '../../src/fda/render/provenance';
import { collectOpenItems } from '../../src/fda/render/openItems';
import { renderSupportCsv, renderVulnerabilitiesCsv, SUPPORT_CSV_HEADERS, VULNERABILITY_CSV_HEADERS } from '../../src/fda/render/tables';
import { joinRows, csvCell, mdCell, bomRefFor } from '../../src/fda/render/input';
import type { FdaRenderInput } from '../../src/fda/render/input';
import { ASOF, SUBJECT, comp, fixtureComponents, fixtureInput } from './renderFixture';

const SCHEMA_DIR = path.join(__dirname, '..', 'schemas');

/**
 * The same Ajv setup tests/report/sbom.test.ts uses for the CRA renderer's
 * output, including the two permissive stubs the CycloneDX schema's external
 * $refs need to compile offline. Duplicated rather than shared because the two
 * suites assert against different renderers and must be able to move
 * independently; if a third needs it, extract then.
 */
function cycloneDxValidator() {
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  ajv.addFormat('iri-reference', true);
  ajv.addFormat('idn-email', true);
  ajv.addSchema({ $id: 'http://cyclonedx.org/schema/spdx.schema.json', type: 'string' });
  ajv.addSchema({ $id: 'http://cyclonedx.org/schema/jsf-0.82.schema.json', definitions: { signature: {} } });
  return ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, 'cyclonedx-1.6.schema.json'), 'utf8')));
}

function cdx(input: FdaRenderInput = fixtureInput()): Record<string, any> {
  return JSON.parse(renderFdaCycloneDx(input));
}

function componentNamed(doc: Record<string, any>, name: string): Record<string, any> {
  const found = doc.components.find((c: Record<string, any>) => c.name === name);
  expect(found, `component ${name} is missing from the document`).toBeDefined();
  return found;
}

function propertyValues(component: Record<string, any>, name: string): string[] {
  return (component.properties ?? []).filter((p: Record<string, string>) => p.name === name).map((p: Record<string, string>) => p.value);
}

describe('renderFdaCycloneDx — schema conformance', () => {
  it('produces a document that validates against the real CycloneDX 1.6 schema', () => {
    const validate = cycloneDxValidator();
    const ok = validate(cdx());
    if (!ok) console.error('CycloneDX validation errors:', JSON.stringify(validate.errors, null, 2));
    expect(ok).toBe(true);
  });

  it('still validates when the manufacturer has named themselves and when nothing names the device', () => {
    const validate = cycloneDxValidator();
    expect(validate(cdx(fixtureInput({ sbomAuthor: 'Acme Medical Devices Inc.' })))).toBe(true);
    expect(validate(cdx(fixtureInput({ subject: undefined })))).toBe(true);
  });

  it('coerces a component type CycloneDX does not define rather than emitting an invalid document', () => {
    const doc = cdx();
    // The fixture's lwip declares type "yocto-recipe"; a real Yocto SBOM does
    // this. Emitting it verbatim would fail the schema's closed enum.
    expect(componentNamed(doc, 'lwip').type).toBe('library');
    const items = collectOpenItems(fixtureInput(), joinRows(fixtureInput()));
    const item = items.find((i) => i.id === 'component-type-coerced');
    expect(item?.components?.[0]).toContain('declared "yocto-recipe", emitted as "library"');
  });

  it('omits a hash whose algorithm CycloneDX cannot name, and says so in the open items', () => {
    const openssl = componentNamed(cdx(), 'openssl');
    expect(openssl.hashes).toEqual([{ alg: 'SHA-256', content: 'b'.repeat(64) }]);
    const item = collectOpenItems(fixtureInput(), joinRows(fixtureInput())).find((i) => i.id === 'component-hash-omitted');
    expect(item?.components?.[0]).toContain('SHA256');
  });

  it('never puts a non-SPDX licence string in license.id, where the schema constrains it to the real SPDX list', () => {
    const doc = cdx(
      fixtureInput({
        components: [comp({ name: 'vendor-blob', version: '1.0', licenses: ['Acme Proprietary EULA v3'] }), ...fixtureComponents()],
      }),
    );
    expect(componentNamed(doc, 'vendor-blob').licenses).toEqual([{ license: { name: 'Acme Proprietary EULA v3' } }]);
    expect(componentNamed(doc, 'jquery').licenses).toEqual([{ license: { id: 'MIT' } }]);
    // A compound expression can only go in the expression form.
    expect(componentNamed(doc, 'left-pad').licenses).toEqual([{ expression: 'WTFPL OR MIT' }]);
    expect(cycloneDxValidator()(doc)).toBe(true);
  });
});

describe('renderFdaCycloneDx — the FDA-specific content', () => {
  it('carries the support level and its basis as properties, including when the level is unknown', () => {
    const doc = cdx();
    const openssl = componentNamed(doc, 'openssl');
    expect(propertyValues(openssl, 'ceproof:fda:supportLevel')).toEqual(['no-longer-maintained']);
    expect(propertyValues(openssl, 'ceproof:fda:endOfSupportDate')).toEqual(['2023-09-11']);
    expect(propertyValues(openssl, 'ceproof:fda:supportSource')).toEqual(['eol-snapshot']);
    expect(propertyValues(openssl, 'ceproof:fda:supportEvidence')[0]).toContain('endoflife.date');

    // An unknown level is STATED, not omitted — an absent property would read
    // as "not screened" rather than "screened, answer unavailable".
    const lwip = componentNamed(doc, 'lwip');
    expect(propertyValues(lwip, 'ceproof:fda:supportLevel')).toEqual(['unknown']);
    expect(propertyValues(lwip, 'ceproof:fda:endOfSupportDate')).toEqual([]);
  });

  it('carries a foreign property through untouched and restates only its own namespace', () => {
    const node = componentNamed(cdx(), 'node');
    // The fixture's node component arrives already carrying
    // ceproof:fda:supportLevel from a previous enrichment pass. It must appear
    // exactly once, as the value THIS run resolved.
    expect(propertyValues(node, 'ceproof:fda:supportLevel')).toEqual(['actively-maintained']);
    expect(propertyValues(node, 'ceproof:fda:supportSource')).toEqual(['sbom-declared']);
    expect(propertyValues(componentNamed(cdx(), 'openssl'), 'syft:package:type')).toEqual(['binary']);
  });

  it('records a possible duplicate and a source conflict on the component rather than resolving either', () => {
    const doc = cdx();
    expect(propertyValues(componentNamed(doc, 'lwip'), 'ceproof:fda:possibleDuplicate')[0]).toContain('NOT merged');
    expect(propertyValues(componentNamed(doc, 'Yocto'), 'ceproof:fda:sourceConflict')[0]).toContain('Linux Foundation');
  });

  it('invents nothing: no version, no licence and no end-of-support date where the source had none', () => {
    const lwip = componentNamed(cdx(), 'lwip');
    expect('version' in lwip).toBe(false);
    expect('licenses' in lwip).toBe(false);
    expect('purl' in lwip).toBe(false);
    expect(componentNamed(cdx(), 'Yocto').version).toBe('kirkstone'); // a fuzzy version is carried verbatim, not "completed"
  });

  it('names the SBOM author only when the manufacturer did, and never names the tool as the author', () => {
    expect(cdx().metadata.manufacturer).toBeUndefined();
    expect(cdx(fixtureInput({ sbomAuthor: 'Acme Medical Devices Inc.' })).metadata.manufacturer).toEqual({ name: 'Acme Medical Devices Inc.' });
    expect(JSON.stringify(cdx().metadata.component)).not.toContain('ceproof');
  });

  it('states in the document itself what its dependency graph and its vulnerability array are', () => {
    const properties = cdx().metadata.properties as { name: string; value: string }[];
    const byName = new Map(properties.map((p) => [p.name, p.value]));
    expect(byName.get('ceproof:fda:dependencyRelationships')).toContain('Carried through verbatim');
    expect(byName.get('ceproof:fda:vulnerabilityScreen')).toContain('Every entry is UNASSESSED');
    expect(byName.get('ceproof:fda:generationContext')).toContain('firmware.json');
    expect(properties.filter((p) => p.name === 'ceproof:fda:disclaimer').length).toBeGreaterThan(0);
  });

  it('gives every component a stable bom-ref, derived rather than random', () => {
    const first = cdx().components.map((c: Record<string, string>) => c['bom-ref']);
    const second = cdx().components.map((c: Record<string, string>) => c['bom-ref']);
    expect(first).toEqual(second);
    expect(first).toContain('pkg:npm/jquery@3.4.1');
    expect(new Set(first).size).toBe(first.length);
  });

  it('suffixes a colliding bom-ref instead of emitting the same ref twice', () => {
    const used = new Set<string>();
    expect(bomRefFor(comp({ name: 'lwip' }), used)).toBe('lwip');
    expect(bomRefFor(comp({ name: 'lwip' }), used)).toBe('lwip#2');
    expect(bomRefFor(comp({ name: 'lwip' }), used)).toBe('lwip#3');
  });
});

/**
 * Dependency relationship is one of the NTIA minimum elements, and the only
 * place it can come from is the source SBOM. The whole surface area of risk
 * here is an edge that this tool created, moved or dropped without saying so.
 */
describe('the dependency graph', () => {
  it('carries the source SBOM’s edges through, mapped onto the refs this document emits', () => {
    const doc = cdx();
    const refOf = (name: string) => componentNamed(doc, name)['bom-ref'] as string;
    const deviceRef = doc.metadata.component['bom-ref'] as string;
    expect(deviceRef).toBe('acme-glucose-monitor@2.0');

    const byRef = new Map((doc.dependencies as { ref: string; dependsOn: string[] }[]).map((d) => [d.ref, d.dependsOn]));
    // Not a source ref anywhere in the output: the document's own refs only.
    expect(JSON.stringify(doc.dependencies)).not.toContain('sbom:firmware.json|');
    expect(byRef.get(deviceRef)).toEqual([refOf('openssl'), refOf('FreeRTOS'), refOf('Yocto')]);
    expect(byRef.get(refOf('openssl'))).toEqual([refOf('lwip')]);
    // A component the source said has no dependencies keeps its empty entry —
    // CycloneDX uses that to mean "recorded, and there are none".
    expect(byRef.get(refOf('FreeRTOS'))).toEqual([]);
  });

  it('drops an edge target the document does not carry, and reports it rather than inventing a node', () => {
    const doc = cdx();
    const refOf = (name: string) => componentNamed(doc, name)['bom-ref'] as string;
    const byRef = new Map((doc.dependencies as { ref: string; dependsOn: string[] }[]).map((d) => [d.ref, d.dependsOn]));
    // The fixture's lwip depends on `missing-from-this-sbom`, which is in no
    // component list. The edge survives, minus the unmappable target.
    expect(byRef.get(refOf('lwip'))).toEqual([]);
    expect(JSON.stringify(doc)).not.toContain('missing-from-this-sbom');

    const item = collectOpenItems(fixtureInput(), joinRows(fixtureInput())).find((i) => i.id === 'dependency-relationships-incomplete');
    expect(item?.detail).toContain('1 individual dependency target named a component this document does not carry');
  });

  it('validates against the real CycloneDX 1.6 schema with the graph present', () => {
    expect(cycloneDxValidator()(cdx())).toBe(true);
  });

  it('says the graph is incomplete when not every component is in it, and names the count', () => {
    const value = (cdx().metadata.properties as { name: string; value: string }[]).find(
      (p) => p.name === 'ceproof:fda:dependencyRelationships',
    )!.value;
    expect(value).toContain('4 of 8 components appear in the graph');
    expect(value).toContain('INCOMPLETE');
    // The reading a consumer is entitled to, in the spec's own terms.
    expect(value).toContain('unknown dependencies, not as being dependency-free');
  });

  it('emits no dependencies key at all when the source carried no graph, rather than an empty array', () => {
    const doc = cdx(fixtureInput({ dependencies: [] }));
    expect('dependencies' in doc).toBe(false);
    const value = (doc.metadata.properties as { name: string; value: string }[]).find(
      (p) => p.name === 'ceproof:fda:dependencyRelationships',
    )!.value;
    expect(value).toContain('Absent.');
    expect(value).toContain('must be read as having unknown dependencies');

    const input = fixtureInput({ dependencies: [] });
    const items = collectOpenItems(input, joinRows(input));
    expect(items.find((i) => i.id === 'dependency-relationships-absent')).toBeDefined();
    expect(items.find((i) => i.id === 'dependency-relationships-incomplete')).toBeUndefined();
  });

  it('calls a graph with only top-level edges incomplete, which is the usual real-world shape', () => {
    const components = fixtureComponents();
    const topLevelOnly = fixtureInput({
      components,
      dependencies: [{ ref: 'sbom:firmware.json|device-root', dependsOn: components.flatMap((c) => c.sourceRefs ?? []) }],
      subject: SUBJECT,
    });
    const value = (cdx(topLevelOnly).metadata.properties as { name: string; value: string }[]).find(
      (p) => p.name === 'ceproof:fda:dependencyRelationships',
    )!.value;
    expect(value).toContain('records only top-level edges');
    const item = collectOpenItems(topLevelOnly, joinRows(topLevelOnly)).find((i) => i.id === 'dependency-relationships-incomplete');
    expect(item?.action).toContain('does not describe the transitive ones');
  });

  it('never infers an edge: a scan-only run has no graph, because a scan contributes no source refs', () => {
    const input = fixtureInput({ components: [comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1' })] });
    expect('dependencies' in cdx(input)).toBe(false);
  });

  it('unions two source documents’ edges for one merged component instead of emitting it twice', () => {
    const shared = comp({
      name: 'openssl',
      version: '1.1.1',
      origins: ['sbom:a.json', 'sbom:b.json'],
      sourceRefs: ['sbom:a.json|ossl', 'sbom:b.json|openssl-1'],
    });
    const left = comp({ name: 'zlib', version: '1.3', origins: ['sbom:a.json'], sourceRefs: ['sbom:a.json|zlib'] });
    const right = comp({ name: 'lwip', version: '2.1.3', origins: ['sbom:b.json'], sourceRefs: ['sbom:b.json|lwip'] });
    const doc = cdx(
      fixtureInput({
        components: [shared, left, right],
        dependencies: [
          { ref: 'sbom:a.json|ossl', dependsOn: ['sbom:a.json|zlib'] },
          { ref: 'sbom:b.json|openssl-1', dependsOn: ['sbom:b.json|lwip'] },
        ],
      }),
    );
    const entries = doc.dependencies as { ref: string; dependsOn: string[] }[];
    expect(entries.filter((d) => d.ref === 'openssl@1.1.1')).toHaveLength(1);
    expect(entries[0].dependsOn).toEqual(['zlib@1.3', 'lwip@2.1.3']);
  });
});

/**
 * The `vulnerabilities[]` array. What it must never grow is an `analysis`
 * object: that is where CycloneDX states whether a vulnerability affects the
 * product, which is the one judgement this tool exists not to make.
 */
describe('the vulnerabilities array', () => {
  it('lists one entry per CVE, with only id, source and affects', () => {
    const vulns = cdx().vulnerabilities as Record<string, unknown>[];
    expect(vulns.length).toBeGreaterThan(0);
    for (const vuln of vulns) {
      expect(Object.keys(vuln).sort()).toEqual(['affects', 'id', 'source']);
      expect(vuln.id).toMatch(/^CVE-/);
      expect(vuln.source).toEqual({
        name: 'CISA Known Exploited Vulnerabilities Catalog',
        url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      });
    }
  });

  it('never emits an analysis object, in any run — that field is the assessment', () => {
    for (const label of ['default', 'no findings', 'stale'] as const) {
      const input =
        label === 'no findings'
          ? fixtureInput({ components: [comp({ name: 'nothing-matches-this', version: '1.0' })] })
          : fixtureInput(label === 'stale' ? { asOf: '2027-06-01' } : {});
      const doc = cdx(input);
      expect(JSON.stringify(doc), `${label}: an analysis object reached the document`).not.toContain('"analysis"');
      for (const vuln of (doc.vulnerabilities ?? []) as Record<string, unknown>[]) {
        expect('analysis' in vuln).toBe(false);
        expect('state' in vuln).toBe(false);
      }
    }
  });

  it('affects every component the screen matched, by this document’s own bom-ref', () => {
    const doc = cdx();
    const jquery = componentNamed(doc, 'jquery')['bom-ref'];
    const jqueryCve = (doc.vulnerabilities as Record<string, any>[]).find((v) => v.id === 'CVE-2020-11023');
    expect(jqueryCve?.affects).toEqual([{ ref: jquery }]);
  });

  it('leaves the not-affected rows out of the array entirely — including them would assert the opposite', () => {
    const doc = cdx();
    // The fixture's left-pad 1.3.0 is outside CVE-2099-0004's affected range.
    expect((doc.vulnerabilities as Record<string, any>[]).some((v) => v.id === 'CVE-2099-0004')).toBe(false);
    // It is still in the CSV, where a `confidence` column can say so.
    expect(renderVulnerabilitiesCsv(joinRows(fixtureInput()))).toContain('CVE-2099-0004');
  });

  it('emits no vulnerabilities key when nothing matched, rather than an empty array', () => {
    const doc = cdx(fixtureInput({ components: [comp({ name: 'nothing-matches-this', version: '1.0' })] }));
    expect('vulnerabilities' in doc).toBe(false);
    const value = (doc.metadata.properties as { name: string; value: string }[]).find(
      (p) => p.name === 'ceproof:fda:vulnerabilityScreen',
    )!.value;
    expect(value).toContain('An empty array is not a statement that the device is free of known vulnerabilities');
  });

  it('never emits a rating, because no bundled dataset carries a severity score to emit', () => {
    expect(JSON.stringify(cdx())).not.toContain('"ratings"');
  });

  it('validates against the real CycloneDX 1.6 schema with the array present', () => {
    expect(cycloneDxValidator()(cdx())).toBe(true);
  });
});

describe('DISCLAIMER.md', () => {
  const contents = () => renderFdaArtifacts(fixtureInput()).find((a) => a.file === FDA_ARTIFACT_FILES.disclaimer)!.contents;

  it('is in the pack', () => {
    expect(renderFdaArtifacts(fixtureInput()).map((a) => a.file)).toContain('DISCLAIMER.md');
  });

  it('names the two CSVs as the files that cannot state the disclaimer inline, and why', () => {
    expect(contents()).toContain('`fda-support-eol.csv`');
    expect(contents()).toContain('`fda-vulnerabilities.csv`');
    expect(contents()).toContain('CSV has nowhere to put prose');
  });

  it('names the device and the run it belongs to, so it cannot be mistaken for a generic boilerplate file', () => {
    expect(contents()).toContain('acme-glucose-monitor 2.0');
    expect(contents()).toContain(ASOF);
  });
});

describe('the vulnerability section', () => {
  const summary = renderFdaSummary(fixtureInput());

  it('states the date the vulnerability data was captured, separately from the run date', () => {
    expect(summary).toContain('**Vulnerabilities identified as of 2026-10-20**');
    expect(summary).toContain('catalogue version 2026.10.20');
    expect(summary).toContain('captured from OSV on 2026-10-21');
    expect(summary).toContain(`This document was generated on ${ASOF}`);
  });

  it('carries the two manufacturer-supplied columns verbatim, and leaves them needing input', () => {
    for (const column of MANUFACTURER_SUPPLIED_COLUMNS) expect(summary).toContain(column);
    const confirmedRow = summary.split('\n').find((line) => line.includes('CVE-2020-11023') && line.startsWith('|'));
    expect(confirmedRow).toContain('| NEEDS-HUMAN-INPUT | NEEDS-HUMAN-INPUT |');
  });

  it('puts not-affected rows in Appendix B only, with the count stated in the main summary', () => {
    const [body, appendixB] = summary.split('## Appendix B');
    expect(body).toContain('1 row was screened and found not to affect the version declared for the component; it is listed in Appendix B.');
    // CVE-2099-0004 is the fixture's one not-affected row: left-pad 1.3.0,
    // outside the advisory's range. It must not appear in the main table.
    expect(body).not.toContain('CVE-2099-0004');
    expect(appendixB).toContain('CVE-2099-0004');
    expect(appendixB).toContain('outside every affected range');
  });

  it('gives every finding a how-it-was-discovered sentence, which is submission content FDA asks for', () => {
    expect(summary).toContain('### How each finding was discovered');
    expect(summary).toContain('Discovered by screening the component list against the bundled CISA Known Exploited Vulnerabilities Catalog');
    expect(summary).toContain('declined to compare version "27.0.0-beta.3"');
  });

  it('carries the screen limits on the document, not only in the README', () => {
    for (const limit of fixtureInput().kev.limits) expect(summary).toContain(limit);
  });

  it('does not read as a clean bill of health when nothing matched', () => {
    const input = fixtureInput({ components: [comp({ name: 'nothing-matches-this', version: '1.0' })] });
    const body = renderFdaSummary(input);
    expect(body).toContain('No component matched an entry in the bundled KEV catalogue in this run');
    expect(body).toContain('That is not a statement that the device is free of known vulnerabilities');
  });
});

describe('the support section', () => {
  it('counts every level, names how many dates are missing, and flags the ones already passed', () => {
    const summary = renderFdaSummary(fixtureInput());
    expect(summary).toContain('| no longer maintained | 1 |');
    expect(summary).toContain('| unknown | 5 |');
    expect(summary).toContain('2 of 8 components have an end-of-support date; 6 have none');
    expect(summary).toContain(`1 component has an end-of-support date that has already passed as of ${ASOF}`);
  });

  it('puts one row per component in Appendix A, each with its basis and its evidence', () => {
    const appendixA = renderFdaSummary(fixtureInput()).split('## Appendix A')[1].split('## Appendix B')[0];
    expect(appendixA).toContain('| openssl | 1.1.1 |');
    expect(appendixA).toContain('eol-snapshot');
    expect(appendixA).toContain('manufacturer-declared');
    // Eight components, plus the header and the rule row.
    expect(appendixA.split('\n').filter((line) => line.startsWith('|')).length).toBe(10);
  });
});

describe('open items', () => {
  const input = fixtureInput();
  const items = collectOpenItems(input, joinRows(input));
  const ids = items.map((i) => i.id);

  it('derives an item for every required value the pack cannot supply', () => {
    expect(ids).toContain('sbom-author-missing');
    expect(ids).toContain('support-level-unknown');
    expect(ids).toContain('end-of-support-date-missing');
    expect(ids).toContain('vulnerability-assessment-missing');
  });

  it('always states the two standing limits, even on a run with no findings and no gaps', () => {
    const clean = fixtureInput({ components: [comp({ name: 'nothing-matches-this', version: '1.0' })], sbomAuthor: 'Acme' });
    const cleanIds = collectOpenItems(clean, joinRows(clean)).map((i) => i.id);
    expect(cleanIds).toContain('dependency-relationships-absent');
    expect(cleanIds).toContain('kev-screen-coverage');
    expect(cleanIds).not.toContain('sbom-author-missing');
    expect(cleanIds).not.toContain('vulnerability-assessment-missing');
  });

  it('derives the declined-comparison item from the finding, not from matching the engine wording', () => {
    const item = items.find((i) => i.id === 'version-comparison-declined');
    expect(item?.components).toEqual(['electron 27.0.0-beta.3']);
  });

  it('warns about a stale dataset, on the same threshold the engines use', () => {
    const fresh = collectOpenItems(input, joinRows(input)).map((i) => i.id);
    expect(fresh).not.toContain('stale-bundled-data');
    // Far enough past the fixture's snapshot dates for both to be stale.
    const later = fixtureInput({ asOf: '2027-06-01' });
    const item = collectOpenItems(later, joinRows(later)).find((i) => i.id === 'stale-bundled-data');
    expect(item?.detail).toContain(`more than ${SNAPSHOT_STALE_AFTER_DAYS} days old`);
    expect(item?.detail).toContain('The end-of-support data and the CISA KEV catalogue are more than 30 days old');
    expect(renderFdaSummary(later)).toContain('past the 30-day freshness threshold');
  });

  it('caps a long component list in the rendering without dropping it from the data', () => {
    const many = Array.from({ length: 40 }, (_, i) => comp({ name: `widget-${i}`, version: '1.0' }));
    const input40 = fixtureInput({ components: many });
    const rendered = renderFdaOpenItems(input40);
    expect(collectOpenItems(input40, joinRows(input40)).find((i) => i.id === 'support-level-unknown')?.components?.length).toBe(40);
    expect(rendered).toContain('…and 15 more');
  });
});

describe('the CSVs', () => {
  const rows = joinRows(fixtureInput());

  it('writes one support row per component, with the header the spec promised', () => {
    const lines = renderSupportCsv(rows).trim().split('\r\n');
    expect(lines[0].split(',')).toEqual(SUPPORT_CSV_HEADERS);
    expect(lines.length).toBe(rows.length + 1);
  });

  it('writes every finding, including the ones screened out, with the confidence column separating them', () => {
    const csv = renderVulnerabilitiesCsv(rows);
    const expected = rows.reduce((n, row) => n + row.findings.length + row.notAffected.length, 0);
    expect(csv.trim().split('\r\n').length).toBe(expected + 1);
    expect(csv).toContain('not-affected');
    expect(csv).toContain('confirmed');
    expect(VULNERABILITY_CSV_HEADERS.slice(-2)).toEqual([...MANUFACTURER_SUPPLIED_COLUMNS]);
    // The two manufacturer columns are marked, not left ambiguously empty.
    expect(csv).toContain('NEEDS-HUMAN-INPUT,NEEDS-HUMAN-INPUT');
  });

  it('quotes a cell containing a comma, a quote or a newline, and doubles embedded quotes', () => {
    expect(csvCell('plain')).toBe('plain');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('one\ntwo')).toBe('"one\ntwo"');
    // Evidence sentences contain both commas and quotes; they must survive.
    expect(renderVulnerabilitiesCsv(rows)).toContain('""electron""');
  });

  it('escapes the two characters that would break a markdown table, and nothing else', () => {
    expect(mdCell('a|b')).toBe('a\\|b');
    expect(mdCell('one\ntwo')).toBe('one two');
    expect(mdCell('pkg:npm/@scope/x@1.0')).toBe('pkg:npm/@scope/x@1.0');
  });
});

describe('the provenance artifact', () => {
  const provenance = buildFdaProvenance(fixtureInput({ sbomAuthor: 'Acme Medical Devices Inc.' }));

  it('records each dataset under its own identifiers, and does not borrow the CRA dataVersion', () => {
    expect(provenance.fdaData.eolSnapshot.upstreamSha256).toBe('f'.repeat(64));
    expect(provenance.fdaData.kevSnapshot.catalogVersion).toBe('2026.10.20');
    expect((provenance.fdaData.kevIndex.builtFrom as Record<string, string>).osvQueriedAt).toBe('2026-10-21T04:05:06.000Z');
    expect(JSON.stringify(provenance)).not.toContain('dataVersion');
  });

  it('records the hash of every input SBOM and the path that was scanned', () => {
    expect(provenance.inputs.sboms).toEqual([
      { sourceLabel: 'firmware.json', format: 'CycloneDX', specVersion: '1.6', sha256: 'd'.repeat(64), componentCount: 5 },
    ]);
    expect(provenance.inputs.repoScan).toEqual({ path: '/repo/companion-app' });
  });

  it('carries every bundled dataset licence, including CISA’s own no-endorsement condition', () => {
    const json = JSON.stringify(provenance);
    expect(json).toContain('CC0-1.0');
    expect(json).toContain('nor should such use be interpreted as an endorsement by CISA or DHS');
    expect(json).toContain('CC-BY-4.0');
    expect(json).toContain('Modified: only affected package names and version ranges are retained.');
  });

  it('counts what the document counts, so the two can never disagree', () => {
    expect(provenance.counts).toEqual({
      components: 8,
      supportDeclared: 3,
      supportUnknown: 5,
      endOfSupportDates: 2,
      confirmed: 1,
      possible: 3,
      notAffected: 1,
    });
  });

  it('carries the guidance citation and the vendored source file the excerpts come from', () => {
    expect(provenance.guidance.support).toContain('February 3, 2026');
    expect(provenance.guidance.sourceFile).toBe('data/sources/fda-premarket-cybersecurity-2026-02-03-extract.md');
  });
});

describe('renderFdaArtifacts', () => {
  it('returns the six files of the pack, each non-empty', () => {
    const artifacts = renderFdaArtifacts(fixtureInput());
    expect(artifacts.map((a) => a.file)).toEqual(Object.values(FDA_ARTIFACT_FILES));
    for (const artifact of artifacts) expect(artifact.contents.length).toBeGreaterThan(200);
  });

  it('names every file it produces inside the summary, so the pack describes itself', () => {
    const summary = renderFdaSummary(fixtureInput());
    for (const file of Object.values(FDA_ARTIFACT_FILES)) expect(summary).toContain(file);
  });

  it('refuses to render when the two engines were run over different component lists', () => {
    const input = fixtureInput();
    const mismatched: FdaRenderInput = { ...input, kev: { ...input.kev, results: input.kev.results.slice(1) } };
    expect(() => renderFdaArtifacts(mismatched)).toThrow(/SAME merged component list/);
  });
});

describe('against the real bundled data', () => {
  // One end-to-end pass over the files that actually ship, asserting only what
  // must hold for ANY refresh of them. CISA adds catalogue entries
  // continuously, so nothing here depends on a specific entry count.
  const components = [
    comp({ name: 'jquery', version: '3.4.1', purl: 'pkg:npm/jquery@3.4.1', licenses: ['MIT'], origins: ['scan'] }),
    comp({ name: 'openssl', version: '1.1.1w', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*', origins: ['sbom:firmware.json'] }),
  ];
  const asOf = '2026-10-31';
  const input: FdaRenderInput = {
    asOf,
    generatedAt: `${asOf}T12:00:00.000Z`,
    toolVersion: '0.3.5',
    subject: comp({ name: 'acme-pump', version: '1.0', type: 'device' }),
    support: resolveSupport(components, { asOf, index: buildEolIndex(loadEolSnapshot()) }),
    kev: screenKev(components, { asOf, lookup: loadKevLookup() }),
    mergeWarnings: [],
    sbomInputs: [{ sourceLabel: 'firmware.json', specVersion: '1.6', sha256: 'e'.repeat(64), componentCount: 1 }],
  };

  it('renders a schema-valid SBOM from the shipped snapshots', () => {
    const validate = cycloneDxValidator();
    const ok = validate(JSON.parse(renderFdaCycloneDx(input)));
    if (!ok) console.error(JSON.stringify(validate.errors, null, 2));
    expect(ok).toBe(true);
  });

  it('resolves OpenSSL 1.1.1w against the real end-of-support data and states it in the pack', () => {
    const summary = renderFdaSummary(input);
    expect(summary).toContain('no longer maintained');
    expect(summary).toContain('2023-09-11');
  });

  it('reports the real jQuery finding with its real catalogue version, if CISA still lists it', () => {
    const summary = renderFdaSummary(input);
    const stillListed = input.kev.results.some((r) => r.findings.some((f) => f.cve === 'CVE-2020-11023'));
    if (!stillListed) {
      // A CISA removal is legitimate; failing the suite for it would be wrong.
      expect(summary).toContain('No component matched an entry in the bundled KEV catalogue');
      return;
    }
    expect(summary).toContain('CVE-2020-11023');
    expect(summary).toContain(`catalogue version ${input.kev.snapshotSource.catalogVersion}`);
    expect(summary).toContain('NEEDS-HUMAN-INPUT');
  });

  it('produces all six artifacts from the shipped data', () => {
    expect(renderFdaArtifacts(input).map((a) => a.file)).toEqual(Object.values(FDA_ARTIFACT_FILES));
  });
});
