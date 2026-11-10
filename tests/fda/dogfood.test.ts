import { describe, it, expect, beforeAll } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { writeFdaPack } from '../../src/cli/report';
import { runFda } from '../../src/fda/run';
import { computeFdaProfile } from '../../src/fda/gap';
import { FDA_ARTIFACT_FILES } from '../../src/fda/render/artifacts';
import { DISCLAIMER } from '../../src/branding';
import { REPO_ROOT } from '../../src/paths';

/**
 * The end-to-end test: the real CLI write path, the real bundled snapshots,
 * real fixture SBOMs, a real directory on disk.
 *
 * Deliberately NOT asserting specific findings or counts. `data/kev-snapshot.json`
 * and `data/eol-snapshot.json` refresh on their own cadence, so "3 confirmed
 * findings" would change meaning the next time someone runs a fetch script.
 * What is asserted is what must hold for ANY refresh: the file list, schema
 * validity, the disclaimer, determinism between two runs of the same input,
 * and the honest-gap statements. `tests/fda/render.test.ts` does the precise
 * content assertions against hand-written data.
 *
 * `writeFdaPack` is called directly rather than through `runReport` because
 * the licence gate sits above it and this machine has no FDA-tier key — and
 * the signing key at ../ceproof-signing-key/ is deliberately never read by
 * this suite. The gate itself is covered exhaustively in
 * tests/cli/fdaGating.test.ts, as a pure function.
 */
const FIXTURES = path.join(REPO_ROOT, 'fixtures');
const SYFT_SBOM = path.join(FIXTURES, 'sbom-import', 'syft-cyclonedx-1.6.json');
const FIRMWARE_SBOM = path.join(FIXTURES, 'sbom-import', 'firmware-no-purls.json');
const NPM_FIXTURE = path.join(FIXTURES, 'package-lock-v3-basic');

const ASOF = '2026-10-31';
const GENERATED_AT = '2026-10-31T09:00:00.000Z';

function scratch(label: string): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), `ceproof-dogfood-${label}-`)), 'pack');
}

function cycloneDxValidator() {
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  ajv.addFormat('iri-reference', true);
  ajv.addFormat('idn-email', true);
  ajv.addSchema({ $id: 'http://cyclonedx.org/schema/spdx.schema.json', type: 'string' });
  ajv.addSchema({ $id: 'http://cyclonedx.org/schema/jsf-0.82.schema.json', definitions: { signature: {} } });
  return ajv.compile(JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'tests', 'schemas', 'cyclonedx-1.6.schema.json'), 'utf8')));
}

describe('the FDA pack, written for real against the real bundled data', () => {
  let dir: string;
  let output: string;

  beforeAll(async () => {
    dir = scratch('firmware');
    const result = await writeFdaPack({
      // A directory with no scannable project plus a firmware SBOM: the
      // customer this mode exists for.
      path: os.tmpdir(),
      productionOnly: true,
      formats: ['fda-pack'],
      out: dir,
      sbomPaths: [SYFT_SBOM],
      asOf: ASOF,
      generatedAt: GENERATED_AT,
    });
    expect(result.exitCode, result.output).toBe(0);
    output = result.output;
  });

  it('writes exactly the seven artifacts the pack is defined as, and nothing else', () => {
    expect(fs.readdirSync(dir).sort()).toEqual(Object.values(FDA_ARTIFACT_FILES).sort());
  });

  it('names every file it wrote, and points at the open-items list', () => {
    for (const file of Object.values(FDA_ARTIFACT_FILES)) expect(output).toContain(file);
    expect(output).toContain('before you rely on any of it');
  });

  it('the enriched SBOM validates against the real CycloneDX 1.6 schema', () => {
    const validate = cycloneDxValidator();
    const doc = JSON.parse(fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.sbom), 'utf8'));
    const ok = validate(doc);
    if (!ok) console.error('CycloneDX validation errors:', JSON.stringify(validate.errors, null, 2));
    expect(ok).toBe(true);
  });

  it('carries the source SBOM’s dependency graph, mapped onto its own refs, with no foreign ref left in it', () => {
    const doc = JSON.parse(fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.sbom), 'utf8'));
    const refs = new Set<string>([
      ...doc.components.map((c: Record<string, string>) => c['bom-ref']),
      doc.metadata.component['bom-ref'],
    ]);
    expect(doc.dependencies.length).toBeGreaterThan(0);
    for (const edge of doc.dependencies) {
      expect(refs.has(edge.ref), `dangling dependency ref ${edge.ref}`).toBe(true);
      for (const target of edge.dependsOn) expect(refs.has(target), `dangling dependsOn ${target}`).toBe(true);
    }
    // Qualified source refs are an internal key and must never reach an artifact.
    expect(fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.sbom), 'utf8')).not.toContain('sbom:syft-cyclonedx-1.6.json|');
  });

  it('never emits an analysis object in the vulnerabilities array, whatever the live catalogue says', () => {
    const raw = fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.sbom), 'utf8');
    expect(raw).not.toContain('"analysis"');
    const doc = JSON.parse(raw);
    for (const vuln of doc.vulnerabilities ?? []) {
      expect(Object.keys(vuln).sort()).toEqual(['affects', 'id', 'source']);
    }
  });

  it('carries the disclaimer on every artifact that has a channel for it', () => {
    const exempt = [FDA_ARTIFACT_FILES.supportCsv, FDA_ARTIFACT_FILES.vulnerabilitiesCsv];
    for (const file of Object.values(FDA_ARTIFACT_FILES)) {
      const contents = fs.readFileSync(path.join(dir, file), 'utf8');
      const carries = contents.includes(DISCLAIMER) || contents.includes(JSON.stringify(DISCLAIMER).slice(1, -1));
      expect(carries, `${file} does not carry the disclaimer`).toBe(exempt.includes(file as never) ? false : true);
    }
    // And the pack discloses the exception itself.
    const disclaimer = fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.disclaimer), 'utf8');
    for (const file of exempt) expect(disclaimer).toContain(file);
  });

  it('leaves every manufacturer-supplied cell unfilled in the real CSV', () => {
    const csv = fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.vulnerabilitiesCsv), 'utf8');
    for (const line of csv.trim().split('\r\n').slice(1)) {
      expect(line.endsWith('NEEDS-HUMAN-INPUT,NEEDS-HUMAN-INPUT')).toBe(true);
    }
  });

  it('records the real bundled snapshot identifiers in the provenance artifact', () => {
    const provenance = JSON.parse(fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.provenance), 'utf8'));
    expect(provenance.asOf).toBe(ASOF);
    expect(provenance.fdaData.kevSnapshot.catalogVersion).toMatch(/^\d{4}\.\d{2}\.\d{2}$/);
    expect(provenance.fdaData.kevSnapshot.license).toBe('CC0-1.0');
    expect(provenance.fdaData.eolSnapshot.license).toBe('MIT');
    // The SHA-256 of the bytes actually read from the file the user named.
    expect(provenance.inputs.sboms[0].sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(provenance.inputs.sboms[0].sourceLabel).toBe('syft-cyclonedx-1.6.json');
  });

  it('is deterministic apart from the CycloneDX serial number, which is a fresh UUID by design', async () => {
    const second = scratch('determinism');
    const result = await writeFdaPack({
      path: os.tmpdir(),
      productionOnly: true,
      formats: ['fda-pack'],
      out: second,
      sbomPaths: [SYFT_SBOM],
      asOf: ASOF,
      generatedAt: GENERATED_AT,
    });
    expect(result.exitCode).toBe(0);
    const strip = (s: string) => s.replace(/"serialNumber": "[^"]*"/, '');
    for (const file of Object.values(FDA_ARTIFACT_FILES)) {
      expect(strip(fs.readFileSync(path.join(second, file), 'utf8')), `${file} is not reproducible`).toBe(
        strip(fs.readFileSync(path.join(dir, file), 'utf8')),
      );
    }
  });
});

describe('the pack over a repo scan and an imported SBOM together', () => {
  it('is additive: both sources appear, and the scan path is recorded', async () => {
    const dir = scratch('both');
    const result = await writeFdaPack({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['fda-pack'],
      out: dir,
      sbomPaths: [FIRMWARE_SBOM],
      asOf: ASOF,
      generatedAt: GENERATED_AT,
    });
    expect(result.exitCode, result.output).toBe(0);
    const provenance = JSON.parse(fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.provenance), 'utf8'));
    expect(provenance.inputs.repoScan.path).toContain('package-lock-v3-basic');
    expect(provenance.inputs.sboms).toHaveLength(1);
    const doc = JSON.parse(fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.sbom), 'utf8'));
    const origins = doc.components.flatMap((c: Record<string, { name: string; value: string }[]>) =>
      c.properties.filter((p) => p.name === 'ceproof:fda:origin').map((p) => p.value),
    );
    expect(origins.some((o: string) => o.includes('scan'))).toBe(true);
    expect(origins.some((o: string) => o.includes('sbom:firmware-no-purls.json'))).toBe(true);
    // The firmware SBOM carries no dependency graph, so the pack must say so
    // rather than let the absence pass for an assertion.
    expect(fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.openItems), 'utf8')).toContain('Dependency relationships are not represented');
  });

  it('refuses an unreadable --sbom with exit 2 and writes nothing', async () => {
    const dir = scratch('missing');
    const result = await writeFdaPack({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['fda-pack'],
      out: dir,
      sbomPaths: [path.join(os.tmpdir(), 'definitely-not-here-9f2a.json')],
    });
    expect(result.exitCode).toBe(2);
    expect(result.output).toContain('cannot read file');
    expect(fs.existsSync(dir)).toBe(false);
  });
});

/**
 * The free view and the paid pack must agree about what was found. If they
 * disagree, the free view is advertising a document the customer will not get.
 */
describe('the free view and the paid pack agree', () => {
  it('reports the same component count, the same findings and the same open-item count', async () => {
    const run = await runFda({
      path: NPM_FIXTURE,
      sbomPaths: [FIRMWARE_SBOM],
      productionOnly: true,
      asOf: ASOF,
      generatedAt: GENERATED_AT,
    });
    const profile = computeFdaProfile(run.input, run.rows);

    const dir = scratch('agreement');
    await writeFdaPack({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['fda-pack'],
      out: dir,
      sbomPaths: [FIRMWARE_SBOM],
      asOf: ASOF,
      generatedAt: GENERATED_AT,
    });
    const provenance = JSON.parse(fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.provenance), 'utf8'));

    expect(profile.counts.components).toBe(provenance.counts.components);
    expect(profile.counts.confirmed).toBe(provenance.counts.confirmed);
    expect(profile.counts.possible).toBe(provenance.counts.possible);
    expect(profile.counts.notAffected).toBe(provenance.counts.notAffected);
    expect(profile.counts.supportUnknown).toBe(provenance.counts.supportUnknown);
    expect(profile.counts.endOfSupportDates).toBe(provenance.counts.endOfSupportDates);
    // The free view promises a number of open items; the pack must list that many.
    const openItems = fs.readFileSync(path.join(dir, FDA_ARTIFACT_FILES.openItems), 'utf8');
    expect(openItems).toContain(`${profile.counts.openItems} open items`);
  });
});
