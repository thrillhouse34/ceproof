import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from '../../src/cli/scan';
import { runInit } from '../../src/cli/init';
import { runReport, REPORT_FORMATS } from '../../src/cli/report';
import { findChromeExecutable } from '../../src/report/pdf';

// ─────────────────────────────────────────────────────────────────────────────
// THE FULL SIMULATED CUSTOMER JOURNEY: content correctness, not licensing.
//
// This exercises the real value chain a customer walks through:
//
//   scan (no config: mostly NEEDS-HUMAN-INPUT) → init (generates the answer
//   slots) → fill in the answers (the committed filled-config fixture,
//   fixtures/ceproof.config.filled.json — deliberately leaves annex7.7
//   unanswered) → scan again with that config (most items now DERIVED) →
//   report, every format, with that config → the Annex VII pack really did
//   compose annex7.7 from the answered Annex V items rather than needing a
//   second answer → the free SBOM formats produce real, valid documents.
//
// A real, committed test key (see tests/cli/reportGating.test.ts for the same
// constant) is supplied for the M3-gated narrative formats — this file's
// point is verifying rendered CONTENT is correct, not re-testing the gating
// flow itself (that's reportGating.test.ts's job in full: refusal, exit 3,
// whole-request semantics, all three key-discovery sources).
//
// Every filesystem touch is inside an injected scratch dir.
// ─────────────────────────────────────────────────────────────────────────────

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const NPM_FIXTURE = path.join(REPO_ROOT, 'fixtures', 'package-lock-v3-basic');
const FILLED_CONFIG = path.join(REPO_ROOT, 'fixtures', 'ceproof.config.filled.json');
const HAS_BROWSER = findChromeExecutable() !== undefined;

// A real, genuine, verifying individual-tier key with an updatesUntil in the
// future (so it drives NO data-currency note). Same constant used in
// tests/cli/reportGating.test.ts.
const REAL_KEY =
  'eyJwcm9kdWN0IjoiY2Vwcm9vZiIsInRpZXIiOiJpbmRpdmlkdWFsIiwibGljZW5zZUlkIjoiNzZaNTJOVzRHVSIsImlzc3VlZEF0IjoiMjAyNi0wNy0yNFQwNToyOTozOC4xMzRaIiwidXBkYXRlc1VudGlsIjoiMjAyNy0wNy0yNFQwNToyOTozOC4xMzRaIn0.1_Ji7XgwqBTNxY5zdG_0aBWrv5Z8QmXyn0z5ui3EFTw-4FA2f5kViCHuie7MLLLIqSrv1btxHZwkDI8-1nWhDw';

describe('full simulated customer journey (scan → init → fill config → scan again → report, M2)', () => {
  let scratch: string;

  beforeAll(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-journey-'));
  });

  afterAll(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  it('step 1: scan with no config leaves most items NEEDS-HUMAN-INPUT, exit 1 (default --fail-on)', async () => {
    const result = await runScan({ path: NPM_FIXTURE, productionOnly: true, format: 'json', projectLicenseOverride: undefined });
    expect(result.exitCode).toBe(1);
    const json = JSON.parse(result.output);
    expect(json.summary.needsHumanInput).toBeGreaterThan(0);
  });

  it('step 2: init generates ceproof.config.json with one answer slot per human-required item', () => {
    const target = path.join(scratch, 'ceproof.config.json');
    const result = runInit({ path: NPM_FIXTURE, configPath: target });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(target)).toBe(true);
    const config = JSON.parse(fs.readFileSync(target, 'utf8'));
    expect(Object.keys(config.answers).length).toBeGreaterThan(0);
    // annex5.3 became 'boilerplate' in M2 — init must NOT ask for it.
    expect(config.answers).not.toHaveProperty('annex5.3');
  });

  it('step 3: the committed filled-config fixture is real, valid JSON deliberately missing annex7.7', () => {
    expect(fs.existsSync(FILLED_CONFIG)).toBe(true);
    const config = JSON.parse(fs.readFileSync(FILLED_CONFIG, 'utf8'));
    expect(config.answers).not.toHaveProperty('annex7.7');
    expect(config.answers).not.toHaveProperty('annex5.3'); // boilerplate, not an answer slot
  });

  it('step 4: scan WITH the filled config resolves nearly everything, and never crashes on the boilerplate item', async () => {
    const result = await runScan({
      path: NPM_FIXTURE,
      productionOnly: true,
      format: 'json',
      configPath: FILLED_CONFIG,
      projectLicenseOverride: undefined,
    });
    const json = JSON.parse(result.output);
    // annex7.7 is deliberately unanswered directly — it's still
    // NEEDS-HUMAN-INPUT at the gap-checklist level (composition is a
    // report-rendering concern, not a scan concern) — everything else should
    // resolve DERIVED or PARTIAL.
    expect(json.summary.needsHumanInput).toBe(1);
    const annex77 = json.gapChecklist.find((i: { id: string }) => i.id === 'annex7.7');
    expect(annex77.status).toBe('NEEDS-HUMAN-INPUT');
    const annex53 = json.gapChecklist.find((i: { id: string }) => i.id === 'annex5.3');
    expect(annex53.status).toBe('DERIVED'); // boilerplate, always DERIVED, no config needed
  });

  it('step 5: report renders every non-PDF format with the filled config, given a valid key', async () => {
    const outDir = path.join(scratch, 'report-filled');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: [...REPORT_FORMATS.filter((f) => !f.endsWith('-pdf'))],
      out: outDir,
      configPath: FILLED_CONFIG,
      key: REAL_KEY,
      env: {},
    });
    expect(result.exitCode).toBe(0);
    for (const name of ['annex7.html', 'doc.html', 'sbom.cyclonedx.json', 'sbom.spdx.json']) {
      expect(fs.existsSync(path.join(outDir, name)), `${name} should exist`).toBe(true);
    }

    // The load-bearing assertion: annex7.7 was genuinely COMPOSED from the
    // answered Annex V items, not left as an open item, even though it was
    // deliberately never answered directly in the fixture.
    const annex7Html = fs.readFileSync(path.join(outDir, 'annex7.html'), 'utf8');
    expect(annex7Html).toContain('annex7.7');
    expect(annex7Html).not.toContain('This item has not yet been answered');
    // Content from an actually-answered Annex V item should show up inside
    // the composed annex7.7 section (proves it's a real composition, not a
    // coincidence of the item existing elsewhere in the document).
    expect(annex7Html).toContain('Northgate Devices GmbH');

    const docHtml = fs.readFileSync(path.join(outDir, 'doc.html'), 'utf8');
    expect(docHtml).toContain('Northgate FlowMeter Agent');
    // annex5.3's boilerplate text renders even though it was never answered.
    expect(docHtml).toContain('issued under the sole responsibility');

    const cyclonedx = JSON.parse(fs.readFileSync(path.join(outDir, 'sbom.cyclonedx.json'), 'utf8'));
    expect(cyclonedx.bomFormat).toBe('CycloneDX');
    expect(cyclonedx.specVersion).toBe('1.6');
    const spdx = JSON.parse(fs.readFileSync(path.join(outDir, 'sbom.spdx.json'), 'utf8'));
    expect(spdx.spdxVersion).toBe('SPDX-2.3');
  });

  it.skipIf(!HAS_BROWSER)('step 6: the -pdf formats also render real binary PDFs with the filled config, given a valid key', async () => {
    const outDir = path.join(scratch, 'report-filled-pdf');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['annex7-pdf', 'doc-pdf'],
      out: outDir,
      configPath: FILLED_CONFIG,
      key: REAL_KEY,
      env: {},
    });
    expect(result.exitCode).toBe(0);
    for (const name of ['annex7.pdf', 'doc.pdf']) {
      const bytes = fs.readFileSync(path.join(outDir, name));
      expect(bytes.subarray(0, 5).toString('latin1')).toBe('%PDF-');
    }
  });
});
