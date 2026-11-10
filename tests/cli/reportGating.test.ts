import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runReport, EXIT_UNLICENSED } from '../../src/cli/report';

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');
const NPM_FIXTURE = path.join(FIXTURES, 'package-lock-v3-basic');

// A real, genuine, verifying key (individual tier, updatesUntil 2027-07-24 — in
// the future relative to the installed 2026.07.x data, so it drives NO currency
// note). Lets the "unlocked" tests run on any machine without the private key.
const REAL_KEY =
  'eyJwcm9kdWN0IjoiY2Vwcm9vZiIsInRpZXIiOiJpbmRpdmlkdWFsIiwibGljZW5zZUlkIjoiNzZaNTJOVzRHVSIsImlzc3VlZEF0IjoiMjAyNi0wNy0yNFQwNToyOTozOC4xMzRaIiwidXBkYXRlc1VudGlsIjoiMjAyNy0wNy0yNFQwNToyOTozOC4xMzRaIn0.1_Ji7XgwqBTNxY5zdG_0aBWrv5Z8QmXyn0z5ui3EFTw-4FA2f5kViCHuie7MLLLIqSrv1btxHZwkDI8-1nWhDw';

describe('runReport — gating (whole-request)', () => {
  let scratch: string;
  let noKeyFile: string;
  const HERMETIC = { env: {} as NodeJS.ProcessEnv };

  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-gate-'));
    noKeyFile = path.join(scratch, 'no-such-license.key'); // guaranteed absent
  });
  afterEach(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  it('EXIT_UNLICENSED is 3', () => {
    expect(EXIT_UNLICENSED).toBe(3);
  });

  it('refuses a gated format (annex7) with NO key: exit 3, price + URL in message, nothing written', async () => {
    const outDir = path.join(scratch, 'out');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['annex7'],
      out: outDir,
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(3);
    expect(result.output).toContain('$99');
    expect(result.output).toContain('$299');
    expect(result.output).toContain('https://ceproof.dev');
    expect(fs.existsSync(outDir)).toBe(false); // nothing written
  });

  it('each gated format alone (annex7-pdf, doc, doc-pdf) also refuses with exit 3', async () => {
    for (const fmt of ['annex7-pdf', 'doc', 'doc-pdf']) {
      const result = await runReport({
        path: NPM_FIXTURE,
        productionOnly: true,
        formats: [fmt],
        out: path.join(scratch, fmt),
        keyFilePath: noKeyFile,
        ...HERMETIC,
      });
      expect(result.exitCode, `format "${fmt}" should refuse with no key`).toBe(3);
    }
  });

  it('a request with ONLY sbom-cyclonedx needs no key: exit 0, real file written', async () => {
    const target = path.join(scratch, 'sbom.cyclonedx.json');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['sbom-cyclonedx'],
      out: target,
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(target)).toBe(true);
    expect(JSON.parse(fs.readFileSync(target, 'utf8')).bomFormat).toBe('CycloneDX');
  });

  it('a request with ONLY sbom-spdx needs no key: exit 0, real file written', async () => {
    const target = path.join(scratch, 'sbom.spdx.json');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['sbom-spdx'],
      out: target,
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(target)).toBe(true);
    expect(JSON.parse(fs.readFileSync(target, 'utf8')).spdxVersion).toBe('SPDX-2.3');
  });

  it('repeated sbom-cyclonedx (still only free formats) needs no key: exit 0', async () => {
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['sbom-cyclonedx', 'sbom-cyclonedx'],
      out: path.join(scratch, 'repeat'),
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(0);
  });

  it('a MIXED request (annex7 + sbom-cyclonedx) with no key refuses the WHOLE request: exit 3, nothing written (not even the free SBOM)', async () => {
    const outDir = path.join(scratch, 'mixed');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['sbom-cyclonedx', 'annex7'],
      out: outDir,
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(3);
    expect(fs.existsSync(outDir)).toBe(false); // the free cyclonedx was NOT partially written
  });

  it('unlocks a gated format with a valid --key: exit 0, artifact written', async () => {
    const target = path.join(scratch, 'annex7.html');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['annex7'],
      out: target,
      key: REAL_KEY,
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(target)).toBe(true);
  });

  it('unlocks via the CEPROOF_KEY env var when no --key is passed', async () => {
    const target = path.join(scratch, 'via-env.html');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['doc'],
      out: target,
      env: { CEPROOF_KEY: REAL_KEY },
      keyFilePath: noKeyFile,
    });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(target)).toBe(true);
  });

  it('unlocks via the activated key file when neither --key nor env is present', async () => {
    const activated = path.join(scratch, 'license.key');
    fs.writeFileSync(activated, REAL_KEY);
    const target = path.join(scratch, 'via-file.html');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['annex7'],
      out: target,
      keyFilePath: activated,
      env: {},
    });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(target)).toBe(true);
  });

  it('an invalid --key (garbage) is treated as no key: exit 3', async () => {
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['annex7'],
      out: path.join(scratch, 'bad'),
      key: 'not-a-real-key.garbage',
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(3);
  });

  it('a valid future-dated key produces NO data-currency note (data within window)', async () => {
    const target = path.join(scratch, 'nonote.html');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['annex7'],
      out: target,
      key: REAL_KEY, // updatesUntil 2027-07-24, after the installed data
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(0);
    expect(result.output.toLowerCase()).not.toContain('newer reference data');
  });
});

// The data-currency note needs a real-signed key with a PAST updatesUntil,
// which only the signing side under scripts/keygen/ can produce, so that
// describe lives in tests/private/reportCurrencyNote.test.ts — excluded from
// the public mirror along with that tooling.
