import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runReport } from '../../src/cli/report';
import { findChromeExecutable } from '../../src/report/pdf';

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');
const NPM_FIXTURE = path.join(FIXTURES, 'package-lock-v3-basic');

// A real, genuine, verifying individual-tier key (updatesUntil in the
// future, so it drives no data-currency note). annex7/annex7-pdf/doc/doc-pdf
// are gated as of M3 (tests/cli/reportGating.test.ts owns gating behavior
// itself); this file is about output-path/format-validation/content
// plumbing, so a real key is supplied wherever a gated format needs to
// actually render, not re-tested here.
const REAL_KEY =
  'eyJwcm9kdWN0IjoiY2Vwcm9vZiIsInRpZXIiOiJpbmRpdmlkdWFsIiwibGljZW5zZUlkIjoiNzZaNTJOVzRHVSIsImlzc3VlZEF0IjoiMjAyNi0wNy0yNFQwNToyOTozOC4xMzRaIiwidXBkYXRlc1VudGlsIjoiMjAyNy0wNy0yNFQwNToyOTozOC4xMzRaIn0.1_Ji7XgwqBTNxY5zdG_0aBWrv5Z8QmXyn0z5ui3EFTw-4FA2f5kViCHuie7MLLLIqSrv1btxHZwkDI8-1nWhDw';

describe('runReport — output-path resolution + plumbing', () => {
  let scratch: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-report-'));
  });

  afterEach(() => {
    process.chdir(originalCwd); // some tests chdir into scratch to exercise the default-dir path
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  it('single format + explicit --out <file>: honors the literal path', async () => {
    const target = path.join(scratch, 'custom-name.html');
    const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: ['annex7'], out: target, key: REAL_KEY, env: {} });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(target)).toBe(true);
    expect(fs.readFileSync(target, 'utf8')).toContain('<!DOCTYPE html>');
    // No default-named file should exist alongside it.
    expect(fs.existsSync(path.join(scratch, 'annex7.html'))).toBe(false);
  });

  it('single format + no --out: writes to ./ceproof-report/ (relative to cwd)', async () => {
    process.chdir(scratch);
    const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: ['annex7'], key: REAL_KEY, env: {} });
    expect(result.exitCode).toBe(0);
    const expected = path.join(scratch, 'ceproof-report', 'annex7.html');
    expect(fs.existsSync(expected)).toBe(true);
  });

  it('multiple formats + --out <dir>: all artifacts land in that dir with default names', async () => {
    const outDir = path.join(scratch, 'artifacts');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['annex7', 'doc', 'sbom-cyclonedx', 'sbom-spdx'],
      out: outDir,
      key: REAL_KEY,
      env: {},
    });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(path.join(outDir, 'annex7.html'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'doc.html'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'sbom.cyclonedx.json'))).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'sbom.spdx.json'))).toBe(true);
  });

  it('multiple formats + no --out: default dir holds all default-named artifacts', async () => {
    process.chdir(scratch);
    const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: ['annex7', 'doc'], key: REAL_KEY, env: {} });
    expect(result.exitCode).toBe(0);
    const dir = path.join(scratch, 'ceproof-report');
    expect(fs.existsSync(path.join(dir, 'annex7.html'))).toBe(true);
    expect(fs.existsSync(path.join(dir, 'doc.html'))).toBe(true);
  });

  it.skipIf(!findChromeExecutable())(
    'annex7-pdf and doc-pdf write valid binary PDF bytes (Buffer write path), not text, when a browser is available',
    async () => {
      for (const [fmt, name] of [
        ['annex7-pdf', 'annex7.pdf'],
        ['doc-pdf', 'doc.pdf'],
      ] as const) {
        const target = path.join(scratch, name);
        const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: [fmt], out: target, key: REAL_KEY, env: {} });
        expect(result.exitCode).toBe(0);
        const bytes = fs.readFileSync(target);
        expect(bytes.subarray(0, 5).toString('latin1')).toBe('%PDF-');
        expect(bytes.subarray(-6).toString('latin1')).toContain('%%EOF');
      }
    },
    60_000 // real browser launch + print; well above the 20s global default
  );

  it.skipIf(Boolean(findChromeExecutable()))(
    'without a browser installed, a *-pdf format exits 2 with the honest no-browser message and writes nothing',
    async () => {
      const target = path.join(scratch, 'out.pdf');
      const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: ['annex7-pdf'], out: target, key: REAL_KEY, env: {} });
      expect(result.exitCode).toBe(2);
      expect(result.output.toLowerCase()).toContain('browser');
      expect(fs.existsSync(target)).toBe(false);
    }
  );
});

describe('runReport — format validation', () => {
  let scratch: string;
  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-report-'));
  });
  afterEach(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  it('rejects an unknown format with a clear error naming the bad value + valid set, exit 2, nothing written', async () => {
    const outDir = path.join(scratch, 'should-not-exist');
    const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: ['annex7', 'bogus'], out: outDir });
    expect(result.exitCode).toBe(2);
    expect(result.output).toContain('bogus');
    expect(result.output).toContain('sbom-cyclonedx'); // names the valid set
    // Validation happens before any scan/write, so no output dir/files were created.
    expect(fs.existsSync(outDir)).toBe(false);
  });

  it('rejects an empty format request (exit 2)', async () => {
    const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: [] });
    expect(result.exitCode).toBe(2);
    expect(result.output).toContain('at least one --format');
  });

  it('de-duplicates repeated formats (writes each artifact once)', async () => {
    const outDir = path.join(scratch, 'dedupe');
    const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: ['annex7', 'annex7'], out: outDir, key: REAL_KEY, env: {} });
    expect(result.exitCode).toBe(0);
    // Message reports one artifact, not two.
    expect(result.output).toContain('wrote 1 report artifact');
  });
});

describe('runReport — no project detected', () => {
  it('exits 2 with a report-specific message naming both npm and Python markers, nothing written', async () => {
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-empty-'));
    try {
      // sbom-cyclonedx (free, ungated) deliberately, so this test exercises
      // the no-project path itself rather than being entangled with M3's
      // gating check (which runs before the project scan and would otherwise
      // refuse this request for lack of a key before ever reaching the
      // no-project error).
      const result = await runReport({
        path: emptyDir,
        productionOnly: true,
        formats: ['sbom-cyclonedx'],
        out: path.join(emptyDir, 'out.json'),
      });
      expect(result.exitCode).toBe(2);
      expect(result.output).toContain('report'); // extended to mention the report command
      expect(result.output).toContain('package.json');
      expect(result.output.toLowerCase()).toContain('pyproject.toml');
      expect(fs.existsSync(path.join(emptyDir, 'out.json'))).toBe(false);
    } finally {
      fs.rmSync(emptyDir, { recursive: true, force: true });
    }
  });
});

describe('runReport — annex7/doc content sanity', () => {
  it('annex7 output contains the disclaimer and a real Annex VII section id', async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-report-'));
    try {
      const target = path.join(scratch, 'annex7.html');
      const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: ['annex7'], out: target, key: REAL_KEY, env: {} });
      expect(result.exitCode).toBe(0);
      const html = fs.readFileSync(target, 'utf8');
      expect(html).toContain('Informational — not legal advice.');
      expect(html).toContain('annex7.1.b');
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('doc output contains a real Annex V section id', async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-report-'));
    try {
      const target = path.join(scratch, 'doc.html');
      const result = await runReport({ path: NPM_FIXTURE, productionOnly: true, formats: ['doc'], out: target, key: REAL_KEY, env: {} });
      expect(result.exitCode).toBe(0);
      const html = fs.readFileSync(target, 'utf8');
      expect(html).toContain('annex5.1');
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});
