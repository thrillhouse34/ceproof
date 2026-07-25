import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from '../../src/cli/scan';

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');

// scan's JSON/terminal output is gap-checklist-shaped now (facts + gapChecklist
// + summary + configStatus), not a per-package license report — that surface
// moved entirely into internal SBOM-readiness evidence for the gap engine.
// These tests exercise runScan's own orchestration (facts collection, CRA
// structure loading, config resolution, exit codes) rather than re-proving the
// dependency/ecosystem-merge engine's internals, which are covered elsewhere
// (tests/ecosystems/**, tests/resolve/**).

describe('runScan', () => {
  it('exits 0 or 1 (never a tool error) and returns a summary string for a normal project', async () => {
    const result = await runScan({ path: path.join(FIXTURES, 'package-lock-v3-basic'), productionOnly: true, format: 'summary', projectLicenseOverride: undefined });
    expect([0, 1]).toContain(result.exitCode);
    expect(result.output).toContain('ceproof scan:');
  });

  it('returns valid JSON with schemaVersion 1 and the expected top-level shape', async () => {
    const result = await runScan({ path: path.join(FIXTURES, 'package-lock-v3-basic'), productionOnly: true, format: 'json', projectLicenseOverride: undefined });
    const parsed = JSON.parse(result.output);
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.projectName).toBe('fixture-package-lock-v3');
    expect(Array.isArray(parsed.gapChecklist)).toBe(true);
    expect(parsed.facts).toBeDefined();
    expect(parsed.summary).toBeDefined();
    expect(parsed.configStatus).toBeDefined();
  });

  it('facts.ecosystems.detected includes npm for an npm project', async () => {
    const result = await runScan({ path: path.join(FIXTURES, 'package-lock-v3-basic'), productionOnly: true, format: 'json', projectLicenseOverride: undefined });
    const parsed = JSON.parse(result.output);
    expect(parsed.facts.ecosystems.detected).toContain('npm');
  });

  it('exits 2 with a one-line message (no stack trace) when the path has no package.json', async () => {
    const result = await runScan({ path: require('os').tmpdir(), productionOnly: true, format: 'summary', projectLicenseOverride: undefined });
    expect(result.exitCode).toBe(2);
    expect(result.output).not.toContain('at Object.'); // no stack trace leaked
    expect(result.output.split('\n').length).toBeLessThanOrEqual(2);
  });

  it('the no-project message names both npm and Python markers', async () => {
    const result = await runScan({ path: require('os').tmpdir(), productionOnly: true, format: 'summary', projectLicenseOverride: undefined });
    expect(result.output).toContain('package.json');
    expect(result.output.toLowerCase()).toContain('pyproject.toml');
  });
});

describe('runScan — gap checklist wiring', () => {
  const FIXTURE = path.join(FIXTURES, 'package-lock-v3-basic');

  it('gapChecklist has one entry per item in the loaded CRA structure', async () => {
    const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'json', projectLicenseOverride: undefined });
    const parsed = JSON.parse(result.output);
    // Every item is one of the three known statuses — a structural check that
    // doesn't hardcode today's placeholder cra-structure.json's exact count or
    // content, since real content will replace it later.
    expect(parsed.gapChecklist.length).toBeGreaterThan(0);
    for (const item of parsed.gapChecklist) {
      expect(['DERIVED', 'PARTIAL', 'NEEDS-HUMAN-INPUT']).toContain(item.status);
      expect(['annexVII', 'annexV']).toContain(item.instrument);
      expect(typeof item.id).toBe('string');
      expect(Array.isArray(item.evidence)).toBe(true);
    }
    expect(parsed.summary.totalItems).toBe(parsed.gapChecklist.length);
  });

  it('with no ceproof.config.json present, every human-required item (if any) is NEEDS-HUMAN-INPUT and configStatus.present is false', async () => {
    const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'json', projectLicenseOverride: undefined });
    const parsed = JSON.parse(result.output);
    expect(parsed.configStatus.present).toBe(false);
    expect(parsed.configStatus.valid).toBeNull();
    const needsHuman = parsed.gapChecklist.filter((i: { status: string }) => i.status === 'NEEDS-HUMAN-INPUT');
    expect(parsed.configStatus.missingAnswers.sort()).toEqual(needsHuman.map((i: { id: string }) => i.id).sort());
  });

  it('supplying a config with real answers moves the matching human-required item(s) to DERIVED', async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-scan-cfg-'));
    try {
      const before = JSON.parse(
        (await runScan({ path: FIXTURE, productionOnly: true, format: 'json', projectLicenseOverride: undefined })).output,
      );
      const humanRequiredIds = before.gapChecklist
        .filter((i: { status: string }) => i.status === 'NEEDS-HUMAN-INPUT')
        .map((i: { id: string }) => i.id);
      if (humanRequiredIds.length === 0) return; // nothing to prove against the current placeholder data

      const configPath = path.join(scratch, 'ceproof.config.json');
      const answers: Record<string, string> = {};
      for (const id of humanRequiredIds) answers[id] = 'a real human-supplied answer';
      fs.writeFileSync(
        configPath,
        JSON.stringify({ manufacturer: { name: 'Acme Corp' }, product: { name: 'Widget' }, supportPeriod: {}, answers }, null, 2),
      );

      const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'json', projectLicenseOverride: undefined, configPath });
      const parsed = JSON.parse(result.output);
      expect(parsed.configStatus.present).toBe(true);
      expect(parsed.configStatus.valid).toBe(true);
      for (const id of humanRequiredIds) {
        const item = parsed.gapChecklist.find((i: { id: string }) => i.id === id);
        expect(item.status).toBe('DERIVED');
        expect(item.evidence.join(' ')).toContain('ceproof.config');
      }
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('an invalid config (malformed JSON) is reported as present but invalid, and does not crash the scan', async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-scan-cfg-'));
    try {
      const configPath = path.join(scratch, 'ceproof.config.json');
      fs.writeFileSync(configPath, '{ not valid json');
      const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'json', projectLicenseOverride: undefined, configPath });
      const parsed = JSON.parse(result.output);
      expect(parsed.configStatus.present).toBe(true);
      expect(parsed.configStatus.valid).toBe(false);
      expect(parsed.configStatus.errors[0]).toContain('Invalid JSON');
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});

describe('runScan — --fail-on semantics', () => {
  const FIXTURE = path.join(FIXTURES, 'package-lock-v3-basic');

  it('--fail-on never always exits 0', async () => {
    const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'summary', projectLicenseOverride: undefined, failOn: 'never' });
    expect(result.exitCode).toBe(0);
  });

  it('default --fail-on (human-required) exits 1 when any item still needs human input', async () => {
    // The current placeholder CRA data has human-required items, and no config
    // is supplied here, so at least one item is guaranteed NEEDS-HUMAN-INPUT.
    const jsonResult = await runScan({ path: FIXTURE, productionOnly: true, format: 'json', projectLicenseOverride: undefined });
    const parsed = JSON.parse(jsonResult.output);
    const hasNeedsHuman = parsed.gapChecklist.some((i: { status: string }) => i.status === 'NEEDS-HUMAN-INPUT');
    expect(hasNeedsHuman).toBe(true); // sanity: the scenario this test needs is real

    const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'summary', projectLicenseOverride: undefined, failOn: 'human-required' });
    expect(result.exitCode).toBe(1);
  });

  it('--fail-on partial also fails when only NEEDS-HUMAN-INPUT items exist (partial is a superset check)', async () => {
    const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'summary', projectLicenseOverride: undefined, failOn: 'partial' });
    expect(result.exitCode).toBe(1);
  });
});

describe('runScan — multi-ecosystem (npm + pypi) merge', () => {
  const MIXED = path.join(FIXTURES, 'mixed-npm-pypi');

  it('detects and reports BOTH ecosystems in facts.ecosystems.detected', async () => {
    const result = await runScan({ path: MIXED, productionOnly: false, format: 'json', projectLicenseOverride: undefined });
    expect(result.exitCode === 0 || result.exitCode === 1).toBe(true);
    const report = JSON.parse(result.output);
    expect(report.facts.ecosystems.detected.sort()).toEqual(['npm', 'pypi']);
  });

  it('applies the mixed-repo project-license tie-break (npm-declared wins) and warns non-silently', async () => {
    const result = await runScan({ path: MIXED, productionOnly: false, format: 'json', projectLicenseOverride: undefined });
    const report = JSON.parse(result.output);
    // package.json declares MIT, pyproject.toml declares Apache-2.0 → npm wins,
    // and the merge layer emits a non-silent warning either way.
    expect(report.warnings.some((w: string) => w.includes('package.json (MIT)') && w.includes('pyproject.toml (Apache-2.0)'))).toBe(true);
  });
});

describe('runScan — NO_COLOR environment variable', () => {
  const ORIGINAL_NO_COLOR = process.env.NO_COLOR;
  const ORIGINAL_ISTTY = process.stdout.isTTY;

  afterEach(() => {
    if (ORIGINAL_NO_COLOR === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = ORIGINAL_NO_COLOR;
    (process.stdout as any).isTTY = ORIGINAL_ISTTY;
  });

  it('disables color when NO_COLOR is set, even if stdout is a TTY and colorEnabled is not explicitly passed', async () => {
    (process.stdout as any).isTTY = true;
    process.env.NO_COLOR = '1';
    const result = await runScan({
      path: path.join(FIXTURES, 'package-lock-v3-basic'), productionOnly: true, format: 'summary',
      projectLicenseOverride: undefined,
    });
    // eslint-disable-next-line no-control-regex
    expect(result.output).not.toMatch(/\x1b\[/);
  });

  it('NO_COLOR set to empty string still disables color (presence, not value, per the NO_COLOR spec)', async () => {
    (process.stdout as any).isTTY = true;
    process.env.NO_COLOR = '';
    const result = await runScan({
      path: path.join(FIXTURES, 'package-lock-v3-basic'), productionOnly: true, format: 'summary',
      projectLicenseOverride: undefined,
    });
    // eslint-disable-next-line no-control-regex
    expect(result.output).not.toMatch(/\x1b\[/);
  });

  it('an explicit colorEnabled: true override still wins even with NO_COLOR set (opts.colorEnabled takes precedence)', async () => {
    process.env.NO_COLOR = '1';
    const result = await runScan({
      path: path.join(FIXTURES, 'package-lock-v3-basic'), productionOnly: true, format: 'summary',
      projectLicenseOverride: undefined, colorEnabled: true,
    });
    // eslint-disable-next-line no-control-regex
    expect(result.output).toMatch(/\x1b\[/);
  });
});
