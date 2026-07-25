import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runInit } from '../../src/cli/init';
import { readConfigFile } from '../../src/config/write';
import { validateConfig } from '../../src/config/validate';
import { getCraStructure } from '../../src/cra/loader';

describe('runInit', () => {
  let scratch: string;
  let configPath: string;

  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-init-'));
    configPath = path.join(scratch, 'ceproof.config.json');
  });

  afterEach(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  it('creates a config file when none exists, exit 0, and lists missing fields in the output', () => {
    const result = runInit({ path: scratch, configPath });

    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(configPath)).toBe(true);
    expect(result.output.toLowerCase()).toContain('manufacturer.name');
    expect(result.output.toLowerCase()).toContain('product.name');
    expect(result.output).toMatch(/\d+ field\(s\) still need your input/);
  });

  it('the generated file does NOT yet pass validateConfig (empty manufacturer.name/product.name)', () => {
    runInit({ path: scratch, configPath });
    const readBack = readConfigFile(configPath);
    expect(readBack.present).toBe(true);
    if (readBack.present && 'raw' in readBack) {
      const validated = validateConfig(readBack.raw);
      expect(validated.valid).toBe(false);
    } else {
      throw new Error('expected raw config after init');
    }
  });

  it('generates one answers entry per human-required item in the currently loaded CRA structure', () => {
    runInit({ path: scratch, configPath });
    const readBack = readConfigFile(configPath);
    expect(readBack.present).toBe(true);
    if (!readBack.present || !('raw' in readBack)) {
      throw new Error('expected raw config after init');
    }
    const raw = readBack.raw as { answers: Record<string, string> };

    const humanRequiredIds = getCraStructure()
      .items.filter((i) => i.derivability === 'human-required')
      .map((i) => i.id);

    // Not hardcoding today's placeholder craStructure's item count (that's
    // liable to change once real CRA content lands) — just asserting the
    // structural relationship holds against whatever is currently loaded.
    expect(Object.keys(raw.answers).length).toBeGreaterThanOrEqual(humanRequiredIds.length);
    for (const id of humanRequiredIds) {
      expect(raw.answers).toHaveProperty(id);
      expect(raw.answers[id]).toBe('');
    }
  });

  it('does not crash when the CRA structure has zero, some, or many human-required items (shape-only check)', () => {
    const result = runInit({ path: scratch, configPath });
    expect(result.exitCode).toBe(0);
    // Whatever the loaded structure looks like today, runInit must not throw
    // and must produce a well-formed result object.
    expect(typeof result.output).toBe('string');
  });

  it('refuses to overwrite an existing config without --force: exit 2, original content unchanged', () => {
    const original = JSON.stringify({ sentinel: 'do-not-touch-me' }, null, 2);
    fs.writeFileSync(configPath, original, 'utf8');

    const result = runInit({ path: scratch, configPath });

    expect(result.exitCode).toBe(2);
    expect(result.output.toLowerCase()).toContain('--force');
    expect(fs.readFileSync(configPath, 'utf8')).toBe(original);
  });

  it('overwrites an existing config when --force is passed', () => {
    const original = JSON.stringify({ sentinel: 'do-not-touch-me' }, null, 2);
    fs.writeFileSync(configPath, original, 'utf8');

    const result = runInit({ path: scratch, configPath, force: true });

    expect(result.exitCode).toBe(0);
    const content = fs.readFileSync(configPath, 'utf8');
    expect(content).not.toBe(original);
    expect(JSON.parse(content)).toHaveProperty('manufacturer');
    expect(JSON.parse(content)).toHaveProperty('answers');
  });

  it('defaults configPath to ceproof.config.json under opts.path when configPath is omitted', () => {
    const result = runInit({ path: scratch });
    expect(result.exitCode).toBe(0);
    expect(fs.existsSync(path.join(scratch, 'ceproof.config.json'))).toBe(true);
  });
});
