import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { readConfigFile, writeConfigFile } from '../../src/config/write';
import type { CeproofConfig } from '../../src/config/types';

describe('writeConfigFile / readConfigFile', () => {
  let scratch: string;

  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-config-write-'));
  });

  afterEach(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  it('round-trips a config: write then read back the same shape', () => {
    const configPath = path.join(scratch, 'ceproof.config.json');
    const config: CeproofConfig = {
      manufacturer: { name: 'Acme Corp', address: '1 Main St' },
      product: { name: 'Widget Agent', classification: 'important' },
      supportPeriod: { years: 5 },
      answers: { 'annex7.2': 'Jane Doe, CTO' },
    };

    writeConfigFile(configPath, config);
    const result = readConfigFile(configPath);

    expect(result.present).toBe(true);
    if (result.present && 'raw' in result) {
      expect(result.raw).toEqual(config);
    } else {
      throw new Error('expected raw config, got parseError or missing');
    }
  });

  it('writes 2-space-indented JSON with a trailing newline', () => {
    const configPath = path.join(scratch, 'ceproof.config.json');
    const config: CeproofConfig = {
      manufacturer: { name: 'Acme Corp' },
      product: { name: 'Widget Agent' },
      supportPeriod: {},
      answers: {},
    };

    writeConfigFile(configPath, config);
    const text = fs.readFileSync(configPath, 'utf8');

    expect(text.endsWith('\n')).toBe(true);
    expect(text).toContain('  "manufacturer"');
    // JSON.stringify(config, null, 2) + '\n' — exact byte match.
    expect(text).toBe(`${JSON.stringify(config, null, 2)}\n`);
  });

  it('readConfigFile on a nonexistent path returns present:false, not a throw', () => {
    const configPath = path.join(scratch, 'does-not-exist.json');
    expect(() => readConfigFile(configPath)).not.toThrow();
    const result = readConfigFile(configPath);
    expect(result).toEqual({ present: false });
  });

  it('readConfigFile on invalid JSON returns a parseError, not a throw', () => {
    const configPath = path.join(scratch, 'broken.json');
    fs.writeFileSync(configPath, '{ this is not valid json', 'utf8');

    expect(() => readConfigFile(configPath)).not.toThrow();
    const result = readConfigFile(configPath);
    expect(result.present).toBe(true);
    if (result.present && 'parseError' in result) {
      expect(typeof result.parseError).toBe('string');
      expect(result.parseError.length).toBeGreaterThan(0);
    } else {
      throw new Error('expected a parseError result');
    }
  });

  it('lets an unexpected fs error (e.g. EACCES-style) propagate rather than being swallowed', () => {
    // Simulate a non-ENOENT fs failure by pointing at a path whose parent
    // directory doesn't exist as a directory (ENOTDIR), which readConfigFile
    // must NOT special-case the way it special-cases ENOENT.
    const configPath = path.join(scratch, 'ceproof.config.json');
    fs.writeFileSync(configPath, '{}', 'utf8'); // now a file, not a directory
    const badPath = path.join(configPath, 'nested.json'); // treats a file as a dir

    expect(() => readConfigFile(badPath)).toThrow();
  });
});
