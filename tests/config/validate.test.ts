import { describe, it, expect } from 'vitest';
import { validateConfig } from '../../src/config/validate';

describe('validateConfig', () => {
  it('accepts a fully populated valid config', () => {
    const result = validateConfig({
      manufacturer: { name: 'Acme Corp', address: '1 Main St', contact: 'security@acme.example' },
      product: { name: 'Widget Agent', classification: 'important' },
      supportPeriod: { years: 5, endDate: '2031-01-01' },
      answers: { 'annex7.2': 'Signed by Jane Doe, CTO.' },
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.config.manufacturer.name).toBe('Acme Corp');
      expect(result.config.answers['annex7.2']).toBe('Signed by Jane Doe, CTO.');
    }
  });

  it('accepts a minimal-but-valid config with only required fields (optional fields genuinely optional)', () => {
    const result = validateConfig({
      manufacturer: { name: 'Acme Corp' },
      product: { name: 'Widget Agent' },
      answers: {},
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.config.manufacturer.address).toBeUndefined();
      expect(result.config.manufacturer.contact).toBeUndefined();
      expect(result.config.product.classification).toBeUndefined();
      expect(result.config.supportPeriod).toEqual({});
    }
  });

  it('fails with a specific message when manufacturer.name is missing', () => {
    const result = validateConfig({
      manufacturer: {},
      product: { name: 'Widget Agent' },
      answers: {},
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('manufacturer.name is required and is missing');
    }
  });

  it('fails with a specific message when manufacturer.name is an empty string', () => {
    const result = validateConfig({
      manufacturer: { name: '   ' },
      product: { name: 'Widget Agent' },
      answers: {},
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('manufacturer.name is required and is missing');
    }
  });

  it('fails with a specific message when product.name is missing', () => {
    const result = validateConfig({
      manufacturer: { name: 'Acme Corp' },
      product: {},
      answers: {},
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('product.name is required and is missing');
    }
  });

  it('fails when answers contains a non-string value, naming the offending key', () => {
    const result = validateConfig({
      manufacturer: { name: 'Acme Corp' },
      product: { name: 'Widget Agent' },
      answers: { 'annex7.2': 42 },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('answers.annex7.2 must be a string');
    }
  });

  it('fails when answers is missing entirely', () => {
    const result = validateConfig({
      manufacturer: { name: 'Acme Corp' },
      product: { name: 'Widget Agent' },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some((e) => e.startsWith('answers'))).toBe(true);
    }
  });

  it('collects ALL validation errors in one pass rather than stopping at the first', () => {
    const result = validateConfig({
      manufacturer: {},
      product: {},
      answers: { a: 1, b: 2 },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('manufacturer.name is required and is missing');
      expect(result.errors).toContain('product.name is required and is missing');
      expect(result.errors).toContain('answers.a must be a string');
      expect(result.errors).toContain('answers.b must be a string');
      expect(result.errors.length).toBeGreaterThanOrEqual(4);
    }
  });

  it('rejects non-object top-level input without throwing', () => {
    expect(() => validateConfig(null)).not.toThrow();
    expect(() => validateConfig('not an object')).not.toThrow();
    expect(() => validateConfig(42)).not.toThrow();
    expect(() => validateConfig(undefined)).not.toThrow();

    const result = validateConfig(null);
    expect(result.valid).toBe(false);
  });

  it('rejects wrong-typed optional fields with specific messages', () => {
    const result = validateConfig({
      manufacturer: { name: 'Acme Corp', address: 123 },
      product: { name: 'Widget Agent', classification: true },
      supportPeriod: { years: 'five', endDate: 2031 },
      answers: {},
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('manufacturer.address must be a string if present');
      expect(result.errors).toContain('product.classification must be a string if present');
      expect(result.errors).toContain('supportPeriod.years must be a number if present');
      expect(result.errors).toContain('supportPeriod.endDate must be a string if present');
    }
  });

  it('never throws even on wildly malformed input', () => {
    expect(() => validateConfig({ manufacturer: 'nope', product: [1, 2, 3], answers: 'nope' })).not.toThrow();
  });
});

describe('validateConfig — the optional fda block', () => {
  const base = { manufacturer: { name: 'Acme Medical' }, product: { name: 'Infusion Pump' }, answers: {} };

  it('leaves fda absent for a CRA-only config, rather than inventing an empty block', () => {
    const result = validateConfig(base);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.config.fda).toBeUndefined();
  });

  it('accepts component support declarations and lower-cases their keys for case-insensitive matching', () => {
    const result = validateConfig({
      ...base,
      fda: {
        componentSupport: {
          'OpenSSL@1.1.1w': { supportLevel: 'no-longer-maintained', endOfSupportDate: '2023-09-11' },
          'pkg:npm/express': { supportLevel: 'actively-maintained' },
          libfoo: { supportLevel: 'abandoned', note: 'Upstream archived in 2021.' },
          libbar: { supportLevel: 'unknown', note: 'Supplier asked 2026-09-01, no answer.' },
        },
      },
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      const declarations = result.config.fda?.componentSupport ?? {};
      expect(Object.keys(declarations).sort()).toEqual(['libbar', 'libfoo', 'openssl@1.1.1w', 'pkg:npm/express']);
      expect(declarations['openssl@1.1.1w'].endOfSupportDate).toBe('2023-09-11');
      expect(declarations.libfoo.note).toBe('Upstream archived in 2021.');
    }
  });

  it('rejects a misspelled support level rather than dropping it, naming the allowed values', () => {
    const result = validateConfig({ ...base, fda: { componentSupport: { libfoo: { supportLevel: 'activelyMaintained' } } } });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain(
        'fda.componentSupport["libfoo"].supportLevel is required and must be one of: actively-maintained, no-longer-maintained, abandoned, unknown',
      );
    }
  });

  it('requires a supportLevel on every declaration', () => {
    const result = validateConfig({ ...base, fda: { componentSupport: { libfoo: { endOfSupportDate: '2021-06-30' } } } });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.errors.some((e) => e.includes('supportLevel is required'))).toBe(true);
  });

  it('rejects a non-ISO end-of-support date instead of reformatting it by guesswork', () => {
    const result = validateConfig({ ...base, fda: { componentSupport: { libfoo: { supportLevel: 'abandoned', endOfSupportDate: '06/2021' } } } });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('fda.componentSupport["libfoo"].endOfSupportDate must be an ISO date (YYYY-MM-DD) if present');
    }
  });

  it('rejects two keys that differ only in case, which would silently discard one', () => {
    const result = validateConfig({
      ...base,
      fda: { componentSupport: { 'OpenSSL@1.1.1w': { supportLevel: 'abandoned' }, 'openssl@1.1.1w': { supportLevel: 'actively-maintained' } } },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.errors.some((e) => e.includes('collides with an earlier key'))).toBe(true);
  });

  it('rejects an empty declaration key and the wrong shapes, without throwing', () => {
    const result = validateConfig({ ...base, fda: { componentSupport: { '': { supportLevel: 'abandoned' }, libfoo: 'abandoned' } } });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('fda.componentSupport has an empty key — a declaration must name the component it applies to');
      expect(result.errors).toContain('fda.componentSupport["libfoo"] must be an object with a supportLevel');
    }
    expect(() => validateConfig({ ...base, fda: 'yes' })).not.toThrow();
    expect(validateConfig({ ...base, fda: 'yes' }).valid).toBe(false);
    expect(validateConfig({ ...base, fda: { componentSupport: [] } }).valid).toBe(false);
  });

  it('still reports CRA-level errors alongside fda errors in one pass', () => {
    const result = validateConfig({ product: { name: 'Pump' }, answers: {}, fda: { componentSupport: { libfoo: { supportLevel: 'nope' } } } });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors).toContain('manufacturer is required and must be an object');
      expect(result.errors.some((e) => e.includes('fda.componentSupport["libfoo"].supportLevel'))).toBe(true);
    }
  });
});
