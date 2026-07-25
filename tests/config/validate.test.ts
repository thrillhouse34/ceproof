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
