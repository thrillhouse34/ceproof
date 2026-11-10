import { describe, it, expect } from 'vitest';
import { verifyLicenseKey } from '../../src/license/verify';

// The real individual-tier key issued by scripts/keygen/issue.mjs (M6 Task 1),
// signed by the committed public key. Verifies here with zero setup.
const REAL_KEY =
  'eyJwcm9kdWN0IjoiY2Vwcm9vZiIsInRpZXIiOiJpbmRpdmlkdWFsIiwibGljZW5zZUlkIjoiNzZaNTJOVzRHVSIsImlzc3VlZEF0IjoiMjAyNi0wNy0yNFQwNToyOTozOC4xMzRaIiwidXBkYXRlc1VudGlsIjoiMjAyNy0wNy0yNFQwNToyOTozOC4xMzRaIn0.1_Ji7XgwqBTNxY5zdG_0aBWrv5Z8QmXyn0z5ui3EFTw-4FA2f5kViCHuie7MLLLIqSrv1btxHZwkDI8-1nWhDw';

describe('verifyLicenseKey — accepts a genuine key', () => {
  it('returns the full LicenseInfo for the real issued key', () => {
    expect(verifyLicenseKey(REAL_KEY)).toEqual({
      product: 'ceproof',
      tier: 'individual',
      licenseId: '76Z52NW4GU',
      issuedAt: '2026-07-24T05:29:38.134Z',
      updatesUntil: '2027-07-24T05:29:38.134Z',
    });
  });

  it('tolerates surrounding whitespace (an email-paste stray newline)', () => {
    expect(verifyLicenseKey(`\n  ${REAL_KEY}\t\n`)).not.toBeNull();
  });
});

describe('verifyLicenseKey — never throws, returns null on adversarial input', () => {
  it('empty string → null', () => {
    expect(verifyLicenseKey('')).toBeNull();
  });

  it('non-string inputs → null (undefined, number, object, null)', () => {
    expect(verifyLicenseKey(undefined)).toBeNull();
    expect(verifyLicenseKey(12345)).toBeNull();
    expect(verifyLicenseKey({})).toBeNull();
    expect(verifyLicenseKey(null)).toBeNull();
  });

  it('a string with no "." separator → null', () => {
    expect(verifyLicenseKey('not-a-key-at-all')).toBeNull();
  });

  it('a bit-flipped signature → null (tamper rejection)', () => {
    const lastDot = REAL_KEY.lastIndexOf('.');
    const s = REAL_KEY.slice(lastDot + 1);
    // Flip the first signature character to a different valid base64url char.
    const flipped = (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
    const tampered = REAL_KEY.slice(0, lastDot + 1) + flipped;
    expect(tampered).not.toBe(REAL_KEY);
    expect(verifyLicenseKey(tampered)).toBeNull();
  });

  it('a truncated key → null', () => {
    expect(verifyLicenseKey(REAL_KEY.slice(0, Math.floor(REAL_KEY.length / 2)))).toBeNull();
  });

  it('a key with extra trailing garbage → null', () => {
    expect(verifyLicenseKey(REAL_KEY + 'GARBAGE')).toBeNull();
  });

  it('a key with an extra trailing ".garbage" segment → null', () => {
    expect(verifyLicenseKey(REAL_KEY + '.GARBAGE')).toBeNull();
  });
});

// The product-confusion guard — a key VALIDLY SIGNED by the real private key
// but carrying a different product string — needs the signing side under
// scripts/keygen/, so it lives in
// tests/private/verifyProductConfusion.test.ts, excluded from the public
// mirror along with that tooling.
