import { describe, it, expect } from 'vitest';
import { base64urlDecode, base64urlEncode, buildPayloadBytes } from '../../src/license/keyFormat';
import { parseLicensePayload, verifyLicenseKey } from '../../src/license/verify';
import { licenseExpiry, licenseExpiryNote } from '../../src/license/expiry';

/**
 * The v1/v2 key-format contract.
 *
 * No signing key is touched anywhere in this file, and none is needed: the
 * signature covers the payload bytes, and adding an optional field changes
 * nothing about how it is computed or checked. What is actually worth proving
 * is (a) that a v1 payload's BYTES are unchanged — the reason every existing
 * perpetual key keeps verifying — and (b) that the field handling and the
 * expiry policy branch correctly. The one real v1 key below is the same one
 * tests/license/verify.test.ts uses, and it is still checked end to end
 * through the real verifier.
 */
const REAL_V1_KEY =
  'eyJwcm9kdWN0IjoiY2Vwcm9vZiIsInRpZXIiOiJpbmRpdmlkdWFsIiwibGljZW5zZUlkIjoiNzZaNTJOVzRHVSIsImlzc3VlZEF0IjoiMjAyNi0wNy0yNFQwNToyOTozOC4xMzRaIiwidXBkYXRlc1VudGlsIjoiMjAyNy0wNy0yNFQwNToyOTozOC4xMzRaIn0.1_Ji7XgwqBTNxY5zdG_0aBWrv5Z8QmXyn0z5ui3EFTw-4FA2f5kViCHuie7MLLLIqSrv1btxHZwkDI8-1nWhDw';

const V1_FIELDS = {
  tier: 'individual',
  licenseId: '76Z52NW4GU',
  issuedAt: '2026-07-24T05:29:38.134Z',
  updatesUntil: '2027-07-24T05:29:38.134Z',
};

describe('v1 keys are untouched by the expiry field', () => {
  it('omitting expiresAt reproduces the real v1 key’s payload segment byte for byte', () => {
    const p = REAL_V1_KEY.slice(0, REAL_V1_KEY.lastIndexOf('.'));
    expect(base64urlEncode(buildPayloadBytes({ product: 'ceproof', ...V1_FIELDS }))).toBe(p);
  });

  it('passing expiresAt: undefined explicitly also reproduces it — the KEY is absent, not the value', () => {
    const p = REAL_V1_KEY.slice(0, REAL_V1_KEY.lastIndexOf('.'));
    expect(base64urlEncode(buildPayloadBytes({ product: 'ceproof', ...V1_FIELDS, expiresAt: undefined }))).toBe(p);
    expect(JSON.parse(buildPayloadBytes({ ...V1_FIELDS }).toString('utf8'))).not.toHaveProperty('expiresAt');
  });

  it('the real v1 key still verifies, and reads as perpetual', () => {
    const info = verifyLicenseKey(REAL_V1_KEY);
    expect(info).not.toBeNull();
    expect(info!.expiresAt).toBeUndefined();
    expect(licenseExpiry(info!)).toEqual({ perpetual: true, expired: false });
    expect(licenseExpiryNote(licenseExpiry(info!))).toBeUndefined();
  });
});

/**
 * `expiresAt` IS INSIDE THE SIGNED PAYLOAD, proven the only way that means
 * anything: by tampering.
 *
 * Structural proof — that `buildPayloadBytes` includes the field in the bytes
 * that get signed — is below, and it is necessary but not sufficient. What a
 * customer could actually attempt is editing the expiry in a key they already
 * hold, and the thing worth asserting is that the signature then fails. No
 * signing key is needed to assert it: the tamper is applied to the REAL issued
 * v1 key's payload segment, with its real signature left in place.
 */
describe('the expiry cannot be edited into or out of a key', () => {
  const [p, s] = [REAL_V1_KEY.slice(0, REAL_V1_KEY.lastIndexOf('.')), REAL_V1_KEY.slice(REAL_V1_KEY.lastIndexOf('.') + 1)];
  const reseal = (fields: Record<string, unknown>) => `${base64urlEncode(Buffer.from(JSON.stringify(fields), 'utf8'))}.${s}`;
  const decoded = () => JSON.parse(base64urlDecode(p).toString('utf8')) as Record<string, unknown>;

  it('the untampered key verifies, so the tamper tests below are measuring the tamper', () => {
    expect(verifyLicenseKey(REAL_V1_KEY)).not.toBeNull();
  });

  it('adding an expiry to a perpetual key breaks the signature', () => {
    // The direction that matters least commercially but proves the field is
    // covered: you cannot turn a perpetual key into an annual one either.
    expect(verifyLicenseKey(reseal({ ...decoded(), expiresAt: '2099-01-01T00:00:00.000Z' }))).toBeNull();
  });

  it('extending an expiry breaks the signature — the only attack that would be worth money', () => {
    const v2 = { ...decoded(), tier: 'fda-company', expiresAt: '2027-10-31T00:00:00.000Z' };
    // Re-encoding the UNCHANGED fields of a v2 payload is not something this
    // test can verify against a real signature (no v2 key has been issued), so
    // the assertion is the one that holds for any signature: a payload whose
    // bytes differ from the signed ones fails, whichever field moved.
    expect(verifyLicenseKey(reseal(v2))).toBeNull();
    expect(verifyLicenseKey(reseal({ ...v2, expiresAt: '2099-01-01T00:00:00.000Z' }))).toBeNull();
  });

  it('removing a field, reordering the fields, or changing the tier all break the signature', () => {
    const { updatesUntil, ...withoutUpdatesUntil } = decoded();
    expect(updatesUntil).toBeDefined();
    expect(verifyLicenseKey(reseal(withoutUpdatesUntil))).toBeNull();
    expect(verifyLicenseKey(reseal({ ...decoded(), tier: 'fda-consultant' }))).toBeNull();
    // Same fields, same values, different insertion order -> different bytes.
    const reversed = Object.fromEntries(Object.entries(decoded()).reverse());
    expect(verifyLicenseKey(reseal(reversed))).toBeNull();
  });

  it('fails closed on a payload that is not parseable at all, rather than throwing', () => {
    expect(verifyLicenseKey(`${base64urlEncode(Buffer.from('not json', 'utf8'))}.${s}`)).toBeNull();
    expect(verifyLicenseKey(`${base64urlEncode(Buffer.from('{"product":"ceproof"', 'utf8'))}.${s}`)).toBeNull();
    expect(verifyLicenseKey('')).toBeNull();
    expect(verifyLicenseKey(`${p}.`)).toBeNull();
    expect(verifyLicenseKey(p)).toBeNull();
  });
});

describe('v2 keys carry the expiry in the signed payload', () => {
  const v2Bytes = buildPayloadBytes({ ...V1_FIELDS, tier: 'fda-company', expiresAt: '2027-10-31T00:00:00.000Z' });

  it('is in the bytes that get signed, not alongside them', () => {
    // The structural half of the proof above: the field is inside the buffer
    // the signature is computed over, so changing it changes those bytes.
    expect(v2Bytes.toString('utf8')).toContain('"expiresAt":"2027-10-31T00:00:00.000Z"');
    const without = buildPayloadBytes({ ...V1_FIELDS, tier: 'fda-company' });
    expect(v2Bytes.equals(without)).toBe(false);
  });

  it('puts expiresAt last, so a decoded payload reads in issuance order', () => {
    expect(Object.keys(JSON.parse(v2Bytes.toString('utf8')))).toEqual([
      'product',
      'tier',
      'licenseId',
      'issuedAt',
      'updatesUntil',
      'expiresAt',
    ]);
  });

  it('round-trips through the base64url codec unchanged', () => {
    expect(base64urlDecode(base64urlEncode(v2Bytes))).toEqual(v2Bytes);
  });

  it('is accepted by the payload parser, with the expiry carried through verbatim', () => {
    const info = parseLicensePayload(JSON.parse(v2Bytes.toString('utf8')));
    expect(info).toEqual({ product: 'ceproof', ...V1_FIELDS, tier: 'fda-company', expiresAt: '2027-10-31T00:00:00.000Z' });
  });
});

describe('parseLicensePayload — the v1/v2 branch', () => {
  const base = { product: 'ceproof', ...V1_FIELDS };

  it('accepts a payload with no expiresAt and reports none', () => {
    expect(parseLicensePayload(base)?.expiresAt).toBeUndefined();
  });

  it('rejects a payload whose expiresAt is present but not a string', () => {
    // The only direction a misread could go wrong in is handing out a free
    // perpetual licence, so a signed-but-unreadable expiry fails the key.
    expect(parseLicensePayload({ ...base, expiresAt: 1799999999999 })).toBeNull();
    expect(parseLicensePayload({ ...base, expiresAt: null })).toBeNull();
    expect(parseLicensePayload({ ...base, expiresAt: { at: '2027-01-01' } })).toBeNull();
  });

  it('still rejects a key for another product, and a missing required field', () => {
    expect(parseLicensePayload({ ...base, product: 'licenseproof' })).toBeNull();
    expect(parseLicensePayload({ ...base, tier: 7 })).toBeNull();
  });
});

describe('licenseExpiry', () => {
  const v2 = (expiresAt: string) => ({ product: 'ceproof', ...V1_FIELDS, tier: 'fda-company', expiresAt });

  it('is not expired the moment before the expiry, and expired the moment after', () => {
    const at = '2027-10-31T00:00:00.000Z';
    expect(licenseExpiry(v2(at), new Date('2027-10-30T23:59:59.999Z')).expired).toBe(false);
    expect(licenseExpiry(v2(at), new Date(at)).expired).toBe(false);
    expect(licenseExpiry(v2(at), new Date('2027-10-31T00:00:00.001Z')).expired).toBe(true);
  });

  it('treats an unreadable expiry as current, and says so instead of hiding it', () => {
    const expiry = licenseExpiry(v2('not a date'), new Date('2027-01-01T00:00:00.000Z'));
    expect(expiry).toEqual({ perpetual: false, expiresAt: 'not a date', expired: false, unreadableExpiry: 'not a date' });
    expect(licenseExpiryNote(expiry)).toContain('cannot read');
    expect(licenseExpiryNote(expiry)).toContain('not with anything you did');
  });

  it('never calls a lapsed subscription an invalid key', () => {
    const note = licenseExpiryNote(licenseExpiry(v2('2027-10-31T00:00:00.000Z'), new Date('2028-01-01T00:00:00.000Z')));
    expect(note).toContain('expired on 2027-10-31');
    expect(note).toContain('renew');
    expect(note).not.toMatch(/invalid/i);
    expect(note).toContain('Everything the free commands do keeps working.');
  });

  it('says when a running subscription runs until, without nagging about it', () => {
    expect(licenseExpiryNote(licenseExpiry(v2('2027-10-31T00:00:00.000Z'), new Date('2027-01-01T00:00:00.000Z')))).toBe(
      'This license runs until 2027-10-31.',
    );
  });

  /**
   * How "an unreadable expiry is treated as current" squares with failing
   * closed, which is the question answer-5 asked.
   *
   * They do not conflict, because they are decisions about different things at
   * different layers, and the unreadable case is much narrower than it looks:
   *
   *  - `verify.ts` already rejects a key whose `expiresAt` is present but not
   *    a STRING. So "unreadable" cannot mean a number, a null or an object —
   *    those never reach expiry.ts at all;
   *  - the field is inside the SIGNED payload (proven by the tamper tests
   *    above), so a customer cannot put a malformed date there. The only way
   *    to reach this branch is a key WE issued with a malformed date;
   *  - which makes the choice: lock a paying customer out of a tool over our
   *    own issuance bug, or let a licence we mis-issued run longer than
   *    intended while saying so loudly on every run. The second is the lesser
   *    failure, and it is bounded by our own issuance rather than by anything
   *    an attacker controls.
   *
   * The place to close it is issuance, not verification: `issue.mjs` should
   * refuse to sign an `expiresAt` that does not parse, so the branch below can
   * only ever be reached by a key issued before that check existed.
   */
  it('cannot be reached by a non-string expiry, because the verifier rejects those first', () => {
    for (const bad of [1799999999999, null, { at: '2027' }, ['2027-01-01'], true]) {
      expect(parseLicensePayload({ product: 'ceproof', ...V1_FIELDS, expiresAt: bad })).toBeNull();
    }
  });

  it('treats only an unparseable DATE STRING as current, and never silently', () => {
    for (const bad of ['not a date', '2027-13-45', 'soon', '']) {
      const expiry = licenseExpiry({ product: 'ceproof', ...V1_FIELDS, tier: 'fda-company', expiresAt: bad }, new Date('2030-01-01'));
      // An empty string is absent-ish but IS a string, so it lands here rather
      // than reading as perpetual — which is the point: it is visible.
      if (bad === '') {
        expect(expiry.perpetual).toBe(false);
      }
      expect(expiry.expired).toBe(false);
      expect(expiry.unreadableExpiry).toBe(bad);
      expect(licenseExpiryNote(expiry)).toContain('cannot read');
      expect(licenseExpiryNote(expiry)).toContain('please report it');
    }
  });

  it('a readable expiry in the past is never treated as current, however far past', () => {
    for (const at of ['2020-01-01T00:00:00.000Z', '1999-12-31T23:59:59.000Z', '2027-10-31']) {
      expect(licenseExpiry(v2(at), new Date('2030-01-01')).expired).toBe(true);
    }
  });
});
