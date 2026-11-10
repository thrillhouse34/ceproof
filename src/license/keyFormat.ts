// Base64url (RFC 4648 §5) codec + license-key payload construction — VERIFY side.
//
// SHIPPED counterpart to scripts/keygen/lib/keyFormat.mjs (the signing side,
// never shipped). The two live on opposite sides of the tsc / never-shipped
// boundary and CANNOT share one file, so base64url encode/decode and the
// payload-byte construction are DELIBERATELY re-implemented independently here
// in TypeScript. That duplication is proven correct not by textual identity but
// by a behavioral round-trip test (tests/license/keyFormat.test.ts): a REAL key
// issued by the .mjs signing side is decoded here and its payload segment is
// re-encoded by the functions below, and the bytes must match exactly. See the
// M6 plan's "shared key-format logic" note for why this is the pragmatic choice.
//
// Wire format (binding, foundations_addendum.md §2 + the M6 plan):
//   payload bytes = Buffer.from(JSON.stringify({product, tier, licenseId,
//                     issuedAt, updatesUntil[, expiresAt]}), 'utf8')
//   P = base64url(payload bytes)
//   S = base64url(raw 64-byte Ed25519 signature of the payload bytes)
//   customer key string = `${P}.${S}`  (one '.' separator, no padding/whitespace)
//
// TWO KEY VERSIONS, distinguished by that one optional field and nothing else:
//
//   v1 — no `expiresAt`. A perpetual licence. Every key issued before the FDA
//        tiers existed is one of these, and they stay valid forever: the field
//        is OMITTED from the signed bytes when absent, so a v1 key's payload is
//        byte-identical to what it always was and its signature still verifies.
//   v2 — `expiresAt` present, an ISO timestamp. An annual subscription (the FDA
//        tiers are sold by the year). The key still verifies cryptographically
//        after that date — expiry is a licensing decision made on the verified
//        contents, in ./expiry.ts, not a signature failure. A customer whose
//        subscription lapsed should be told their subscription lapsed, not that
//        their key is invalid.
//
// There is deliberately no `keyVersion` field. The presence or absence of
// `expiresAt` IS the discriminator, it cannot disagree with itself, and a
// version number nobody branches on is a field that rots.

/** The one and only product string a genuine ceproof key ever carries. */
export const PRODUCT = 'ceproof';

/** The payload fields, in the canonical insertion order used for signing. `expiresAt` is last, and is the only optional one. */
export interface LicensePayloadFields {
  product?: string;
  tier: string;
  licenseId: string;
  issuedAt: string;
  updatesUntil: string;
  /** ISO timestamp. Present on a v2 (annual) key only; absent means perpetual. */
  expiresAt?: string;
}

/**
 * Base64url-encode bytes per RFC 4648 §5: '+' -> '-', '/' -> '_', no '=' padding.
 * Independent re-implementation of the signing side's `base64urlEncode`; used
 * only by the round-trip agreement test (the verifier itself never re-encodes).
 */
export function base64urlEncode(bytes: Buffer | Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Base64url-decode a string back to a Buffer. Symmetric inverse of
 * `base64urlEncode`. `Buffer.from(..., 'base64')` tolerates missing padding, so
 * no re-padding step is needed. Never throws on malformed input — it decodes
 * whatever prefix is valid base64 and stops — so the caller (verify.ts) can rely
 * on a subsequent signature/length check to reject garbage rather than needing
 * this to fail loudly.
 */
export function base64urlDecode(str: string): Buffer {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * Reconstruct the exact bytes that were signed and base64url-encoded as segment
 * P. Independent re-implementation of the signing side's `buildPayloadBytes`.
 * `product` defaults to the `PRODUCT` constant above. The verifier does NOT use
 * this to check signatures (it verifies against the raw decoded P bytes, since a
 * re-stringify could differ in field order or whitespace from the original) —
 * this exists purely so the round-trip test can prove the TS encode agrees with
 * the .mjs encode byte-for-byte on a real key's fields.
 */
export function buildPayloadBytes({
  product = PRODUCT,
  tier,
  licenseId,
  issuedAt,
  updatesUntil,
  expiresAt,
}: LicensePayloadFields): Buffer {
  return Buffer.from(
    JSON.stringify({
      product,
      tier,
      licenseId,
      issuedAt,
      updatesUntil,
      // Spread, not `expiresAt: undefined` — JSON.stringify drops an undefined
      // value but this way the KEY itself is absent from the object, which is
      // what keeps a v1 payload byte-identical to the pre-expiry format no
      // matter how JSON.stringify treats undefined in a future runtime.
      ...(expiresAt !== undefined ? { expiresAt } : {}),
    }),
    'utf8',
  );
}
