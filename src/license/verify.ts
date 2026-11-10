import * as crypto from 'crypto';
import { PUBLIC_KEY_SPKI_DER_BASE64 } from './publicKey';
import { base64urlDecode, PRODUCT } from './keyFormat';

/**
 * The verified, trusted contents of a genuine ceproof license key. Every
 * field is the exact value that was signed. `product` is always the `PRODUCT`
 * constant from keyFormat.ts (the verifier rejects anything else before ever
 * returning), kept on the shape so a caller can assert it if it wants to.
 */
export interface LicenseInfo {
  product: string;
  tier: string;
  licenseId: string;
  issuedAt: string;
  updatesUntil: string;
  /**
   * ISO timestamp, present on a v2 (annual-subscription) key only. Absent on
   * every v1 key, which is perpetual — see keyFormat.ts's two-version note.
   * Whether an expiry has passed is NOT decided here: see ./expiry.ts.
   */
  expiresAt?: string;
}

// Reconstruct the Ed25519 public KeyObject once from the committed SPKI-DER
// base64 constant (src/license/publicKey.ts). This is the sole root of trust;
// verification is 100% offline, no network call, ever (addendum §2 / §4).
let cachedPublicKey: crypto.KeyObject | undefined;
function getPublicKey(): crypto.KeyObject {
  if (!cachedPublicKey) {
    cachedPublicKey = crypto.createPublicKey({
      key: Buffer.from(PUBLIC_KEY_SPKI_DER_BASE64, 'base64'),
      format: 'der',
      type: 'spki',
    });
  }
  return cachedPublicKey;
}

/**
 * Verify a license key string and return its trusted contents, or `null`.
 *
 * This is the actual business-model enforcement mechanism. It NEVER throws — the
 * same "never throws" contract the SPDX-expression parser holds elsewhere in
 * this codebase. Feed it anything (garbage, truncated strings, a bit-flipped
 * signature, wrong JSON, a validly-signed key for a DIFFERENT product) and it
 * returns `null` on any failure at any step.
 *
 * Steps (the M6 wire format, decode/verify half):
 *  1. Trim surrounding whitespace (tolerates an email-paste stray newline).
 *  2. Split on the LAST '.' — base64url never contains '.', so the segment
 *     boundary is unambiguous. Reject if either segment is empty.
 *  3. base64url-decode P (payload bytes) and S (raw signature).
 *  4. `crypto.verify(null, payloadBytes, publicKey, signature)` — the `null`
 *     digest is required for Ed25519 (no pre-hash step).
 *  5. On a good signature, JSON.parse the payload bytes.
 *  6. Reject unless `product === PRODUCT` — the product-confusion guard:
 *     a key legitimately signed by the same private key but issued for a
 *     different product in a future product family can never activate this tool.
 *  7. Reject unless every expected field is a string, and unless `expiresAt`
 *     — the one optional field — is a string when it is present at all. A
 *     signed key carrying an expiry we cannot read is a key we must not
 *     silently treat as perpetual.
 */
export function verifyLicenseKey(keyString: unknown): LicenseInfo | null {
  try {
    if (typeof keyString !== 'string') return null;
    const key = keyString.trim();
    if (key.length === 0) return null;

    const lastDot = key.lastIndexOf('.');
    // Need a non-empty P before the dot and a non-empty S after it.
    if (lastDot <= 0 || lastDot === key.length - 1) return null;

    const payloadBytes = base64urlDecode(key.slice(0, lastDot));
    const signature = base64urlDecode(key.slice(lastDot + 1));
    if (payloadBytes.length === 0) return null;
    // Ed25519 signatures are exactly 64 bytes; a wrong length can never verify.
    if (signature.length !== 64) return null;

    if (!crypto.verify(null, payloadBytes, getPublicKey(), signature)) return null;

    return parseLicensePayload(JSON.parse(payloadBytes.toString('utf8')));
  } catch {
    // Any unexpected throw (bad base64 edge, malformed JSON, crypto error) is a
    // rejection, never a crash.
    return null;
  }
}

/**
 * Steps 6 and 7 on their own: turn an already-signature-verified payload object
 * into a LicenseInfo, or null.
 *
 * Exported so the v1/v2 field handling can be tested directly, with no signing
 * key and no key material of any kind — the signature is what secures the
 * payload, and adding an optional field changes nothing about it, so the thing
 * actually worth testing here is the field validation. Never throws, same
 * contract as its caller.
 */
export function parseLicensePayload(parsed: unknown): LicenseInfo | null {
  if (parsed === null || typeof parsed !== 'object') return null;
  const p = parsed as Record<string, unknown>;

  if (p.product !== PRODUCT) return null;
  if (
    typeof p.tier !== 'string' ||
    typeof p.licenseId !== 'string' ||
    typeof p.issuedAt !== 'string' ||
    typeof p.updatesUntil !== 'string'
  ) {
    return null;
  }
  // Absent is a v1 key and legitimate. Present-but-not-a-string is a key whose
  // expiry we cannot read, and the safe answer there is to reject the key
  // rather than to read it as perpetual — that one is the only direction in
  // which a misread could hand out a free perpetual licence.
  if (p.expiresAt !== undefined && typeof p.expiresAt !== 'string') return null;

  return {
    product: p.product,
    tier: p.tier,
    licenseId: p.licenseId,
    issuedAt: p.issuedAt,
    updatesUntil: p.updatesUntil,
    ...(typeof p.expiresAt === 'string' ? { expiresAt: p.expiresAt } : {}),
  };
}
