"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PUBLIC_KEY_SPKI_DER_BASE64 = void 0;
/**
 * The real, permanent Ed25519 PUBLIC key for verifying ceproof license keys.
 *
 * This is the SPKI DER encoding of the signing keypair's public half, then
 * base64-encoded. It ships with every install and is the sole root of trust for
 * fully-offline license verification (foundations_addendum.md §2; the Milestone 6
 * key wire-format spec). Verification never makes a network call.
 *
 * DO NOT REGENERATE OR EDIT THIS ONCE REAL LICENSE KEYS EXIST IN THE WILD. Every
 * license key is signed by the matching private half (stored OUTSIDE this repo,
 * at a real sibling directory, ../ceproof-signing-key/signing-key — never inside
 * ceproof-private's own working tree) and keys can never be reissued — changing
 * this constant would instantly invalidate every license already sold. It was
 * generated once by scripts/keygen/generateSigningKey.mjs and is permanent.
 */
exports.PUBLIC_KEY_SPKI_DER_BASE64 = 'MCowBQYDK2VwAyEAQP/qBJsQAhFlmm++7Of/F6Gvh2EA7n8qnImjdB6bfjE=';
//# sourceMappingURL=publicKey.js.map