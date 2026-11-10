/**
 * Whether a verified licence has lapsed — the v2 (annual-subscription) half of
 * the key format.
 *
 * Kept out of verify.ts on purpose, and out of the gating path entirely for
 * now. Three separate decisions get confused if they share a function:
 *
 *  1. is this key GENUINE? — verify.ts, cryptography, no dates involved;
 *  2. has the subscription LAPSED? — this file, a date comparison on the
 *     verified contents;
 *  3. what does a lapsed subscription STOP you doing? — a product decision
 *     that lands with the CLI wiring, not here.
 *
 * The split matters because a lapsed subscription is not an invalid key. A
 * customer whose year is up must be told their subscription needs renewing, in
 * those words, with the renewal link — never "invalid license key", which reads
 * as "you were sold something broken" and generates the support email.
 *
 * Perpetual keys (every key issued before the FDA tiers existed) carry no
 * `expiresAt` and come back `perpetual`, forever, by construction rather than
 * by a special case someone could delete.
 */
import type { LicenseInfo } from './verify';

export interface LicenseExpiry {
  /** True when the key carries no expiry at all: a v1 key, perpetual. */
  perpetual: boolean;
  /** The verified `expiresAt`, verbatim, when there is one. */
  expiresAt?: string;
  /** True only when an expiry is present, readable, and in the past. */
  expired: boolean;
  /**
   * Set when `expiresAt` is present but not a date any runtime can parse.
   * That can only be an issuance bug on our side — the field is signed, so a
   * customer cannot have put it there — and the key is treated as NOT expired
   * while the problem is visible, because locking a paying customer out of a
   * tool over our own malformed date is the worse of the two failures.
   */
  unreadableExpiry?: string;
}

export function licenseExpiry(info: LicenseInfo, now: Date = new Date()): LicenseExpiry {
  if (info.expiresAt === undefined) return { perpetual: true, expired: false };
  const expiresAtTime = new Date(info.expiresAt).getTime();
  if (Number.isNaN(expiresAtTime)) {
    return { perpetual: false, expiresAt: info.expiresAt, expired: false, unreadableExpiry: info.expiresAt };
  }
  return { perpetual: false, expiresAt: info.expiresAt, expired: now.getTime() > expiresAtTime };
}

/**
 * The one sentence a user surface shows about expiry, or undefined when there
 * is nothing to say (a perpetual key, or a subscription still running). Worded
 * here rather than per surface, for the same reason branding.ts owns the
 * disclaimer.
 */
export function licenseExpiryNote(expiry: LicenseExpiry): string | undefined {
  if (expiry.unreadableExpiry !== undefined) {
    return (
      `This license key carries an expiry date this tool cannot read ("${expiry.unreadableExpiry}"). ` +
      'The license is being treated as current. This is a problem with how the key was issued, not with anything you did — please report it.'
    );
  }
  if (expiry.perpetual || expiry.expiresAt === undefined) return undefined;
  const day = expiry.expiresAt.slice(0, 10);
  return expiry.expired
    ? `This license expired on ${day}. It was an annual subscription; renew it to keep generating the paid artifacts. Everything the free commands do keeps working.`
    : `This license runs until ${day}.`;
}
