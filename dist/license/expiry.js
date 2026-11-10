"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.licenseExpiry = licenseExpiry;
exports.licenseExpiryNote = licenseExpiryNote;
function licenseExpiry(info, now = new Date()) {
    if (info.expiresAt === undefined)
        return { perpetual: true, expired: false };
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
function licenseExpiryNote(expiry) {
    if (expiry.unreadableExpiry !== undefined) {
        return (`This license key carries an expiry date this tool cannot read ("${expiry.unreadableExpiry}"). ` +
            'The license is being treated as current. This is a problem with how the key was issued, not with anything you did — please report it.');
    }
    if (expiry.perpetual || expiry.expiresAt === undefined)
        return undefined;
    const day = expiry.expiresAt.slice(0, 10);
    return expiry.expired
        ? `This license expired on ${day}. It was an annual subscription; renew it to keep generating the paid artifacts. Everything the free commands do keeps working.`
        : `This license runs until ${day}.`;
}
//# sourceMappingURL=expiry.js.map