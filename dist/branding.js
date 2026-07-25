"use strict";
// Central product-identity constants for ceproof.
//
// licenseproof (the codebase this tool was bootstrapped from) scattered its
// product name, URL, disclaimer wording, and pricing as string literals
// throughout the renderer/CLI layer. That made a rebrand (this bootstrap) and
// any future pricing change a grep-and-pray exercise. This module is the
// single source of truth instead — every user-facing surface should import
// from here rather than hardcoding the product name, URL, config directory,
// env var name, disclaimer, or price.
Object.defineProperty(exports, "__esModule", { value: true });
exports.PRICE_AGENCY = exports.PRICE_INDIVIDUAL = exports.DISCLAIMER = exports.ENV_KEY_VAR = exports.CONFIG_DIR_NAME = exports.PRODUCT_URL = exports.PRODUCT_NAME = void 0;
/** The product name as shown to users (CLI banner, report headers, etc). */
exports.PRODUCT_NAME = 'ceproof';
/** Marketing/docs site URL (ceproof-site, deployed separately from this repo). */
exports.PRODUCT_URL = 'https://ceproof.dev';
/** Directory name under `~/.config/` where an activated license key is stored. */
exports.CONFIG_DIR_NAME = 'ceproof';
/** Environment variable name used to pass a license key without activating it. */
exports.ENV_KEY_VAR = 'CEPROOF_KEY';
/** The standing "not legal advice" disclaimer, shown on every user-facing report/output. */
exports.DISCLAIMER = 'Informational — not legal advice.';
/**
 * Perpetual-license pricing (Milestone 3's paid `report` command, not yet wired
 * up in M1). Defined here now — not when M3 needs it — so pricing never gets
 * re-scattered as literals the way licenseproof's was.
 */
exports.PRICE_INDIVIDUAL = '$99';
exports.PRICE_AGENCY = '$299';
//# sourceMappingURL=branding.js.map