// Central product-identity constants for ceproof.
//
// licenseproof (the codebase this tool was bootstrapped from) scattered its
// product name, URL, disclaimer wording, and pricing as string literals
// throughout the renderer/CLI layer. That made a rebrand (this bootstrap) and
// any future pricing change a grep-and-pray exercise. This module is the
// single source of truth instead — every user-facing surface should import
// from here rather than hardcoding the product name, URL, config directory,
// env var name, disclaimer, or price.

/** The product name as shown to users (CLI banner, report headers, etc). */
export const PRODUCT_NAME = 'ceproof';

/** Marketing/docs site URL (ceproof-site, deployed separately from this repo). */
export const PRODUCT_URL = 'https://ceproof.dev';

/** Directory name under `~/.config/` where an activated license key is stored. */
export const CONFIG_DIR_NAME = 'ceproof';

/** Environment variable name used to pass a license key without activating it. */
export const ENV_KEY_VAR = 'CEPROOF_KEY';

/** The standing "not legal advice" disclaimer, shown on every user-facing report/output. */
export const DISCLAIMER = 'Informational — not legal advice.';

/**
 * Perpetual-license pricing (Milestone 3's paid `report` command, not yet wired
 * up in M1). Defined here now — not when M3 needs it — so pricing never gets
 * re-scattered as literals the way licenseproof's was.
 */
export const PRICE_INDIVIDUAL = '$99';
export const PRICE_AGENCY = '$299';
