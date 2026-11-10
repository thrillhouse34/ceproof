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

/** Where a customer writes when something needs a human. Here rather than as a literal for the same reason PRODUCT_URL is. */
export const SUPPORT_EMAIL = 'support@ceproof.dev';

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

/**
 * The FDA premarket-SBOM mode's standing disclaimer, carried on every artifact
 * that mode generates (the enriched SBOM's metadata properties included, per
 * the "disclaimer on every surface" doctrine).
 *
 * It lives here beside DISCLAIMER rather than in the FDA renderers because
 * this file is the single source of truth for disclaimer text — the whole point
 * being that no surface gets to re-word it. The generic DISCLAIMER still
 * applies and is printed alongside it; this adds the two things that are
 * specific to a premarket submission and that no CRA artifact needs to say:
 * the output is not an FDA submission and carries no FDA or CISA endorsement,
 * and it supports the manufacturer's own review of their submission rather
 * than replacing it.
 *
 * Wording note, binding: nothing in this mode may describe its output as
 * FDA-approved, as compliant, or as submission-ready. Those are claims about
 * the customer's regulatory filing, which this tool is in no position to make.
 * tests/fda/forbiddenClaims.test.ts enforces that against every rendered
 * artifact.
 */
export const FDA_DISCLAIMER: readonly string[] = [
  DISCLAIMER,
  'This document is generated from the component data you supplied and from your own declarations. It is not an FDA submission, it is not regulatory advice, and it has not been reviewed or endorsed by FDA or by CISA.',
  'It supports your own review of your premarket submission; it does not replace it. You remain responsible for everything you submit — including the safety and security risk assessment of every vulnerability listed here, and the risk controls you apply.',
];
