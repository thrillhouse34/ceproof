# Changelog

This file starts at 0.4.0. Releases up to and including 0.3.5 are recorded only
in the git history and in `distribution/RELEASE-*-COMMANDS-*.md`; they are not
reconstructed here, because a changelog written after the fact from a diff is a
guess about what mattered, and this file is meant to be checkable.

Dates are the date the version was published to npm, in UTC, as the npm
registry itself records it (`npm view ceproof time`) — not the date the release
commit was made, which can fall on the previous day. An unpublished version is
marked as such.

## 0.4.0 — 2026-11-01

The FDA premarket-SBOM mode, and the licence format that sells it. Nothing a
0.3.x user does changes: the CRA scan, the Annex VII pack and the Annex V
Declaration of Conformity behave exactly as they did, and every perpetual key
issued so far keeps working, perpetually.

### Added

- **`ceproof scan --profile fda`** — a free, offline diagnosis against the 13
  content items in FDA's February 3, 2026 premarket cybersecurity guidance
  (`data/fda-structure.json`). Needs no key, writes no file, and makes no
  network call. `--profile cra` stays the default and is byte-identical to a run
  with no `--profile` at all.
- **`ceproof report --format fda-pack`** — the paid FDA evidence pack, under the
  new `fda-company` / `fda-consultant` tiers. One format that writes a
  DIRECTORY of seven artifacts: `fda-sbom.cyclonedx.json` (CycloneDX 1.6,
  enriched with support level and end-of-support as `ceproof:fda:*` properties,
  the imported SBOM's dependency graph carried through verbatim, and the screen's
  findings as an explicitly unassessed `vulnerabilities` array),
  `fda-support-eol.csv`, `fda-vulnerabilities.csv`, `fda-summary.md`,
  `fda-open-items.md`, `fda-provenance.json` and `DISCLAIMER.md`.
- **`--sbom <file>`**, repeatable, on both `scan --profile fda` and
  `report --format fda-pack`: imports CycloneDX JSON 1.4–1.6 (SPDX is rejected
  with a message saying so, not silently ignored) and merges it with whatever a
  repo scan found. Passing `--sbom` where no FDA format or profile will read it
  is a usage error, never a silent no-op.
- **A support-level and end-of-support engine** (`src/fda/support.ts`) resolving
  the two per-component values FDA asks for beyond the NTIA minimum elements, in
  strict precedence: your own declaration in `ceproof.config.json`
  (`fda.componentSupport`) > a declaration already on the imported SBOM >
  the bundled `data/eol-snapshot.json` > an unknown that states its own reason.
  It never derives `abandoned` and never invents a date.
- **A known-exploited-vulnerability screen** (`src/fda/kev.ts`) against the
  bundled CISA KEV catalogue (`data/kev-snapshot.json`), refined by
  `data/kev-index.json` — a build-time OSV/GitHub/PyPA join carrying affected
  npm and PyPI version ranges. Three confidences: `confirmed` needs an ecosystem
  advisory AND an evaluable version comparison, `possible` is everything else
  (including every C/C++ component, since KEV carries no version data at all),
  and `not-affected` is reported rather than silently dropped. It screens; it
  never assesses. The two columns FDA asks the manufacturer for are left reading
  `NEEDS-HUMAN-INPUT` on every surface.
- **`fda.*` keys in `ceproof.config.json`**: the device/firmware identity, the
  SBOM author, and per-component support declarations. Existing config files are
  unaffected and still validate.
- **New bundled data, with attribution in `NOTICE`**: `eol-snapshot.json`
  (endoflife.date, MIT), `kev-snapshot.json` (CISA KEV, CC0-1.0),
  `kev-index.json` (OSV.dev Apache-2.0 + GitHub/PyPA Advisory Databases,
  CC-BY-4.0), and `fda-structure.json` (this repo's own extraction of a US
  Government work). Refreshed by `npm run fetch-eol-snapshot`,
  `npm run fetch-kev-snapshot` and `npm run build-kev-index`; each carries its
  own identifiers in `data/manifest.json` rather than moving `dataVersion`.
- **A v2 licence-key format**: one optional `expiresAt` field inside the signed
  payload, which is what makes an annual subscription possible. `src/license/
  expiry.ts` answers "has the subscription lapsed" as a date comparison on the
  verified contents, separately from "is this key genuine" (`verify.ts`) and from
  what a lapsed subscription stops you doing (`gateRequest` in
  `src/cli/report.ts`). A lapsed subscription is never reported as an invalid
  key and never falls through to the free formats silently.

### Changed

- **`--fail-on` now defaults per profile** (`DEFAULT_FAIL_ON` in
  `src/cli/scan.ts`). `cra` keeps `human-required`, unchanged forever. `fda`
  defaults to `never` — report-only, exit 0 — because three of its thirteen
  items can only ever be answered by a human, so any other default would fail
  every FDA run no matter how complete the SBOM. Failing a build on the FDA
  profile is opt-in: pass `--fail-on partial` or `--fail-on human-required`.
  The findings themselves are identical either way; only the exit code moves.
- A lapsed FDA key's refusal now reads: *"Your ceproof FDA license expired on
  &lt;date&gt;. Update payment or renew from the link in your receipt email, or
  write to support@ceproof.dev."* — the same words the renewal email uses, so a
  customer reading both is told one thing rather than two. Lapsed CRA-tier keys
  keep the generic sentence.
- `scripts/keygen/issue.mjs` refuses to sign an `expiresAt` that does not parse
  as a date. The CLI treats an unreadable expiry as current and says so loudly,
  which is the lesser of two failures — so the place to close the hole is
  issuance.
- **npm's own metadata now says FDA.** `package.json`'s `description` reads
  *"Offline SBOM evidence packs for the EU Cyber Resilience Act and FDA
  medical-device premarket submissions."* and `keywords` gains `fda`,
  `medical-device`, `premarket`, `cybersecurity` and `end-of-life` (`sbom` and
  `cyclonedx` were already there). Search surface only — no code reads either
  field.

### Unchanged, deliberately

- Every v1 (perpetual) key's signed payload, and therefore its signature, is
  byte-identical to what it always was: `expiresAt` is omitted from the signed
  bytes when absent. `tests/license/keyExpiry.test.ts` proves that against the
  real issued key.
- `individual` and `agency` keys do not unlock `fda-pack`, and FDA keys do not
  unlock the Annex VII pack or the Annex V DoC. `TIER_FORMATS` fails closed: a
  tier this build does not recognise unlocks nothing.
- `sbom-cyclonedx` and `sbom-spdx` stay free.
- Fully offline at runtime, in every mode. `tests/fda/offline.test.ts` enforces
  it per file for the new code rather than by a grep someone remembers to run.
