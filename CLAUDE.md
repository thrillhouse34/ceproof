# CLAUDE.md

Guidance for Claude Code sessions working in this repo. Keep this concise —
it's operating doctrine, not a spec.

## What this is

ceproof is an EU Cyber Resilience Act (CRA) compliance-posture scanner
(`npx ceproof scan`) and, as of M2, a document-generation tool
(`npx ceproof report`). It was bootstrapped from a sibling tool, licenseproof
(a dependency-license scanner), by reusing its dependency/SBOM/license
resolution engine and stripping licenseproof-specific concepts (license
"conflict" detection) that don't apply here. ceproof's own compliance
concept — a per-CRA-requirement gap checklist (DERIVED / PARTIAL /
NEEDS-HUMAN-INPUT), built against `data/cra-structure.json`'s real,
traceable extraction from the regulation text — is structurally unrelated to
conflict severity.

## Architecture

- `src/cli` — commander CLI. `scan`, `init`, `report`, `activate`, and
  `deactivate` are all registered (M1 + M2 + M3). `report`'s narrative
  formats (`annex7`/`annex7-pdf`/`doc`/`doc-pdf`) require a valid license key
  (`src/cli/report.ts`'s `GATED_FORMATS`); `sbom-cyclonedx`/`sbom-spdx` stay
  free.
- `src/ecosystems` — npm/PyPI dependency scanning (lockfile parsing,
  installed-package disk verification).
- `src/resolve` — license resolution: SPDX expression parsing, license-text
  fingerprinting, category classification.
- `src/detect` — repo-fact detectors for CRA-relevant signals (security
  disclosure, project license, ecosystems, runtimes, VCS facts, update
  mechanism) — composed into `RepoFacts` by `src/detect/index.ts`.
- `src/gap` — the CRA gap-checklist engine (`computeGapChecklist`): resolves
  every `data/cra-structure.json` item to DERIVED/PARTIAL/NEEDS-HUMAN-INPUT
  against `RepoFacts`, resolved packages, and an optional `ceproof.config`.
- `src/cra` — `CraStructureItem`/`CraStructureFile` types and the
  `data/cra-structure.json` loader. Four derivability values: `derivable`,
  `partial` (both evidence-key-driven), `human-required` (needs a
  `ceproof.config` answer), `boilerplate` (fixed regulatory text, always
  DERIVED, no evidence or config needed — e.g. Annex V point 3).
- `src/config` — `CeproofConfig` (`ceproof.config.json`) types, hand-rolled
  validation, and `ceproof init`'s interview-file generation.
- `src/report` — `provenance.ts` (release-identifier + tool/data-version/
  timestamp stamping for every rendered artifact), `annexContent.ts` (turns a
  gap checklist + `ceproof.config` into renderer-agnostic Annex VII/Annex V
  section content, including the `annex7.7`-composed-from-Annex-V special
  case), `html.ts`/`pdf.ts` (the Annex VII pack / Annex V DoC renderers),
  `sbom/{cyclonedx,spdx}.ts` (SBOM formats — CycloneDX 1.6, SPDX 2.3 pending a
  future 3.0.1 rewrite), `reportData.ts` (the reused dependency/SBOM
  pipeline, no conflict concept).
- `data/` — vendored reference data: SPDX license list, license category
  mappings, license texts, `cra-structure.json` (the real, traceable CRA
  extraction — see `tests/cra/traceability.test.ts`), plus `manifest.json`
  (`{dataVersion, spdxListVersion, craSourceVersion, generatedAt}`).
  `data/sources/` (the full vendored primary-source text) is build-time-only
  and never ships in the published package (`verify-pack.sh` asserts this).

## Doctrine (non-negotiable)

- **Fully offline at runtime.** No network calls, no telemetry, no "phone
  home," ever — in `scan`, in any future `report`/`gap` command, anywhere.
- **Honest UNKNOWNs.** Never silently guess or omit. If a signal can't be
  resolved confidently, say so (`UNKNOWN`, a warning, an explicit
  "unspecified") — never fabricate a value to fill a gap.
- **"Informational — not legal advice"** appears on every user-facing
  output (terminal, JSON, and any future HTML/PDF/notices artifact). Use the
  `DISCLAIMER` constant in `src/branding.ts`, don't re-word it per surface.
- **Never-silent assumptions.** Any assumption made on the user's behalf
  (e.g. treating an unspecified project license as a default) must be printed
  prominently in the output, never silent.
- **Never commit failing tests.** `npm test` must be green before any commit.
  If a test can't legitimately be made to pass (e.g. it depends on signing
  infrastructure that doesn't exist yet), skip it explicitly with a comment
  explaining why — never delete it just to silence a failure, and never leave
  it red.
- **Verify `git remote -v` before any push.** Never push without checking
  what remote you're pushing to.
- **Work that exists only in an ephemeral sandbox or an unpushed local
  folder does not exist.** Two real, expensive incidents in this portfolio:
  ceproof's original Ed25519 signing keypair was generated inside an
  ephemeral build sandbox and was lost outright when that sandbox was
  reclaimed — recoverable only because no key had ever been sold yet, so
  regenerating before first sale was still an option. That was luck, not
  design. Separately, the live Stripe-fulfillment Worker's entire source
  (`licenseproof-fulfillment`) survived for a while only as an unpushed
  local folder on a Mac — invisible to any other environment or session
  working on this portfolio — and had to be pushed to GitHub before it
  could be extended by anyone else. Push to a verified real remote before
  any session or work session ends, and confirm the push actually landed by
  running `git remote -v` again *after* pushing, not only before. Not
  "eventually," not "when convenient" — before the session ends.
- **A release gate must be re-run whenever the thing it guards changes, not
  just when the gate itself changes.** `verify-pack.sh`'s `data/sources/`
  exclusion check was written and genuinely passed during M1's T11 task —
  but `data/sources/` didn't exist yet at that point, so the pass was truthful
  but vacuous (nothing to catch). `data/sources/` was populated for real one
  task later (T9), and the script was never re-run before M1 was declared
  done — so a real packaging bug (`data/sources/` shipping in the npm
  tarball, `package.json`'s `files` array never got the exclusion it needed)
  went undetected until M2. The check's logic was never buggy; the discipline
  gap was trusting an old pass after the repo state the check depends on had
  moved. Any milestone that adds/changes what `data/`, `scripts/`, or the
  packed tarball contains (a new vendored directory, a new build artifact, a
  new `files`-array entry) must re-run `verify-pack.sh` before that milestone
  is declared done — a stale pass is worse than no check at all.
- **Niche selection ends with a written competitive map, not a single
  conditional — and every kill-trigger names a calendar date.** ceproof's
  original kill-trigger ("reassess if a category occupant ships a sub-€300
  one-time pack tier") was never written down anywhere in this repo or
  `licenseproof-private`, so per the ephemeral-sandbox doctrine above it
  effectively never existed as a safeguard — and it monitored the wrong
  variable besides (price, not category occupancy). The corrected,
  durable reassessment gate lives in this repo's internal planning
  material (excluded from the public mirror, like all of it — see
  `scripts/publish-mirror.sh`), reviewed on two scheduled dates.
  Portfolio-wide rule for tool #3 and beyond: niche selection ends with a
  written competitive map (who occupies the category, what they sell, what
  it costs, and whether it can be bought today); every kill-trigger names a
  calendar date, not a milestone, because milestones get reviewed by
  whoever is deep in the build and dates don't; and at least one trigger
  must be outcome-based (no sales, no downloads) so it can fire on a
  failure mode nobody predicted.

## Branding

`src/branding.ts` is the single source of truth for product name, URL, config
directory, env var name, disclaimer text, and pricing constants. Import from
there — don't hardcode "ceproof", a URL, or a price as a literal.
