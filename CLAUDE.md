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
  formats (`annex7`/`annex7-pdf`/`doc`/`doc-pdf`) and `fda-pack` require a
  valid license key (`src/cli/report.ts`'s `GATED_FORMATS`);
  `sbom-cyclonedx`/`sbom-spdx` stay free. `scan --profile cra|fda` picks which
  gap view to compute; `cra` is the default and the original behaviour,
  byte-identical to a run with no `--profile` at all. `--fail-on` defaults
  PER PROFILE (`DEFAULT_FAIL_ON` in `src/cli/scan.ts`): `human-required` for
  `cra`, unchanged forever, and `never` for `fda` — that profile is
  report-only because three of its items can only ever be answered by a
  human, so any other default would fail every FDA run no matter how good the
  SBOM, and an exit code that is red on a flawless run trains people to stop
  reading exit codes. Failing a build on the FDA profile is opt-in. Three
  things in
  `report.ts` are load-bearing and separate on purpose: `verifyLicenseKey`
  answers "is this key genuine" (cryptography), `gateRequest` answers "does
  this key entitle you to these formats, and has it lapsed" (a pure function
  of a verified `LicenseInfo`, which is why every branch is testable with no
  key material — see `tests/cli/fdaGating.test.ts`), and `writeFdaPack`
  generates the pack with no licence in scope at all. `TIER_FORMATS` FAILS
  CLOSED: an unrecognised tier unlocks nothing, by lookup rather than by
  default. `fda-pack` must be requested alone and `--out` is a DIRECTORY for
  it; `--sbom` passed where no FDA format/profile will read it is a usage
  error, never a silent no-op.
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
- `src/fda` — the FDA premarket-SBOM mode, COMPLETE on branch
  `feature/fda-sbom` (all five milestones: CycloneDX JSON import + merge;
  support-level/end-of-support engine; KEV screen; renderers; CLI wiring,
  the free profile and licensing). Its own component model
  (`FdaComponent`) deliberately is NOT `ResolvedPackage` — imported firmware
  components have no npm/PyPI ecosystem, lockfile path or install dir;
  `componentsFromScan` in `src/fda/merge.ts` is the single bridge, so nothing
  in the scan pipeline changes shape. `support.ts` resolves the two
  per-component values FDA asks for beyond the NTIA minimum elements (level of
  support, end-of-support date) against `data/eol-snapshot.json`, in strict
  precedence: manufacturer declaration (`ceproof.config.json`'s `fda.
  componentSupport`) > a declaration already on the imported SBOM's
  `ceproof:fda:*` properties > the snapshot > an unknown that states its own
  reason. It never derives `abandoned` and never invents a date.
  `kev.ts` screens every component against the bundled CISA KEV catalogue
  (`data/kev-snapshot.json`) and refines it with `data/kev-index.json`, the
  build-time OSV join carrying affected npm/PyPI version ranges for KEV CVEs.
  Three confidences, and the asymmetry between them is the whole design:
  `confirmed` needs an ecosystem advisory AND an evaluable version comparison;
  `possible` is everything else, including every C/C++ component (KEV carries no
  version data at all) and every version string `compareVersions` refuses;
  `not-affected` is reported, never silently dropped. It screens, it never
  assesses — the two columns FDA asks the manufacturer for are named in
  `MANUFACTURER_SUPPLIED_COLUMNS` and left blank. `compareVersions` handles
  plain dotted-numeric versions only and refuses everything else on purpose:
  SEMVER and PEP 440 disagree about pre-release ordering, and a wrong
  "not affected" next to a known-exploited CVE is the worst output this tool
  could produce.
  `render/` turns those three results into the seven-file pack
  (`FDA_ARTIFACT_FILES` in `render/artifacts.ts`): the enriched CycloneDX 1.6
  SBOM, two CSVs, `fda-summary.md`, `fda-open-items.md`,
  `fda-provenance.json` and `DISCLAIMER.md`. `render/input.ts` is the single
  input type, the `joinRows` join — on component object IDENTITY, throwing if
  the support and KEV results came from different lists, because a support row
  rendered beside another component's findings is a wrong statement in a
  submission — and `resolveDependencies`, which maps the imported SBOM's
  `dependencies[]` onto the refs this document emits. Nothing in `render/`
  writes a file; `writeFdaPack` in `src/cli/report.ts` does.
  Four things are deliberate and must not be "fixed":
  (1) the enriched SBOM's `vulnerabilities[]` carries `id`, `source` and
  `affects` ONLY — never an `analysis` object, which is where CycloneDX states
  whether a vulnerability affects the product and is therefore the assessment
  this tool must never make; its absence is the claim that the rows are
  unassessed, `ceproof:fda:vulnerabilityScreen` says so in words, and
  `not-affected` rows are left out of the array entirely because `affects`
  would assert the opposite of what the screen concluded;
  (2) `ratings` is never emitted, because no bundled dataset carries a
  severity score — KEV has none and the advisory index contributes version
  ranges only, so a rating would have to be invented;
  (3) dependency edges are carried through VERBATIM and never inferred; a
  source `bom-ref` is qualified by its origin at import time (`qualifyRef`)
  because a bom-ref is document-local, the merge ACCUMULATES `sourceRefs`
  rather than treating two documents' differing refs as a conflict, and
  `dependencyRelationshipsNote` states which of three cases the output is in
  (carried / incomplete / absent) so the SBOM, the summary's inventory and the
  open-items list cannot drift;
  (4) the two CSVs are the one disclosed exception to the
  disclaimer-on-every-surface rule (CSV has no metadata channel), and the
  exception is now disclosed IN THE PACK, in `DISCLAIMER.md`, naming both
  files — not only in `tests/fda/forbiddenClaims.test.ts`, which pins both
  halves. No disclaimer COLUMN on the CSVs; that was considered and rejected.
  The wording bans live in that same test, against the RENDERED artifacts:
  never FDA-approved, compliant, submission-ready, certified, nor any phrasing
  implying the risk assessment was performed.
  `tests/fda/offline.test.ts` is what enforces the fully-offline doctrine for
  this mode, per file, instead of a grep someone remembers to run — which is
  why `run.ts` (the one run of the mode, shared by both CLI surfaces) lives
  here rather than in `src/cli`.
  `structure.ts` + `data/fda-structure.json` are the traceable extraction of
  the guidance's content items, held to the same verbatim-excerpt standard as
  `cra-structure.json` (`tests/fda/structure.test.ts`); each item names a
  `measure` instead of CRA's `evidenceKeys`, because the FDA items resolve
  against this mode's three engine results rather than against `RepoFacts`.
  `gap.ts` resolves them, and three ceilings there are permanent and must not
  be made data-dependent: "identify ALL known vulnerabilities" is always
  PARTIAL (this screens one catalogue), the risk assessment and risk controls
  are always NEEDS-HUMAN-INPUT, and zero KEV matches is PARTIAL rather than
  DERIVED — nothing matched is not nothing is there. A view that read better
  the less the tool found would be worse than no view.
  `profile.ts` renders the free view's two surfaces and reuses the CRA
  summary's wrapping/colour helpers so the two terminal views look like one
  tool.
- `src/license` — offline Ed25519 key verification. The payload has TWO
  versions, distinguished by one optional field and nothing else (no
  `keyVersion`): a v1 key has no `expiresAt` and is perpetual, a v2 key has one
  and is an annual subscription (the FDA tiers are sold by the year). The field
  is omitted from the signed bytes when absent, so every v1 key's payload — and
  therefore its signature — is byte-identical to what it always was;
  `tests/license/keyExpiry.test.ts` proves that against the real issued key.
  Three decisions stay separate on purpose: `verify.ts` answers "is this key
  genuine" (cryptography, no dates), `expiry.ts` answers "has the subscription
  lapsed" (a date comparison on the verified contents), and what a lapsed
  subscription stops you doing is `gateRequest` in `src/cli/report.ts`. A
  lapsed subscription is never reported as an invalid key, and never falls
  through to the free formats silently. `expiry.ts` treats an UNREADABLE
  expiry as current and says so loudly: `verify.ts` already rejects a
  non-string `expiresAt`, and the field is inside the signed payload
  (`keyExpiry.test.ts` proves that by TAMPERING with the real issued key, not
  only structurally), so the only way to reach that branch is a key WE
  mis-issued — which makes the real choice "lock a paying customer out over
  our own bug" versus "a mis-issued licence runs long while saying so on every
  run", and the second is the lesser failure. The place to close it is
  issuance: `issue.mjs` should refuse to sign an `expiresAt` that does not
  parse. No key material is needed to test any of this, and none is used.
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
  extraction — see `tests/cra/traceability.test.ts`), `fda-structure.json`
  (the same for the FDA guidance — see `tests/fda/structure.test.ts`; it is
  this repo's own extraction of a US Government work, so it needs no NOTICE
  entry of its own, and `tests/fda/kevIndexLicensing.test.ts` lists it with
  that reason, while NOTICE still names the source it came from and the NTIA
  document FDA incorporates by reference and this repo does NOT vendor), plus
  `manifest.json`
  (`{dataVersion, spdxListVersion, craSourceVersion, generatedAt}`, plus
  `fdaStructureVersion`/`fdaStructureGeneratedAt`).
  `data/sources/` (the full vendored primary-source text) is build-time-only
  and never ships in the published package (`verify-pack.sh` asserts this).
  `eol-snapshot.json` is the FDA mode's distilled endoflife.date data (MIT —
  attribution in the repo-root `NOTICE`, which therefore has to ship too, hence
  its entry in `package.json`'s `files`). It refreshes on its own cadence via
  `npm run fetch-eol-snapshot` and carries its own identifiers in
  `manifest.json` (`eolSnapshotSource`, `eolSnapshotGeneratedAt`) rather than
  moving `dataVersion`, which stays the CRA/SPDX data version the Annex VII
  artifacts stamp. `kev-snapshot.json` (CISA KEV, CC0-1.0) and `kev-index.json`
  (OSV.dev Apache-2.0 + GitHub/PyPA Advisory Databases, CC-BY-4.0) follow the
  same pattern — `npm run fetch-kev-snapshot` then `npm run build-kev-index`,
  own `manifest.json` identifiers (`kevSnapshotSource`, `kevSnapshotReleased`),
  attribution in `NOTICE`. Only CC0/CC-BY-4.0/MIT/Apache-2.0 data may be
  bundled, and `tests/fda/kevIndexLicensing.test.ts` is what enforces that
  against the shipped files — not the build scripts' comments.

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
  it red. Green here is not green everywhere: the public source mirror
  excludes `scripts/keygen/**`, so a test that reaches the signing side passes
  in this repo and fails in the mirror (TS2307 at typecheck, or
  `ERR_MODULE_NOT_FOUND` at runtime for the child-process variant). Those tests
  live under `tests/private/`, excluded with the tooling they read, and
  `npm run test:public-tree` is the gate that proves BOTH trees are green —
  run it after touching `tests/`, `scripts/`, or `publish-mirror.sh`'s
  exclusion list.
- **Verify `git remote -v` before any push.** Never push without checking
  what remote you're pushing to.
- **Work that exists only in an ephemeral sandbox or an unpushed local
  folder does not exist.** Three real, expensive incidents in this
  portfolio now, not two — the third is why this bullet was rewritten
  rather than left as-is. (1) ceproof's original Ed25519 signing keypair
  was generated inside an ephemeral build sandbox and was lost outright
  when that sandbox was reclaimed — recoverable only because no key had
  ever been sold yet, so regenerating before first sale was still an
  option. That was luck, not design. (2) The live Stripe-fulfillment
  Worker's entire source (`licenseproof-fulfillment`) survived for a while
  only as an unpushed local folder on a Mac — invisible to any other
  environment or session working on this portfolio — and had to be pushed
  to GitHub before it could be extended by anyone else. (3) The ceproof.dev
  marketing site was built and iterated on for real — real HTML, real SEO
  work, a real sitemap and analytics tag — entirely inside an untracked
  local directory (`/home/user/ceproof-site`) with zero relationship to any
  git repo, until that was noticed and it was moved into this repo's own
  `site/` (see the commit that did this). "Push before the session ends"
  (below) did not catch incident 3, and that's the actual lesson: that rule
  only fires once you're already thinking about a specific repo's
  uncommitted changes. A directory that was never inside ANY tracked repo's
  working tree in the first place is invisible to `git status`,
  `verify-pack.sh`, the test suite, and every other routine check — none of
  them can see something that was never in their scope to begin with. So,
  binding, in addition to "push before the session ends": **the moment a
  new top-level working directory is created for real, non-throwaway
  output — a new site, a new tool's bootstrap, a new script's persistent
  output — the first action taken in it, before real content accumulates,
  is deciding where it lives in version control** (an existing repo's
  subdirectory, or a genuinely new repo) **and getting at least an initial
  commit pushed to a real remote before doing the actual work.** Not at the
  end — first, before there's anything real to lose. And before declaring
  any session's work complete, explicitly account for every directory
  touched or created during that session: each one resolves to either (a)
  inside an already-tracked, already-pushed repo, or (b) a deliberate,
  disclosed exception stated as such (e.g. a real private key file, which
  must NEVER be git-tracked — but even then must be copied to secure
  storage OUTSIDE this sandbox, never left as the only copy anywhere,
  which is exactly how incident 1 happened). If a new directory's permanent
  home isn't obvious, stop and ask rather than guessing and letting it sit
  ungoverned. Push to a verified real remote before any session or work
  session ends, and confirm the push actually landed by running
  `git remote -v` again *after* pushing, not only before. Not "eventually,"
  not "when convenient" — before the session ends.
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
