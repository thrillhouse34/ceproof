# ceproof

`npx ceproof scan` looks at your repo and derives a compliance-posture gap
checklist against the EU Cyber Resilience Act (CRA), Annex VII (technical
documentation) and Annex V (EU Declaration of Conformity) — offline, from
files already on disk (package manifests, lockfiles, installed dependency
metadata, git facts) plus, once answered, a `ceproof.config.json` interview
file for anything a repo scan genuinely can't infer (product description,
support-period rationale, standards applied, and similar). Every item is
reported honestly as DERIVED (scan evidence alone is enough), PARTIAL (some
evidence, incomplete), or NEEDS-HUMAN-INPUT (no evidence and no config answer
yet) — never guessed, never silently assumed.

`npx ceproof report` renders that same checklist into two audit-ready
artifacts — the Annex VII technical documentation pack and the Annex V
Declaration of Conformity draft (a perpetual license: $99 individual, $299
agency) — plus standalone, free CycloneDX/SPDX SBOM formats.

There is a second mode for a different regulator. `npx ceproof scan --profile
fda` checks the same repo — or an SBOM you already have — against the SBOM
content items in **FDA's premarket cybersecurity guidance** (February 3, 2026),
free; `npx ceproof report --format fda-pack` generates the documentation pack
itself. See [The FDA premarket SBOM mode](#the-fda-premarket-sbom-mode).

**Informational — not legal advice.** ceproof runs entirely offline: no
network calls, no telemetry, ever. It is not an FDA submission, it is not
regulatory advice, and it has not been reviewed or endorsed by FDA or by CISA.

## Install & run

```
npx ceproof scan [path]
npx ceproof init [path]      # generate ceproof.config.json, one prompt per human-required item
npx ceproof report [path] --format <formats>
npx ceproof activate <key>   # unlock the paid Annex VII pack / Annex V DoC / FDA pack formats
npx ceproof deactivate

npx ceproof scan --profile fda --sbom firmware.cdx.json        # free FDA content view
npx ceproof report --format fda-pack --sbom firmware.cdx.json  # the FDA pack (FDA-tier key)
```

### `scan`

Options: `--format summary|json`, `--fail-on human-required|partial|never`,
`--config <path>`, `--include-dev`, `--project-license <id>`,
`--profile cra|fda` (default `cra`), `--sbom <file>` (repeatable,
`--profile fda` only), `--no-color`. Exit codes: `0` clean (nothing at or
above the `--fail-on` threshold), `1` threshold hit, `2` tool error. See
`ceproof scan --help` for the full list.

`--fail-on` defaults **per profile**: `human-required` for `--profile cra`
(unchanged), and `never` for `--profile fda`, which is **report-only** — it
exits `0` and puts the findings in the output. Three FDA items can only ever
be answered by a human, so `human-required` would fail every FDA run forever
no matter how complete the SBOM. Failing a build on the FDA profile is opt-in:
pass `--fail-on partial` or `--fail-on human-required` yourself.

### `init`

Generates `ceproof.config.json` with one empty answer slot per item the scan
engine can't derive on its own (`--force` to overwrite an existing file).
Fill in the answers, then re-run `scan`/`report` — every item you've answered
resolves DERIVED.

### `report`

`--format <formats>` (comma-separated or repeatable): `annex7`, `annex7-pdf`,
`doc`, `doc-pdf`, `fda-pack` (require a license key), `sbom-cyclonedx`,
`sbom-spdx` (free). `--key <key>` (or the `CEPROOF_KEY` env var, or a key
activated via `ceproof activate`), `--out <path>` (a file for a single format,
a directory for multiple — defaults to `./ceproof-report/`), `--config <path>`,
`--sbom <file>` (repeatable, `fda-pack` only), `--include-dev`,
`--project-license <id>`. Exit codes: `0` success (open
items in the rendered content don't fail the command — the pack itself
states what's still missing), `2` tool/runtime error (e.g. a `*-pdf` format
with no installed browser — use the non-PDF format instead, no dependencies
required), `3` a gated format was requested without a valid license key, with
a key for the wrong tier, or with a lapsed subscription (nothing is written —
a request mixing a free and a gated format refuses the whole request, not just
the gated part). See `ceproof report --help` for the full list.

`fda-pack` must be requested on its own, and `--out` is always a **directory**
for it: it writes seven artifacts, not one file (defaults to `./ceproof-fda/`).

`annex7`/`doc` are self-contained HTML files (open directly in a browser, or
print to PDF yourself); `annex7-pdf`/`doc-pdf` render the same content
through a locally-installed Chrome/Chromium/Edge. `annex7.7` (the DoC copy
required inside the Annex VII pack) is automatically compiled from the
answered Annex V items rather than asked for twice.

### `activate` / `deactivate`

`ceproof activate <key>` verifies a license key and stores it at
`~/.config/ceproof/license.key` so every later `report` run unlocks
automatically. `ceproof deactivate` removes the stored key (idempotent).

The CRA tiers (`individual`, `agency`) are **perpetual** — valid forever once
purchased. The FDA tiers (`fda-company`, `fda-consultant`) are **annual**: the
key carries its own renewal date, says when it runs until, and when the year is
up it tells you the subscription needs renewing and names the date. It is never
reported as an invalid key, nothing you have generated stops working, and every
free command keeps working. Neither family of tiers unlocks the other; they are
different products.

## The FDA premarket SBOM mode

For a medical-device manufacturer, FDA asks for a machine-readable SBOM with
the NTIA minimum elements, plus two things per component those elements do not
cover — the **level of support** provided through monitoring and maintenance,
and the **end-of-support date** — plus the **known vulnerabilities** associated
with the device and its components, including those in **CISA's Known Exploited
Vulnerabilities Catalog**. (FDA, *Cybersecurity in Medical Devices: Quality
Management System Considerations and Content of Premarket Submissions*, issued
February 3, 2026, section V.A.4(b).)

Device firmware is usually C/C++, so this mode does not need a lockfile:
`--sbom <file>` imports a CycloneDX JSON SBOM you already have (spec 1.4, 1.5
or 1.6, detected from the file's own contents) and enriches it. A repo scan and
one or more imported SBOMs are **additive**, not competing — a device team with
firmware plus a Node companion app gets both, each component recording where it
came from.

```
# Free: what's missing, with the counts that make it concrete
npx ceproof scan --profile fda --sbom firmware.cdx.json
npx ceproof scan --profile fda --sbom firmware.cdx.json --format json

# Paid: the documentation pack
npx ceproof report --format fda-pack --sbom firmware.cdx.json --out ./fda-pack
```

**In CI this profile is report-only by default**: it exits `0` and reports the
findings, so adding it to a pipeline never turns a build red on its own. Three
of its items — the risk assessment, the risk controls and the cyber-device
determination — are permanently `NEEDS-HUMAN-INPUT` because no tool can answer
them, so a threshold of `human-required` would fail every run forever. Gate the
build on it deliberately with `--fail-on partial`, or read `--format json`.

The pack is seven files:

| File | What it is |
|---|---|
| `fda-sbom.cyclonedx.json` | The enriched CycloneDX 1.6 SBOM: level of support and end-of-support date as `ceproof:fda:*` properties, your source SBOM's dependency graph carried through verbatim, and the screen's findings as an unassessed `vulnerabilities` array |
| `fda-support-eol.csv` | One row per component: identifiers, origin, level of support, end-of-support date, and the basis for each |
| `fda-vulnerabilities.csv` | One row per finding, including the ones screened out, with the two columns you fill in |
| `fda-summary.md` | The document a human reads: scope, method, inventory, the two per-component values, the vulnerability table, the open items, the provenance |
| `fda-open-items.md` | Everything still needing a human, with what to do about each |
| `fda-provenance.json` | What produced the pack, from what inputs, against which datasets, under which licences |
| `DISCLAIMER.md` | The standing disclaimer, naming which artifacts carry it inline and which cannot |

**What it does, and what it deliberately does not.** It *screens* and records
how it found each row. You *assess*. FDA asks the manufacturer for two things
per known vulnerability — a safety and security risk assessment including device
and system impacts, and the applicable risk controls — and both read
`NEEDS-HUMAN-INPUT` in every artifact until you write them. Nothing here claims
they were done, and nothing here is an FDA submission.

Known limits, stated here rather than discovered later:

- The vulnerability screen covers the **CISA KEV catalogue only** — the subset
  FDA names explicitly. FDA asks for *all* known vulnerabilities; identify the
  rest by other means. That item can never read DERIVED.
- A `confirmed` finding needs an npm or PyPI advisory with affected version
  ranges. No version-precise data is bundled for C/C++, so **a C/C++ component
  can only ever reach `possible`**, and the output says why.
- The bundled KEV catalogue and end-of-support data are snapshots. Both carry a
  visible warning in the output once they are more than 30 days old.
- A level of support and an end-of-support date are commitments made by whoever
  maintains a component. Where no public dataset answers one, declare it
  yourself under `fda.componentSupport` in `ceproof.config.json` — a declaration
  outranks every derived value, and `abandoned` can only ever arrive that way.
- Dependency relationships are carried through from your SBOM and **never
  inferred**. If your source SBOM has no `dependencies` array, or only top-level
  edges, the pack says so rather than letting the absence pass for an assertion
  that there are none.
- No SPDX import and no PDF output in this version. CycloneDX JSON in,
  CycloneDX JSON plus CSV plus markdown out.

Everything is resolved offline against vendored snapshots of CISA KEV
(CC0-1.0), OSV.dev (Apache-2.0), the GitHub and PyPA Advisory Databases
(CC-BY-4.0) and endoflife.date (MIT); see [NOTICE](NOTICE).

## Use it in CI

### GitHub Actions

The least work is the published action, which wraps this CLI:

```yaml
name: CRA posture
on: [push, pull_request]
jobs:
  ceproof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci
      - uses: thrillhouse34/ceproof-action@v1
        with:
          fail-on: never            # start report-only; tighten to partial / human-required later
          # license-key: ${{ secrets.CEPROOF_LICENSE_KEY }}   # adds the Annex VII pack + Annex V DoC (+ SBOMs) artifact
      # Free SBOMs without a key (the action's report-formats is only read when license-key is set):
      - run: npx --yes ceproof@0.4.0 report . --format sbom-cyclonedx,sbom-spdx --out sbom
```

Run `npx ceproof init` once locally and commit `ceproof.config.json` so the
NEEDS-HUMAN-INPUT items resolve in CI too.

**The FDA profile in CI.** The published action takes it directly: `fda: true`
swaps the CRA gap view for the FDA one, and `fda-sbom:` is where the CycloneDX
JSON SBOM goes (one path per line, or comma-separated). `fda-sbom` is only read
when `fda: true` — setting it with `fda` off is an error rather than a silent
no-op. The FDA profile is **report-only by default**: `fail-on` left empty
resolves to `never`, so it exits `0` and puts the findings in the step output
and the job summary, and it cannot turn a build red on its own.

```yaml
      - uses: thrillhouse34/ceproof-action@v1
        with:
          fda: true
          fda-sbom: firmware.cdx.json
          # fail-on: partial          # opt in to failing the build, once your SBOM can hold it
```

A plain `npx` step still works if you would rather not use the action:

```yaml
      # Report-only: exits 0, and the findings land in the job summary.
      - run: |
          { echo '```'
            npx --yes ceproof@0.4.0 scan --profile fda --sbom firmware.cdx.json --no-color
            echo '```'
          } >> "$GITHUB_STEP_SUMMARY"
```

### GitLab CI

```yaml
ceproof:
  image: node:22
  stage: test
  script:
    - npm ci
    - npx --yes ceproof@0.4.0 scan . --fail-on never
    - npx --yes ceproof@0.4.0 report . --format sbom-cyclonedx,sbom-spdx --out ceproof-reports
  artifacts:
    paths: [ceproof-reports/]
# Paid packs: add a masked CI/CD variable CEPROOF_KEY and append annex7,doc to --format.
```

Any other CI runner works the same way: it is a plain `npx` call with no network
access at scan time. Gate the build on the exit code (`0` ok, `1` threshold hit,
`2` tool error, `3` key rejected) and keep the `--out` directory as an artifact.

## Status

`scan` (gap checklist + `init`), `report` (Annex VII pack, Annex V DoC draft,
standalone SBOM), and license-key gating (`activate`/`deactivate`, paid
narrative formats) are all shipped. The FDA premarket SBOM mode — `scan
--profile fda`, `--sbom` import and `report --format fda-pack` — shipped in
**0.4.0**, which is the current npm release, and the published action exposes
it as `fda:` / `fda-sbom:`. SPDX JSON import is not implemented: `--sbom` reads
CycloneDX JSON (spec 1.4, 1.5, 1.6) and refuses anything else by name rather
than half-parsing it. See `CLAUDE.md` for the architecture and doctrine this
repo follows, and `README-DEV.md` for build/test instructions.

## License

Source-available under the Elastic License 2.0 (SPDX: `Elastic-2.0`). See
[LICENSE](LICENSE). Free to use, including commercially on your own projects and
for your own clients; you may not resell it as a hosted or managed service, and
you may not remove, disable, or circumvent its license-key functionality.
