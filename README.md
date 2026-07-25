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

**Informational — not legal advice.** ceproof runs entirely offline: no
network calls, no telemetry, ever.

## Install & run

```
npx ceproof scan [path]
npx ceproof init [path]      # generate ceproof.config.json, one prompt per human-required item
npx ceproof report [path] --format <formats>
npx ceproof activate <key>   # unlock the paid Annex VII pack / Annex V DoC formats
npx ceproof deactivate
```

### `scan`

Options: `--format summary|json`, `--fail-on human-required|partial|never`
(default `human-required`), `--config <path>`, `--include-dev`,
`--project-license <id>`, `--no-color`. Exit codes: `0` clean (nothing at or
above the `--fail-on` threshold), `1` threshold hit, `2` tool error. See
`ceproof scan --help` for the full list.

### `init`

Generates `ceproof.config.json` with one empty answer slot per item the scan
engine can't derive on its own (`--force` to overwrite an existing file).
Fill in the answers, then re-run `scan`/`report` — every item you've answered
resolves DERIVED.

### `report`

`--format <formats>` (comma-separated or repeatable): `annex7`, `annex7-pdf`,
`doc`, `doc-pdf` (require a license key), `sbom-cyclonedx`, `sbom-spdx`
(free). `--key <key>` (or the `CEPROOF_KEY` env var, or a key activated via
`ceproof activate`), `--out <path>` (a file for a single format, a directory
for multiple — defaults to `./ceproof-report/`), `--config <path>`,
`--include-dev`, `--project-license <id>`. Exit codes: `0` success (open
items in the rendered content don't fail the command — the pack itself
states what's still missing), `2` tool/runtime error (e.g. a `*-pdf` format
with no installed browser — use the non-PDF format instead, no dependencies
required), `3` a gated format was requested without a valid license key
(nothing is written — a request mixing a free and a gated format refuses the
whole request, not just the gated part). See `ceproof report --help` for the
full list.

`annex7`/`doc` are self-contained HTML files (open directly in a browser, or
print to PDF yourself); `annex7-pdf`/`doc-pdf` render the same content
through a locally-installed Chrome/Chromium/Edge. `annex7.7` (the DoC copy
required inside the Annex VII pack) is automatically compiled from the
answered Annex V items rather than asked for twice.

### `activate` / `deactivate`

`ceproof activate <key>` verifies a license key and stores it at
`~/.config/ceproof/license.key` so every later `report` run unlocks
automatically — a perpetual license, valid forever once purchased.
`ceproof deactivate` removes the stored key (idempotent).

## Status

M1 (scan + gap checklist + init), M2 (report: Annex VII pack, Annex V DoC
draft, standalone SBOM), and M3 (license-key gating: `activate`/`deactivate`,
paid narrative formats) are all shipped. See `CLAUDE.md` for the architecture
and doctrine this repo follows, `milestone2_brief.md`/`milestone3_brief.md`
for the M2/M3 design decisions, and `README-DEV.md` for build/test
instructions.
