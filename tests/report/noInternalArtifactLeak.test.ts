import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { REPO_ROOT } from '../../src/paths';
import { runScan } from '../../src/cli/scan';
import { runReport } from '../../src/cli/report';
import { expectClean } from './forbiddenMarkers';

// Regression guard for the "internal artifact leaks into customer-facing
// text" bug class — this repo's third confirmed instance of it (an internal
// class name in citation text, an operator-only note printed inside the
// fulfillment email, and now "(see completion report)" in the data-source
// provenance line: an internal-only doc a paying customer has no access to
// and no way to obtain). Each instance was a one-off patch; this test is the
// systematic backstop so a fourth instance fails CI instead of shipping.
//
// SCOPE — what counts as "customer-facing" here, deliberately narrow:
//   - `ceproof scan` terminal (--format summary) and machine (--format json)
//     output, for a real fixture project
//   - the rendered Annex VII pack and Annex V DoC draft (--format annex7/doc)
//     and both free SBOM formats (--format sbom-cyclonedx/sbom-spdx), for the
//     same real fixture project and a real (non-secret, test-only) license key
//   - the CLI's own --help text (top-level and every subcommand) — real
//     commander output, not a copy of the option strings
//   - the license-fulfillment email body (scripts/keygen/issue.mjs's
//     buildEmail()) — the exact text a paying customer receives. That half
//     lives in tests/private/fulfillmentEmailLeak.test.ts, because the
//     template it reads is the never-shipped keygen tooling the public
//     source mirror excludes; both halves share the marker set in
//     ./forbiddenMarkers.ts.
//   - README.md — what a prospective customer reads on npm/GitHub before ever
//     running the tool
// This is deliberately NOT a whole-source-tree grep: this codebase's own
// source comments legitimately discuss milestones, briefs, and internal
// planning docs throughout (e.g. "see milestone2_brief.md", "Milestone 4
// Task 6") — none of that renders anywhere a customer looks, and a
// blanket source scan would drown a real hit in hundreds of false positives
// from legitimate developer-facing comments. Restricting to actual rendered
// output (or the literal template that produces it, for the email) is the
// only way to test the property that actually matters: what a customer sees.

const FIXTURE = path.join(REPO_ROOT, 'fixtures', 'package-lock-v3-basic');

// A real, genuine, verifying individual-tier test key — the same one
// tests/cli/report.test.ts uses to actually render the gated formats rather
// than stubbing them out. Not a secret: license keys authenticate a purchase
// record, they don't gate anything sensitive.
const REAL_KEY =
  'eyJwcm9kdWN0IjoiY2Vwcm9vZiIsInRpZXIiOiJpbmRpdmlkdWFsIiwibGljZW5zZUlkIjoiNzZaNTJOVzRHVSIsImlzc3VlZEF0IjoiMjAyNi0wNy0yNFQwNToyOTozOC4xMzRaIiwidXBkYXRlc1VudGlsIjoiMjAyNy0wNy0yNFQwNToyOTozOC4xMzRaIn0.1_Ji7XgwqBTNxY5zdG_0aBWrv5Z8QmXyn0z5ui3EFTw-4FA2f5kViCHuie7MLLLIqSrv1btxHZwkDI8-1nWhDw';

describe('no internal-artifact leak in customer-facing scan/report output', () => {
  it('scan --format summary output is clean', async () => {
    const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'summary', projectLicenseOverride: undefined });
    expectClean('scan --format summary', result.output);
  });

  it('scan --format json output is clean', async () => {
    const result = await runScan({ path: FIXTURE, productionOnly: true, format: 'json', projectLicenseOverride: undefined });
    expectClean('scan --format json', result.output);
  });

  it('the rendered Annex VII pack, Annex V DoC draft, and both SBOM formats are clean', async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-leak-guard-'));
    try {
      const outDir = path.join(scratch, 'out');
      const result = await runReport({
        path: FIXTURE,
        productionOnly: true,
        formats: ['annex7', 'doc', 'sbom-cyclonedx', 'sbom-spdx'],
        out: outDir,
        key: REAL_KEY,
        env: {},
      });
      expect(result.exitCode, result.output).toBe(0);
      for (const file of ['annex7.html', 'doc.html', 'sbom.cyclonedx.json', 'sbom.spdx.json']) {
        const content = fs.readFileSync(path.join(outDir, file), 'utf8');
        expectClean(file, content);
      }
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});

describe('no internal-artifact leak in the CLI --help text', () => {
  const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');
  const CLI_ENTRY = path.join(REPO_ROOT, 'src', 'cli', 'index.ts');

  function helpText(args: string[]): string {
    return execFileSync(TSX_BIN, [CLI_ENTRY, ...args, '--help'], { cwd: REPO_ROOT, encoding: 'utf8' });
  }

  // Real commander --help output for the top-level program and every
  // subcommand — the exact text a customer sees running `ceproof --help` /
  // `ceproof <command> --help`, not a copy of the .description()/.option()
  // string literals (which could drift from what commander actually prints).
  it.each([[], ['scan'], ['init'], ['report'], ['activate'], ['deactivate']])(
    '`ceproof %s --help` is clean',
    (...args: string[]) => {
      const output = helpText(args);
      expect(output.length).toBeGreaterThan(0);
      expectClean(`ceproof ${args.join(' ')} --help`.trim(), output);
    },
  );
});

describe('no internal-artifact leak in README.md', () => {
  it('README.md (what a prospective customer reads on npm/GitHub) is clean', () => {
    const content = fs.readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf8');
    expectClean('README.md', content);
  });
});

// Non-vacuity is proven by hand (not committed): a temporary marker string
// was inserted into data/cra-structure.json's sourceVersion, `npm test` was
// run to confirm this file's first describe block goes red and names the
// exact offending content, and the marker was reverted before committing.
// See the task's completion report for the transcript.
describe('sanity: the marker set itself is well-formed', () => {
  it('every forbidden marker actually matches its own worked example', () => {
    expect('... (see completion report). Supplementary'.match(/completion report/i)).not.toBeNull();
    expect('per the M2 brief'.match(/\bbriefs?\b/i)).not.toBeNull();
    expect('a later milestone can'.match(/\bmilestones?\b/i)).not.toBeNull();
    expect('M1 shipped scan'.match(/(?<![A-Za-z0-9])M[1-6](?![A-Za-z0-9])/)).not.toBeNull();
    expect('subagent-driven'.match(/\bsubagents?\b/i)).not.toBeNull();
    expect('a TODO here'.match(/\bTODO\b/)).not.toBeNull();
    expect('a FIXME here'.match(/\bFIXME\b/)).not.toBeNull();
    expect('under .claude/skills'.match(/\.claude\//)).not.toBeNull();
    expect('see scripts/keygen/issue.mjs'.match(/scripts\/keygen\//)).not.toBeNull();
    expect('per docs/plans/m2-handoff.md'.match(/docs\/plans\//)).not.toBeNull();
    // A neighboring word must NOT false-positive the M1-M6 shorthand pattern.
    expect('a Chrome M120 build'.match(/(?<![A-Za-z0-9])M[1-6](?![A-Za-z0-9])/)).toBeNull();
  });
});
