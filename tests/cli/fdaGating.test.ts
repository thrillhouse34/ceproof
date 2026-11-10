import { describe, it, expect, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { gateRequest, runReport, EXIT_UNLICENSED, type ReportFormat } from '../../src/cli/report';
import { runScan, DEFAULT_FAIL_ON } from '../../src/cli/scan';
import type { LicenseInfo } from '../../src/license/verify';

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');
const NPM_FIXTURE = path.join(FIXTURES, 'package-lock-v3-basic');
const FIRMWARE_SBOM = path.join(FIXTURES, 'sbom-import', 'firmware-no-purls.json');

/**
 * NO KEY MATERIAL IS TOUCHED ANYWHERE IN THIS FILE, and none is needed.
 *
 * `gateRequest` takes a `LicenseInfo` — the already-VERIFIED contents of a
 * key — so every entitlement and expiry branch is reachable from a hand-built
 * object. Whether a key is genuine is `verify.ts`'s question and needs real
 * cryptography (`tests/license/verify.test.ts` covers it, against the one real
 * issued key). What a genuine key ENTITLES you to is this file's question and
 * needs none, which is why the gating was extracted as a pure function in the
 * first place.
 *
 * The signing key at ../ceproof-signing-key/ is deliberately never read here.
 */
function license(tier: string, expiresAt?: string): LicenseInfo {
  return {
    product: 'ceproof',
    tier,
    licenseId: 'TESTKEY001',
    issuedAt: '2026-01-01T00:00:00.000Z',
    updatesUntil: '2027-01-01T00:00:00.000Z',
    ...(expiresAt ? { expiresAt } : {}),
  };
}

const FDA: ReportFormat[] = ['fda-pack'];
const CRA: ReportFormat[] = ['annex7'];
const FREE: ReportFormat[] = ['sbom-cyclonedx'];

describe('gateRequest — a free-only request never asks for a key', () => {
  it('returns no refusal and no note, with or without a licence', () => {
    expect(gateRequest(null, FREE)).toEqual({});
    expect(gateRequest(license('fda-company'), FREE)).toEqual({});
  });
});

describe('gateRequest — no key at all', () => {
  it('refuses the FDA pack with the FDA message, not the Annex VII price list', () => {
    const refusal = gateRequest(null, FDA).refusal!;
    expect(refusal).toContain('FDA premarket SBOM pack needs an FDA-tier');
    expect(refusal).toContain('scan --profile fda');
    // Quoting a CRA price at someone who asked for FDA artifacts reads as a
    // tool that did not understand the question.
    expect(refusal).not.toContain('$99');
    expect(refusal).not.toContain('Annex VII');
  });

  it('still refuses a CRA format with the CRA message', () => {
    const refusal = gateRequest(null, CRA).refusal!;
    expect(refusal).toContain('$99');
    expect(refusal).toContain('Annex VII');
  });
});

/**
 * Answer-5 item 6(b): a key the verifier does not recognise must fail closed.
 * At this layer that means an unrecognised TIER unlocks nothing — the lookup
 * misses and every gated format is refused. There is deliberately no default
 * and no fallback.
 */
describe('gateRequest — entitlement fails closed', () => {
  it('a CRA key does not unlock the FDA pack, and the message names the tiers that do', () => {
    for (const tier of ['individual', 'agency']) {
      const refusal = gateRequest(license(tier), FDA).refusal!;
      expect(refusal).toContain(`its tier ("${tier}") does not include fda-pack`);
      expect(refusal).toContain('fda-company, fda-consultant');
      expect(refusal).toContain('Your key unlocks: annex7, annex7-pdf, doc, doc-pdf');
    }
  });

  it('an FDA key does not unlock the Annex VII pack — they are different products', () => {
    const refusal = gateRequest(license('fda-company'), CRA).refusal!;
    expect(refusal).toContain('does not include annex7');
    expect(refusal).toContain('individual, agency');
  });

  it('a tier this build has never heard of unlocks NOTHING, and says so rather than guessing', () => {
    for (const tier of ['', 'enterprise', 'fda-COMPANY', 'fda_company', 'admin', 'individual ']) {
      const refusal = gateRequest(license(tier), FDA).refusal;
      expect(refusal, `tier "${tier}" was not refused`).toBeDefined();
      expect(refusal).toContain('no paid formats in this version');
    }
    // And it refuses the CRA formats just as hard.
    expect(gateRequest(license('enterprise'), CRA).refusal).toBeDefined();
  });

  it('both FDA tiers unlock the pack: the difference between them is a licence term, not a feature', () => {
    for (const tier of ['fda-company', 'fda-consultant']) {
      expect(gateRequest(license(tier), FDA).refusal).toBeUndefined();
    }
  });
});

/**
 * Answer-5 item 6(c): an expired key gives the clear lapsed message and never
 * silently falls back to free with no message.
 */
describe('gateRequest — a lapsed subscription', () => {
  const EXPIRED = license('fda-company', '2027-01-01T00:00:00.000Z');
  const AFTER = new Date('2027-06-01T00:00:00.000Z');
  const BEFORE = new Date('2026-12-01T00:00:00.000Z');

  it('opens with the exact FDA lapsed sentence, and with no second renewal route', () => {
    // Pinned verbatim, because licenseproof-fulfillment's renewal email says
    // the same words: a customer who reads both must be told one thing, not two.
    const refusal = gateRequest(EXPIRED, FDA, AFTER).refusal!;
    expect(refusal.split('\n')[0]).toBe(
      'Your ceproof FDA license expired on 2027-01-01. Update payment or renew from the link in your receipt email, or write to support@ceproof.dev.',
    );
    // The generic CRA renewal line would be a third, contradictory route.
    expect(refusal).not.toContain('Renew at https://ceproof.dev');
  });

  it('still uses the generic sentence for a lapsed CRA-tier key, unchanged', () => {
    // No CRA key has ever carried an expiry — every one issued is perpetual —
    // but the branch exists, and an FDA-only reword must not have taken it over.
    const refusal = gateRequest(license('individual', '2027-01-01T00:00:00.000Z'), CRA, AFTER).refusal!;
    expect(refusal).toContain('This license expired on 2027-01-01.');
    expect(refusal).toContain('annual subscription');
    expect(refusal).toContain('Renew at https://ceproof.dev');
    expect(refusal).not.toContain('receipt email');
  });

  it('is never worded as an invalid or broken key', () => {
    const refusal = gateRequest(EXPIRED, FDA, AFTER).refusal!;
    expect(refusal).not.toMatch(/invalid/i);
    expect(refusal).not.toMatch(/\bbroken\b/i);
    expect(refusal).not.toMatch(/not (?:a )?valid/i);
  });

  it('never falls through to the free formats silently: it refuses, and names what still works', () => {
    const refusal = gateRequest(EXPIRED, FDA, AFTER).refusal!;
    expect(refusal).toContain('Nothing was written');
    expect(refusal).toContain('scan --profile fda');
    expect(refusal).toContain('sbom-cyclonedx');
    expect(refusal).toContain('Still free, with no key and no subscription');
  });

  it('says nothing at all while the subscription is still running, beyond when it runs until', () => {
    const gate = gateRequest(EXPIRED, FDA, BEFORE);
    expect(gate.refusal).toBeUndefined();
    expect(gate.expiryNote).toBe('This license runs until 2027-01-01.');
  });

  it('a perpetual key produces no note whatsoever — which is every CRA key ever issued', () => {
    expect(gateRequest(license('individual'), CRA)).toEqual({});
  });

  it('checks the tier BEFORE the expiry: a wrong-product key is not an expiry problem', () => {
    // An expired CRA key asked for the FDA pack. The useful thing to say is
    // "that is the wrong product", not "renew this".
    const refusal = gateRequest(license('individual', '2027-01-01T00:00:00.000Z'), FDA, AFTER).refusal!;
    expect(refusal).toContain('does not include fda-pack');
    expect(refusal).not.toContain('expired on');
  });

  it('treats an expiry it cannot read as CURRENT, says so, and does not refuse', () => {
    // The only way to reach this is a key WE mis-issued — the field is signed,
    // and verify.ts already rejects a non-string expiry — so the two failure
    // modes are "lock a paying customer out over our own malformed date" and
    // "a licence we issued wrong runs longer than it should". The second is
    // the lesser, and it is loudly visible every run rather than silent.
    const gate = gateRequest(license('fda-company', 'not a date'), FDA, AFTER);
    expect(gate.refusal).toBeUndefined();
    expect(gate.expiryNote).toContain('cannot read');
    expect(gate.expiryNote).toContain('not with anything you did');
  });
});

describe('runReport — the FDA pack end to end, with no key available', () => {
  let scratch: string;
  let noKeyFile: string;
  const HERMETIC = { env: {} as NodeJS.ProcessEnv };

  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-fda-gate-'));
    noKeyFile = path.join(scratch, 'no-such-license.key');
  });

  it('refuses with exit 3 and writes nothing — not even the output directory', async () => {
    const out = path.join(scratch, 'pack');
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['fda-pack'],
      out,
      sbomPaths: [FIRMWARE_SBOM],
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    expect(result.exitCode).toBe(EXIT_UNLICENSED);
    expect(result.output).toContain('FDA premarket SBOM pack needs an FDA-tier');
    expect(fs.existsSync(out)).toBe(false);
  });

  it('refuses before reading the SBOM, so an unlicensed run cannot be used as a free file validator', async () => {
    const result = await runReport({
      path: NPM_FIXTURE,
      productionOnly: true,
      formats: ['fda-pack'],
      out: path.join(scratch, 'pack'),
      sbomPaths: [path.join(scratch, 'does-not-exist.json')],
      keyFilePath: noKeyFile,
      ...HERMETIC,
    });
    // Exit 3, not the exit 2 an unreadable --sbom would give: gating runs first.
    expect(result.exitCode).toBe(EXIT_UNLICENSED);
  });
});

describe('runReport — the usage rules around the FDA format', () => {
  const HERMETIC = { env: {} as NodeJS.ProcessEnv };
  const base = { path: NPM_FIXTURE, productionOnly: true, ...HERMETIC };

  it('refuses fda-pack combined with any other format, before any gating or scanning', async () => {
    for (const formats of [['fda-pack', 'annex7'], ['fda-pack', 'sbom-cyclonedx'], ['sbom-spdx', 'fda-pack']]) {
      const result = await runReport({ ...base, formats });
      expect(result.exitCode).toBe(2);
      expect(result.output).toContain('fda-pack must be requested on its own');
    }
  });

  it('refuses --sbom with a non-FDA format rather than ignoring the file', async () => {
    const result = await runReport({ ...base, formats: ['sbom-cyclonedx'], sbomPaths: [FIRMWARE_SBOM] });
    expect(result.exitCode).toBe(2);
    expect(result.output).toContain('--sbom is only read by the FDA formats');
  });

  it('still accepts every pre-existing format list unchanged', async () => {
    // The whole CRA surface must behave exactly as it did. An unknown format
    // is still exit 2 with the valid list, which now includes fda-pack.
    const result = await runReport({ ...base, formats: ['annex-7'] });
    expect(result.exitCode).toBe(2);
    expect(result.output).toContain('unknown format "annex-7"');
    expect(result.output).toContain('fda-pack');
  });
});

describe('runScan --profile fda — the free view needs no key and no network', () => {
  it('runs against an imported firmware SBOM in a directory with no scannable project', async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-fda-scan-'));
    const result = await runScan({
      path: scratch,
      productionOnly: true,
      format: 'json',
      projectLicenseOverride: undefined,
      profile: 'fda',
      sbomPaths: [FIRMWARE_SBOM],
      colorEnabled: false,
      asOf: '2026-10-31',
      generatedAt: '2026-10-31T00:00:00.000Z',
    });
    const json = JSON.parse(result.output);
    expect(json.profile).toBe('fda');
    expect(json.counts.components).toBe(4);
    expect(json.device.name).toBe('acme-glucose-monitor');
    // The firmware case: no lockfile is not an error, it is the normal state.
    expect(json.warnings.join(' ')).toContain('no components came from a repo scan');
    expect(json.inputs.repoScan).toBeUndefined();
  });

  it('fails with exit 2, naming --sbom, when there is neither a project nor an SBOM', async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-fda-empty-'));
    const result = await runScan({
      path: scratch,
      productionOnly: true,
      format: 'summary',
      projectLicenseOverride: undefined,
      profile: 'fda',
      colorEnabled: false,
    });
    expect(result.exitCode).toBe(2);
    expect(result.output).toContain('--sbom <file.json>');
  });

  it('refuses an unsupported SBOM with exit 2 and a message naming what the file actually is', async () => {
    const result = await runScan({
      path: NPM_FIXTURE,
      productionOnly: true,
      format: 'summary',
      projectLicenseOverride: undefined,
      profile: 'fda',
      sbomPaths: [path.join(FIXTURES, 'sbom-import', 'spdx-2.3-tiny.json')],
      colorEnabled: false,
    });
    expect(result.exitCode).toBe(2);
    expect(result.output).toContain('SPDX JSON document');
  });

  it('refuses --sbom on the cra profile rather than ignoring it', async () => {
    const result = await runScan({
      path: NPM_FIXTURE,
      productionOnly: true,
      format: 'summary',
      projectLicenseOverride: undefined,
      sbomPaths: [FIRMWARE_SBOM],
      colorEnabled: false,
    });
    expect(result.exitCode).toBe(2);
    expect(result.output).toContain('--sbom is only read by the FDA profile');
  });

  it('leaves the cra profile byte-identical to a run with no profile argument at all', async () => {
    const opts = {
      path: NPM_FIXTURE,
      productionOnly: true,
      format: 'json' as const,
      projectLicenseOverride: undefined,
      colorEnabled: false,
    };
    const before = await runScan(opts);
    const explicit = await runScan({ ...opts, profile: 'cra' as const });
    // scanTimestamp differs between runs; everything else must not.
    const strip = (s: string) => s.replace(/"scanTimestamp": "[^"]*"/, '');
    expect(strip(explicit.output)).toBe(strip(before.output));
    expect(explicit.exitCode).toBe(before.exitCode);
  });
});

describe('scan --profile fda is report-only by default', () => {
  /**
   * The exit code is the whole subject here. Three FDA items are permanently
   * NEEDS-HUMAN-INPUT by design, so the CRA default threshold would fail every
   * run of this profile forever — red on a flawless SBOM, which trains people
   * to ignore the exit code entirely. Report-only is the default; failing a
   * build is opt-in.
   *
   * Also pinned: the CRA profile's default did NOT move. That is the promise
   * made to every workflow already running `ceproof scan`.
   */
  const fdaScan = (failOn?: 'human-required' | 'partial' | 'never') =>
    runScan({
      path: NPM_FIXTURE,
      productionOnly: true,
      format: 'json',
      projectLicenseOverride: undefined,
      profile: 'fda',
      sbomPaths: [FIRMWARE_SBOM],
      colorEnabled: false,
      asOf: '2026-10-31',
      generatedAt: '2026-10-31T00:00:00.000Z',
      ...(failOn ? { failOn } : {}),
    });

  it('exits 0 with no --fail-on, even though items still need human input', async () => {
    const result = await fdaScan();
    const json = JSON.parse(result.output);
    // Sanity: the scenario this test needs is real, not an empty run.
    expect(json.items.some((i: { status: string }) => i.status === 'NEEDS-HUMAN-INPUT')).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it('still reports every finding — report-only changes the exit code and nothing else', async () => {
    const reportOnly = await fdaScan();
    const failing = await fdaScan('human-required');
    expect(reportOnly.output).toBe(failing.output);
    expect(failing.exitCode).toBe(1);
  });

  it('fails the build when asked explicitly: --fail-on partial and --fail-on human-required', async () => {
    expect((await fdaScan('partial')).exitCode).toBe(1);
    expect((await fdaScan('human-required')).exitCode).toBe(1);
  });

  it('did not move the CRA default: no --profile and no --fail-on still exits 1', async () => {
    const result = await runScan({
      path: NPM_FIXTURE,
      productionOnly: true,
      format: 'json',
      projectLicenseOverride: undefined,
      colorEnabled: false,
    });
    const json = JSON.parse(result.output);
    expect(json.gapChecklist.some((i: { status: string }) => i.status === 'NEEDS-HUMAN-INPUT')).toBe(true);
    expect(result.exitCode).toBe(1);
  });

  it('DEFAULT_FAIL_ON names both profiles, so neither default can be changed silently', () => {
    expect(DEFAULT_FAIL_ON).toEqual({ cra: 'human-required', fda: 'never' });
  });
});
