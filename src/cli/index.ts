#!/usr/bin/env node
import { Command } from 'commander';
import { runScan, SCAN_PROFILES } from './scan';
import type { FailOnMode, ScanProfile } from './scan';
import { runInit } from './init';
import { runReport } from './report';
import { runActivate } from './activate';
import { runDeactivate } from './deactivate';
import { getToolVersion } from '../toolVersion';
import { PRODUCT_NAME } from '../branding';

// M1 shipped `scan` and `init`. M2 added `report` (the Annex VII pack, Annex V
// DoC draft, and standalone SBOM formats). M3 gates the narrative formats
// (annex7/annex7-pdf/doc/doc-pdf) behind a license key and registers
// `activate`/`deactivate` — see milestone3_brief.md. `sbom-cyclonedx`/
// `sbom-spdx` stay free.

const FAIL_ON_MODES: FailOnMode[] = ['human-required', 'partial', 'never'];

/**
 * Commander option parser for a repeatable/comma-separated `--format` flag:
 * `--format annex7,doc` and `--format annex7 --format doc` are equivalent.
 * Raw values are collected as-is here; format-name validity is checked
 * downstream in runReport, not here.
 */
function collectFormats(value: string, previous: string[]): string[] {
  return previous.concat(
    value
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
  );
}

/**
 * `--sbom` is repeatable: `--sbom a.json --sbom b.json`. NOT comma-separated,
 * unlike `--format` — a filename can legitimately contain a comma, and
 * splitting on one would turn a readable path into two unreadable ones.
 */
function collectSboms(value: string, previous: string[]): string[] {
  return previous.concat(value);
}

const program = new Command();

program
  .name(PRODUCT_NAME)
  .description('Derive an EU Cyber Resilience Act compliance posture from your repo — offline, informational.')
  .version(getToolVersion());

program
  .command('scan')
  .argument('[path]', 'project path to scan', '.')
  .option('--production-only', 'skip devDependencies (default: true)', true)
  .option('--include-dev', 'include devDependencies (inverse of --production-only)')
  .option('--format <format>', 'output format: summary or json', 'summary')
  .option('--project-license <id>', 'declared license of your own project (SPDX id or expression); overrides package.json')
  .option(
    '--fail-on <mode>',
    'exit code 1 trigger: human-required, partial, or never. Default: human-required for ' +
      '--profile cra, never (report-only) for --profile fda',
    // Deliberately NO commander default: the default depends on --profile, and
    // is resolved once in runScan (DEFAULT_FAIL_ON) so both entry points agree.
  )
  .option('--config <path>', 'path to ceproof.config.json (default: <path>/ceproof.config.json)')
  .option(
    '--profile <profile>',
    'which gap view to compute: cra (EU Cyber Resilience Act, the default) or fda ' +
      '(the free FDA premarket SBOM content view)',
    'cra',
  )
  .option(
    '--sbom <file>',
    'import an existing CycloneDX JSON SBOM (spec 1.4-1.6). Repeatable. Read by --profile fda only; ' +
      'use it for device firmware, which has no lockfile to scan',
    collectSboms,
    [],
  )
  .option('--no-color', 'disable ANSI color output')
  .addHelpText(
    'after',
    '\nProfiles: --profile cra is the original behaviour and the default — nothing\n' +
      'about an existing command changes. --profile fda computes the FDA premarket\n' +
      'SBOM content view instead: same statuses, same --format and --fail-on, same\n' +
      'exit codes, resolved against data/fda-structure.json. It is free and needs no\n' +
      'license key.\n\n' +
      '--profile fda is REPORT-ONLY by default: it exits 0 and puts the findings in\n' +
      'the output, because three of its items can only ever be answered by a human,\n' +
      'so a threshold of human-required would fail every run forever. To fail a build\n' +
      'on it, ask for that explicitly with --fail-on partial or --fail-on\n' +
      'human-required. --profile cra is unchanged: it still defaults to\n' +
      'human-required.\n\n' +
      'The documentation pack itself is\n' +
      `\`${PRODUCT_NAME} report --format fda-pack\`, which does need an FDA-tier key.\n\n` +
      'For device firmware (C/C++, Yocto, Buildroot) there is no lockfile to scan, so\n' +
      'pass your own SBOM:\n' +
      `  ${PRODUCT_NAME} scan --profile fda --sbom firmware.cdx.json\n`,
  )
  .action(async (pathArg: string, options: any) => {
    // undefined when not supplied (or not recognised), so runScan applies the
    // per-profile default rather than this file guessing one profile's answer
    // for both.
    const failOn: FailOnMode | undefined = FAIL_ON_MODES.includes(options.failOn) ? options.failOn : undefined;
    // An unknown --profile is refused rather than silently falling back to
    // cra: a typo'd profile that quietly computes the OTHER view is exactly
    // the kind of silent assumption this repo bans.
    if (!(SCAN_PROFILES as readonly string[]).includes(options.profile)) {
      console.log(`${PRODUCT_NAME} scan: unknown profile "${options.profile}". Valid profiles: ${SCAN_PROFILES.join(', ')}.`);
      process.exit(2);
    }
    const result = await runScan({
      path: pathArg,
      productionOnly: options.includeDev ? false : true,
      format: options.format === 'json' ? 'json' : 'summary',
      projectLicenseOverride: options.projectLicense,
      failOn,
      configPath: options.config,
      colorEnabled: options.color === false ? false : undefined,
      profile: options.profile as ScanProfile,
      sbomPaths: options.sbom,
    });
    console.log(result.output);
    process.exit(result.exitCode);
  });

program
  .command('init')
  .argument('[path]', 'project path to generate ceproof.config.json for', '.')
  .option('--config <path>', 'config file path (default: <path>/ceproof.config.json)')
  .option('--force', 'overwrite an existing config file')
  .action((pathArg: string, options: any) => {
    const result = runInit({ path: pathArg, configPath: options.config, force: Boolean(options.force) });
    console.log(result.output);
    process.exit(result.exitCode);
  });

program
  .command('report')
  .argument('[path]', 'project path to scan', '.')
  .description('generate the Annex VII pack, Annex V DoC draft, and/or SBOM artifacts from a scan')
  .option(
    '--format <formats>',
    'artifact format(s): annex7, annex7-pdf, doc, doc-pdf, sbom-cyclonedx, sbom-spdx, fda-pack. ' +
      'Comma-separated (--format annex7,doc) or repeatable (--format annex7 --format doc). ' +
      'annex7, annex7-pdf, doc, doc-pdf and fda-pack require a license key; sbom-cyclonedx and ' +
      'sbom-spdx are free. fda-pack must be requested on its own.',
    collectFormats,
    []
  )
  .option(
    '--out <path>',
    'output location. With exactly one --format, a literal file path. With multiple formats ' +
      '(or omitted), a directory holding per-format default filenames (annex7.html, annex7.pdf, ' +
      'doc.html, doc.pdf, sbom.cyclonedx.json, sbom.spdx.json). Omitted entirely: ./ceproof-report/ ' +
      '— except fda-pack, which always writes a DIRECTORY of artifacts, defaulting to ./ceproof-fda/'
  )
  .option(
    '--sbom <file>',
    'import an existing CycloneDX JSON SBOM (spec 1.4-1.6). Repeatable. Read by fda-pack only; ' +
      'use it for device firmware, which has no lockfile to scan',
    collectSboms,
    [],
  )
  .option('--key <key>', 'license key (overrides CEPROOF_KEY and the activated key file for this run)')
  .option('--config <path>', 'path to ceproof.config.json (default: <path>/ceproof.config.json)')
  .option('--production-only', 'skip devDependencies (default: true)', true)
  .option('--include-dev', 'include devDependencies (inverse of --production-only)')
  .option('--project-license <id>', 'declared license of your own project (SPDX id or expression); overrides package.json')
  .addHelpText(
    'after',
    '\nGating: annex7, annex7-pdf, doc, doc-pdf and fda-pack require a valid license\n' +
      'key (resolved in order from --key, then $CEPROOF_KEY, then\n' +
      '~/.config/ceproof/license.key). If any requested format is gated and no valid\n' +
      'key is found, the WHOLE request is refused (nothing is written) with exit code\n' +
      '3. sbom-cyclonedx and sbom-spdx alone need no key. Activate a key once with\n' +
      `\`${PRODUCT_NAME} activate <key>\`.\n\n` +
      'Tiers: the CRA tiers (individual, agency) unlock annex7/annex7-pdf/doc/doc-pdf\n' +
      'and are perpetual. The FDA tiers (fda-company, fda-consultant) unlock fda-pack\n' +
      'and are annual. Neither unlocks the other — they are different products. A key\n' +
      'whose subscription has lapsed is reported as lapsed, with the renewal date,\n' +
      'never as an invalid key, and the free commands keep working.\n\n' +
      'The FDA pack: writes a directory of artifacts (enriched CycloneDX SBOM, the\n' +
      'support and end-of-support addendum, the vulnerability table with the two\n' +
      'columns you fill in, the open-items list, the provenance record and\n' +
      'DISCLAIMER.md). For device firmware, pass your own SBOM:\n' +
      `  ${PRODUCT_NAME} report --format fda-pack --sbom firmware.cdx.json --out ./fda-pack\n` +
      `The free diagnosis is \`${PRODUCT_NAME} scan --profile fda\`.\n\n` +
      'Exit codes: 0 success (open items in the content do not fail the command) ·\n' +
      '2 usage/tool error · 3 a gated format was requested without a valid license key,\n' +
      'with a key for the wrong tier, or with a lapsed subscription.'
  )
  .action(async (pathArg: string, options: any) => {
    const result = await runReport({
      path: pathArg,
      productionOnly: options.includeDev ? false : true,
      formats: options.format,
      out: options.out,
      key: options.key,
      configPath: options.config,
      projectLicenseOverride: options.projectLicense,
      sbomPaths: options.sbom,
    });
    console.log(result.output);
    process.exit(result.exitCode);
  });

program
  .command('activate')
  .argument('<key>', 'the license key from your purchase email')
  .description('verify and store a license key so the report command unlocks its paid formats')
  .action((key: string) => {
    const result = runActivate(key);
    console.log(result.output);
    process.exit(result.exitCode);
  });

program
  .command('deactivate')
  .description(`remove the stored license key (~/.config/${PRODUCT_NAME}/license.key); idempotent`)
  .action(() => {
    const result = runDeactivate();
    console.log(result.output);
    process.exit(result.exitCode);
  });

program.parse(process.argv);
