#!/usr/bin/env node
import { Command } from 'commander';
import { runScan } from './scan';
import type { FailOnMode } from './scan';
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
    'exit code 1 trigger: human-required, partial, or never',
    'human-required',
  )
  .option('--config <path>', 'path to ceproof.config.json (default: <path>/ceproof.config.json)')
  .option('--no-color', 'disable ANSI color output')
  .action(async (pathArg: string, options: any) => {
    const failOn: FailOnMode = FAIL_ON_MODES.includes(options.failOn) ? options.failOn : 'human-required';
    const result = await runScan({
      path: pathArg,
      productionOnly: options.includeDev ? false : true,
      format: options.format === 'json' ? 'json' : 'summary',
      projectLicenseOverride: options.projectLicense,
      failOn,
      configPath: options.config,
      colorEnabled: options.color === false ? false : undefined,
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
    'artifact format(s): annex7, annex7-pdf, doc, doc-pdf, sbom-cyclonedx, sbom-spdx. ' +
      'Comma-separated (--format annex7,doc) or repeatable (--format annex7 --format doc). ' +
      'annex7, annex7-pdf, doc, and doc-pdf require a license key; sbom-cyclonedx and ' +
      'sbom-spdx are free.',
    collectFormats,
    []
  )
  .option(
    '--out <path>',
    'output location. With exactly one --format, a literal file path. With multiple formats ' +
      '(or omitted), a directory holding per-format default filenames (annex7.html, annex7.pdf, ' +
      'doc.html, doc.pdf, sbom.cyclonedx.json, sbom.spdx.json). Omitted entirely: ./ceproof-report/'
  )
  .option('--key <key>', 'license key (overrides CEPROOF_KEY and the activated key file for this run)')
  .option('--config <path>', 'path to ceproof.config.json (default: <path>/ceproof.config.json)')
  .option('--production-only', 'skip devDependencies (default: true)', true)
  .option('--include-dev', 'include devDependencies (inverse of --production-only)')
  .option('--project-license <id>', 'declared license of your own project (SPDX id or expression); overrides package.json')
  .addHelpText(
    'after',
    '\nGating: annex7, annex7-pdf, doc, and doc-pdf require a valid license key\n' +
      '(resolved in order from --key, then $CEPROOF_KEY, then\n' +
      '~/.config/ceproof/license.key). If any requested format is gated and no valid\n' +
      'key is found, the WHOLE request is refused (nothing is written) with exit code\n' +
      '3. sbom-cyclonedx and sbom-spdx alone need no key. Activate a key once with\n' +
      `\`${PRODUCT_NAME} activate <key>\`.\n\n` +
      'Exit codes: 0 success (open items in the content do not fail the command) ·\n' +
      '2 usage/tool error · 3 a gated format was requested without a valid license key.'
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
