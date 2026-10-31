"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runScan = runScan;
exports.computeExitCode = computeExitCode;
const reportData_1 = require("../report/reportData");
const summary_1 = require("../report/summary");
const json_1 = require("../report/json");
const detect_1 = require("../detect");
const loader_1 = require("../cra/loader");
const write_1 = require("../config/write");
const validate_1 = require("../config/validate");
const gapEngine_1 = require("../gap/gapEngine");
const branding_1 = require("../branding");
function resolveConfigStatus(configPath) {
    const read = (0, write_1.readConfigFile)(configPath);
    if (!read.present) {
        return { status: { present: false, valid: null, missingAnswers: [] }, config: null };
    }
    if ('parseError' in read) {
        return { status: { present: true, valid: false, errors: [read.parseError], missingAnswers: [] }, config: null };
    }
    const result = (0, validate_1.validateConfig)(read.raw);
    if (result.valid) {
        return { status: { present: true, valid: true, missingAnswers: [] }, config: result.config };
    }
    // An invalid config's fields aren't trustworthy as a whole — we don't cherry-pick
    // .answers out of a shape validateConfig rejected. Treated as "no config" for the
    // gap engine, but the JSON/summary output still honestly reports it as present+invalid.
    return { status: { present: true, valid: false, errors: result.errors, missingAnswers: [] }, config: null };
}
async function runScan(opts) {
    try {
        // Resolved FIRST, before any scan work: a `--config` path that doesn't
        // exist is a usage error, and there's no reason to make the user wait
        // through a full dependency scan to be told about a typo.
        const configPath = (0, write_1.resolveConfigPath)(opts.path, opts.configPath);
        const data = await (0, reportData_1.buildReportData)(opts.path, {
            productionOnly: opts.productionOnly,
            projectLicenseOverride: opts.projectLicenseOverride,
        });
        const facts = (0, detect_1.collectRepoFacts)(opts.path);
        const craStructure = (0, loader_1.getCraStructure)();
        const dataVersion = (0, loader_1.getCraSourceVersion)();
        const { status: configStatusBase, config } = resolveConfigStatus(configPath);
        const gapChecklist = (0, gapEngine_1.computeGapChecklist)(facts, data.packages, config, craStructure.items);
        // Fill in missingAnswers from the computed checklist now that we have it —
        // this is the single source of truth for "which human-required items still
        // need an answer", never recomputed a second, possibly-divergent way.
        const configStatus = {
            ...configStatusBase,
            missingAnswers: gapChecklist.filter((i) => i.status === 'NEEDS-HUMAN-INPUT').map((i) => i.id),
        };
        const output = opts.format === 'json'
            ? JSON.stringify((0, json_1.buildJsonReport)({
                projectName: data.projectName,
                toolVersion: data.toolVersion,
                dataVersion,
                scanTimestamp: data.scanTimestamp,
                facts,
                gapChecklist,
                configStatus,
                warnings: data.warnings,
            }), null, 2)
            : (0, summary_1.renderSummary)({
                projectName: data.projectName,
                toolVersion: data.toolVersion,
                dataVersion,
                scanTimestamp: data.scanTimestamp,
                gapChecklist,
                configPresent: configStatus.present,
                colorEnabled: opts.colorEnabled ?? (process.stdout.isTTY === true && process.env.NO_COLOR === undefined),
            });
        const exitCode = computeExitCode(gapChecklist, opts.failOn ?? 'human-required');
        return { exitCode, output };
    }
    catch (err) {
        return { exitCode: 2, output: `${branding_1.PRODUCT_NAME}: ${err.message}` };
    }
}
function computeExitCode(gapChecklist, failOn) {
    if (failOn === 'never')
        return 0;
    const hasNeedsHuman = gapChecklist.some((i) => i.status === 'NEEDS-HUMAN-INPUT');
    const hasPartial = gapChecklist.some((i) => i.status === 'PARTIAL');
    if (failOn === 'human-required' && hasNeedsHuman)
        return 1;
    if (failOn === 'partial' && (hasNeedsHuman || hasPartial))
        return 1;
    return 0;
}
//# sourceMappingURL=scan.js.map