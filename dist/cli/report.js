"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.EXIT_UNLICENSED = exports.REPORT_FORMATS = void 0;
exports.runReport = runReport;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const reportData_1 = require("../report/reportData");
const html_1 = require("../report/html");
const pdf_1 = require("../report/pdf");
const cyclonedx_1 = require("../report/sbom/cyclonedx");
const spdx_1 = require("../report/sbom/spdx");
const annexContent_1 = require("../report/annexContent");
const provenance_1 = require("../report/provenance");
const detect_1 = require("../detect");
const loader_1 = require("../cra/loader");
const write_1 = require("../config/write");
const validate_1 = require("../config/validate");
const gapEngine_1 = require("../gap/gapEngine");
const discovery_1 = require("../license/discovery");
const verify_1 = require("../license/verify");
const dataCurrency_1 = require("../license/dataCurrency");
const branding_1 = require("../branding");
// `report` renders the paid Annex VII technical documentation pack and
// Annex V Declaration of Conformity draft (both driven by the same
// data/cra-structure.json + gap-checklist engine `scan` uses), plus the free
// standalone SBOM formats. See milestone2_brief.md for the M2 content model
// and milestone3_brief.md (M3) for the gating below.
exports.REPORT_FORMATS = ['annex7', 'annex7-pdf', 'doc', 'doc-pdf', 'sbom-cyclonedx', 'sbom-spdx'];
/**
 * The four narrative formats — the actual paid product — require a valid
 * license key. `sbom-cyclonedx`/`sbom-spdx` stay free: per the M1 plan's
 * SBOM-placement decision, the SBOM isn't the differentiated paid product —
 * it's largely mechanical output of the already-free `scan` engine, and
 * CRA's Annex VII SBOM requirement is closer to required plumbing than
 * compiled deliverable. The paid product is the compiled, cited, per-release
 * narrative pack + DoC.
 */
const GATED_FORMATS = new Set(['annex7', 'annex7-pdf', 'doc', 'doc-pdf']);
/** Request refused for lack of a key. */
exports.EXIT_UNLICENSED = 3;
/**
 * The friendly, non-naggy refusal shown when a gated format is requested
 * without a valid key. States what the paid report includes, the price, and
 * where to buy.
 */
const UNLICENSED_MESSAGE = [
    `This report format needs a ${branding_1.PRODUCT_NAME} license.`,
    '',
    'The paid report gives you an audit-ready Annex VII technical documentation',
    `pack and Annex V Declaration of Conformity draft. It is a perpetual license:`,
    `${branding_1.PRICE_INDIVIDUAL} individual, ${branding_1.PRICE_AGENCY} agency. See samples and buy a key at ${branding_1.PRODUCT_URL}`,
    '',
    `Already have a key? Run:  ${branding_1.PRODUCT_NAME} activate <key>`,
    'The free scan, JSON output, and SBOM formats never need a key.',
].join('\n');
/** Default per-format filenames used whenever `--out` names a directory (or is omitted). */
const DEFAULT_FILENAMES = {
    annex7: 'annex7.html',
    'annex7-pdf': 'annex7.pdf',
    doc: 'doc.html',
    'doc-pdf': 'doc.pdf',
    'sbom-cyclonedx': 'sbom.cyclonedx.json',
    'sbom-spdx': 'sbom.spdx.json',
};
/** Default output directory when `--out` is omitted. */
const DEFAULT_OUT_DIR = `./${branding_1.PRODUCT_NAME}-report`;
const VALID_LIST = exports.REPORT_FORMATS.join(', ');
/**
 * Resolves the on-disk config (if any) into a `CeproofConfig | null` for the
 * content builders. An absent or invalid config degrades to `null` — every
 * item that would have needed it just renders as an honest open item; this
 * never throws.
 */
function resolveConfig(configPath) {
    const read = (0, write_1.readConfigFile)(configPath);
    if (!read.present || 'parseError' in read)
        return null;
    const result = (0, validate_1.validateConfig)(read.raw);
    return result.valid ? result.config : null;
}
/**
 * The shared scan+facts+gap-checklist+provenance assembly both annex7 and doc
 * formats need. Computed at most once per `runReport` call regardless of how
 * many of the two formats are requested together (see the memoized call site
 * in `renderFormat`'s caller).
 */
async function buildAnnexContext(opts) {
    const data = await (0, reportData_1.buildReportData)(opts.path, {
        productionOnly: opts.productionOnly,
        projectLicenseOverride: opts.projectLicenseOverride,
    });
    const facts = (0, detect_1.collectRepoFacts)(opts.path);
    const craStructure = (0, loader_1.getCraStructure)();
    const dataVersion = (0, loader_1.getCraSourceVersion)();
    const configPath = opts.configPath ?? path.join(opts.path, 'ceproof.config.json');
    const config = resolveConfig(configPath);
    const gapChecklist = (0, gapEngine_1.computeGapChecklist)(facts, data.packages, config, craStructure.items);
    const provenance = (0, provenance_1.computeProvenance)({
        toolVersion: data.toolVersion,
        dataVersion,
        scanTimestamp: data.scanTimestamp,
        vcs: facts.vcs,
    });
    return { data, provenance, craItems: craStructure.items, config, gapChecklist };
}
/** Produce the artifact bytes for one format. String artifacts and the binary PDFs are both handled. */
async function renderFormat(fmt, sbomData, annexCtx) {
    switch (fmt) {
        case 'annex7': {
            const ctx = annexCtx;
            const content = (0, annexContent_1.computeAnnexViiPackContent)(ctx.craItems, ctx.gapChecklist, ctx.config, ctx.provenance, ctx.data.projectName);
            return (0, html_1.renderAnnexHtml)(content);
        }
        case 'annex7-pdf': {
            const ctx = annexCtx;
            const content = (0, annexContent_1.computeAnnexViiPackContent)(ctx.craItems, ctx.gapChecklist, ctx.config, ctx.provenance, ctx.data.projectName);
            return (0, pdf_1.renderAnnexPdf)((0, html_1.renderAnnexHtml)(content), content);
        }
        case 'doc': {
            const ctx = annexCtx;
            const content = (0, annexContent_1.computeAnnexVDocContent)(ctx.craItems, ctx.gapChecklist, ctx.config, ctx.provenance, ctx.data.projectName);
            return (0, html_1.renderAnnexHtml)(content);
        }
        case 'doc-pdf': {
            const ctx = annexCtx;
            const content = (0, annexContent_1.computeAnnexVDocContent)(ctx.craItems, ctx.gapChecklist, ctx.config, ctx.provenance, ctx.data.projectName);
            return (0, pdf_1.renderAnnexPdf)((0, html_1.renderAnnexHtml)(content), content);
        }
        case 'sbom-cyclonedx':
            return (0, cyclonedx_1.renderCycloneDx)(sbomData);
        case 'sbom-spdx':
            return (0, spdx_1.renderSpdx)(sbomData);
    }
}
const ANNEX_FORMATS = new Set(['annex7', 'annex7-pdf', 'doc', 'doc-pdf']);
/**
 * Validate + de-duplicate the requested formats. Returns the ordered unique
 * format list on success, or an error message string on failure (unknown value
 * or empty request) — never silently drops a typo'd format.
 */
function validateFormats(requested) {
    if (requested.length === 0) {
        return { error: `${branding_1.PRODUCT_NAME} report: at least one --format is required (${VALID_LIST}).` };
    }
    const seen = new Set();
    const formats = [];
    for (const raw of requested) {
        const value = raw.trim();
        if (!exports.REPORT_FORMATS.includes(value)) {
            return { error: `${branding_1.PRODUCT_NAME} report: unknown format "${raw}". Valid formats: ${VALID_LIST}.` };
        }
        if (!seen.has(value)) {
            seen.add(value);
            formats.push(value);
        }
    }
    return { formats };
}
/**
 * `--out` reconciliation (documented in the CLI --help and README): honor `--out`
 * as a literal file path ONLY when exactly one format was requested; otherwise
 * (multiple formats, or `--out` omitted) treat it as an output DIRECTORY and
 * write each artifact under it with its default filename. When `--out` is omitted
 * entirely, default to the product's default report dir regardless of format count. Returns
 * the absolute target path for each requested format.
 */
function resolveOutputTargets(formats, out) {
    if (out !== undefined && formats.length === 1) {
        return [{ format: formats[0], target: path.resolve(out) }];
    }
    const dir = path.resolve(out ?? DEFAULT_OUT_DIR);
    return formats.map((format) => ({ format, target: path.join(dir, DEFAULT_FILENAMES[format]) }));
}
async function runReport(opts) {
    // Validate formats FIRST, before any scan work or filesystem writes, so an
    // unknown/typo'd format fails cleanly with nothing written.
    const validated = validateFormats(opts.formats);
    if ('error' in validated) {
        return { exitCode: 2, output: validated.error };
    }
    const formats = validated.formats;
    // GATING — WHOLE-REQUEST, NOT PER-ARTIFACT (deliberate design decision).
    //
    // If ANY requested format in this single invocation is gated, the request
    // needs a valid key; without one we refuse the ENTIRE request (write
    // nothing, exit 3) even if a free `sbom-cyclonedx` was also requested
    // alongside. A request for ONLY free formats needs no key and proceeds
    // exactly as before.
    //
    // Rationale: gating per-artifact-within-one-invocation would mean
    // partially fulfilling a request (writing the free SBOM, skipping the
    // paid pack) and then having to pick a mixed exit code — a confusing
    // "some of what you asked for" outcome. Whole-request gating is
    // unambiguous: the invocation either fully succeeds or writes nothing.
    const needsKey = formats.some((f) => GATED_FORMATS.has(f));
    let license = null;
    if (needsKey) {
        const keyString = (0, discovery_1.discoverLicenseKey)({
            cliKey: opts.key,
            env: opts.env,
            keyFilePath: opts.keyFilePath,
        });
        license = keyString ? (0, verify_1.verifyLicenseKey)(keyString) : null;
        if (!license) {
            // Refuse the whole request. Nothing is scanned, nothing is written.
            return { exitCode: exports.EXIT_UNLICENSED, output: UNLICENSED_MESSAGE };
        }
    }
    let sbomData;
    let annexCtx;
    try {
        // annex7/annex7-pdf/doc/doc-pdf all need the fuller AnnexContext (facts,
        // gap checklist, provenance) — computed once and reused across however
        // many of those four formats were requested together, never per-format.
        // sbom-cyclonedx/sbom-spdx only need the base ReportData; if any annex
        // format is ALSO requested, annexCtx.data is the identical ReportData
        // and is reused directly rather than scanning twice.
        if (formats.some((f) => ANNEX_FORMATS.has(f))) {
            annexCtx = await buildAnnexContext(opts);
            sbomData = annexCtx.data;
        }
        else {
            sbomData = await (0, reportData_1.buildReportData)(opts.path, {
                productionOnly: opts.productionOnly,
                projectLicenseOverride: opts.projectLicenseOverride,
            });
        }
    }
    catch (err) {
        if (err instanceof reportData_1.NoProjectFoundError) {
            // Match the `scan` command's exit-2 "no project" style, extended to name
            // the `report` command. Nothing is written.
            return { exitCode: 2, output: `${branding_1.PRODUCT_NAME} report: ${err.message}. No artifacts were generated.` };
        }
        return { exitCode: 2, output: `${branding_1.PRODUCT_NAME} report: ${err.message}` };
    }
    const targets = resolveOutputTargets(formats, opts.out);
    const written = [];
    try {
        for (const { format, target } of targets) {
            fs.mkdirSync(path.dirname(target), { recursive: true });
            const content = await renderFormat(format, sbomData, annexCtx);
            fs.writeFileSync(target, content);
            written.push(target);
        }
    }
    catch (err) {
        // Covers, among other things, a PDF format requested with no installed
        // browser (renderAnnexPdf throws NO_BROWSER_MESSAGE) — exit 2, per
        // addendum D ("tool/runtime error"), same bucket as every other render
        // failure. An open item in the rendered CONTENT is never an error here —
        // only a genuine failure to produce the artifact is.
        return { exitCode: 2, output: `${branding_1.PRODUCT_NAME} report: ${err.message}` };
    }
    const lines = [
        `${branding_1.PRODUCT_NAME}: wrote ${written.length} report artifact${written.length === 1 ? '' : 's'}:`,
        ...written.map((w) => `  ${w}`),
    ];
    // Data-currency FYI: when a gated format was generated with a valid key AND
    // the installed reference data postdates the key's update window, append
    // ONE purely informational line. Report generation is perpetual and
    // completely unaffected — this never nags, degrades, or blocks.
    if (license) {
        const note = (0, dataCurrency_1.dataCurrencyNote)(license.updatesUntil, sbomData.dataVersion);
        if (note)
            lines.push('', note);
    }
    return { exitCode: 0, output: lines.join('\n') };
}
//# sourceMappingURL=report.js.map