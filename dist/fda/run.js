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
exports.NoComponentsError = exports.SbomImportError = void 0;
exports.runFda = runFda;
/**
 * One run of the FDA mode: inputs in, a joined `FdaRenderInput` out.
 *
 * Both CLI surfaces need exactly this — `scan --profile fda` renders the free
 * gap view from it, `report --format fda-pack` renders the paid artifacts from
 * it — and they must agree about what was found, or the free view becomes a
 * sales pitch for a different document. So the assembly happens once, here,
 * and neither command owns any part of it.
 *
 * It lives under src/fda rather than src/cli so that
 * `tests/fda/offline.test.ts` covers it: this is the file that would be most
 * tempting to "just fetch the latest KEV data" from, and it is the one place
 * in the mode where a network call would look reasonable. It makes none. The
 * only I/O is reading the user's SBOM files (through `importSbomFile`) and the
 * vendored snapshots (through `resolveSupport`/`screenKev`, both of which
 * resolve `DATA_DIR` themselves).
 *
 * `NoProjectFoundError` is DOWNGRADED to a warning when an SBOM was supplied.
 * That is the whole point of the mode: a device-firmware repo is C/C++, has no
 * lockfile, and is not a scannable project — refusing to run there would make
 * the import path unreachable for exactly the customers it exists for. With
 * neither an SBOM nor a scannable project, the run fails with a usage error
 * that says so.
 */
const path = __importStar(require("path"));
const toolVersion_1 = require("../toolVersion");
const reportData_1 = require("../report/reportData");
const write_1 = require("../config/write");
const validate_1 = require("../config/validate");
const importSbom_1 = require("./importSbom");
Object.defineProperty(exports, "SbomImportError", { enumerable: true, get: function () { return importSbom_1.SbomImportError; } });
const merge_1 = require("./merge");
const support_1 = require("./support");
const kev_1 = require("./kev");
const input_1 = require("./render/input");
/** Nothing to screen. Exit 2 at the CLI, with nothing written. */
class NoComponentsError extends Error {
    constructor(message) {
        super(message);
        this.name = 'NoComponentsError';
    }
}
exports.NoComponentsError = NoComponentsError;
function readConfig(configPath) {
    const read = (0, write_1.readConfigFile)(configPath);
    if (!read.present || 'parseError' in read)
        return null;
    const result = (0, validate_1.validateConfig)(read.raw);
    return result.valid ? result.config : null;
}
/**
 * The device the pack is about. An imported SBOM's own `metadata.component`
 * is authoritative — it is the producer's statement about what they built —
 * and the config's `product.name` is the fallback. Never the scanned
 * directory's name: a directory is not a device.
 *
 * The FIRST imported SBOM's subject wins when several name one, and the
 * disagreement is warned about rather than resolved silently.
 */
function resolveSubject(subjects, config, warnings) {
    if (subjects.length > 1) {
        const names = subjects.map((s) => `"${s.subject.name}" (${s.label})`);
        const distinct = new Set(subjects.map((s) => s.subject.name));
        if (distinct.size > 1) {
            warnings.push(`More than one imported SBOM names a different subject: ${names.join(', ')}. ` +
                `The first was used as the device this pack describes. If that is wrong, run them separately or set product.name in ceproof.config.json.`);
        }
    }
    if (subjects.length > 0)
        return subjects[0].subject;
    if (config?.product?.name) {
        return {
            name: config.product.name,
            type: 'device',
            licenses: [],
            hashes: [],
            properties: {},
            origins: ['override'],
        };
    }
    return undefined;
}
async function runFda(options) {
    const asOf = options.asOf ?? new Date().toISOString().slice(0, 10);
    const generatedAt = options.generatedAt ?? new Date().toISOString();
    const config = readConfig((0, write_1.resolveConfigPath)(options.path, options.configPath));
    const warnings = [];
    // SBOMs first: an SbomImportError is a usage error about a file the user
    // named, and there is no reason to make them wait through a dependency scan
    // to hear about a typo'd path or an SPDX file.
    const sources = [];
    const dependencies = [];
    const subjects = [];
    const sbomInputs = [];
    for (const sbomPath of options.sbomPaths) {
        const imported = (0, importSbom_1.importSbomFile)(sbomPath);
        sources.push(imported.components);
        dependencies.push(...imported.dependencies);
        if (imported.subject)
            subjects.push({ label: imported.sourceLabel, subject: imported.subject });
        sbomInputs.push({
            sourceLabel: imported.sourceLabel,
            specVersion: imported.specVersion,
            ...(imported.sha256 ? { sha256: imported.sha256 } : {}),
            componentCount: imported.components.length,
        });
        warnings.push(...imported.warnings);
    }
    let scanPath;
    try {
        const data = await (0, reportData_1.buildReportData)(options.path, { productionOnly: options.productionOnly });
        const scanned = (0, merge_1.componentsFromScan)(data.packages);
        if (scanned.length > 0) {
            sources.push(scanned);
            scanPath = path.resolve(options.path);
        }
        warnings.push(...data.warnings);
    }
    catch (err) {
        if (!(err instanceof reportData_1.NoProjectFoundError))
            throw err;
        if (sbomInputs.length === 0) {
            throw new NoComponentsError(`${err.message}. For device firmware there is usually no lockfile to scan — supply your own SBOM with --sbom <file.json> (CycloneDX JSON, spec 1.4-1.6).`);
        }
        // Expected, not exceptional: this is the firmware case.
        warnings.push(`No npm or PyPI project was found at ${path.resolve(options.path)}, so no components came from a repo scan. ` +
            `Everything in this run came from the imported SBOM${sbomInputs.length === 1 ? '' : 's'}.`);
    }
    const merged = (0, merge_1.mergeComponents)(sources);
    if (merged.components.length === 0) {
        throw new NoComponentsError('No software components were found to screen. An imported SBOM with no components, and no scannable project, leaves nothing to report on.');
    }
    const support = (0, support_1.resolveSupport)(merged.components, { asOf, ...(config?.fda ? { fda: config.fda } : {}) });
    const kev = (0, kev_1.screenKev)(merged.components, { asOf });
    const input = {
        asOf,
        generatedAt,
        toolVersion: (0, toolVersion_1.getToolVersion)(),
        ...(() => {
            const subject = resolveSubject(subjects, config, warnings);
            return subject ? { subject } : {};
        })(),
        // "Author of the SBOM data" is an NTIA minimum element and only the
        // manufacturer can supply it. Absent stays absent.
        ...(config?.manufacturer?.name ? { sbomAuthor: config.manufacturer.name } : {}),
        support,
        kev,
        mergeWarnings: [...warnings, ...merged.warnings],
        sbomInputs,
        ...(scanPath ? { scanPath } : {}),
        ...(dependencies.length > 0 ? { dependencies } : {}),
    };
    return { input, rows: (0, input_1.joinRows)(input), config };
}
//# sourceMappingURL=run.js.map