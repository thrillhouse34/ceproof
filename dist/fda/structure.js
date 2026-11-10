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
exports.FDA_MEASURES = void 0;
exports.isFdaMeasure = isFdaMeasure;
exports.parseFdaStructure = parseFdaStructure;
exports.getFdaStructure = getFdaStructure;
exports.getFdaStructureVersion = getFdaStructureVersion;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const paths_1 = require("../paths");
/**
 * `data/fda-structure.json`: the content items FDA's premarket cybersecurity
 * guidance asks for around the SBOM, extracted from the vendored primary text
 * and held to the same traceability standard as `data/cra-structure.json` —
 * every item's `sourceExcerpt` must appear verbatim in the file it cites
 * (`tests/fda/structure.test.ts`).
 *
 * Why this is a separate file and a separate loader from `src/cra/loader.ts`
 * rather than a second instrument on the CRA one: a `CraStructureItem` carries
 * an `instrument` of `annexVII | annexV` and `evidenceKeys` that are dot-paths
 * into `RepoFacts`. Neither means anything here. The FDA items resolve against
 * the FDA mode's own three engine results (the merged component list, the
 * support resolution, the KEV screen), not against repo facts, so they carry a
 * `measure` naming which of those metrics answers the item instead. Widening
 * the CRA types to cover both would make `instrument` and `evidenceKeys`
 * optional for every CRA item in order to serve a mode that does not use them.
 *
 * The resolution vocabulary IS shared — `GapStatus`, and the
 * DERIVED/PARTIAL/NEEDS-HUMAN-INPUT meanings — because a user reading both
 * views should not have to learn two scales. See `src/fda/gap.ts`.
 */
/**
 * Which run metric answers an item. A closed set: `src/fda/gap.ts` owns one
 * resolver per value, and `tests/fda/structure.test.ts` asserts the set in the
 * data file and the set the resolver handles are the SAME set, in both
 * directions — an item with a measure nothing resolves would silently render
 * as an unexplained gap, and a resolver for a measure no item names is dead
 * code that looks like coverage.
 */
exports.FDA_MEASURES = [
    'sbom-provided',
    'ntia-minimum-elements',
    'support-placement',
    'support-level',
    'end-of-support-date',
    'unknown-justification',
    'all-known-vulnerabilities',
    'kev-screen',
    'how-discovered',
    'risk-assessment',
    'risk-controls',
    'kev-designed-out',
    'cyber-device-determination',
];
function isFdaMeasure(value) {
    return typeof value === 'string' && exports.FDA_MEASURES.includes(value);
}
function assertString(value, field, where) {
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`Malformed FDA structure data: ${where} field "${field}" must be a non-empty string`);
    }
    return value;
}
function parseFdaStructure(raw) {
    if (typeof raw !== 'object' || raw === null) {
        throw new Error('Malformed FDA structure data: expected a top-level object');
    }
    const data = raw;
    if (!Array.isArray(data.items)) {
        throw new Error('Malformed FDA structure data: field "items" must be an array');
    }
    const seen = new Set();
    const items = data.items.map((raw, index) => {
        const where = `items[${index}]`;
        if (typeof raw !== 'object' || raw === null)
            throw new Error(`Malformed FDA structure data: ${where} must be an object`);
        const item = raw;
        const id = assertString(item.id, 'id', where);
        // A duplicate id would make one of the two items unreachable by id in the
        // JSON output, which is the surface a CI pipeline keys off.
        if (seen.has(id))
            throw new Error(`Malformed FDA structure data: duplicate item id "${id}"`);
        seen.add(id);
        if (!isFdaMeasure(item.measure)) {
            throw new Error(`Malformed FDA structure data: ${where} field "measure" must be one of ${exports.FDA_MEASURES.join(', ')}`);
        }
        return {
            id,
            requirementSummary: assertString(item.requirementSummary, 'requirementSummary', where),
            citation: assertString(item.citation, 'citation', where),
            sourceFile: assertString(item.sourceFile, 'sourceFile', where),
            sourceExcerpt: assertString(item.sourceExcerpt, 'sourceExcerpt', where),
            measure: item.measure,
        };
    });
    return {
        sourceVersion: assertString(data.sourceVersion, 'sourceVersion', 'root'),
        shortVersion: assertString(data.shortVersion, 'shortVersion', 'root'),
        generatedAt: assertString(data.generatedAt, 'generatedAt', 'root'),
        notVendored: assertString(data.notVendored, 'notVendored', 'root'),
        items,
    };
}
let cached;
function getFdaStructure(dataDir = paths_1.DATA_DIR) {
    if (cached)
        return cached;
    const filePath = path.join(dataDir, 'fda-structure.json');
    let raw;
    try {
        raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
    catch (err) {
        throw new Error(`Failed to read/parse FDA structure data at ${filePath}: ${err.message}`);
    }
    cached = parseFdaStructure(raw);
    return cached;
}
function getFdaStructureVersion(dataDir) {
    return getFdaStructure(dataDir).sourceVersion;
}
//# sourceMappingURL=structure.js.map