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
exports.parseCraStructure = parseCraStructure;
exports.getCraStructure = getCraStructure;
exports.getCraSourceVersion = getCraSourceVersion;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const paths_1 = require("../paths");
const VALID_INSTRUMENTS = ['annexVII', 'annexV'];
const VALID_DERIVABILITY = ['derivable', 'partial', 'human-required', 'boilerplate'];
function isNonEmptyString(v) {
    return typeof v === 'string' && v.length > 0;
}
function assertString(value, field, itemLabel) {
    if (!isNonEmptyString(value)) {
        throw new Error(`Malformed CRA structure data: ${itemLabel} field "${field}" must be a non-empty string`);
    }
}
function validateItem(raw, index) {
    const itemLabel = `items[${index}]`;
    if (typeof raw !== 'object' || raw === null) {
        throw new Error(`Malformed CRA structure data: ${itemLabel} must be an object`);
    }
    const item = raw;
    assertString(item.id, 'id', itemLabel);
    assertString(item.requirementSummary, 'requirementSummary', itemLabel);
    assertString(item.citation, 'citation', itemLabel);
    assertString(item.sourceFile, 'sourceFile', itemLabel);
    assertString(item.sourceExcerpt, 'sourceExcerpt', itemLabel);
    if (typeof item.instrument !== 'string' || !VALID_INSTRUMENTS.includes(item.instrument)) {
        throw new Error(`Malformed CRA structure data: ${itemLabel} field "instrument" must be one of ${VALID_INSTRUMENTS.join(', ')}`);
    }
    if (typeof item.derivability !== 'string' || !VALID_DERIVABILITY.includes(item.derivability)) {
        throw new Error(`Malformed CRA structure data: ${itemLabel} field "derivability" must be one of ${VALID_DERIVABILITY.join(', ')}`);
    }
    if (!Array.isArray(item.evidenceKeys) || !item.evidenceKeys.every((k) => typeof k === 'string')) {
        throw new Error(`Malformed CRA structure data: ${itemLabel} field "evidenceKeys" must be an array of strings`);
    }
    if (item.derivability === 'boilerplate') {
        assertString(item.boilerplateText, 'boilerplateText', itemLabel);
    }
    else if (item.boilerplateText !== undefined) {
        throw new Error(`Malformed CRA structure data: ${itemLabel} has "boilerplateText" set but derivability is not "boilerplate"`);
    }
    return {
        id: item.id,
        instrument: item.instrument,
        requirementSummary: item.requirementSummary,
        citation: item.citation,
        sourceFile: item.sourceFile,
        sourceExcerpt: item.sourceExcerpt,
        derivability: item.derivability,
        evidenceKeys: item.evidenceKeys,
        ...(item.boilerplateText !== undefined ? { boilerplateText: item.boilerplateText } : {}),
    };
}
function parseCraStructure(raw) {
    if (typeof raw !== 'object' || raw === null) {
        throw new Error('Malformed CRA structure data: expected a top-level object');
    }
    const data = raw;
    assertString(data.sourceVersion, 'sourceVersion', 'root');
    assertString(data.generatedAt, 'generatedAt', 'root');
    if (!Array.isArray(data.items)) {
        throw new Error('Malformed CRA structure data: field "items" must be an array');
    }
    const items = data.items.map((item, index) => validateItem(item, index));
    return {
        sourceVersion: data.sourceVersion,
        generatedAt: data.generatedAt,
        items,
    };
}
let cached;
function load() {
    if (!cached) {
        const filePath = path.join(paths_1.DATA_DIR, 'cra-structure.json');
        let raw;
        try {
            raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        }
        catch (err) {
            throw new Error(`Failed to read/parse CRA structure data at ${filePath}: ${err.message}`);
        }
        cached = parseCraStructure(raw);
    }
    return cached;
}
function getCraStructure() {
    return load();
}
function getCraSourceVersion() {
    return load().sourceVersion;
}
//# sourceMappingURL=loader.js.map