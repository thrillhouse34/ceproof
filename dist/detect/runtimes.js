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
exports.runtimesDetector = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const smol_toml_1 = require("smol-toml");
/**
 * Read package.json's "engines"."node" field, if present as a non-empty
 * string. Malformed/unreadable package.json yields undefined (UNKNOWN),
 * never a crash — mirrors readNpmDeclaredLicense in ./projectLicense.ts.
 */
function readNodeEngine(projectPath) {
    const pkgJsonPath = path.join(projectPath, 'package.json');
    if (!fs.existsSync(pkgJsonPath))
        return undefined;
    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    }
    catch {
        return undefined; // malformed package.json — UNKNOWN, not a crash
    }
    const node = manifest.engines?.node;
    return typeof node === 'string' && node.length > 0 ? node : undefined;
}
/**
 * Read pyproject.toml's PEP 621 `[project]` `requires-python` field, if
 * present as a non-empty string. Malformed/unreadable/absent pyproject.toml
 * yields undefined (UNKNOWN), never a crash.
 */
function readPyprojectRequiresPython(projectPath) {
    const pyprojectPath = path.join(projectPath, 'pyproject.toml');
    if (!fs.existsSync(pyprojectPath))
        return undefined;
    let doc;
    try {
        doc = (0, smol_toml_1.parse)(fs.readFileSync(pyprojectPath, 'utf8'));
    }
    catch {
        return undefined; // malformed pyproject.toml — UNKNOWN, not a crash
    }
    const project = doc.project;
    const requiresPython = project?.['requires-python'];
    return typeof requiresPython === 'string' && requiresPython.length > 0 ? requiresPython : undefined;
}
/**
 * Read setup.cfg's `[options]` section `python_requires` key, if present as
 * a non-empty value. setup.cfg is INI, not TOML — this is a minimal
 * line-based reader scoped to exactly the one section/key this detector
 * needs, not a general INI parser. Malformed/unreadable/absent setup.cfg
 * yields undefined (UNKNOWN), never a crash.
 */
function readSetupCfgPythonRequires(projectPath) {
    const setupCfgPath = path.join(projectPath, 'setup.cfg');
    if (!fs.existsSync(setupCfgPath))
        return undefined;
    let raw;
    try {
        raw = fs.readFileSync(setupCfgPath, 'utf8');
    }
    catch {
        return undefined; // unreadable setup.cfg — UNKNOWN, not a crash
    }
    const lines = raw.split(/\r\n|\n|\r/);
    let inOptionsSection = false;
    for (const line of lines) {
        const sectionMatch = line.match(/^\s*\[([^\]]+)]\s*(?:[;#].*)?$/);
        if (sectionMatch) {
            inOptionsSection = sectionMatch[1].trim() === 'options';
            continue;
        }
        if (!inOptionsSection)
            continue;
        // A continuation line (indented, no "key = value") belongs to a
        // multi-line value of the previous key — python_requires is always a
        // single-line value in practice, so continuation lines are irrelevant
        // here and simply skipped rather than mis-parsed as a new key.
        const kvMatch = line.match(/^([A-Za-z0-9_.-]+)\s*[:=]\s*(.*)$/);
        if (!kvMatch)
            continue;
        if (kvMatch[1].trim() !== 'python_requires')
            continue;
        const value = kvMatch[2].trim();
        return value.length > 0 ? value : undefined;
    }
    return undefined;
}
function run(projectPath) {
    const node = readNodeEngine(projectPath);
    // pyproject.toml's PEP 621 requires-python takes precedence over the
    // setup.cfg fallback per the task's stated ordering (pyproject.toml wins
    // when it declares the field at all).
    const python = readPyprojectRequiresPython(projectPath) ?? readSetupCfgPythonRequires(projectPath);
    return {
        ...(node !== undefined ? { node } : {}),
        ...(python !== undefined ? { python } : {}),
    };
}
exports.runtimesDetector = { id: 'runtimes', run };
//# sourceMappingURL=runtimes.js.map