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
exports.projectLicenseDetector = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const smol_toml_1 = require("smol-toml");
/**
 * Root-license-file candidates, in priority order (first match wins when a
 * project happens to carry more than one — e.g. both LICENSE and COPYING).
 * Matching is case-insensitive (`license`, `License.MD`, etc. all count),
 * mirroring the "case variations acceptable" note in the task brief. This is
 * a deliberately narrower list than src/resolve/resolveProject.ts's
 * `readLicenseFile` (which also handles LICENCE spellings and a PyPI
 * `licenses/` subdir) — that function scans a *dependency's* install path;
 * this one only ever looks at the scanned project's own root.
 */
const ROOT_LICENSE_CANDIDATES = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'COPYING.md'];
/**
 * Find the first root-level license-ish file, matching candidate names
 * case-insensitively against the actual directory entries. Returns the
 * repo-relative path (using the real on-disk casing) of the first candidate
 * (in ROOT_LICENSE_CANDIDATES order) that has a match, or undefined if none
 * of the candidates are present.
 */
function findRootLicenseFile(projectPath) {
    let entries;
    try {
        entries = fs.readdirSync(projectPath, { withFileTypes: true });
    }
    catch {
        return undefined; // unreadable project root — nothing to report, not a crash
    }
    const filesByLowerName = new Map();
    for (const entry of entries) {
        if (!entry.isFile())
            continue;
        // First entry wins on a case-colliding filesystem tie (won't happen on
        // typical case-sensitive/insensitive setups, but keeps this total).
        if (!filesByLowerName.has(entry.name.toLowerCase())) {
            filesByLowerName.set(entry.name.toLowerCase(), entry.name);
        }
    }
    for (const candidate of ROOT_LICENSE_CANDIDATES) {
        const actualName = filesByLowerName.get(candidate.toLowerCase());
        if (actualName)
            return actualName;
    }
    return undefined;
}
/** Read package.json's top-level "license" field, if present as a plain string. */
function readNpmDeclaredLicense(projectPath) {
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
    return typeof manifest.license === 'string' && manifest.license.length > 0 ? manifest.license : undefined;
}
/**
 * Read pyproject.toml's PEP 621 `[project.license]`, supporting both the
 * plain-string shape (`license = "MIT"`) and the table shape with a `text`
 * key (`license = { text = "MIT" }`). A `{ file = "..." }` table (license
 * lives in a referenced file, not as an SPDX-ish string here) yields
 * undefined — there is no id to report, and this function never reads
 * other files to go find one.
 */
function readPyprojectDeclaredLicense(projectPath) {
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
    const license = project?.license;
    if (typeof license === 'string' && license.length > 0)
        return license;
    if (license !== null && typeof license === 'object' && !Array.isArray(license)) {
        const text = license.text;
        if (typeof text === 'string' && text.length > 0)
            return text;
    }
    return undefined;
}
function run(projectPath) {
    const rootLicenseFilePath = findRootLicenseFile(projectPath);
    // npm's package.json takes precedence over pyproject.toml when a mixed
    // (or ambiguous) repo declares a license in both — same "npm wins" rule
    // used for the analogous mixed-ecosystem tie-break in
    // src/report/reportData.ts's mergeScanResults (projectLicenseRaw).
    const declaredLicenseId = readNpmDeclaredLicense(projectPath) ?? readPyprojectDeclaredLicense(projectPath);
    return {
        rootLicenseFilePresent: rootLicenseFilePath !== undefined,
        ...(rootLicenseFilePath !== undefined ? { rootLicenseFilePath } : {}),
        ...(declaredLicenseId !== undefined ? { declaredLicenseId } : {}),
    };
}
exports.projectLicenseDetector = { id: 'project-license', run };
//# sourceMappingURL=projectLicense.js.map