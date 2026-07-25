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
exports.securityDetector = void 0;
/**
 * Detects presence of security-disclosure artifacts at a project root:
 * SECURITY.md, SECURITY (no extension), .well-known/security.txt, and
 * security.txt.
 *
 * Facts-only: this detector makes no judgment about whether a found policy
 * is well-formed or adequate (e.g. it does not parse security.txt per RFC
 * 9116) — it only reports presence and repo-relative paths.
 *
 * A "vulnerability disclosure policy" is treated as present whenever either
 * security.txt variant (.well-known/security.txt or security.txt) is found:
 * RFC 9116 security.txt is itself the vulnerability-disclosure-policy
 * mechanism, so the two concepts are the same artifact family in practice.
 */
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/** Candidate repo-relative paths, in the order they're checked. */
const SECURITY_MD_CANDIDATES = ['SECURITY.md', 'SECURITY'];
const SECURITY_TXT_CANDIDATES = [path.join('.well-known', 'security.txt'), 'security.txt'];
function findExisting(projectPath, candidates) {
    const found = [];
    for (const candidate of candidates) {
        if (fs.existsSync(path.join(projectPath, candidate))) {
            found.push(candidate.split(path.sep).join('/'));
        }
    }
    return found;
}
function run(projectPath) {
    const mdPaths = findExisting(projectPath, SECURITY_MD_CANDIDATES);
    const txtPaths = findExisting(projectPath, SECURITY_TXT_CANDIDATES);
    const securityMdPresent = mdPaths.length > 0;
    const securityTxtPresent = txtPaths.length > 0;
    return {
        securityMdPresent,
        securityTxtPresent,
        vulnDisclosurePolicyPresent: securityTxtPresent,
        paths: [...mdPaths, ...txtPaths],
    };
}
exports.securityDetector = { id: 'security', run };
//# sourceMappingURL=security.js.map