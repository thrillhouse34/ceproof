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
exports.updateMechanismDetector = void 0;
/**
 * Detects presence of automated dependency-update tooling configuration at
 * a project root: Dependabot (.github/dependabot.yml or
 * .github/dependabot.yaml) and Renovate (renovate.json, renovate.json5,
 * .renovaterc, .renovaterc.json, or a "renovate" key inside package.json).
 *
 * Facts-only: this detector makes no judgment about whether a found config
 * is well-formed or effective — it only reports presence.
 *
 * The package.json "renovate" key is only checked when package.json exists
 * and parses as valid JSON; a malformed package.json is treated as "no
 * embedded renovate config found" rather than thrown as an error (per the
 * "run() must not throw for the nothing-found case" doctrine in ./types).
 */
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const DEPENDABOT_CANDIDATES = [path.join('.github', 'dependabot.yml'), path.join('.github', 'dependabot.yaml')];
const RENOVATE_FILE_CANDIDATES = ['renovate.json', 'renovate.json5', '.renovaterc', '.renovaterc.json'];
function anyExists(projectPath, candidates) {
    return candidates.some((candidate) => fs.existsSync(path.join(projectPath, candidate)));
}
/** Returns true only if package.json exists, parses as valid JSON, and has a "renovate" key. */
function hasEmbeddedRenovateConfig(projectPath) {
    const pkgPath = path.join(projectPath, 'package.json');
    if (!fs.existsSync(pkgPath))
        return false;
    let raw;
    try {
        raw = fs.readFileSync(pkgPath, 'utf8');
    }
    catch {
        return false;
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        return false;
    }
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) && 'renovate' in parsed;
}
function run(projectPath) {
    const dependabotPresent = anyExists(projectPath, DEPENDABOT_CANDIDATES);
    const renovatePresent = anyExists(projectPath, RENOVATE_FILE_CANDIDATES) || hasEmbeddedRenovateConfig(projectPath);
    return {
        dependabotPresent,
        renovatePresent,
    };
}
exports.updateMechanismDetector = { id: 'update-mechanism', run };
//# sourceMappingURL=updateMechanism.js.map