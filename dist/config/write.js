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
exports.ConfigFileNotFoundError = exports.CONFIG_FILENAME = void 0;
exports.readConfigFile = readConfigFile;
exports.writeConfigFile = writeConfigFile;
exports.resolveConfigPath = resolveConfigPath;
const fs = __importStar(require("fs"));
const nodePath = __importStar(require("path"));
/**
 * Reads and JSON.parses `path`, if it exists.
 *
 * - Missing file: `{ present: false }` — not a throw. Only ENOENT is treated
 *   this way; a genuinely unexpected fs error (e.g. EACCES) propagates as a
 *   thrown exception rather than being silently swallowed into "not present",
 *   since that would misreport a real permissions problem as a simple
 *   first-run case.
 * - Present but invalid JSON: `{ present: true, parseError }` — not a throw,
 *   so callers can present a clear, actionable message instead of an
 *   unhandled exception.
 * - Present and valid JSON: `{ present: true, raw }` — the caller is
 *   responsible for shape-validating `raw` (see validateConfig).
 */
function readConfigFile(path) {
    let text;
    try {
        text = fs.readFileSync(path, 'utf8');
    }
    catch (err) {
        if (err.code === 'ENOENT') {
            return { present: false };
        }
        throw err;
    }
    try {
        return { present: true, raw: JSON.parse(text) };
    }
    catch (err) {
        return { present: true, parseError: `Invalid JSON in ${path}: ${err.message}` };
    }
}
/**
 * Writes `config` to `path` as pretty-printed (2-space indent) JSON with a
 * trailing newline.
 */
function writeConfigFile(path, config) {
    fs.writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
}
/** The conventional config filename, looked for under the scanned project path. */
exports.CONFIG_FILENAME = 'ceproof.config.json';
/**
 * Thrown when `--config <path>` names a file that isn't there. Distinct type so
 * callers can map it to a usage exit code rather than guessing from the message.
 */
class ConfigFileNotFoundError extends Error {
    constructor(configPath) {
        super(`config file not found: ${configPath}`);
        this.name = 'ConfigFileNotFoundError';
    }
}
exports.ConfigFileNotFoundError = ConfigFileNotFoundError;
/**
 * Resolves which config file a command should read: the explicitly-passed
 * `--config` value if there is one, else `<projectPath>/ceproof.config.json`.
 *
 * An explicitly-passed path that doesn't exist is a usage error, NOT a
 * first-run case. Treating it as "no config present" (what this used to do by
 * falling straight through to readConfigFile) silently discards every answer
 * the user wrote and then fails their build on the very items that config was
 * answering, with nothing on screen explaining why — a single typo in a CI
 * workflow looked exactly like a genuine wall of open CRA items. The DEFAULT
 * path is still allowed to be absent: that one genuinely is the first run.
 */
function resolveConfigPath(projectPath, explicitPath) {
    if (explicitPath === undefined)
        return nodePath.join(projectPath, exports.CONFIG_FILENAME);
    if (!fs.existsSync(explicitPath))
        throw new ConfigFileNotFoundError(explicitPath);
    return explicitPath;
}
//# sourceMappingURL=write.js.map