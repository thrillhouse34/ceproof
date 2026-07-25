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
exports.runInit = runInit;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const loader_1 = require("../cra/loader");
const validate_1 = require("../config/validate");
const write_1 = require("../config/write");
const branding_1 = require("../branding");
const DEFAULT_CONFIG_FILENAME = 'ceproof.config.json';
/**
 * `ceproof init` — generate `ceproof.config.json`.
 *
 * SCOPING DECISION (M1): a real interview flow would prompt interactively,
 * one question per `human-required` CraStructureItem (src/cra/types.ts), and
 * write the operator's actual answers. There's no interactive-prompt library
 * in this repo's dependency set, and picking one (inquirer, prompts, enquirer,
 * or hand-rolled readline) is a decision this milestone deliberately leaves
 * for later — M1's deliverable is "generate + validate the config shape",
 * not "build a TUI". So instead this generates a config file with honest,
 * visibly-empty placeholder values (manufacturer.name: '', product.name: '',
 * and one empty-string `answers` entry per human-required item id) and prints
 * exactly what still needs to be filled in by hand. This is consistent with
 * the never-silent-assumptions doctrine: nothing here is guessed or defaulted
 * to a plausible-looking value — every unanswered field is left visibly
 * blank and named in the output. A later milestone can swap the placeholder
 * generation for a real interactive interview without changing this
 * function's contract (opts in, { exitCode, output } out).
 *
 * Behavior:
 * - Default configPath is `ceproof.config.json` under opts.path.
 * - If that file already exists and !opts.force: refuses (exit 2), one-line
 *   message pointing at --force. Nothing is read from, or written to, the
 *   existing file.
 * - Otherwise: writes a freshly generated config, then runs validateConfig
 *   on what was actually written back off disk, and reports exactly which
 *   fields/answers still need human input before the file will validate.
 *   The freshly generated file is EXPECTED to fail validateConfig (empty
 *   manufacturer.name/product.name) — that's correct, not a bug: `init`
 *   never claims success it hasn't earned.
 */
function runInit(opts) {
    const configPath = opts.configPath ?? path.join(opts.path, DEFAULT_CONFIG_FILENAME);
    if (fs.existsSync(configPath) && !opts.force) {
        return {
            exitCode: 2,
            output: `${branding_1.PRODUCT_NAME} init: ${configPath} already exists. Re-run with --force to overwrite it.`,
        };
    }
    const humanRequiredItems = (0, loader_1.getCraStructure)().items.filter((item) => item.derivability === 'human-required');
    const answers = {};
    for (const item of humanRequiredItems) {
        answers[item.id] = '';
    }
    const config = {
        manufacturer: { name: '' },
        product: { name: '' },
        supportPeriod: {},
        answers,
    };
    (0, write_1.writeConfigFile)(configPath, config);
    // Validate what actually landed on disk (not just the in-memory object) —
    // this is what a user would see if they hand-inspected the file, and
    // guards against writeConfigFile/readConfigFile drifting apart later.
    const readBack = (0, write_1.readConfigFile)(configPath);
    const validationErrors = readBack.present && 'raw' in readBack
        ? (() => {
            const result = (0, validate_1.validateConfig)(readBack.raw);
            return result.valid ? [] : result.errors;
        })()
        : [`could not re-read ${configPath} after writing it`];
    // Beyond what validateConfig strictly requires (non-empty manufacturer.name
    // / product.name; answers values merely need to be strings, so an empty
    // string is technically well-typed), every answers entry generated above is
    // a placeholder that still needs a real human answer. List those
    // separately so nothing is silently left blank without being called out.
    const emptyAnswerItems = humanRequiredItems.filter((item) => answers[item.id] === '');
    const lines = [];
    lines.push(`${branding_1.PRODUCT_NAME} init: wrote ${configPath}`);
    lines.push('');
    lines.push('This file was generated with placeholder values only — nothing was assumed on your behalf. ' +
        'It will not pass validation until you fill in the fields below by hand:');
    lines.push('');
    if (validationErrors.length > 0) {
        lines.push('Required fields:');
        for (const err of validationErrors) {
            lines.push(`  - ${err}`);
        }
        lines.push('');
    }
    if (emptyAnswerItems.length > 0) {
        lines.push(`Answers needed (${emptyAnswerItems.length} human-required CRA item(s)):`);
        for (const item of emptyAnswerItems) {
            lines.push(`  - answers.${item.id}: ${item.requirementSummary} (${item.citation})`);
        }
        lines.push('');
    }
    const totalNeeded = validationErrors.length + emptyAnswerItems.length;
    lines.push(`${totalNeeded} field(s) still need your input.`);
    return { exitCode: 0, output: lines.join('\n') };
}
//# sourceMappingURL=init.js.map