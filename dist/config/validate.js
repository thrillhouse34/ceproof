"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateConfig = validateConfig;
const support_1 = require("../fda/support");
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/**
 * Hand-rolled structural validator for `ceproof.config.json` against the
 * `CeproofConfig` shape (src/config/types.ts). No schema-validation library
 * (e.g. ajv) is used here — ajv stays a devDependency for the existing SBOM
 * schema tests only; this repo's runtime dependency set (commander,
 * picocolors, puppeteer-core, smol-toml, yaml) deliberately doesn't include a
 * validation library, and the shape here is small/stable enough that hand
 * rolling it is simpler than adding one.
 *
 * Never throws. Collects every error found in one pass — rather than
 * stopping at the first — so a user re-running `ceproof init`/a future
 * `ceproof validate` sees everything wrong with the file at once instead of
 * discovering issues one re-run at a time.
 */
function validateConfig(raw) {
    const errors = [];
    if (!isPlainObject(raw)) {
        return { valid: false, errors: ['config must be a JSON object'] };
    }
    // --- manufacturer ---
    let manufacturerName = '';
    let manufacturerAddress;
    let manufacturerContact;
    if (!isPlainObject(raw.manufacturer)) {
        errors.push('manufacturer is required and must be an object');
    }
    else {
        const manufacturer = raw.manufacturer;
        if (typeof manufacturer.name !== 'string' || manufacturer.name.trim() === '') {
            errors.push('manufacturer.name is required and is missing');
        }
        else {
            manufacturerName = manufacturer.name;
        }
        if (manufacturer.address !== undefined) {
            if (typeof manufacturer.address !== 'string') {
                errors.push('manufacturer.address must be a string if present');
            }
            else {
                manufacturerAddress = manufacturer.address;
            }
        }
        if (manufacturer.contact !== undefined) {
            if (typeof manufacturer.contact !== 'string') {
                errors.push('manufacturer.contact must be a string if present');
            }
            else {
                manufacturerContact = manufacturer.contact;
            }
        }
    }
    // --- product ---
    let productName = '';
    let productClassification;
    if (!isPlainObject(raw.product)) {
        errors.push('product is required and must be an object');
    }
    else {
        const product = raw.product;
        if (typeof product.name !== 'string' || product.name.trim() === '') {
            errors.push('product.name is required and is missing');
        }
        else {
            productName = product.name;
        }
        if (product.classification !== undefined) {
            if (typeof product.classification !== 'string') {
                errors.push('product.classification must be a string if present');
            }
            else {
                productClassification = product.classification;
            }
        }
    }
    // --- supportPeriod ---
    let supportYears;
    let supportEndDate;
    // supportPeriod itself is optional scaffolding-wise, but the field must be
    // an object if present at all (an empty {} is valid — both its members are
    // optional).
    if (raw.supportPeriod !== undefined) {
        if (!isPlainObject(raw.supportPeriod)) {
            errors.push('supportPeriod must be an object if present');
        }
        else {
            const supportPeriod = raw.supportPeriod;
            if (supportPeriod.years !== undefined) {
                if (typeof supportPeriod.years !== 'number' || !Number.isFinite(supportPeriod.years)) {
                    errors.push('supportPeriod.years must be a number if present');
                }
                else {
                    supportYears = supportPeriod.years;
                }
            }
            if (supportPeriod.endDate !== undefined) {
                if (typeof supportPeriod.endDate !== 'string') {
                    errors.push('supportPeriod.endDate must be a string if present');
                }
                else {
                    supportEndDate = supportPeriod.endDate;
                }
            }
        }
    }
    // --- answers ---
    const answers = {};
    if (!isPlainObject(raw.answers)) {
        errors.push('answers is required and must be an object (Record<string, string>)');
    }
    else {
        for (const [key, value] of Object.entries(raw.answers)) {
            if (typeof value !== 'string') {
                errors.push(`answers.${key} must be a string`);
            }
            else {
                answers[key] = value;
            }
        }
    }
    // --- fda (optional; absent for every CRA-only user) ---
    const fda = validateFda(raw.fda, errors);
    if (errors.length > 0) {
        return { valid: false, errors };
    }
    const config = {
        manufacturer: {
            name: manufacturerName,
            ...(manufacturerAddress !== undefined ? { address: manufacturerAddress } : {}),
            ...(manufacturerContact !== undefined ? { contact: manufacturerContact } : {}),
        },
        product: {
            name: productName,
            ...(productClassification !== undefined ? { classification: productClassification } : {}),
        },
        supportPeriod: {
            ...(supportYears !== undefined ? { years: supportYears } : {}),
            ...(supportEndDate !== undefined ? { endDate: supportEndDate } : {}),
        },
        answers,
        ...(fda !== undefined ? { fda } : {}),
    };
    return { valid: true, config };
}
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
/**
 * Validate the optional `fda` block. Values are checked strictly rather than
 * coerced: a misspelled support level or a date written "11/2023" must be a
 * loud error here, because the alternative is it being silently dropped or
 * normalised and the manufacturer believing they declared something they
 * didn't. This block feeds a premarket submission document, so the usual
 * "be forgiving with input" instinct is the wrong one.
 */
function validateFda(raw, errors) {
    if (raw === undefined)
        return undefined;
    if (!isPlainObject(raw)) {
        errors.push('fda must be an object if present');
        return undefined;
    }
    const fda = {};
    if (raw.componentSupport !== undefined) {
        if (!isPlainObject(raw.componentSupport)) {
            errors.push('fda.componentSupport must be an object keyed by purl, "name@version", or component name');
            return fda;
        }
        const componentSupport = {};
        for (const [rawKey, value] of Object.entries(raw.componentSupport)) {
            const where = `fda.componentSupport["${rawKey}"]`;
            if (rawKey.trim() === '') {
                errors.push('fda.componentSupport has an empty key — a declaration must name the component it applies to');
                continue;
            }
            if (!isPlainObject(value)) {
                errors.push(`${where} must be an object with a supportLevel`);
                continue;
            }
            if (!(0, support_1.isSupportLevel)(value.supportLevel)) {
                errors.push(`${where}.supportLevel is required and must be one of: ${support_1.SUPPORT_LEVELS.join(', ')}`);
                continue;
            }
            const declaration = { supportLevel: value.supportLevel };
            if (value.endOfSupportDate !== undefined) {
                if (typeof value.endOfSupportDate !== 'string' || !ISO_DATE.test(value.endOfSupportDate)) {
                    errors.push(`${where}.endOfSupportDate must be an ISO date (YYYY-MM-DD) if present`);
                }
                else {
                    declaration.endOfSupportDate = value.endOfSupportDate;
                }
            }
            if (value.note !== undefined) {
                if (typeof value.note !== 'string') {
                    errors.push(`${where}.note must be a string if present`);
                }
                else {
                    declaration.note = value.note;
                }
            }
            // Keys are matched case-insensitively by the engine, so they are
            // lower-cased once here rather than at every comparison — which means two
            // keys differing only in case would silently overwrite each other. Say so
            // instead.
            const key = rawKey.trim().toLowerCase();
            if (componentSupport[key] !== undefined) {
                errors.push(`${where} collides with an earlier key that differs only in case or surrounding whitespace — keys are matched case-insensitively, so one of the two would be silently discarded`);
                continue;
            }
            componentSupport[key] = declaration;
        }
        fda.componentSupport = componentSupport;
    }
    return fda;
}
//# sourceMappingURL=validate.js.map