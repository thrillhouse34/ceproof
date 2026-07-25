"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateConfig = validateConfig;
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
    };
    return { valid: true, config };
}
//# sourceMappingURL=validate.js.map