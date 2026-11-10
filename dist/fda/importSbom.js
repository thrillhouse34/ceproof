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
exports.SbomImportError = exports.SUPPORTED_CYCLONEDX_VERSIONS = void 0;
exports.normalizePurl = normalizePurl;
exports.parseCycloneDx = parseCycloneDx;
exports.importSbomFile = importSbomFile;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const crypto_1 = require("crypto");
const types_1 = require("./types");
/**
 * Import an existing CycloneDX JSON SBOM into the FDA mode's component model.
 *
 * This exists because device firmware is usually C/C++: ceproof does not scan C
 * or C++ source, does not run a compiler, and does not parse Yocto, Buildroot,
 * Conan or CMake trees. For a firmware project the component list has to come
 * from the customer's own SBOM (syft, cdxgen, Trivy, Yocto's create-spdx, their
 * vendor). ceproof's job starts at that file.
 *
 * Thin-v1 scope, per the cleared plan: CycloneDX JSON only. SPDX JSON import is
 * a later milestone and is refused here with a message that says so, rather than
 * being half-parsed. Nothing in this module touches the network — the repo's
 * fully-offline doctrine applies unchanged.
 */
/** CycloneDX spec versions this importer accepts. */
exports.SUPPORTED_CYCLONEDX_VERSIONS = ['1.4', '1.5', '1.6'];
/**
 * A file the user named could not be imported. The CLI layer turns this into
 * exit 2 with nothing written, the same bucket as every other usage error.
 * The message always names the actual problem (which format this really is,
 * which spec version it declares) rather than a generic "unsupported file".
 */
class SbomImportError extends Error {
    constructor(message) {
        super(message);
        this.name = 'SbomImportError';
    }
}
exports.SbomImportError = SbomImportError;
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function asString(value) {
    if (typeof value !== 'string')
        return undefined;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
}
/**
 * Strip a purl's `?qualifiers` and `#subpath`. Real generators attach
 * qualifiers freely (`?arch=x86_64`, `?distro=debian-12`,
 * `?download_url=...`), and comparing full purl strings would then fail to
 * match the same component across two sources — which is the whole point of
 * the purl key in the merge. The type/namespace/name/version part is what
 * identifies the component; the qualifiers describe how it was obtained.
 */
function normalizePurl(purl) {
    const cut = purl.search(/[?#]/);
    return (cut === -1 ? purl : purl.slice(0, cut)).trim();
}
/**
 * Decide what the file actually is from its own contents, never from its
 * extension, and refuse the unsupported shapes by name. An unhelpful "could not
 * parse" on a CycloneDX XML file sends people hunting for a JSON syntax error
 * that isn't there.
 */
function parseJsonOrExplain(text, label) {
    const head = text.slice(0, 4000);
    if (text.trimStart().startsWith('<')) {
        if (/<bom\b|cyclonedx/i.test(head)) {
            throw new SbomImportError(`${label}: this is CycloneDX XML. Only CycloneDX JSON is supported — re-export with "--output cyclonedx-json" (syft) or "-f json" (cdxgen).`);
        }
        throw new SbomImportError(`${label}: this is an XML document, not a CycloneDX JSON SBOM.`);
    }
    if (/^SPDXVersion:/m.test(head)) {
        throw new SbomImportError(`${label}: this is an SPDX tag-value file. Only CycloneDX JSON is supported in this version — SPDX import is not implemented yet.`);
    }
    try {
        return JSON.parse(text);
    }
    catch (err) {
        throw new SbomImportError(`${label}: not valid JSON (${err.message}).`);
    }
}
function licensesFrom(raw, warnings, label) {
    if (!Array.isArray(raw))
        return [];
    const out = [];
    for (const entry of raw) {
        if (!isRecord(entry))
            continue;
        // CycloneDX licenseChoice: either { license: { id | name } } or { expression }.
        const expression = asString(entry.expression);
        if (expression) {
            out.push(expression);
            continue;
        }
        const license = entry.license;
        if (isRecord(license)) {
            const value = asString(license.id) ?? asString(license.name);
            if (value)
                out.push(value);
            else
                warnings.push(`${label}: a license entry had neither an id nor a name and was recorded as unresolved.`);
        }
    }
    return out;
}
function hashesFrom(raw) {
    if (!Array.isArray(raw))
        return [];
    const out = [];
    for (const entry of raw) {
        if (!isRecord(entry))
            continue;
        const alg = asString(entry.alg);
        const content = asString(entry.content);
        if (alg && content)
            out.push({ alg, content });
    }
    return out;
}
function propertiesFrom(raw) {
    const out = {};
    if (!Array.isArray(raw))
        return out;
    for (const entry of raw) {
        if (!isRecord(entry))
            continue;
        const name = asString(entry.name);
        const value = asString(entry.value);
        // A property with a name and no value is legal CycloneDX; keep the name
        // with an empty value rather than dropping the fact it was asserted.
        if (name)
            out[name] = value ?? '';
    }
    return out;
}
function supplierFrom(raw) {
    const supplier = raw.supplier;
    if (isRecord(supplier)) {
        const name = asString(supplier.name);
        if (name)
            return name;
    }
    // NTIA's "supplier name" element has no single home in CycloneDX; publisher
    // and author are the usual fallbacks real generators populate instead.
    return asString(raw.publisher) ?? asString(raw.author);
}
function componentFrom(raw, origin, warnings, label) {
    const name = asString(raw.name);
    if (!name) {
        warnings.push(`${label}: skipped a component with no name — a nameless component cannot be identified or reported on.`);
        return undefined;
    }
    const purl = asString(raw.purl);
    const component = {
        name,
        licenses: licensesFrom(raw.licenses, warnings, label),
        hashes: hashesFrom(raw.hashes),
        properties: propertiesFrom(raw.properties),
        origins: [origin],
    };
    const version = asString(raw.version);
    if (version)
        component.version = version;
    if (purl)
        component.purl = normalizePurl(purl);
    const cpe = asString(raw.cpe);
    if (cpe)
        component.cpe = cpe;
    const supplier = supplierFrom(raw);
    if (supplier)
        component.supplier = supplier;
    const type = asString(raw.type);
    if (type)
        component.type = type;
    // The document's own identifier for this component, qualified with the
    // origin. Kept ONLY so `dependencies[]` can be mapped onto the enriched
    // document's re-derived refs; it is never emitted as-is, because a ref from
    // a foreign document means nothing in ours.
    const bomRef = asString(raw['bom-ref']);
    if (bomRef)
        component.sourceRefs = [(0, types_1.qualifyRef)(origin, bomRef)];
    return component;
}
/**
 * Read `dependencies[]`, qualify every ref, and drop nothing silently.
 *
 * Entries are NOT validated against the component list here: a ref may point
 * at `metadata.component` (the normal case for the graph's root), and at this
 * point in the pipeline the merge has not happened yet, so an unresolvable ref
 * is not yet distinguishable from one that another source will supply. That
 * check belongs where the emitted refs exist — see `resolveDependencies` in
 * render/input.ts, which reports every ref it could not map.
 */
function dependenciesFrom(raw, origin, warnings, label) {
    if (!Array.isArray(raw))
        return [];
    const out = [];
    let malformed = 0;
    for (const entry of raw) {
        if (!isRecord(entry)) {
            malformed += 1;
            continue;
        }
        const ref = asString(entry.ref);
        if (!ref) {
            malformed += 1;
            continue;
        }
        const dependsOn = Array.isArray(entry.dependsOn)
            ? entry.dependsOn.map(asString).filter((v) => v !== undefined).map((v) => (0, types_1.qualifyRef)(origin, v))
            : [];
        out.push({ ref: (0, types_1.qualifyRef)(origin, ref), dependsOn });
    }
    if (malformed > 0) {
        warnings.push(`${label}: ${malformed} ${malformed === 1 ? 'entry' : 'entries'} in the SBOM's dependencies array had no "ref" and could not be carried through. ` +
            'The dependency graph in the output is incomplete by that many entries.');
    }
    return out;
}
/**
 * Walk `components[]` including nested `components[].components[]`. syft and
 * cdxgen both nest in real output (an OS package carrying its own files, a
 * monorepo workspace carrying its dependencies); flattening is what keeps those
 * from being silently absent from the FDA artifact.
 */
function collectComponents(raw, origin, warnings, label, out) {
    if (!Array.isArray(raw))
        return;
    for (const entry of raw) {
        if (!isRecord(entry))
            continue;
        const component = componentFrom(entry, origin, warnings, label);
        if (component)
            out.push(component);
        collectComponents(entry.components, origin, warnings, label, out);
    }
}
/**
 * Parse CycloneDX JSON text. Split from `importSbomFile` so the parse is
 * testable without touching the filesystem (and so a large synthetic SBOM can
 * be exercised in memory rather than committed as a fixture).
 *
 * `sourceLabel` is the name used in messages and in each component's origin —
 * pass the file's basename.
 */
function parseCycloneDx(text, sourceLabel) {
    const doc = parseJsonOrExplain(text, sourceLabel);
    if (!isRecord(doc)) {
        throw new SbomImportError(`${sourceLabel}: the JSON root is not an object, so this is not a CycloneDX SBOM.`);
    }
    // SPDX checked BEFORE the CycloneDX check so an SPDX file gets the message
    // that names SPDX, not the generic "neither format" one.
    if (asString(doc.spdxVersion) || asString(doc.SPDXID)) {
        const version = asString(doc.spdxVersion) ?? 'unknown version';
        throw new SbomImportError(`${sourceLabel}: this is an SPDX JSON document (${version}). Only CycloneDX JSON is supported in this version — SPDX import is not implemented yet.`);
    }
    if (asString(doc.bomFormat) !== 'CycloneDX') {
        throw new SbomImportError(`${sourceLabel}: not a CycloneDX SBOM (no "bomFormat": "CycloneDX" field) and not SPDX JSON either.`);
    }
    const specVersion = asString(doc.specVersion);
    if (!specVersion) {
        throw new SbomImportError(`${sourceLabel}: CycloneDX document declares no "specVersion".`);
    }
    if (!exports.SUPPORTED_CYCLONEDX_VERSIONS.includes(specVersion)) {
        throw new SbomImportError(`${sourceLabel}: CycloneDX ${specVersion} is not supported. Supported spec versions: ${exports.SUPPORTED_CYCLONEDX_VERSIONS.join(', ')}.`);
    }
    const origin = `sbom:${sourceLabel}`;
    const warnings = [];
    const components = [];
    collectComponents(doc.components, origin, warnings, sourceLabel, components);
    if (components.length === 0) {
        warnings.push(`${sourceLabel}: the SBOM contains no components. Nothing was imported from it.`);
    }
    const result = {
        format: 'cyclonedx',
        specVersion,
        sourceLabel,
        components,
        dependencies: dependenciesFrom(doc.dependencies, origin, warnings, sourceLabel),
        warnings,
    };
    const metadata = doc.metadata;
    if (isRecord(metadata) && isRecord(metadata.component)) {
        const subject = componentFrom(metadata.component, origin, warnings, sourceLabel);
        if (subject)
            result.subject = subject;
    }
    return result;
}
/** Read and parse a CycloneDX JSON file, stamping the SHA-256 of the bytes read for the provenance artifact. */
function importSbomFile(filePath) {
    let text;
    try {
        text = fs.readFileSync(filePath, 'utf8');
    }
    catch (err) {
        throw new SbomImportError(`--sbom ${filePath}: cannot read file (${err.message}).`);
    }
    const parsed = parseCycloneDx(text, path.basename(filePath));
    parsed.sha256 = (0, crypto_1.createHash)('sha256').update(text, 'utf8').digest('hex');
    return parsed;
}
//# sourceMappingURL=importSbom.js.map