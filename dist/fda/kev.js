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
exports.KEV_INDEX_SCHEMA = exports.KEV_SNAPSHOT_SCHEMA = exports.KEV_SCREEN_LIMITS = exports.MANUFACTURER_SUPPLIED_COLUMNS = exports.FDA_VULN_SOURCE = void 0;
exports.normalizeKevKey = normalizeKevKey;
exports.loadKevSnapshot = loadKevSnapshot;
exports.loadKevIndex = loadKevIndex;
exports.buildKevLookup = buildKevLookup;
exports.loadKevLookup = loadKevLookup;
exports.compareVersions = compareVersions;
exports.evaluateRange = evaluateRange;
exports.evaluateRanges = evaluateRanges;
exports.screenKev = screenKev;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const paths_1 = require("../paths");
const support_1 = require("./support");
/**
 * The known-vulnerability screen, centred on CISA's Known Exploited
 * Vulnerabilities Catalog.
 *
 * FDA's premarket cybersecurity guidance (section V.A.4(b)) asks for this
 * alongside the SBOM itself — quoting the vendored source text in data/sources/:
 *
 *   "As part of the premarket submission, manufacturers should also identify all
 *    known vulnerabilities associated with the device and the software
 *    components, including those identified in CISA's Known Exploited
 *    Vulnerabilities Catalog. For each known vulnerability, manufacturers should
 *    describe how the vulnerabilities were discovered ..."
 *
 * and then, for components with known vulnerabilities:
 *
 *   "A safety and security risk assessment of each known vulnerability
 *    (including device and system impacts); and
 *    Details of applicable safety and security risk controls to address the
 *    vulnerability."
 *
 * The division of labour this module is built around, and will not cross: it
 * SCREENS, the manufacturer ASSESSES. Those two bullets are the manufacturer's
 * to write — they require device and system impact knowledge no scanner has —
 * so what this produces is a candidate list with a stated basis and confidence
 * for every row, plus (via MANUFACTURER_SUPPLIED_COLUMNS) the names of the two
 * columns the manufacturer has to fill in. Nothing here ever claims a risk
 * assessment was performed.
 *
 * What the screen can and cannot be precise about, and why:
 *
 *  - The KEV catalogue identifies a vulnerability by free-text vendor and
 *    product ("OpenSSL"/"OpenSSL", "Linux"/"Kernel") and carries NO version
 *    information at all. So a match against the catalogue alone can only ever be
 *    `possible` — it says "a known-exploited vulnerability exists in this
 *    product", never "in your version of it". This is the normal case for the
 *    C/C++ firmware components this whole mode exists for, and every such row
 *    says so in its own evidence string rather than leaving the customer to
 *    discover the limit.
 *  - `confirmed` requires version-range evidence, which only an ecosystem
 *    advisory can supply. data/kev-index.json is the build-time join of the KEV
 *    CVE list against OSV, carrying the affected version ranges for the npm and
 *    PyPI packages involved — the ecosystems ceproof's own scanner can produce.
 *    That is deliberately NOT an NVD/CPE layer (excluded from this version): it
 *    maps advisories to package versions, so it cannot confirm anything for a
 *    component that has no npm or PyPI identity.
 *  - `not-affected` is only ever reported when an advisory names the exact
 *    package AND the component's version is provably outside every affected
 *    range. Those rows are kept and reported, not dropped, so a reviewer can see
 *    the CVE was considered and why it was set aside.
 *
 * Fully offline, like the rest of the tool: both datasets are vendored under
 * data/ and nothing here makes a network call. See scripts/fetch-kev-snapshot.ts
 * and scripts/build-kev-index.ts for how they are built, and NOTICE for the
 * licence attribution each one requires.
 */
/**
 * The exact passages of the guidance this module implements, kept as data so
 * they can be checked verbatim against the vendored primary-source text — the
 * same standard data/cra-structure.json is held to by
 * tests/cra/traceability.test.ts, and the same arrangement src/fda/support.ts
 * uses for the support-level fields.
 *
 * Every excerpt is a single line of the pdftotext extract, with the PDF's own
 * line-wrapping left intact, because a sentence spanning two lines has no
 * verbatim form.
 */
exports.FDA_VULN_SOURCE = {
    citation: 'FDA, "Cybersecurity in Medical Devices: Quality Management System Considerations and Content of Premarket Submissions", issued February 3, 2026, sections V.A.2 (p. 14) and V.A.4(b) (pp. 17-18)',
    sourceFile: 'data/sources/fda-premarket-cybersecurity-2026-02-03-extract.md',
    excerpts: {
        /** Why this screen exists at all, and why KEV specifically is named. */
        identifyAll: 'vulnerabilities associated with the device and the software components, including those',
        kevCatalog: 'identified in CISA’s Known Exploited Vulnerabilities Catalog. For each known vulnerability,',
        /** Why every finding carries an `evidence` sentence naming how it was found. */
        howDiscovered: 'manufacturers should describe how the vulnerabilities were discovered to demonstrate whether',
        /** The two columns this module deliberately leaves to the manufacturer. */
        riskAssessment: 'A safety and security risk assessment of each known vulnerability (including device and',
        riskControls: 'Details of applicable safety and security risk controls to address the vulnerability. If risk',
        /** Why a KEV hit is more than informational: V.A.2, p. 14. */
        designedOut: 'in CISA’s Known Exploited Vulnerabilities Catalog should be designed out of the device, as',
    },
};
/**
 * The two things FDA asks the MANUFACTURER to provide for each known
 * vulnerability. Exported as the single agreed wording so the milestone-4
 * renderers emit these as blank columns for the manufacturer to complete
 * instead of each paraphrasing the guidance, and so no surface can imply the
 * tool filled them in.
 */
exports.MANUFACTURER_SUPPLIED_COLUMNS = [
    'Safety and security risk assessment (including device and system impacts)',
    'Details of applicable safety and security risk controls',
];
/**
 * What this screen does NOT cover, stated as fixed text so it travels with
 * every artifact that carries the findings. A screen whose limits are only in
 * the README is a screen whose limits a reviewer will discover at the worst
 * possible moment.
 */
exports.KEV_SCREEN_LIMITS = [
    'This screen covers the CISA Known Exploited Vulnerabilities Catalog only. FDA asks for ALL known vulnerabilities associated with the device and its software components; vulnerabilities that are not in the KEV catalogue are not searched for here and must be identified by other means.',
    'The KEV catalogue identifies vulnerabilities by vendor and product name and carries no version information, so a match against it alone cannot establish that the specific version in this device is affected. Such rows are reported as "possible".',
    'A "confirmed" row means an ecosystem advisory (npm or PyPI, via OSV) names this exact package and the component version falls inside an affected range. No equivalent version-precise data is bundled for C/C++ or other non-npm/PyPI components, so those components can never reach "confirmed" in this version.',
    'The safety and security risk assessment of each vulnerability, and the risk controls applied, are the manufacturer’s to provide. This screen identifies candidates and records how each was found; it does not assess them.',
];
/** Bumped only when the snapshot's own shape changes incompatibly, so an old vendored file fails loudly instead of being half-read. */
exports.KEV_SNAPSHOT_SCHEMA = 1;
/** Likewise for the OSV-derived index. Separate from the snapshot's, because the two files are built by separate scripts on separate cadences. */
exports.KEV_INDEX_SCHEMA = 1;
/** Strongest first. Used to pick one row when the same CVE matches a component more than one way. */
const BASIS_STRENGTH = ['ecosystem-advisory', 'cpe', 'vendor-product', 'product-name'];
/**
 * Reduce a vendor or product string to a comparison key: lowercased with every
 * non-alphanumeric character removed, so "Connect Secure", "connect-secure" and
 * "ConnectSecure" land on one key.
 *
 * Stripping separators rather than normalising them to a single dash is
 * deliberate: CISA's product strings are prose ("Internet Explorer", "Smart
 * Install"), SBOM component names are package identifiers ("internet_explorer",
 * "smart-install"), and the separator convention between the two is arbitrary.
 * Returns undefined for a string with no alphanumeric content, which must never
 * become a key that matches everything.
 */
function normalizeKevKey(value) {
    const key = value.toLowerCase().replace(/[^a-z0-9]+/g, '');
    return key.length > 0 ? key : undefined;
}
let cachedSnapshot;
let cachedIndex;
function readJson(file, what) {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
    catch (err) {
        throw new Error(`Cannot read the ${what} at ${file} (${err.message}). Reinstall the package — data/ did not ship or is corrupt.`);
    }
}
/**
 * Load and structurally check the vendored KEV snapshot. Throws rather than
 * returning an empty catalogue: a missing or wrong-schema file in an installed
 * package is a broken install, and screening every component against nothing
 * would produce a clean-looking "no known exploited vulnerabilities" result
 * that is the most dangerous possible output of this tool.
 */
function loadKevSnapshot(dataDir = paths_1.DATA_DIR) {
    if (dataDir === paths_1.DATA_DIR && cachedSnapshot)
        return cachedSnapshot;
    const file = path.join(dataDir, 'kev-snapshot.json');
    const snapshot = readJson(file, 'KEV catalogue snapshot');
    if (!snapshot || typeof snapshot !== 'object' || !Array.isArray(snapshot.entries) || !snapshot.source) {
        throw new Error(`The KEV catalogue snapshot at ${file} is not in the expected shape.`);
    }
    if (snapshot.schema !== exports.KEV_SNAPSHOT_SCHEMA) {
        throw new Error(`The KEV catalogue snapshot at ${file} declares schema ${String(snapshot.schema)}, but this version of the tool reads schema ${exports.KEV_SNAPSHOT_SCHEMA}. Re-run scripts/fetch-kev-snapshot.ts.`);
    }
    if (snapshot.entries.length === 0) {
        throw new Error(`The KEV catalogue snapshot at ${file} contains no entries. Screening against an empty catalogue would report every component as having no known exploited vulnerabilities, which is worse than failing. Re-run scripts/fetch-kev-snapshot.ts.`);
    }
    if (dataDir === paths_1.DATA_DIR)
        cachedSnapshot = snapshot;
    return snapshot;
}
/**
 * Load the OSV-derived version-range index. An EMPTY index is legitimate here,
 * unlike an empty snapshot — it only means no KEV CVE currently has an npm or
 * PyPI advisory — so the floor check is on shape, not on size. Losing the index
 * costs `confirmed` rows, never whole findings: without it every match falls
 * back to `possible`.
 */
function loadKevIndex(dataDir = paths_1.DATA_DIR) {
    if (dataDir === paths_1.DATA_DIR && cachedIndex)
        return cachedIndex;
    const file = path.join(dataDir, 'kev-index.json');
    const index = readJson(file, 'KEV ecosystem-advisory index');
    if (!index || typeof index !== 'object' || !Array.isArray(index.entries) || !Array.isArray(index.sources) || !index.builtFrom) {
        throw new Error(`The KEV ecosystem-advisory index at ${file} is not in the expected shape.`);
    }
    if (index.schema !== exports.KEV_INDEX_SCHEMA) {
        throw new Error(`The KEV ecosystem-advisory index at ${file} declares schema ${String(index.schema)}, but this version of the tool reads schema ${exports.KEV_INDEX_SCHEMA}. Re-run scripts/build-kev-index.ts.`);
    }
    if (dataDir === paths_1.DATA_DIR)
        cachedIndex = index;
    return index;
}
function push(map, key, value) {
    const existing = map.get(key);
    if (existing)
        existing.push(value);
    else
        map.set(key, [value]);
}
function buildKevLookup(snapshot, index) {
    const lookup = {
        snapshot,
        index,
        byVendorProduct: new Map(),
        byProduct: new Map(),
        byPurlKey: new Map(),
        byCve: new Map(),
    };
    for (const entry of snapshot.entries) {
        lookup.byCve.set(entry.cve, entry);
        const vendor = normalizeKevKey(entry.vendor);
        const product = normalizeKevKey(entry.product);
        if (!product)
            continue;
        push(lookup.byProduct, product, entry);
        if (vendor)
            push(lookup.byVendorProduct, `${vendor}:${product}`, entry);
    }
    for (const entry of index.entries) {
        push(lookup.byPurlKey, entry.purlKey, entry);
    }
    return lookup;
}
/** Build the lookup from the two bundled files. */
function loadKevLookup(dataDir = paths_1.DATA_DIR) {
    return buildKevLookup(loadKevSnapshot(dataDir), loadKevIndex(dataDir));
}
const PLAIN_NUMERIC = /^\d+(\.\d+)*$/;
/**
 * Compare two version strings, or REFUSE by returning undefined.
 *
 * Deliberately narrow: it compares plain dotted-numeric versions ("0", "1.2",
 * "4.17.21") and nothing else. Anything carrying a pre-release, post-release,
 * dev, epoch, build-metadata or distro suffix — "1.0.0-rc.1", "2.0.0rc1",
 * "1.0.post1", "1:1.1.1n-0+deb11u5" — is refused outright.
 *
 * Refusing is the whole point. npm ranges are SEMVER-ordered and PyPI ranges
 * are PEP 440-ordered, and those two orderings disagree about exactly the
 * suffixed versions above. Implementing both correctly is a large amount of
 * code; implementing one of them approximately and applying it to both would
 * put a wrong "not affected" next to a known-exploited CVE in a premarket
 * submission. A refusal degrades the finding to `possible` with the reason
 * stated, which is the safe direction: the row still appears, it just isn't
 * version-precise.
 *
 * ponytail: plain-numeric comparison only; add a real SEMVER/PEP 440 comparator
 * if pre-release component versions turn out to be common in real device SBOMs.
 */
function compareVersions(a, b) {
    if (!PLAIN_NUMERIC.test(a) || !PLAIN_NUMERIC.test(b))
        return undefined;
    const left = a.split('.').map(Number);
    const right = b.split('.').map(Number);
    const length = Math.max(left.length, right.length);
    for (let i = 0; i < length; i += 1) {
        // A missing trailing segment is zero: "1.2" and "1.2.0" are the same
        // version in both SEMVER and PEP 440.
        const diff = (left[i] ?? 0) - (right[i] ?? 0);
        if (diff !== 0)
            return diff < 0 ? -1 : 1;
    }
    return 0;
}
/**
 * Does `version` fall inside this range? `undefined` means the comparison was
 * refused (see compareVersions) and the caller must not conclude anything.
 *
 * OSV's own event semantics: a version is affected once it is at or after an
 * `introduced` bound, and stops being affected at or after a `fixed` or `limit`
 * bound, or after a `last_affected` one. Events are applied in version order
 * rather than file order, because OSV does not guarantee the array is sorted.
 */
function evaluateRange(version, range) {
    const bounds = [];
    if (range.introduced !== undefined)
        bounds.push({ at: range.introduced, affectedFromHere: true, inclusive: true });
    if (range.fixed !== undefined)
        bounds.push({ at: range.fixed, affectedFromHere: false, inclusive: true });
    if (range.limit !== undefined)
        bounds.push({ at: range.limit, affectedFromHere: false, inclusive: true });
    // last_affected is the final affected version, so the flip happens strictly
    // AFTER it — one off-by-one away from fixed, and the difference matters.
    if (range.lastAffected !== undefined)
        bounds.push({ at: range.lastAffected, affectedFromHere: false, inclusive: false });
    if (bounds.length === 0)
        return undefined;
    // Sort the bounds themselves, refusing the whole range if any pair is
    // incomparable rather than falling back to file order.
    for (const bound of bounds) {
        if (compareVersions(version, bound.at) === undefined)
            return undefined;
    }
    const sorted = [...bounds].sort((x, y) => compareVersions(x.at, y.at) ?? 0);
    let affected = false;
    for (const bound of sorted) {
        const cmp = compareVersions(version, bound.at);
        if (cmp === undefined)
            return undefined;
        const reached = bound.inclusive ? cmp >= 0 : cmp > 0;
        if (reached)
            affected = bound.affectedFromHere;
    }
    return affected;
}
/** `true` if any range covers the version, `false` if all evaluable ranges exclude it, `undefined` if the comparison was refused. */
function evaluateRanges(version, ranges) {
    let sawRefusal = false;
    let sawEvaluable = false;
    for (const range of ranges) {
        const result = evaluateRange(version, range);
        if (result === undefined)
            sawRefusal = true;
        else if (result)
            return true;
        else
            sawEvaluable = true;
    }
    if (sawRefusal || !sawEvaluable)
        return undefined;
    return false;
}
function today() {
    return new Date().toISOString().slice(0, 10);
}
/** Candidate `vendor:product` and `product` keys a component offers, cheapest identity signal last. */
function componentKeys(component) {
    const cpeKey = component.cpe ? (0, support_1.normalizeCpeKey)(component.cpe) : undefined;
    const supplierKey = component.supplier ? normalizeKevKey(component.supplier) : undefined;
    const nameKeys = [];
    const fromName = normalizeKevKey(component.name);
    if (fromName)
        nameKeys.push(fromName);
    // The product half of a CPE is frequently a better product name than the
    // component's own name (a Yocto SBOM may call it "openssl-bin" while the CPE
    // says "openssl").
    if (cpeKey) {
        const product = normalizeKevKey(cpeKey.slice(cpeKey.indexOf(':') + 1));
        if (product && !nameKeys.includes(product))
            nameKeys.push(product);
    }
    return { ...(cpeKey ? { cpeKey } : {}), ...(supplierKey ? { supplierKey } : {}), nameKeys };
}
function baseFinding(entry) {
    return {
        cve: entry.cve,
        vulnerabilityName: entry.vulnerabilityName,
        kevVendor: entry.vendor,
        kevProduct: entry.product,
        dateAdded: entry.dateAdded,
        ...(entry.dueDate ? { dueDate: entry.dueDate } : {}),
        ...(entry.ransomware ? { ransomware: true } : {}),
        ...(entry.cwes && entry.cwes.length > 0 ? { cwes: [...entry.cwes] } : {}),
    };
}
/** The sentence every finding opens with — FDA asks how the vulnerability was discovered, and the answer is the same for all of them. */
function discoveredBy(catalogVersion) {
    return `Discovered by screening the component list against the bundled CISA Known Exploited Vulnerabilities Catalog (catalogue version ${catalogVersion}), offline.`;
}
/**
 * The ecosystem-advisory pass: npm/PyPI components matched by purl against
 * data/kev-index.json, which carries real affected version ranges. This is the
 * only path that can produce `confirmed` or `not-affected`.
 */
function advisoryFindings(component, lookup, discovery) {
    const byCve = new Map();
    const warnings = [];
    const purlKey = component.purl ? (0, support_1.normalizePurlKey)(component.purl) : undefined;
    if (!purlKey)
        return { byCve, warnings };
    const matches = lookup.byPurlKey.get(purlKey);
    if (!matches)
        return { byCve, warnings };
    for (const match of matches) {
        const entry = lookup.byCve.get(match.cve);
        // An index entry whose CVE is not in the snapshot means the two files were
        // built from different catalogue versions. Say so rather than dropping the
        // row: the index exists only to refine KEV findings.
        if (!entry) {
            warnings.push(`data/kev-index.json references ${match.cve} (via ${match.advisory}) but data/kev-snapshot.json does not contain it, so the finding for ${component.name} was skipped. ` +
                'The two files were built from different catalogue versions — re-run "npm run fetch-kev-snapshot" then "npm run build-kev-index".');
            continue;
        }
        const where = `${match.advisorySource} advisory ${match.advisory} names ${match.ecosystem} package "${match.package}" as affected by ${match.cve}`;
        const ranges = match.ranges
            .map((r) => [
            r.introduced !== undefined ? `>= ${r.introduced}` : undefined,
            r.fixed !== undefined ? `< ${r.fixed} (fixed)` : undefined,
            r.lastAffected !== undefined ? `<= ${r.lastAffected} (last affected)` : undefined,
            r.limit !== undefined ? `< ${r.limit} (limit)` : undefined,
        ]
            .filter(Boolean)
            .join(' and '))
            .filter((s) => s.length > 0)
            .join('; ');
        const common = { ...baseFinding(entry), basis: 'ecosystem-advisory', advisory: match.advisory, advisorySource: match.advisorySource };
        let finding;
        if (!component.version) {
            finding = {
                ...common,
                confidence: 'possible',
                evidence: `${discovery} ${where}, with affected ranges ${ranges}. The component carries no version, so whether this device's copy is inside an affected range could not be determined.`,
            };
        }
        else {
            const affected = evaluateRanges(component.version, match.ranges);
            if (affected === true) {
                finding = {
                    ...common,
                    confidence: 'confirmed',
                    evidence: `${discovery} ${where}. Version ${component.version} falls inside the affected range ${ranges} (${match.rangeType} ordering).`,
                };
            }
            else if (affected === false) {
                finding = {
                    ...common,
                    confidence: 'not-affected',
                    evidence: `${discovery} ${where}, but version ${component.version} is outside every affected range (${ranges}, ${match.rangeType} ordering). Recorded so the CVE is visibly considered rather than silently omitted.`,
                };
            }
            else {
                finding = {
                    ...common,
                    confidence: 'possible',
                    evidence: `${discovery} ${where}, with affected ranges ${ranges}. This tool declined to compare version "${component.version}" against those bounds — ` +
                        'it only compares plain dotted-numeric versions, because SEMVER and PEP 440 order pre-release and post-release versions differently and a wrong comparison here would mean a wrong "not affected" next to a known-exploited vulnerability. Check this one by hand.',
                };
            }
        }
        const existing = byCve.get(entry.cve);
        // The same CVE can name two packages that both match (e.g. a scoped and an
        // unscoped alias). Keep the most severe verdict.
        if (!existing || rank(finding.confidence) < rank(existing.confidence))
            byCve.set(entry.cve, finding);
    }
    return { byCve, warnings };
}
function rank(confidence) {
    return confidence === 'confirmed' ? 0 : confidence === 'possible' ? 1 : 2;
}
/**
 * The identity pass over the KEV catalogue itself. Produces `possible` rows
 * only, always — the catalogue has no version data, so no amount of identity
 * confidence can make a row version-precise.
 */
function identityFindings(component, lookup, discovery) {
    const byCve = new Map();
    const { cpeKey, supplierKey, nameKeys } = componentKeys(component);
    const noVersions = 'The KEV catalogue records no version information, so this identifies a known-exploited vulnerability in the product, not in this specific version of it; the match is reported as possible and needs confirmation against the component version by hand.';
    const consider = (entry, basis, how) => {
        const existing = byCve.get(entry.cve);
        if (existing && BASIS_STRENGTH.indexOf(existing.basis) <= BASIS_STRENGTH.indexOf(basis))
            return;
        byCve.set(entry.cve, {
            ...baseFinding(entry),
            confidence: 'possible',
            basis,
            evidence: `${discovery} ${how} ${noVersions}`,
        });
    };
    if (cpeKey) {
        for (const entry of lookup.byVendorProduct.get(cpeKey) ?? []) {
            consider(entry, 'cpe', `The component's CPE resolves to vendor:product "${cpeKey}", which equals CISA's listed vendor "${entry.vendor}" and product "${entry.product}".`);
        }
    }
    for (const nameKey of nameKeys) {
        if (supplierKey) {
            for (const entry of lookup.byVendorProduct.get(`${supplierKey}:${nameKey}`) ?? []) {
                consider(entry, 'vendor-product', `The SBOM's supplier "${component.supplier}" and component name "${component.name}" match CISA's listed vendor "${entry.vendor}" and product "${entry.product}".`);
            }
        }
        for (const entry of lookup.byProduct.get(nameKey) ?? []) {
            const supplierMismatch = supplierKey && normalizeKevKey(entry.vendor) !== supplierKey
                ? ` The SBOM names supplier "${component.supplier}" while CISA lists vendor "${entry.vendor}", so this may well be a different product that shares a name — check before carrying it forward.`
                : ' The vendor could not be corroborated (the component declares no supplier), so this may be a different product that shares a name — check before carrying it forward.';
            consider(entry, 'product-name', `Component name "${component.name}" matches CISA's listed product "${entry.product}" (vendor "${entry.vendor}").${supplierMismatch}`);
        }
    }
    return byCve;
}
/**
 * Screen every component against the bundled KEV catalogue, refined by the
 * bundled ecosystem-advisory index where it applies.
 *
 * Ordering of the two passes is deliberate: the advisory pass runs first and its
 * verdict for a CVE wins, because a version-range comparison is strictly better
 * evidence than a product-name match for the same CVE. A CVE the advisory pass
 * ruled `not-affected` is therefore NOT re-raised as `possible` by the identity
 * pass — that would be the tool arguing with its own better evidence — but it
 * still appears in `notAffected` with the comparison written out.
 */
function screenKev(components, options = {}) {
    const asOf = options.asOf ?? today();
    const lookup = options.lookup ?? loadKevLookup();
    const { snapshot, index } = lookup;
    const warnings = [];
    const seenIndexWarnings = new Set();
    const stale = (0, support_1.snapshotStalenessWarning)({
        label: `CISA Known Exploited Vulnerabilities Catalog (catalogue version ${snapshot.source.catalogVersion})`,
        generatedAt: snapshot.source.dateReleased,
        asOf,
        consequence: 'CISA adds newly-exploited vulnerabilities to the catalogue continuously, so a component shown here as having no known exploited vulnerability may have had one catalogued since this snapshot was taken.',
        refreshCommand: 'npm run fetch-kev-snapshot, then npm run build-kev-index',
    });
    if (stale)
        warnings.push(stale);
    const results = [];
    const totals = {
        components: components.length,
        componentsWithFindings: 0,
        confirmed: 0,
        possible: 0,
        notAffected: 0,
        ransomware: 0,
        productNameOnly: 0,
    };
    for (const component of components) {
        const discovery = discoveredBy(snapshot.source.catalogVersion);
        const advisory = advisoryFindings(component, lookup, discovery);
        for (const warning of advisory.warnings) {
            if (!seenIndexWarnings.has(warning)) {
                seenIndexWarnings.add(warning);
                warnings.push(warning);
            }
        }
        const byCve = advisory.byCve;
        for (const [cve, finding] of identityFindings(component, lookup, discovery)) {
            if (!byCve.has(cve))
                byCve.set(cve, finding);
        }
        const all = [...byCve.values()].sort((a, b) => rank(a.confidence) - rank(b.confidence) || BASIS_STRENGTH.indexOf(a.basis) - BASIS_STRENGTH.indexOf(b.basis) || a.cve.localeCompare(b.cve));
        const findings = all.filter((f) => f.confidence !== 'not-affected');
        const notAffected = all.filter((f) => f.confidence === 'not-affected');
        if (findings.length > 0)
            totals.componentsWithFindings += 1;
        for (const finding of findings) {
            if (finding.confidence === 'confirmed')
                totals.confirmed += 1;
            else
                totals.possible += 1;
            if (finding.ransomware)
                totals.ransomware += 1;
            if (finding.basis === 'product-name')
                totals.productNameOnly += 1;
        }
        totals.notAffected += notAffected.length;
        results.push({ component, findings, notAffected });
    }
    if (totals.confirmed > 0) {
        warnings.push(`${totals.confirmed} known-exploited ${totals.confirmed === 1 ? 'vulnerability is' : 'vulnerabilities are'} confirmed against a component version in this device. ` +
            'FDA’s guidance states that vulnerabilities in CISA’s catalogue should be designed out of the device, so each one needs a safety and security risk assessment and the risk controls applied, written by the manufacturer.');
    }
    if (totals.productNameOnly > 0) {
        warnings.push(`${totals.productNameOnly} of the ${totals.confirmed + totals.possible} findings rest on a product-name match with no corroborating vendor, and some of those will be a different product that happens to share a name. ` +
            'They are listed rather than filtered because missing a real known-exploited vulnerability is the worse error; each row names CISA’s vendor so it can be ruled out quickly.');
    }
    if (index.entries.length === 0) {
        warnings.push('data/kev-index.json is empty, so no finding in this run can be version-precise and everything is reported as "possible". Re-run "npm run build-kev-index".');
    }
    return {
        results,
        warnings,
        limits: exports.KEV_SCREEN_LIMITS,
        snapshotSource: snapshot.source,
        indexSources: index.sources,
        indexBuiltFrom: index.builtFrom,
        totals,
    };
}
//# sourceMappingURL=kev.js.map