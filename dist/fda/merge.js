"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.componentsFromScan = componentsFromScan;
exports.mergeComponents = mergeComponents;
const purl_1 = require("../report/sbom/purl");
const importSbom_1 = require("./importSbom");
/**
 * The bridge from the existing scan pipeline into the FDA component model, and
 * the merge of a repo scan with one or more imported SBOMs.
 *
 * A repo scan and an imported SBOM are additive, not competing: a device team
 * can have a firmware SBOM AND a Node-based companion app in the same repo, and
 * the FDA artifact has to list both. So every source contributes and the merge
 * deduplicates — it never picks a winner between sources.
 */
/**
 * Adapt resolved npm/PyPI packages into FDA components. The only place the two
 * models meet; see the comment at the top of ./types.ts for why they are
 * separate models at all.
 *
 * An unresolved license produces an EMPTY `licenses` array rather than the
 * display string ("UNKNOWN", "UNLICENSED"), matching the existing CycloneDX
 * renderer's rule: omit rather than assert a license that was never resolved.
 */
function componentsFromScan(packages) {
    return packages.map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        purl: (0, importSbom_1.normalizePurl)((0, purl_1.toPurl)(pkg)),
        type: 'library',
        licenses: pkg.licenseIds.length > 0 ? [pkg.license] : [],
        hashes: [],
        properties: {},
        origins: ['scan'],
    }));
}
/** `name@version`, case-insensitive. Undefined when the component has no version — a nameless-version component can never be matched this way. */
function nameVersionKey(c) {
    return c.version ? `${c.name.toLowerCase()}@${c.version.toLowerCase()}` : undefined;
}
function cloneComponent(c) {
    return {
        ...c,
        licenses: [...c.licenses],
        hashes: c.hashes.map((h) => ({ ...h })),
        properties: { ...c.properties },
        origins: [...c.origins],
        conflicts: c.conflicts ? [...c.conflicts] : undefined,
        sourceRefs: c.sourceRefs ? [...c.sourceRefs] : undefined,
    };
}
function hashKey(h) {
    return `${h.alg}:${h.content}`;
}
/** The scalar fields a later source can fill in or disagree about. */
const SCALAR_FIELDS = ['version', 'purl', 'cpe', 'supplier', 'type'];
function originLabel(c) {
    return c.origins[0] ?? 'unknown source';
}
/**
 * Fold `incoming` into `target`. First non-empty value wins for every scalar;
 * a differing later value is recorded in `target.conflicts` rather than
 * dropped, because a silently discarded supplier or CPE is exactly the kind of
 * invisible data loss that makes a generated submission document untrustworthy.
 * Returns the number of conflicts recorded.
 */
function mergeInto(target, incoming) {
    let conflicts = 0;
    for (const origin of incoming.origins) {
        if (!target.origins.includes(origin))
            target.origins.push(origin);
    }
    for (const field of SCALAR_FIELDS) {
        const next = incoming[field];
        if (!next)
            continue;
        const current = target[field];
        if (!current) {
            target[field] = next;
        }
        else if (current !== next) {
            // version/purl can only differ in case here (they are part of the match
            // key), so a recorded conflict on them is always a real disagreement.
            (target.conflicts ??= []).push(`${field}: kept "${current}" (${originLabel(target)}), also reported as "${next}" (${originLabel(incoming)})`);
            conflicts += 1;
        }
    }
    for (const license of incoming.licenses) {
        if (!target.licenses.includes(license))
            target.licenses.push(license);
    }
    const seenHashes = new Set(target.hashes.map(hashKey));
    for (const hash of incoming.hashes) {
        if (!seenHashes.has(hashKey(hash))) {
            target.hashes.push(hash);
            seenHashes.add(hashKey(hash));
        }
    }
    for (const [key, value] of Object.entries(incoming.properties)) {
        const current = target.properties[key];
        if (current === undefined) {
            target.properties[key] = value;
        }
        else if (current !== value) {
            (target.conflicts ??= []).push(`property ${key}: kept "${current}" (${originLabel(target)}), also reported as "${value}" (${originLabel(incoming)})`);
            conflicts += 1;
        }
    }
    if (incoming.possibleDuplicate)
        target.possibleDuplicate = true;
    // Source refs ACCUMULATE rather than conflict. Two documents naming the same
    // component with different `bom-ref`s is not a disagreement about the
    // component — a bom-ref is a document-local identifier, not a fact about the
    // software — and both have to be kept, or the dependency edges from
    // whichever document lost would be unmappable and silently dropped.
    for (const ref of incoming.sourceRefs ?? []) {
        if (!(target.sourceRefs ??= []).includes(ref))
            target.sourceRefs.push(ref);
    }
    return conflicts;
}
/**
 * Merge component lists from several sources into one deduplicated list.
 * Sources are processed in the order given, and earlier sources win scalar
 * ties — so the caller decides precedence by ordering, not by a flag.
 *
 * Match order, deliberately conservative:
 *  1. normalized purl, when both sides have one;
 *  2. else case-insensitive `name@version`;
 *  3. name alone is NOT a match. Two components with the same name and a
 *     missing or differing version are kept as two entries and flagged
 *     `possibleDuplicate`, with a warning. Collapsing them would mean asserting
 *     that "openssl" (no version) from a firmware SBOM and "openssl 3.0.11"
 *     from another source are the same component — an assumption a reviewer
 *     has no way to see, and one this repo's doctrine forbids making silently.
 */
function mergeComponents(sources) {
    const components = [];
    const byPurl = new Map();
    const byNameVersion = new Map();
    const byName = new Map();
    const warnings = [];
    const ambiguousNames = new Set();
    let conflictCount = 0;
    for (const source of sources) {
        for (const raw of source) {
            const purl = raw.purl;
            const nv = nameVersionKey(raw);
            const existing = (purl ? byPurl.get(purl) : undefined) ?? (nv ? byNameVersion.get(nv) : undefined);
            if (existing) {
                conflictCount += mergeInto(existing, raw);
                // Index whichever key the merged-in component contributed that the
                // surviving entry didn't already have, so a third source matching on
                // either key still lands on the same component.
                if (purl && !byPurl.has(purl))
                    byPurl.set(purl, existing);
                if (nv && !byNameVersion.has(nv))
                    byNameVersion.set(nv, existing);
                continue;
            }
            const component = cloneComponent(raw);
            const nameKey = component.name.toLowerCase();
            const sameName = byName.get(nameKey);
            if (sameName && sameName.length > 0) {
                component.possibleDuplicate = true;
                for (const other of sameName)
                    other.possibleDuplicate = true;
                if (!ambiguousNames.has(nameKey)) {
                    ambiguousNames.add(nameKey);
                    warnings.push(`Possible duplicate, unresolved: "${component.name}" appears in more than one source with a missing or differing version. ` +
                        `Both entries were kept and flagged; neither was merged, because matching on name alone would be a guess.`);
                }
            }
            components.push(component);
            if (component.purl)
                byPurl.set(component.purl, component);
            const newNv = nameVersionKey(component);
            if (newNv && !byNameVersion.has(newNv))
                byNameVersion.set(newNv, component);
            byName.set(nameKey, [...(sameName ?? []), component]);
        }
    }
    if (conflictCount > 0) {
        warnings.push(`${conflictCount} field conflict${conflictCount === 1 ? '' : 's'} between sources were recorded on the affected components ` +
            `(the first source's value was kept). Every one is listed in the component's own "conflicts" entry.`);
    }
    return { components, warnings };
}
//# sourceMappingURL=merge.js.map