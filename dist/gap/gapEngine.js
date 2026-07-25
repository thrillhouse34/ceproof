"use strict";
/**
 * The gap-checklist engine: for every CraStructureItem (data/cra-structure.json,
 * loaded via src/cra/loader.ts), decide whether the current repo scan +
 * (optional) ceproof.config.json answers give us enough to call the item
 * DERIVED, PARTIAL, or NEEDS-HUMAN-INPUT.
 *
 * This module is pure/no-I/O by design: it takes already-collected
 * RepoFacts (src/detect/index.ts), already-resolved dependency packages
 * (src/resolve/resolveProject.ts), an optional already-loaded config
 * (src/config/types.ts), and the already-loaded CRA structure list
 * (src/cra/loader.ts) — the caller (CLI layer) owns all file I/O.
 *
 * ---------------------------------------------------------------------
 * Status decision (per CraStructureItem):
 * ---------------------------------------------------------------------
 *
 * 1. derivability === 'human-required':
 *    - If `config.answers[item.id]` exists (a non-empty string), the item
 *      is DERIVED, with evidence noting it came from the config file. An
 *      answer key present but set to an empty string is treated as "not
 *      answered" (still NEEDS-HUMAN-INPUT) — an empty string is not a real
 *      answer, and we never silently treat "present key" as "present
 *      value" when the value itself is empty.
 *    - Otherwise NEEDS-HUMAN-INPUT, with no evidence (there is none yet).
 *    `config` may be null/undefined (no ceproof.config.json yet) — treated
 *    identically to "no answers supplied", never a crash.
 *
 * 2. derivability === 'derivable' | 'partial':
 *    - Empty `evidenceKeys` array: this is a data-authoring inconsistency
 *      (a derivable/partial item ought to declare how it's derived). Never
 *      crash on it — it's the real state of the current synthetic
 *      placeholder data. Falls back to PARTIAL with an explanatory
 *      evidence note.
 *    - Non-empty `evidenceKeys`: each key is resolved (see "Evidence key
 *      resolution" below) against RepoFacts, or against the resolved
 *      dependency packages for `packages.*`-prefixed keys.
 *        - All keys resolve  -> DERIVED
 *        - Some keys resolve -> PARTIAL
 *        - No keys resolve   -> PARTIAL (never DERIVED with zero evidence;
 *          this holds regardless of whether the item's declared
 *          derivability was 'derivable' or 'partial' — a 'derivable' item
 *          that failed to find any evidence in THIS repo is exactly as
 *          incomplete as a 'partial' one for THIS repo).
 *      Evidence text always lists every key with a human-readable note on
 *      whether it resolved, so a PARTIAL/DERIVED verdict is always
 *      traceable back to what was actually checked (honest UNKNOWNs).
 *
 * ---------------------------------------------------------------------
 * Evidence key resolution
 * ---------------------------------------------------------------------
 *
 * A key is a dot-path, e.g. "security.securityMdPresent" or "vcs.isGitRepo".
 *
 * - Keys prefixed "packages." are resolved against the resolved dependency
 *   packages (SBOM-readiness signal only — never surfaced as per-package
 *   license findings here, that's src/resolve's own report surface):
 *     - "packages.count": resolves (present) if resolvedPackages.length >= 1.
 *     - "packages.allLicensesKnown": resolves (present) if and only if zero
 *       resolved packages have category 'unknown'. An empty resolvedPackages
 *       array is vacuously "all known" (there are no unknowns to find) and
 *       so resolves true — this mirrors the plain English of the key
 *       ("zero packages have unknown category") rather than requiring
 *       packages to exist first; "packages.count" is the key that answers
 *       "did we even scan anything".
 *     - Any other "packages.*" key is unrecognized: it never resolves, and
 *       gets an evidence note saying so, rather than crashing or guessing
 *       what it might mean. (The current synthetic data/cra-structure.json
 *       fixture doesn't use any other packages.* key; this is a documented,
 *       safe default for whatever the real CRA data eventually needs.)
 *
 * - Any other key is looked up as a dot-path directly against the RepoFacts
 *   object (e.g. "vcs.isGitRepo" -> facts.vcs.isGitRepo). Missing
 *   intermediate segments (including keys like "repo.manifest.name" that
 *   don't exist anywhere on RepoFacts — the current placeholder data uses
 *   some of these) resolve to `undefined`, i.e. "not present" — never a
 *   thrown error.
 *
 * "Present" (the key resolves / counts as evidence) is defined per value
 * shape, not raw JS truthiness (JS truthiness alone is wrong for arrays —
 * `[]` is truthy in JS but represents "nothing found" here):
 *   - undefined/null            -> not present
 *   - boolean                   -> present iff true
 *   - string                    -> present iff non-empty
 *   - array                     -> present iff non-empty
 *   - plain object               -> present iff it has at least one own key
 *   - anything else (number, …) -> standard JS truthiness
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeGapChecklist = computeGapChecklist;
function isPlainObjectValue(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function isPresent(value) {
    if (value === undefined || value === null)
        return false;
    if (typeof value === 'boolean')
        return value;
    if (typeof value === 'string')
        return value.length > 0;
    if (Array.isArray(value))
        return value.length > 0;
    if (isPlainObjectValue(value))
        return Object.keys(value).length > 0;
    return Boolean(value);
}
function getByPath(root, dotPath) {
    const parts = dotPath.split('.');
    let cur = root;
    for (const part of parts) {
        if (typeof cur !== 'object' || cur === null)
            return undefined;
        cur = cur[part];
    }
    return cur;
}
function describeFactValue(key, value) {
    if (typeof value === 'boolean')
        return `${key}: ${value}`;
    if (typeof value === 'string')
        return `${key}: "${value}"`;
    if (Array.isArray(value))
        return `${key}: [${value.length} item(s)]`;
    return `${key}: present`;
}
function resolvePackagesKey(key, resolvedPackages) {
    if (key === 'packages.count') {
        const count = resolvedPackages.length;
        return {
            resolved: count >= 1,
            evidence: count >= 1
                ? `packages.count: ${count} package(s) identified via dependency scan`
                : 'packages.count: no packages identified via dependency scan',
        };
    }
    if (key === 'packages.allLicensesKnown') {
        const unknownCount = resolvedPackages.filter((p) => p.category === 'unknown').length;
        const allKnown = unknownCount === 0;
        return {
            resolved: allKnown,
            evidence: allKnown
                ? `packages.allLicensesKnown: all ${resolvedPackages.length} resolved package(s) have a known license category`
                : `packages.allLicensesKnown: ${unknownCount} of ${resolvedPackages.length} resolved package(s) have an unknown license category`,
        };
    }
    // Unrecognized packages.* key: never resolves, never guessed at.
    return {
        resolved: false,
        evidence: `${key}: unrecognized SBOM evidence key (not implemented by the gap engine)`,
    };
}
function resolveFactsKey(key, facts) {
    const value = getByPath(facts, key);
    return {
        resolved: isPresent(value),
        evidence: value === undefined ? `${key}: not detected` : describeFactValue(key, value),
    };
}
function resolveEvidenceKey(key, facts, resolvedPackages) {
    if (key.startsWith('packages.')) {
        return resolvePackagesKey(key, resolvedPackages);
    }
    return resolveFactsKey(key, facts);
}
function hasNonEmptyAnswer(config, id) {
    const answer = config?.answers?.[id];
    return typeof answer === 'string' && answer.length > 0;
}
function computeItem(item, facts, resolvedPackages, config) {
    const base = {
        id: item.id,
        instrument: item.instrument,
        requirementSummary: item.requirementSummary,
        citation: item.citation,
    };
    if (item.derivability === 'boilerplate') {
        // Fixed regulatory text, never per-repo evidence and never a human-input
        // interview question: item.boilerplateText IS the content. The loader
        // guarantees boilerplateText is a non-empty string whenever derivability
        // is 'boilerplate', so this is always DERIVED.
        return {
            ...base,
            status: 'DERIVED',
            evidence: [`Fixed regulatory boilerplate (no per-repo evidence needed): "${item.boilerplateText}"`],
        };
    }
    if (item.derivability === 'human-required') {
        if (hasNonEmptyAnswer(config, item.id)) {
            return {
                ...base,
                status: 'DERIVED',
                evidence: [`Supplied via ceproof.config (answers["${item.id}"])`],
            };
        }
        return {
            ...base,
            status: 'NEEDS-HUMAN-INPUT',
            evidence: [],
        };
    }
    // derivability is 'derivable' or 'partial' from here on.
    if (item.evidenceKeys.length === 0) {
        return {
            ...base,
            status: 'PARTIAL',
            evidence: ['No evidence keys defined for this item (data-authoring inconsistency in CRA structure data).'],
        };
    }
    const resolutions = item.evidenceKeys.map((key) => resolveEvidenceKey(key, facts, resolvedPackages));
    const resolvedCount = resolutions.filter((r) => r.resolved).length;
    let status;
    if (resolvedCount === item.evidenceKeys.length) {
        status = 'DERIVED';
    }
    else {
        // Both "some resolved" and "none resolved" land here — a declared
        // derivability of 'derivable' does not entitle an item with zero
        // resolved evidence in this repo to a DERIVED verdict.
        status = 'PARTIAL';
    }
    return {
        ...base,
        status,
        evidence: resolutions.map((r) => r.evidence),
    };
}
function computeGapChecklist(facts, resolvedPackages, config, craStructure) {
    return craStructure.map((item) => computeItem(item, facts, resolvedPackages, config));
}
//# sourceMappingURL=gapEngine.js.map