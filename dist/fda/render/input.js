"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CDX_HASH_ALGORITHMS = exports.CDX_COMPONENT_TYPES = exports.NOT_STATED = exports.NEEDS_HUMAN_INPUT = void 0;
exports.joinRows = joinRows;
exports.bomRefFor = bomRefFor;
exports.subjectBomRef = subjectBomRef;
exports.resolveDependencies = resolveDependencies;
exports.componentLabel = componentLabel;
exports.runWarnings = runWarnings;
exports.cdxType = cdxType;
exports.coercedType = coercedType;
exports.usableHashes = usableHashes;
exports.unusableHashes = unusableHashes;
exports.isDeclinedComparison = isDeclinedComparison;
exports.isUnversionedAgainstAdvisory = isUnversionedAgainstAdvisory;
exports.mdCell = mdCell;
exports.mdTable = mdTable;
exports.csvCell = csvCell;
exports.csvRows = csvRows;
/** The value every renderer prints where the manufacturer has to supply something. Same string the CRA gap checklist uses, so one vocabulary covers both modes. */
exports.NEEDS_HUMAN_INPUT = 'NEEDS-HUMAN-INPUT';
/** What a renderer prints where the SOURCE DATA was silent. Distinct from NEEDS-HUMAN-INPUT: nobody is being asked for it in that cell, it simply was not in the SBOM. */
exports.NOT_STATED = 'not stated';
/**
 * Join the support resolution and the KEV screen per component.
 *
 * Order comes from `support.results`, which is one entry per component in the
 * order the merge produced them. The KEV screen is looked up by component
 * object identity; a component the screen never saw throws, because rendering
 * "no known exploited vulnerabilities" for a component that was never screened
 * is the single most dangerous output this tool could produce.
 */
function joinRows(input) {
    const kevByComponent = new Map(input.kev.results.map((r) => [r.component, r]));
    const usedRefs = new Set();
    return input.support.results.map(({ component, support }) => {
        const kev = kevByComponent.get(component);
        if (!kev) {
            throw new Error(`The KEV screen has no result for component "${component.name}". ` +
                'resolveSupport and screenKev must be run over the SAME merged component list before rendering — ' +
                'a component rendered without its screen would read as having no known exploited vulnerabilities.');
        }
        return { component, support, findings: kev.findings, notAffected: kev.notAffected, bomRef: bomRefFor(component, usedRefs) };
    });
}
/**
 * A stable, human-readable `bom-ref`: the purl when there is one, else
 * `name@version`, else the bare name, with a numeric suffix on collision.
 * Deliberately derived rather than a UUID so two runs over the same input
 * produce the same refs and the artifacts diff cleanly.
 */
function bomRefFor(component, used) {
    const base = component.purl ?? (component.version ? `${component.name}@${component.version}` : component.name);
    let ref = base;
    let n = 2;
    while (used.has(ref))
        ref = `${base}#${n++}`;
    used.add(ref);
    return ref;
}
/**
 * The `bom-ref` for the BOM's subject (the device, `metadata.component`).
 *
 * Derived the same way a component's is, from a set seeded with every
 * component ref so the device can never collide with one of its own
 * components. It exists because a source SBOM's dependency graph is almost
 * always rooted at `metadata.component`: without a ref on the subject, the
 * root edge — the one that says which components the device depends on
 * directly — would be the one edge that could not be carried through.
 */
function subjectBomRef(input, rows) {
    if (!input.subject)
        return undefined;
    return bomRefFor(input.subject, new Set(rows.map((row) => row.bomRef)));
}
/**
 * Map the imported edges onto the refs this document actually emits, and
 * report every one that could not be mapped.
 *
 * Nothing is inferred and nothing is repaired. An edge naming a ref no
 * component here carries is a real gap — the component may have been dropped
 * as nameless, or the source document may reference a service or an external
 * BOM this mode does not import — and the honest response is to leave the edge
 * out and say which ref it was.
 *
 * Only the target of the mapping is this document's business; the SOURCE
 * document's own `dependencies[]` ordering is preserved, because the order a
 * producer emitted its graph in is their data, not ours.
 */
function resolveDependencies(input, rows) {
    const bySourceRef = new Map();
    for (const row of rows) {
        for (const ref of row.component.sourceRefs ?? [])
            bySourceRef.set(ref, row.bomRef);
    }
    const subject = subjectBomRef(input, rows);
    if (subject !== undefined) {
        for (const ref of input.subject?.sourceRefs ?? [])
            bySourceRef.set(ref, subject);
    }
    // Keyed by EMITTED ref, in first-seen order. Two source documents that both
    // describe the same component produce two entries naming one emitted ref,
    // and CycloneDX allows a component to appear in `dependencies[]` once — so
    // their edge sets are unioned. Both producers asserted their edges; neither
    // set is invented, and dropping one because the other arrived first would
    // lose a real relationship.
    const byRef = new Map();
    const unmappedRefs = [];
    let unmappedEdgeTargets = 0;
    for (const dependency of input.dependencies ?? []) {
        const ref = bySourceRef.get(dependency.ref);
        if (ref === undefined) {
            if (!unmappedRefs.includes(dependency.ref))
                unmappedRefs.push(dependency.ref);
            continue;
        }
        const dependsOn = byRef.get(ref) ?? [];
        for (const target of dependency.dependsOn) {
            const mapped = bySourceRef.get(target);
            if (mapped === undefined) {
                unmappedEdgeTargets += 1;
                continue;
            }
            // A self-edge says nothing, and the schema requires unique entries.
            if (mapped !== ref && !dependsOn.includes(mapped))
                dependsOn.push(mapped);
        }
        byRef.set(ref, dependsOn);
    }
    const edges = [...byRef.entries()].map(([ref, dependsOn]) => ({ ref, dependsOn }));
    const inGraph = new Set();
    let hasComponentEdges = false;
    for (const { ref, dependsOn } of edges) {
        inGraph.add(ref);
        for (const target of dependsOn)
            inGraph.add(target);
        if (ref !== subject && dependsOn.length > 0)
            hasComponentEdges = true;
    }
    return {
        edges,
        unmappedRefs,
        unmappedEdgeTargets,
        componentsInGraph: rows.filter((row) => inGraph.has(row.bomRef)).length,
        hasComponentEdges,
    };
}
/** `name 1.2.3`, or `name (version not stated)` — never `name@0.0.0`. */
function componentLabel(component) {
    return component.version ? `${component.name} ${component.version}` : `${component.name} (version ${exports.NOT_STATED})`;
}
/** Every warning the run produced, in the order a reader should meet them: what the inputs disagreed about, then what the data could not answer. */
function runWarnings(input) {
    return [...input.mergeWarnings, ...input.support.warnings, ...input.kev.warnings];
}
/**
 * The CycloneDX 1.6 `component.type` enum, verbatim from the vendored schema
 * (tests/schemas/cyclonedx-1.6.schema.json). An imported SBOM can carry any
 * string here; one outside this set would make the enriched document fail
 * schema validation, so `cdxType` maps it to `library` and `coercedType` makes
 * the substitution visible as an open item instead of a silent rewrite.
 */
exports.CDX_COMPONENT_TYPES = [
    'application',
    'framework',
    'library',
    'container',
    'platform',
    'operating-system',
    'device',
    'device-driver',
    'firmware',
    'file',
    'machine-learning-model',
    'data',
    'cryptographic-asset',
];
/** The CycloneDX 1.6 `hashes[].alg` enum, verbatim from the vendored schema. Same reason as above. */
exports.CDX_HASH_ALGORITHMS = [
    'MD5',
    'SHA-1',
    'SHA-256',
    'SHA-384',
    'SHA-512',
    'SHA3-256',
    'SHA3-384',
    'SHA3-512',
    'BLAKE2b-256',
    'BLAKE2b-384',
    'BLAKE2b-512',
    'BLAKE3',
];
function cdxType(component) {
    return component.type && exports.CDX_COMPONENT_TYPES.includes(component.type) ? component.type : 'library';
}
/** The component's own type when it is NOT a CycloneDX type, i.e. the value `cdxType` had to replace. */
function coercedType(component) {
    return component.type && !exports.CDX_COMPONENT_TYPES.includes(component.type) ? component.type : undefined;
}
function usableHashes(component) {
    return component.hashes.filter((h) => exports.CDX_HASH_ALGORITHMS.includes(h.alg));
}
/** Hashes whose algorithm CycloneDX has no name for. Omitted from the document, reported as an open item — an invented algorithm name would be worse than a stated omission. */
function unusableHashes(component) {
    return component.hashes.filter((h) => !exports.CDX_HASH_ALGORITHMS.includes(h.alg));
}
/**
 * A finding where the tool declined to compare the component's version against
 * the advisory's ranges (see `compareVersions`' refusal list). Derived from the
 * finding's own fields rather than by matching its evidence text: an
 * ecosystem-advisory finding that stayed `possible` even though the component
 * HAS a version can only be a refused comparison.
 */
function isDeclinedComparison(component, finding) {
    return finding.basis === 'ecosystem-advisory' && finding.confidence === 'possible' && component.version !== undefined;
}
/** Same derivation, for the other reason an advisory finding stays `possible`: the component carries no version at all. */
function isUnversionedAgainstAdvisory(component, finding) {
    return finding.basis === 'ecosystem-advisory' && finding.confidence === 'possible' && component.version === undefined;
}
/** Markdown table cells cannot contain a raw pipe or newline. Nothing is truncated — only the two characters that would break the table are escaped. */
function mdCell(value) {
    return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}
function mdTable(headers, rows) {
    const head = `| ${headers.map(mdCell).join(' | ')} |`;
    const rule = `|${headers.map(() => '---').join('|')}|`;
    const body = rows.map((r) => `| ${r.map(mdCell).join(' | ')} |`);
    return [head, rule, ...body].join('\n');
}
/**
 * One CSV cell, RFC 4180: quoted when it contains a comma, a quote, or a
 * newline, with embedded quotes doubled.
 *
 * Values are written through verbatim otherwise — a leading `=`, `+` or `@`
 * (an npm scoped name like `@scope/pkg`) is NOT prefixed or altered to defuse
 * spreadsheet formula interpretation. In a submission artifact the cell has to
 * match the component data it came from; changing the bytes to improve how one
 * spreadsheet displays them is the wrong trade here.
 */
function csvCell(value) {
    return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
function csvRows(headers, rows) {
    return [headers, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
//# sourceMappingURL=input.js.map