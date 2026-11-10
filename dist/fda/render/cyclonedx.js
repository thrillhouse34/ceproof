"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VULNERABILITY_SCREEN_NOTE = exports.SOURCE_CONFLICT_PROPERTY = exports.POSSIBLE_DUPLICATE_PROPERTY = exports.VULNERABILITY_SCREEN_PROPERTY = exports.DEPENDENCY_RELATIONSHIPS_PROPERTY = exports.GENERATION_CONTEXT_PROPERTY = void 0;
exports.dependencyRelationshipsNote = dependencyRelationshipsNote;
exports.renderFdaCycloneDx = renderFdaCycloneDx;
/**
 * The enriched CycloneDX 1.6 SBOM — the machine-readable artifact of the FDA
 * premarket mode.
 *
 * It is a SEPARATE renderer from src/report/sbom/cyclonedx.ts, not a flag on
 * it, and that is deliberate: that one renders npm/PyPI `ResolvedPackage`s for
 * the CRA product and must not change shape, while this one renders
 * `FdaComponent`s that may have come from someone else's firmware SBOM and
 * carries per-component values CycloneDX has no native field for.
 *
 * What FDA asks for, and where each piece lands:
 *  - the NTIA minimum elements ("baseline attributes"): supplier
 *    (`component.supplier`), component name, version, other unique identifiers
 *    (`purl`, `cpe`), SBOM author (`metadata.manufacturer`, from the
 *    manufacturer's own config — never invented), timestamp
 *    (`metadata.timestamp`), and DEPENDENCY RELATIONSHIP (`dependencies[]`),
 *    carried through from the imported SBOM's own graph with every ref mapped
 *    onto this document's refs and nothing inferred. Where the source carried
 *    no graph, or only the device's own top-level edges, the array reflects
 *    exactly that and `metadata.properties` says which of the three cases this
 *    document is — the absence of an edge is never allowed to pass for an
 *    assertion that none exists.
 *  - CISA's 2026 minimum-elements update adds fields FDA does not yet cite but
 *    which cost nothing to emit honestly: data format and version (`bomFormat`,
 *    `specVersion`), tool name and version (`metadata.tools`), SBOM version
 *    (`version`), component hashes (`component.hashes`), component licence
 *    (`component.licenses`) and generation context
 *    (`ceproof:fda:generationContext`). SBOM Author Signature is NOT emitted —
 *    signing this document is the manufacturer's act, not the tool's.
 *  - the software level of support and the end-of-support date, which have no
 *    CycloneDX field at all, as `ceproof:fda:*` properties. The guidance allows
 *    them in the SBOM or separately in an addendum; this mode does both, and
 *    the addendum is the human-readable one in fda-summary.md.
 *
 * The `vulnerabilities[]` array carries the screen's findings with FOUR member
 * fields and no others: `id`, `source`, `affects`, and `ratings` only where a
 * rating is actually known. `analysis` is deliberately absent in every row —
 * that object is where CycloneDX expresses a finding's STATE ("not affected",
 * "exploitable", "in triage"), which is the assessment FDA asks the
 * manufacturer for and this tool must never make. Its absence is what says, in
 * the format's own vocabulary, that these rows are unassessed; the
 * `ceproof:fda:vulnerabilityScreen` property says it in words, and
 * `tests/fda/render.test.ts` asserts no row ever grows one.
 *
 * The one thing this document never contains is an invented value. A component
 * with no version has no `version` key; an unresolved licence has no
 * `licenses` entry; a hash whose algorithm CycloneDX cannot name is omitted and
 * reported, never relabelled.
 */
const crypto_1 = require("crypto");
const branding_1 = require("../../branding");
const spdxData_1 = require("../../resolve/spdxData");
const support_1 = require("../support");
const input_1 = require("./input");
/** Property names this renderer owns. A property on an imported component in this namespace is replaced by the value this run resolved; everything else is carried through untouched. */
const CEPROOF_NAMESPACE = 'ceproof:fda:';
exports.GENERATION_CONTEXT_PROPERTY = `${CEPROOF_NAMESPACE}generationContext`;
exports.DEPENDENCY_RELATIONSHIPS_PROPERTY = `${CEPROOF_NAMESPACE}dependencyRelationships`;
exports.VULNERABILITY_SCREEN_PROPERTY = `${CEPROOF_NAMESPACE}vulnerabilityScreen`;
exports.POSSIBLE_DUPLICATE_PROPERTY = `${CEPROOF_NAMESPACE}possibleDuplicate`;
exports.SOURCE_CONFLICT_PROPERTY = `${CEPROOF_NAMESPACE}sourceConflict`;
/**
 * What the `dependencies[]` array in THIS document says, in one of three
 * states, derived from the graph that was actually carried through.
 *
 * Exported as a function rather than a constant because the three cases are
 * genuinely different facts about the output, and a single fixed sentence
 * could only be true of one of them. The open-items list calls the same
 * function, so the document and the list can never disagree.
 *
 * The CycloneDX 1.6 schema's own words for the `incomplete` and `absent`
 * cases are quoted because they are the reading a consumer of this file is
 * entitled to: "Components or services that are not represented in the
 * dependency graph may have unknown dependencies. It is recommended that
 * implementations assume this to be opaque and not an indicator of an object
 * being dependency-free."
 */
function dependencyRelationshipsNote(deps, componentCount) {
    if (deps.edges.length === 0) {
        return ('Absent. No imported SBOM carried a dependencies array, so this document records no relationship between components. ' +
            'Dependency relationship is one of the NTIA minimum elements. Per the CycloneDX specification, a component not represented in the dependency graph ' +
            'must be read as having unknown dependencies, NOT as being dependency-free — nothing here states that these components have no dependencies. ' +
            'Nothing in this mode infers an edge; take the graph from the source SBOM that has it, or regenerate the source SBOM with its dependency data included.');
    }
    const base = `Carried through verbatim from the imported SBOM's own dependencies array, with every reference mapped onto this document's bom-refs. ` +
        `${deps.edges.length} ${deps.edges.length === 1 ? 'entry' : 'entries'}; ${deps.componentsInGraph} of ${componentCount} components appear in the graph. ` +
        'No edge was inferred, added or removed.';
    if (!deps.hasComponentEdges) {
        return (`${base} The graph is INCOMPLETE: it records only top-level edges, and no component-to-component relationship, ` +
            'so the transitive dependencies of these components are not described here. Per the CycloneDX specification, a component not represented in the graph ' +
            'must be read as having unknown dependencies, not as being dependency-free.');
    }
    if (deps.componentsInGraph < componentCount || deps.unmappedRefs.length > 0) {
        return (`${base} The graph is INCOMPLETE: not every component appears in it. Per the CycloneDX specification, a component not represented in the graph ` +
            'must be read as having unknown dependencies, not as being dependency-free.');
    }
    return base;
}
/**
 * What the `vulnerabilities[]` array in this document is, and — the part that
 * matters — what it is not.
 *
 * Every row is a finding the screen produced and NOBODY has assessed. The
 * array carries `id`, `source`, `affects` and nothing else per row; in
 * particular it carries no `analysis`, which is where CycloneDX puts a
 * finding's state. That omission is the claim: this document asserts that
 * these CVEs were matched to these components, and asserts nothing whatever
 * about whether they affect the device.
 */
exports.VULNERABILITY_SCREEN_NOTE = 'Each entry in this document\'s vulnerabilities array is a finding from an offline screen against the CISA Known Exploited Vulnerabilities Catalog, ' +
    'refined where possible by npm/PyPI advisory version ranges. Every entry is UNASSESSED: the screen identified the CVE as matching the component named in its ' +
    '"affects" reference, and nothing more. No entry carries an "analysis" object, because that is where CycloneDX states whether a vulnerability actually ' +
    'affects the product — the safety and security risk assessment of each vulnerability, and the risk controls applied, are the manufacturer\'s to provide and ' +
    'are not in this document. The confidence of each match (confirmed or possible), what it was matched on, and how it was discovered are in ' +
    'fda-vulnerabilities.csv and in the vulnerability section of fda-summary.md. Rows the screen set aside as not affecting the declared version are NOT in this ' +
    'array; they are in fda-vulnerabilities.csv. An empty array is not a statement that the device is free of known vulnerabilities: this screen covers one ' +
    'catalogue, and its limits are listed in fda-summary.md and fda-provenance.json.';
function licensesFor(component) {
    if (component.licenses.length === 0) {
        // Nothing resolved. CycloneDX has no NOASSERTION, so the honest form is to
        // omit the field rather than assert a licence that was never resolved.
        return undefined;
    }
    return component.licenses.map((value) => 
    // A compound expression can only go in the `expression` form; a bare SPDX
    // id goes in `license.id`; anything else is a NAME, never dressed up as an
    // id — `license.id` is schema-constrained to the real SPDX list, and a
    // fabricated id there is both invalid and a false statement about the
    // component's licence.
    / (OR|AND|WITH) /.test(value)
        ? { expression: value }
        : (0, spdxData_1.isKnownSpdxId)(value)
            ? { license: { id: value } }
            : { license: { name: value } });
}
function supportProperties(support) {
    const properties = [
        { name: support_1.SUPPORT_LEVEL_PROPERTY, value: support.supportLevel },
        { name: support_1.SUPPORT_SOURCE_PROPERTY, value: support.basis },
        { name: support_1.SUPPORT_EVIDENCE_PROPERTY, value: support.evidence },
    ];
    // Emitted only when a date is actually known. `supportLevel` IS emitted even
    // when it is `unknown`, because an absent level would read as "not screened"
    // rather than "screened, and the answer is not available".
    if (support.endOfSupportDate)
        properties.push({ name: support_1.END_OF_SUPPORT_PROPERTY, value: support.endOfSupportDate });
    if (support.note)
        properties.push({ name: support_1.SUPPORT_NOTE_PROPERTY, value: support.note });
    return properties;
}
function componentProperties(row) {
    const properties = [];
    // Foreign properties first, verbatim. An imported SBOM's own properties are
    // the producer's data and dropping them would lose information the
    // manufacturer may need; only this tool's own namespace is re-stated, since
    // a stale `ceproof:fda:supportLevel` from a previous run must not sit next to
    // the one this run resolved.
    for (const [name, value] of Object.entries(row.component.properties)) {
        if (!name.startsWith(CEPROOF_NAMESPACE))
            properties.push({ name, value });
    }
    properties.push({ name: support_1.ORIGIN_PROPERTY, value: row.component.origins.join(', ') });
    properties.push(...supportProperties(row.support));
    if (row.component.possibleDuplicate) {
        properties.push({
            name: exports.POSSIBLE_DUPLICATE_PROPERTY,
            value: 'true — another source named the same component with a missing or different version, and the two were NOT merged.',
        });
    }
    for (const conflict of row.component.conflicts ?? []) {
        properties.push({ name: exports.SOURCE_CONFLICT_PROPERTY, value: conflict });
    }
    return properties;
}
function renderComponent(row) {
    const { component } = row;
    const out = {
        type: (0, input_1.cdxType)(component),
        'bom-ref': row.bomRef,
        name: component.name,
    };
    if (component.version)
        out.version = component.version;
    if (component.supplier)
        out.supplier = { name: component.supplier };
    if (component.purl)
        out.purl = component.purl;
    if (component.cpe)
        out.cpe = component.cpe;
    const hashes = (0, input_1.usableHashes)(component);
    if (hashes.length > 0)
        out.hashes = hashes.map((h) => ({ alg: h.alg, content: h.content }));
    const licenses = licensesFor(component);
    if (licenses)
        out.licenses = licenses;
    out.properties = componentProperties(row);
    return out;
}
/**
 * The screen's findings as CycloneDX `vulnerabilities[]`.
 *
 * One entry per CVE, not per finding: the same CVE matching three components is
 * one vulnerability affecting three things, which is exactly what `affects`
 * expresses. Only `confirmed` and `possible` rows appear — a `not-affected` row
 * in `affects` would be an assertion that the component IS affected, which is
 * the opposite of what the screen concluded, and the only way CycloneDX can say
 * "considered and ruled out" is `analysis.state`, which this tool must not
 * write. Those rows stay in fda-vulnerabilities.csv, where the `confidence`
 * column states the conclusion without the format making it for us.
 *
 * `ratings` is never emitted, and that is not an omission: the bundled KEV
 * catalogue carries no severity score of any kind, and neither does the
 * advisory index (which contributes affected version ranges only). A rating
 * here would have to be invented.
 */
function vulnerabilities(rows, kev) {
    const affectsByCve = new Map();
    for (const row of rows) {
        for (const finding of row.findings) {
            const refs = affectsByCve.get(finding.cve) ?? [];
            if (!refs.includes(row.bomRef))
                refs.push(row.bomRef);
            affectsByCve.set(finding.cve, refs);
        }
    }
    return [...affectsByCve.entries()].map(([cve, refs]) => ({
        id: cve,
        // The catalogue the screen is built on, named once per row so this file
        // read on its own says where its vulnerability data came from.
        source: { name: kev.snapshotSource.name, url: kev.snapshotSource.url },
        affects: refs.map((ref) => ({ ref })),
    }));
}
/** The device or firmware the BOM is about, as `metadata.component`. Never one of the dependencies. */
function subjectComponent(input, bomRef) {
    const subject = input.subject;
    if (!subject) {
        // No imported SBOM named a subject and no project name was supplied. Say
        // so in the document rather than naming the tool or a directory as if it
        // were the device.
        return { type: 'device', name: `device not named — see ${support_1.ORIGIN_PROPERTY} on each component for where the data came from` };
    }
    const out = { type: (0, input_1.cdxType)(subject), name: subject.name };
    // Carried so the dependency graph's root edge has something to point at.
    if (bomRef !== undefined)
        out['bom-ref'] = bomRef;
    if (subject.version)
        out.version = subject.version;
    if (subject.supplier)
        out.supplier = { name: subject.supplier };
    if (subject.purl)
        out.purl = subject.purl;
    if (subject.cpe)
        out.cpe = subject.cpe;
    return out;
}
function generationContext(input) {
    const sources = [];
    if (input.scanPath)
        sources.push(`a dependency scan of ${input.scanPath}`);
    for (const sbom of input.sbomInputs) {
        sources.push(`the imported CycloneDX ${sbom.specVersion} SBOM "${sbom.sourceLabel}"${sbom.sha256 ? ` (sha256 ${sbom.sha256})` : ''}`);
    }
    return (`Assembled by ${branding_1.PRODUCT_NAME} ${input.toolVersion} on ${input.generatedAt} from ${sources.length > 0 ? sources.join(' and ') : 'no source'}, ` +
        `and enriched offline with the level of support and end-of-support date FDA asks for per software component (${support_1.FDA_SOURCE.citation}).`);
}
function metadataProperties(input, deps, componentCount) {
    const properties = [
        { name: exports.GENERATION_CONTEXT_PROPERTY, value: generationContext(input) },
        { name: exports.DEPENDENCY_RELATIONSHIPS_PROPERTY, value: dependencyRelationshipsNote(deps, componentCount) },
        { name: exports.VULNERABILITY_SCREEN_PROPERTY, value: exports.VULNERABILITY_SCREEN_NOTE },
        {
            name: `${CEPROOF_NAMESPACE}eolSnapshot`,
            value: `${input.support.snapshotSource.name} (${input.support.snapshotSource.license}), upstream data generated ${input.support.snapshotSource.upstreamGeneratedAt}, sha256 ${input.support.snapshotSource.upstreamSha256}`,
        },
        {
            name: `${CEPROOF_NAMESPACE}kevSnapshot`,
            value: `${input.kev.snapshotSource.name} (${input.kev.snapshotSource.license}), catalogue version ${input.kev.snapshotSource.catalogVersion}, released ${input.kev.snapshotSource.dateReleased.slice(0, 10)}, sha256 ${input.kev.snapshotSource.upstreamSha256}`,
        },
    ];
    for (const line of branding_1.FDA_DISCLAIMER)
        properties.push({ name: `${CEPROOF_NAMESPACE}disclaimer`, value: line });
    return properties;
}
function renderFdaCycloneDx(input, rows = (0, input_1.joinRows)(input)) {
    const deps = (0, input_1.resolveDependencies)(input, rows);
    const metadata = {
        timestamp: input.generatedAt,
        tools: [{ vendor: branding_1.PRODUCT_NAME, name: branding_1.PRODUCT_NAME, version: input.toolVersion }],
        component: subjectComponent(input, (0, input_1.subjectBomRef)(input, rows)),
        properties: metadataProperties(input, deps, rows.length),
    };
    // "SBOM Author" is an NTIA minimum element and ceproof cannot know who you
    // are. Emitted only from the manufacturer's own config; its absence is an
    // open item, not a field filled with the tool's name.
    if (input.sbomAuthor)
        metadata.manufacturer = { name: input.sbomAuthor };
    const doc = {
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        serialNumber: `urn:uuid:${(0, crypto_1.randomUUID)()}`,
        version: 1,
        metadata,
        components: rows.map(renderComponent),
    };
    // Both arrays are emitted ONLY when there is something in them. An empty
    // `dependencies: []` would assert a graph that says every component has no
    // dependencies, and an empty `vulnerabilities: []` reads as a clean bill of
    // health; in both cases the absence of the key plus the metadata property
    // that explains it is the honest form. The properties are emitted either way.
    if (deps.edges.length > 0)
        doc.dependencies = deps.edges;
    const vulns = vulnerabilities(rows, input.kev);
    if (vulns.length > 0)
        doc.vulnerabilities = vulns;
    return JSON.stringify(doc, null, 2) + '\n';
}
//# sourceMappingURL=cyclonedx.js.map