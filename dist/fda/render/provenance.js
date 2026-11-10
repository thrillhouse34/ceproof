"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FDA_PROVENANCE_SCHEMA = void 0;
exports.buildFdaProvenance = buildFdaProvenance;
exports.renderFdaProvenanceJson = renderFdaProvenanceJson;
exports.renderProvenanceSection = renderProvenanceSection;
/**
 * The provenance artifact: what produced this pack, from what, on what date,
 * and under which licences.
 *
 * Separate from src/report/provenance.ts on purpose. That one stamps the CRA
 * documents with a release identifier and the CRA consolidation version; this
 * one has a different job — a premarket reviewer needs to know WHEN the data
 * behind a vulnerability screen was captured, which is not the same date as
 * when the document was rendered, and which dataset answered each question.
 *
 * `dataVersion` is deliberately NOT in here. In this repo that string means the
 * CRA/SPDX reference-data version the Annex VII artifacts stamp, and reusing it
 * for the FDA mode would make it mean two things. The FDA datasets carry their
 * own identifiers instead, under `fdaData`: the end-of-support snapshot's
 * upstream generated-at and hash, the KEV catalogue's version, release date and
 * hash, and the advisory index's build record.
 *
 * Every bundled dataset's licence travels with the artifact, including CISA's
 * own condition that use of their data is not an endorsement by CISA or DHS —
 * a generated file has to be able to carry its attribution without a network
 * call, because nothing in this tool makes one.
 */
const branding_1 = require("../../branding");
const branding_2 = require("../../branding");
const support_1 = require("../support");
const kev_1 = require("../kev");
const input_1 = require("./input");
exports.FDA_PROVENANCE_SCHEMA = 1;
function buildFdaProvenance(input, rows = (0, input_1.joinRows)(input)) {
    const eol = input.support.snapshotSource;
    const kev = input.kev.snapshotSource;
    return {
        schema: exports.FDA_PROVENANCE_SCHEMA,
        tool: { name: branding_1.PRODUCT_NAME, version: input.toolVersion },
        generatedAt: input.generatedAt,
        asOf: input.asOf,
        ...(input.subject
            ? {
                device: {
                    name: input.subject.name,
                    ...(input.subject.version ? { version: input.subject.version } : {}),
                    ...(input.subject.supplier ? { supplier: input.subject.supplier } : {}),
                },
            }
            : {}),
        ...(input.sbomAuthor ? { sbomAuthor: input.sbomAuthor } : {}),
        guidance: {
            support: support_1.FDA_SOURCE.citation,
            vulnerabilities: kev_1.FDA_VULN_SOURCE.citation,
            sourceFile: support_1.FDA_SOURCE.sourceFile,
        },
        inputs: {
            ...(input.scanPath ? { repoScan: { path: input.scanPath } } : {}),
            sboms: input.sbomInputs.map((sbom) => ({
                sourceLabel: sbom.sourceLabel,
                format: 'CycloneDX',
                specVersion: sbom.specVersion,
                ...(sbom.sha256 ? { sha256: sbom.sha256 } : {}),
                componentCount: sbom.componentCount,
            })),
        },
        fdaData: {
            eolSnapshot: {
                name: eol.name,
                url: eol.url,
                license: eol.license,
                licenseUrl: eol.licenseUrl,
                copyright: eol.copyright,
                upstreamGeneratedAt: eol.upstreamGeneratedAt,
                upstreamSha256: eol.upstreamSha256,
            },
            kevSnapshot: {
                name: kev.name,
                url: kev.url,
                license: kev.license,
                licenseUrl: kev.licenseUrl,
                licenseStatement: kev.licenseStatement,
                catalogVersion: kev.catalogVersion,
                dateReleased: kev.dateReleased,
                upstreamCount: kev.upstreamCount,
                upstreamSha256: kev.upstreamSha256,
            },
            kevIndex: {
                sources: input.kev.indexSources.map((source) => ({
                    name: source.name,
                    url: source.url,
                    license: source.license,
                    licenseUrl: source.licenseUrl,
                    attribution: source.attribution,
                })),
                builtFrom: input.kev.indexBuiltFrom,
            },
        },
        counts: {
            components: rows.length,
            supportDeclared: rows.filter((row) => row.support.basis === 'manufacturer-declared' || row.support.basis === 'sbom-declared').length,
            supportUnknown: rows.filter((row) => row.support.supportLevel === 'unknown').length,
            endOfSupportDates: rows.filter((row) => row.support.endOfSupportDate !== undefined).length,
            confirmed: input.kev.totals.confirmed,
            possible: input.kev.totals.possible,
            notAffected: input.kev.totals.notAffected,
        },
        warnings: (0, input_1.runWarnings)(input),
        limits: [...input.kev.limits],
        disclaimer: [...branding_2.FDA_DISCLAIMER],
    };
}
function renderFdaProvenanceJson(input, rows) {
    return JSON.stringify(buildFdaProvenance(input, rows), null, 2) + '\n';
}
/** The same facts as a readable section for the summary document. The JSON is the record; this is the part a reviewer reads. */
function renderProvenanceSection(input) {
    const eol = input.support.snapshotSource;
    const kev = input.kev.snapshotSource;
    const lines = [
        `Generated by ${branding_1.PRODUCT_NAME} ${input.toolVersion} on ${input.generatedAt}. Every date comparison in this pack is made against ${input.asOf}.`,
        '',
        '**Where the components came from**',
        '',
    ];
    if (input.scanPath)
        lines.push(`- a dependency scan of \`${input.scanPath}\``);
    for (const sbom of input.sbomInputs) {
        lines.push(`- the imported CycloneDX ${sbom.specVersion} SBOM \`${sbom.sourceLabel}\` — ${sbom.componentCount} components${sbom.sha256 ? `, sha256 \`${sbom.sha256}\`` : ''}`);
    }
    if (!input.scanPath && input.sbomInputs.length === 0)
        lines.push('- no source was recorded for this run, which should not happen; do not rely on this pack.');
    lines.push('', '**The reference data this run used, and its licences**', '', `- ${eol.name} (${eol.license}, ${eol.licenseUrl}) — upstream data generated ${eol.upstreamGeneratedAt}, sha256 \`${eol.upstreamSha256}\`. ${eol.copyright}`, `- ${kev.name} (${kev.license}, ${kev.licenseUrl}) — catalogue version ${kev.catalogVersion}, released ${kev.dateReleased.slice(0, 10)}, ${kev.upstreamCount} entries, sha256 \`${kev.upstreamSha256}\`. ${kev.licenseStatement}`, ...input.kev.indexSources.map((source) => `- ${source.name} (${source.license}, ${source.licenseUrl}) — ${source.attribution}`), '', `The advisory index was built from catalogue version ${input.kev.indexBuiltFrom.kevCatalogVersion} and queried OSV on ${input.kev.indexBuiltFrom.osvQueriedAt.slice(0, 10)}: ${input.kev.indexBuiltFrom.cvesQueried} KEV CVEs looked up, ${input.kev.indexBuiltFrom.cvesWithOsvRecord} with an OSV record.`, '', `The guidance this pack is organised against: ${support_1.FDA_SOURCE.citation}; ${kev_1.FDA_VULN_SOURCE.citation}. The passages each section implements are quoted verbatim in \`${support_1.FDA_SOURCE.sourceFile}\`.`, '', 'The full record, including every input hash, is in fda-provenance.json.');
    return lines.join('\n');
}
//# sourceMappingURL=provenance.js.map