"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FDA_ARTIFACT_FILES = void 0;
exports.renderFdaArtifacts = renderFdaArtifacts;
/**
 * The entry point: one call, the whole pack.
 *
 * Milestone 5 (the CLI wiring) writes these to disk under `--out`; nothing
 * here touches the filesystem, so every artifact is testable as a string and a
 * caller can write, diff or stream them however it needs to. The join between
 * the three engines' results happens ONCE here and is passed to every
 * renderer, so no two artifacts can disagree about which support row belongs to
 * which component.
 */
const input_1 = require("./input");
const cyclonedx_1 = require("./cyclonedx");
const tables_1 = require("./tables");
const summary_1 = require("./summary");
const provenance_1 = require("./provenance");
/** The file names the pack is written as. One place, so the summary's own file table and the CLI cannot drift apart. */
exports.FDA_ARTIFACT_FILES = {
    sbom: 'fda-sbom.cyclonedx.json',
    supportCsv: 'fda-support-eol.csv',
    vulnerabilitiesCsv: 'fda-vulnerabilities.csv',
    summary: 'fda-summary.md',
    openItems: 'fda-open-items.md',
    provenance: 'fda-provenance.json',
    /**
     * Not `fda-`prefixed, deliberately: this is the one file in the pack whose
     * job is to be noticed by someone who was handed the directory and does not
     * know what any of it is.
     */
    disclaimer: 'DISCLAIMER.md',
};
function renderFdaArtifacts(input) {
    const rows = (0, input_1.joinRows)(input);
    return [
        { file: exports.FDA_ARTIFACT_FILES.sbom, contents: (0, cyclonedx_1.renderFdaCycloneDx)(input, rows) },
        { file: exports.FDA_ARTIFACT_FILES.supportCsv, contents: (0, tables_1.renderSupportCsv)(rows) },
        { file: exports.FDA_ARTIFACT_FILES.vulnerabilitiesCsv, contents: (0, tables_1.renderVulnerabilitiesCsv)(rows) },
        { file: exports.FDA_ARTIFACT_FILES.summary, contents: (0, summary_1.renderFdaSummary)(input, rows) },
        { file: exports.FDA_ARTIFACT_FILES.openItems, contents: (0, summary_1.renderFdaOpenItems)(input, rows) },
        { file: exports.FDA_ARTIFACT_FILES.provenance, contents: (0, provenance_1.renderFdaProvenanceJson)(input, rows) },
        { file: exports.FDA_ARTIFACT_FILES.disclaimer, contents: (0, summary_1.renderFdaDisclaimer)(input) },
    ];
}
//# sourceMappingURL=artifacts.js.map