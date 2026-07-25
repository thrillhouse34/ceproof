"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildJsonReport = buildJsonReport;
function buildJsonReport(input) {
    const summary = {
        totalItems: input.gapChecklist.length,
        derived: input.gapChecklist.filter((i) => i.status === 'DERIVED').length,
        partial: input.gapChecklist.filter((i) => i.status === 'PARTIAL').length,
        needsHumanInput: input.gapChecklist.filter((i) => i.status === 'NEEDS-HUMAN-INPUT').length,
    };
    return {
        schemaVersion: 1,
        toolVersion: input.toolVersion,
        dataVersion: input.dataVersion,
        scanTimestamp: input.scanTimestamp,
        projectName: input.projectName,
        facts: input.facts,
        gapChecklist: input.gapChecklist,
        summary,
        configStatus: input.configStatus,
        warnings: input.warnings,
    };
}
//# sourceMappingURL=json.js.map