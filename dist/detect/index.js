"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.collectRepoFacts = collectRepoFacts;
/**
 * Orchestrates the individual repo-fact detectors into a single RepoFacts
 * object. Runs each detector synchronously against `projectPath` and wires
 * its output to the matching RepoFacts field.
 *
 * `ecosystems` isn't produced by one of the five Detector<T> implementations
 * under src/detect/ — it's assembled here from the existing
 * src/ecosystems/{npm,pypi}.ts `detect()` functions (the same
 * already-battle-tested presence check the scan pipeline uses), so ecosystem
 * detection logic isn't duplicated.
 *
 * Per the doctrine in ./types.ts, this must never throw for the
 * "nothing found" case — every detector it calls already degrades to an
 * honest "not present"/UNKNOWN fact set rather than throwing, so
 * collectRepoFacts simply composes them without any additional try/catch.
 */
const security_1 = require("./security");
const projectLicense_1 = require("./projectLicense");
const runtimes_1 = require("./runtimes");
const vcs_1 = require("./vcs");
const updateMechanism_1 = require("./updateMechanism");
const npm_1 = require("../ecosystems/npm");
const pypi_1 = require("../ecosystems/pypi");
function detectEcosystems(projectPath) {
    const detected = [];
    if (npm_1.npmEcosystem.detect(projectPath))
        detected.push('npm');
    if (pypi_1.pypiEcosystem.detect(projectPath))
        detected.push('pypi');
    return { detected };
}
function collectRepoFacts(projectPath) {
    return {
        security: security_1.securityDetector.run(projectPath),
        projectLicense: projectLicense_1.projectLicenseDetector.run(projectPath),
        ecosystems: detectEcosystems(projectPath),
        runtimes: runtimes_1.runtimesDetector.run(projectPath),
        vcs: vcs_1.vcsDetector.run(projectPath),
        updateMechanism: updateMechanism_1.updateMechanismDetector.run(projectPath),
    };
}
//# sourceMappingURL=index.js.map