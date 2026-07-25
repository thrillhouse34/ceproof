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
import { securityDetector } from './security';
import { projectLicenseDetector } from './projectLicense';
import { runtimesDetector } from './runtimes';
import { vcsDetector } from './vcs';
import { updateMechanismDetector } from './updateMechanism';
import { npmEcosystem } from '../ecosystems/npm';
import { pypiEcosystem } from '../ecosystems/pypi';
import type { EcosystemFacts, RepoFacts } from './types';

function detectEcosystems(projectPath: string): EcosystemFacts {
  const detected: EcosystemFacts['detected'] = [];
  if (npmEcosystem.detect(projectPath)) detected.push('npm');
  if (pypiEcosystem.detect(projectPath)) detected.push('pypi');
  return { detected };
}

export function collectRepoFacts(projectPath: string): RepoFacts {
  return {
    security: securityDetector.run(projectPath),
    projectLicense: projectLicenseDetector.run(projectPath),
    ecosystems: detectEcosystems(projectPath),
    runtimes: runtimesDetector.run(projectPath),
    vcs: vcsDetector.run(projectPath),
    updateMechanism: updateMechanismDetector.run(projectPath),
  };
}
