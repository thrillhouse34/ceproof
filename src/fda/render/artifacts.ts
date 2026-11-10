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
import { joinRows, type FdaRenderInput } from './input';
import { renderFdaCycloneDx } from './cyclonedx';
import { renderSupportCsv, renderVulnerabilitiesCsv } from './tables';
import { renderFdaSummary, renderFdaOpenItems, renderFdaDisclaimer } from './summary';
import { renderFdaProvenanceJson } from './provenance';

/** The file names the pack is written as. One place, so the summary's own file table and the CLI cannot drift apart. */
export const FDA_ARTIFACT_FILES = {
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
} as const;

export interface FdaArtifact {
  file: string;
  contents: string;
}

export function renderFdaArtifacts(input: FdaRenderInput): FdaArtifact[] {
  const rows = joinRows(input);
  return [
    { file: FDA_ARTIFACT_FILES.sbom, contents: renderFdaCycloneDx(input, rows) },
    { file: FDA_ARTIFACT_FILES.supportCsv, contents: renderSupportCsv(rows) },
    { file: FDA_ARTIFACT_FILES.vulnerabilitiesCsv, contents: renderVulnerabilitiesCsv(rows) },
    { file: FDA_ARTIFACT_FILES.summary, contents: renderFdaSummary(input, rows) },
    { file: FDA_ARTIFACT_FILES.openItems, contents: renderFdaOpenItems(input, rows) },
    { file: FDA_ARTIFACT_FILES.provenance, contents: renderFdaProvenanceJson(input, rows) },
    { file: FDA_ARTIFACT_FILES.disclaimer, contents: renderFdaDisclaimer(input) },
  ];
}
