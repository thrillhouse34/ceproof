/**
 * fda-summary.md — the one document a human reads.
 *
 * It is markdown, not HTML or PDF, because the thin v1 deliberately excludes
 * the PDF renderer: the existing puppeteer path (src/report/pdf.ts) is built
 * around the Annex VII pack's HTML, and pointing it at this document is a
 * milestone of its own. Markdown is readable as-is, diffs cleanly between two
 * runs of the same device, and converts to whatever an eSTAR attachment needs
 * without this tool having an opinion about page furniture.
 *
 * What it must never do, in order of how badly it would matter:
 *  - claim the output is FDA-approved, compliant, or submission-ready. Those
 *    are claims about the customer's filing. tests/fda/forbiddenClaims.test.ts
 *    fails the build on any of them.
 *  - imply the risk assessment was performed. The pack identifies candidates;
 *    the two columns FDA asks the manufacturer for stay NEEDS-HUMAN-INPUT.
 *  - read like a clean bill of health when a dataset is stale, a comparison
 *    was declined, or a required value is missing. Every one of those is
 *    stated in the body, not only in an appendix.
 *
 * The document's own structure mirrors what the guidance asks for, which is
 * why the section order is what it is: what this is → where the data came from
 * → the component inventory → the two per-component values (level of support,
 * end-of-support date) → the known vulnerabilities → what is still open.
 */
import { PRODUCT_NAME, FDA_DISCLAIMER } from '../../branding';
import { FDA_SOURCE } from '../support';
import { collectOpenItems, renderOpenItemsBody } from './openItems';
import { renderProvenanceSection } from './provenance';
import {
  renderNotAffectedAppendix,
  renderSupportAppendix,
  renderSupportSection,
  renderVulnerabilitySection,
} from './tables';
import {
  NEEDS_HUMAN_INPUT,
  componentLabel,
  joinRows,
  resolveDependencies,
  runWarnings,
  type FdaRenderInput,
  type FdaRow,
} from './input';

const SUPPORT_APPENDIX = 'Appendix A';
const NOT_AFFECTED_APPENDIX = 'Appendix B';

/** The pack's own description of itself. Deliberately a claim about what was assembled, never about the submission it goes into. */
export const PACK_DESCRIPTION =
  'a documentation pack assembled from your software bill of materials and your own declarations, organised against the content items in FDA\'s February 3, 2026 premarket cybersecurity guidance';

/**
 * The seventh NTIA minimum element, in the words the state of this run earns.
 * Derived from the same `resolveDependencies` result the enriched SBOM and the
 * open-items list use, so the three cannot drift.
 */
function dependencySentence(input: FdaRenderInput, rows: FdaRow[]): string {
  const deps = resolveDependencies(input, rows);
  if (deps.edges.length === 0) {
    return (
      'Dependency relationship — the seventh minimum element — is **not** represented: no imported SBOM carried a `dependencies` array, so this pack records ' +
      'no relationship between components. That is not a statement that they have none. Nothing here infers an edge; regenerate your source SBOM with its ' +
      'dependency data and re-import it.'
    );
  }
  const carried =
    `Dependency relationship — the seventh minimum element — is carried through from your source SBOM verbatim: ${deps.edges.length} ` +
    `${deps.edges.length === 1 ? 'entry' : 'entries'}, covering ${deps.componentsInGraph} of ${rows.length} components. No edge was inferred.`;
  if (!deps.hasComponentEdges) {
    return `${carried} The graph records only top-level edges, with no component-to-component relationship, so the transitive dependencies are not described here.`;
  }
  if (deps.componentsInGraph < rows.length || deps.unmappedRefs.length > 0) {
    return `${carried} Not every component appears in the graph; a component missing from it has unknown dependencies, not none. See the open items.`;
  }
  return carried;
}

function inventorySection(input: FdaRenderInput, rows: FdaRow[]): string {
  const byOrigin = new Map<string, number>();
  for (const row of rows) {
    for (const origin of row.component.origins) byOrigin.set(origin, (byOrigin.get(origin) ?? 0) + 1);
  }
  const withVersion = rows.filter((row) => row.component.version).length;
  const withIdentifier = rows.filter((row) => row.component.purl ?? row.component.cpe).length;
  const withSupplier = rows.filter((row) => row.component.supplier).length;
  const withLicense = rows.filter((row) => row.component.licenses.length > 0).length;
  const withHash = rows.filter((row) => row.component.hashes.length > 0).length;

  return [
    `**${rows.length} components**, from ${byOrigin.size} ${byOrigin.size === 1 ? 'source' : 'sources'}:`,
    '',
    ...[...byOrigin.entries()].map(([origin, count]) => `- \`${origin}\` — ${count}`),
    '',
    'How complete the NTIA minimum elements are, per component, in the data supplied:',
    '',
    `- a version: ${withVersion} of ${rows.length}`,
    `- a purl or a CPE: ${withIdentifier} of ${rows.length}`,
    `- a supplier: ${withSupplier} of ${rows.length}`,
    `- a licence: ${withLicense} of ${rows.length}`,
    `- a hash: ${withHash} of ${rows.length}`,
    '',
    'The author of the SBOM data and the timestamp are on the document itself (CycloneDX `metadata`). ' + dependencySentence(input, rows),
    '',
    `Nothing in the counts above is filled in on your behalf. A component with no version has no version in the enriched SBOM either, and every row in ${SUPPORT_APPENDIX} says where its values came from.`,
  ].join('\n');
}

function warningsSection(input: FdaRenderInput): string {
  const warnings = runWarnings(input);
  if (warnings.length === 0) return 'This run produced no warnings.';
  return [
    'Read these before the rest of the pack. They are the things this run could not resolve or had to choose between:',
    '',
    ...warnings.map((warning) => `- ${warning}`),
  ].join('\n');
}

export function renderFdaSummary(input: FdaRenderInput, rows: FdaRow[] = joinRows(input)): string {
  const items = collectOpenItems(input, rows);
  const deviceLine = input.subject
    ? `**Device / firmware:** ${componentLabel(input.subject)}${input.subject.supplier ? ` — ${input.subject.supplier}` : ''}`
    : '**Device / firmware:** not named in any input. Name it as `metadata.component` in your source SBOM, or set `product.name` in `ceproof.config.json`.';

  return [
    '# FDA premarket cybersecurity: software bill of materials pack',
    '',
    deviceLine,
    `**SBOM author:** ${input.sbomAuthor ?? 'not named — see the open items'}`,
    `**Generated:** ${input.generatedAt} by ${PRODUCT_NAME} ${input.toolVersion}`,
    '',
    ...FDA_DISCLAIMER.map((line) => `> ${line}`),
    '',
    `This is ${PACK_DESCRIPTION}.`,
    '',
    '## 1. What is in this pack',
    '',
    '| File | What it is |',
    '|---|---|',
    '| `fda-sbom.cyclonedx.json` | The enriched machine-readable SBOM: CycloneDX 1.6, with the level of support and end-of-support date carried as `ceproof:fda:*` properties, your source SBOM’s dependency graph, and the screen’s findings as an unassessed `vulnerabilities` array. |',
    '| `fda-support-eol.csv` | One row per component: identifiers, origin, level of support, end-of-support date, and the basis for each. |',
    '| `fda-vulnerabilities.csv` | One row per finding, including the ones screened out, with the two columns you fill in. |',
    '| `fda-summary.md` | This document. |',
    '| `fda-open-items.md` | Everything still needing a human, with what to do about each. |',
    '| `fda-provenance.json` | What produced this pack, from what inputs, against which datasets, under which licences. |',
    '| `DISCLAIMER.md` | The standing disclaimer, as its own file, naming which artifacts carry it inline and which cannot. |',
    '',
    '## 2. Warnings from this run',
    '',
    warningsSection(input),
    '',
    '## 3. Component inventory',
    '',
    inventorySection(input, rows),
    '',
    '## 4. Level of support and end-of-support dates',
    '',
    renderSupportSection(input, rows, SUPPORT_APPENDIX),
    '',
    '## 5. Known vulnerabilities',
    '',
    renderVulnerabilitySection(input, rows, NOT_AFFECTED_APPENDIX),
    '',
    '## 6. Open items',
    '',
    `${items.length} open ${items.length === 1 ? 'item' : 'items'}. The same list, standalone, is fda-open-items.md.`,
    '',
    renderOpenItemsBody(items),
    '',
    '## 7. How this pack was produced',
    '',
    renderProvenanceSection(input),
    '',
    `## ${SUPPORT_APPENDIX} — level of support and end-of-support, per component`,
    '',
    renderSupportAppendix(rows),
    '',
    `## ${NOT_AFFECTED_APPENDIX} — vulnerabilities screened and set aside`,
    '',
    renderNotAffectedAppendix(rows),
    '',
    '---',
    '',
    ...FDA_DISCLAIMER.map((line) => `> ${line}`),
    '',
    `Guidance cited: ${FDA_SOURCE.citation}.`,
    '',
  ].join('\n');
}

/**
 * DISCLAIMER.md — the standing disclaimer as its own file in the pack.
 *
 * It exists because the two CSVs cannot carry it: CSV has no metadata channel,
 * and a line of prose at either end of the file is a malformed row that breaks
 * parsers and shows up as a stray row in the spreadsheet the file exists to be
 * opened in. The alternative — repeating the text as a column on every row of
 * a file that can run to thousands of rows — makes the working copy worse to
 * work in without telling the reader anything the pack does not already say
 * three times over.
 *
 * So the exception is disclosed HERE, in the pack itself, naming the two files
 * by name, rather than only in this repo's test suite.
 * `tests/fda/forbiddenClaims.test.ts` pins both halves: that every other
 * artifact carries the disclaimer inline, and that this file names the two that
 * do not.
 */
export function renderFdaDisclaimer(input: FdaRenderInput): string {
  return [
    '# Read this first',
    '',
    ...FDA_DISCLAIMER.map((line) => `> ${line}`),
    '',
    `This file belongs with every other file generated beside it on ${input.generatedAt} by ${PRODUCT_NAME} ${input.toolVersion}` +
      `${input.subject ? ` for ${componentLabel(input.subject)}` : ''}. It applies to all of them, and it travels with them: if you send any artifact from ` +
      'this pack to anyone, send this file too.',
    '',
    '## Which files state it inline, and which cannot',
    '',
    'The text above is embedded in `fda-summary.md` (twice), in `fda-open-items.md`, in `fda-provenance.json` (as its `disclaimer` field), and in',
    '`fda-sbom.cyclonedx.json` (as `ceproof:fda:disclaimer` properties on the document metadata).',
    '',
    'Two files do **not** state it inline, and this is the reason:',
    '',
    '- `fda-support-eol.csv`',
    '- `fda-vulnerabilities.csv`',
    '',
    'CSV has nowhere to put prose. A line of text at the top or bottom of the file is a malformed row: it breaks the parsers these files exist to be read by,',
    'and it appears as a stray row in the spreadsheet they exist to be opened in. Both are working copies of tables that appear in full in `fda-summary.md`,',
    'which does carry the text. Nothing about their contents is exempt from anything said above.',
    '',
    '## What this pack does and does not do',
    '',
    `This is ${PACK_DESCRIPTION}.`,
    '',
    'It identifies candidates and records how each one was found. It does not assess them. The safety and security risk assessment of each known vulnerability,',
    `and the risk controls applied to it, are the two things FDA asks the manufacturer for, and they read \`${NEEDS_HUMAN_INPUT}\` in every artifact here until you`,
    'write them. Read `fda-open-items.md` before you rely on any of it.',
    '',
    `Guidance cited: ${FDA_SOURCE.citation}.`,
    '',
  ].join('\n');
}

/** fda-open-items.md: the same body as section 6, as its own document. */
export function renderFdaOpenItems(input: FdaRenderInput, rows: FdaRow[] = joinRows(input)): string {
  const items = collectOpenItems(input, rows);
  return [
    '# FDA premarket SBOM pack — open items',
    '',
    `${input.subject ? componentLabel(input.subject) : 'Device not named'} — generated ${input.generatedAt} by ${PRODUCT_NAME} ${input.toolVersion}.`,
    '',
    ...FDA_DISCLAIMER.map((line) => `> ${line}`),
    '',
    `${items.length} open ${items.length === 1 ? 'item' : 'items'}.`,
    '',
    renderOpenItemsBody(items),
    '',
  ].join('\n');
}
