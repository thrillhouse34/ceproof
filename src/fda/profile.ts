/**
 * The two output surfaces of the free FDA-profile view: the terminal summary
 * and the JSON report.
 *
 * Both are built from one `FdaProfile` (src/fda/gap.ts), so the terminal can
 * never say something the JSON does not. The terminal renderer reuses the CRA
 * summary's wrapping and colour helpers rather than re-implementing them — the
 * two views are the same tool and should look like it, and a second wrapper
 * would be a second place for the 80-column rule to be got wrong.
 *
 * The JSON is versioned separately from `scan`'s CRA JSON (`schemaVersion: 1`
 * on both, but different shapes under different commands) because a consumer
 * asking for `--profile fda` is asking a different question and a union type
 * would make every field optional for both.
 */
import { DISCLAIMER, PRODUCT_NAME, PRODUCT_URL } from '../branding';
import { colorsFor, statusLabel, wrapAt80 } from '../report/summary';
import type { GapStatus } from '../gap/types';
import type { FdaGapItem, FdaProfile } from './gap';

/** Least alarming to most actionable, the same reading order the CRA summary uses. */
const STATUS_ORDER: GapStatus[] = ['DERIVED', 'PARTIAL', 'NEEDS-HUMAN-INPUT'];

export interface FdaProfileJson {
  schemaVersion: 1;
  profile: 'fda';
  toolVersion: string;
  /** `data/fda-structure.json`'s own sourceVersion — the guidance edition the items were extracted from. */
  structureVersion: string;
  generatedAt: string;
  asOf: string;
  device?: { name: string; version?: string; supplier?: string };
  sbomAuthor?: string;
  inputs: { repoScan?: string; sboms: { sourceLabel: string; specVersion: string; sha256?: string; componentCount: number }[] };
  /** The dataset identifiers the screen ran against. Named `fdaData`, matching the paid pack's provenance artifact. */
  fdaData: {
    eolSnapshotGeneratedAt: string;
    eolSnapshotSha256: string;
    kevCatalogVersion: string;
    kevSnapshotReleased: string;
    osvQueriedAt: string;
  };
  counts: FdaProfile['counts'];
  summary: FdaProfile['summary'];
  items: FdaGapItem[];
  warnings: string[];
  limits: string[];
  disclaimer: string;
}

export interface FdaProfileRenderInput {
  profile: FdaProfile;
  toolVersion: string;
  generatedAt: string;
  asOf: string;
  device?: { name: string; version?: string; supplier?: string };
  sbomAuthor?: string;
  repoScan?: string;
  sboms: { sourceLabel: string; specVersion: string; sha256?: string; componentCount: number }[];
  fdaData: FdaProfileJson['fdaData'];
  limits: readonly string[];
}

export function buildFdaProfileJson(input: FdaProfileRenderInput): FdaProfileJson {
  return {
    schemaVersion: 1,
    profile: 'fda',
    toolVersion: input.toolVersion,
    structureVersion: input.profile.structureVersion,
    generatedAt: input.generatedAt,
    asOf: input.asOf,
    ...(input.device ? { device: input.device } : {}),
    ...(input.sbomAuthor ? { sbomAuthor: input.sbomAuthor } : {}),
    inputs: { ...(input.repoScan ? { repoScan: input.repoScan } : {}), sboms: input.sboms },
    fdaData: input.fdaData,
    counts: input.profile.counts,
    summary: input.profile.summary,
    items: input.profile.items,
    warnings: input.profile.warnings,
    limits: [...input.limits],
    disclaimer: DISCLAIMER,
  };
}

function renderItem(item: FdaGapItem, colorEnabled: boolean): string {
  const c = colorsFor(colorEnabled);
  const headerPlain = `[${item.status}] ${item.id} — ${item.requirementSummary}`;
  const lines = [wrapAt80(headerPlain, '  ').replace(`[${item.status}]`, `[${statusLabel(item.status, c)}]`)];
  lines.push(c.dim(wrapAt80(item.citation, '    ')));
  for (const evidence of item.evidence) lines.push(c.dim(wrapAt80(`- ${evidence}`, '      ')));
  return lines.join('\n');
}

/**
 * The counts block. This is the part that makes the problem concrete for
 * someone deciding whether to buy the pack, so it leads with the component
 * total and the two values FDA asks for beyond the minimum elements.
 */
function countsBlock(input: FdaProfileRenderInput, colorEnabled: boolean): string {
  const c = colorsFor(colorEnabled);
  const n = input.profile.counts;
  const lines = [
    c.bold('What this run found'),
    `  components screened: ${n.components}`,
    `  with a level of support that is not "unknown": ${n.components - n.supportUnknown} of ${n.components}` +
      (n.supportDeclared > 0 ? ` (${n.supportDeclared} declared by you)` : ''),
    `  with an end-of-support date: ${n.endOfSupportDates} of ${n.components}` +
      (n.endOfSupportPassed > 0 ? ` — ${n.endOfSupportPassed} already past` : ''),
    `  in the source SBOM's dependency graph: ${n.inDependencyGraph} of ${n.components}`,
    `  KEV findings: ${n.confirmed} confirmed, ${n.possible} possible, ${n.notAffected} screened and set aside` +
      (n.ransomware > 0 ? ` — ${n.ransomware} flagged by CISA as used in a known ransomware campaign` : ''),
    `  open items the paid pack would list: ${n.openItems}`,
  ];
  return lines.join('\n');
}

export function renderFdaProfileSummary(input: FdaProfileRenderInput, colorEnabled: boolean): string {
  const c = colorsFor(colorEnabled);
  const { summary, items, warnings } = input.profile;
  const lines: string[] = [
    c.bold(`${PRODUCT_NAME} scan --profile fda: ${input.device ? `${input.device.name}${input.device.version ? ` ${input.device.version}` : ''}` : 'device not named'}`),
    c.dim(
      `${PRODUCT_NAME} ${input.toolVersion} · KEV ${input.fdaData.kevCatalogVersion} · ` +
        `end-of-support data ${input.fdaData.eolSnapshotGeneratedAt.slice(0, 10)} · as of ${input.asOf}`,
    ),
    // The SHORT guidance identifier only. The full one — docket number,
    // superseded edition, the NTIA secondary sources — runs to ~650 characters
    // and would be six wrapped lines of header on a terminal. It is in the
    // `--format json` output (`structureVersion`) and on every artifact the
    // paid pack generates, which are the surfaces that need it.
    c.dim(`Guidance: ${input.profile.structureVersionShort}`),
    c.dim(DISCLAIMER),
    '',
    wrapAt80(
      `${summary.totalItems} FDA SBOM content item${summary.totalItems === 1 ? '' : 's'} checked — ` +
        `${summary.derived} derived, ${summary.partial} partial, ${summary.needsHumanInput} needs human input`,
      '',
    ),
    '',
    countsBlock(input, colorEnabled),
  ];

  if (warnings.length > 0) {
    lines.push('', c.bold('Warnings'), ...warnings.map((warning) => c.yellow(wrapAt80(`- ${warning}`, '  '))));
  }

  lines.push('', c.bold('FDA SBOM content items'));
  for (const status of STATUS_ORDER) {
    for (const item of items.filter((i) => i.status === status)) lines.push(renderItem(item, colorEnabled));
  }

  lines.push(
    '',
    c.bold('What this view does not cover'),
    ...input.limits.map((limit) => c.dim(wrapAt80(`- ${limit}`, '  '))),
  );

  // The upsell, once, at the foot, naming what the pack contains rather than
  // what this view withholds. No price: pricing lives in branding.ts for the
  // CRA tiers and the FDA tiers are annual, so the site is the single place
  // that stays correct.
  lines.push(
    '',
    wrapAt80(
      `This is the free diagnosis. \`${PRODUCT_NAME} report --format fda-pack\` generates the documentation pack itself — ` +
        'the enriched CycloneDX SBOM, the support and end-of-support addendum, the vulnerability table with the two columns you fill in, ' +
        `the open-items list and the provenance record. It needs an FDA-tier license key: see ${PRODUCT_URL}`,
      '',
    ),
  );
  return lines.join('\n');
}
