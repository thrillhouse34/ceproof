/**
 * The free FDA-profile gap view: for every item in `data/fda-structure.json`,
 * what this run can and cannot answer.
 *
 * Free diagnosis, paid artifact — the same split the CRA side already has.
 * This view gives a manufacturer the counts that make the problem concrete
 * (how many components, how many with a declared level of support, how many
 * with an end-of-support date, how many KEV findings, how many items still
 * need a human) without generating any of the submission documentation. It
 * reuses `GapStatus` from `src/gap/types.ts` so a user reading both the CRA
 * and the FDA view does not have to learn two scales.
 *
 * Three rules this resolver will not bend:
 *
 *  - **An item nothing can satisfy never reads DERIVED.** `all-known-
 *    vulnerabilities` is permanently PARTIAL: FDA asks for ALL known
 *    vulnerabilities and this tool screens one catalogue. `risk-assessment`
 *    and `risk-controls` are permanently NEEDS-HUMAN-INPUT, because they are
 *    the two things the guidance asks the manufacturer for and no scanner can
 *    produce. A ceiling that moves with the data would be a lie that gets
 *    better-looking the less the tool finds.
 *  - **Zero findings is never evidence of health.** `kev-designed-out` with no
 *    matches is PARTIAL, not DERIVED — nothing matched the bundled catalogue,
 *    which is a different statement from "nothing is there".
 *  - **Every status carries the numbers it was computed from.** The evidence
 *    lines are the view; the status is a summary of them. A PARTIAL with no
 *    explanation is indistinguishable from a bug.
 */
import type { GapChecklistItem, GapStatus } from '../gap/types';
import { getFdaStructure, type FdaMeasure, type FdaStructureItem } from './structure';
import { SNAPSHOT_STALE_AFTER_DAYS, isSnapshotStale } from './support';
import { collectOpenItems } from './render/openItems';
import { joinRows, resolveDependencies, type FdaRenderInput, type FdaRow } from './render/input';

/**
 * One resolved FDA-profile item. Deliberately the same shape as
 * `GapChecklistItem` minus `instrument` (which is a CRA concept — annexVII or
 * annexV), plus the measure that produced it, so a JSON consumer can tell why
 * two items with the same status got there differently.
 */
export interface FdaGapItem extends Omit<GapChecklistItem, 'instrument'> {
  measure: FdaMeasure;
}

export interface FdaProfileCounts {
  components: number;
  withVersion: number;
  withIdentifier: number;
  withSupplier: number;
  withLicense: number;
  withHash: number;
  inDependencyGraph: number;
  supportDeclared: number;
  supportUnknown: number;
  endOfSupportDates: number;
  endOfSupportPassed: number;
  confirmed: number;
  possible: number;
  notAffected: number;
  ransomware: number;
  openItems: number;
}

export interface FdaProfile {
  items: FdaGapItem[];
  counts: FdaProfileCounts;
  /** Every warning the three engines produced, plus the staleness notes. */
  warnings: string[];
  summary: { totalItems: number; derived: number; partial: number; needsHumanInput: number };
  /** `data/fda-structure.json`'s own `sourceVersion`, for the JSON output's provenance. */
  structureVersion: string;
  /** The same, short enough for a terminal header line. */
  structureVersionShort: string;
}

function countsFor(input: FdaRenderInput, rows: FdaRow[]): FdaProfileCounts {
  const deps = resolveDependencies(input, rows);
  return {
    components: rows.length,
    withVersion: rows.filter((r) => r.component.version).length,
    withIdentifier: rows.filter((r) => r.component.purl ?? r.component.cpe).length,
    withSupplier: rows.filter((r) => r.component.supplier).length,
    withLicense: rows.filter((r) => r.component.licenses.length > 0).length,
    withHash: rows.filter((r) => r.component.hashes.length > 0).length,
    inDependencyGraph: deps.componentsInGraph,
    supportDeclared: rows.filter((r) => r.support.basis === 'manufacturer-declared' || r.support.basis === 'sbom-declared').length,
    supportUnknown: rows.filter((r) => r.support.supportLevel === 'unknown').length,
    endOfSupportDates: rows.filter((r) => r.support.endOfSupportDate !== undefined).length,
    endOfSupportPassed: rows.filter((r) => r.support.endOfSupportDate !== undefined && r.support.endOfSupportDate < input.asOf).length,
    confirmed: input.kev.totals.confirmed,
    possible: input.kev.totals.possible,
    notAffected: input.kev.totals.notAffected,
    ransomware: input.kev.totals.ransomware,
    openItems: collectOpenItems(input, rows).length,
  };
}

/** "all" / "none" / "N of M" — the three cases a coverage count can be in, said the same way every time. */
function coverage(label: string, have: number, total: number): string {
  if (total === 0) return `${label}: no components were screened`;
  if (have === total) return `${label}: all ${total}`;
  if (have === 0) return `${label}: none of ${total}`;
  return `${label}: ${have} of ${total}`;
}

/** DERIVED when every component has it, NEEDS-HUMAN-INPUT when none does, PARTIAL in between. Never DERIVED on an empty component list. */
function fromCoverage(have: number, total: number): GapStatus {
  if (total === 0 || have === 0) return 'NEEDS-HUMAN-INPUT';
  return have === total ? 'DERIVED' : 'PARTIAL';
}

interface Resolution {
  status: GapStatus;
  evidence: string[];
}

function resolve(measure: FdaMeasure, input: FdaRenderInput, rows: FdaRow[], counts: FdaProfileCounts): Resolution {
  const kevStale = isSnapshotStale(input.kev.snapshotSource.dateReleased, input.asOf);
  const eolStale = isSnapshotStale(input.support.snapshotSource.upstreamGeneratedAt, input.asOf);
  const findings = counts.confirmed + counts.possible;

  switch (measure) {
    case 'sbom-provided': {
      if (counts.components === 0) {
        return {
          status: 'NEEDS-HUMAN-INPUT',
          evidence: ['No components were found. Import your firmware SBOM with --sbom, or run this against a project with a lockfile.'],
        };
      }
      const origins = new Set(rows.flatMap((r) => r.component.origins));
      return {
        status: 'DERIVED',
        evidence: [
          `${counts.components} components, from ${origins.size} ${origins.size === 1 ? 'source' : 'sources'}: ${[...origins].join(', ')}`,
          'Whether that list is COMPLETE is yours to confirm: this tool reports what its inputs contained and cannot know what a source left out.',
        ],
      };
    }

    case 'ntia-minimum-elements': {
      // Supplier name, component name, version, other unique identifiers,
      // dependency relationship, author of SBOM data, timestamp. The names are
      // NTIA's; see fda-structure.json's `notVendored`.
      const elements: [string, number][] = [
        ['component name', counts.components],
        ['version', counts.withVersion],
        ['supplier name', counts.withSupplier],
        ['other unique identifiers (purl or CPE)', counts.withIdentifier],
        ['dependency relationship (in the source SBOM graph)', counts.inDependencyGraph],
      ];
      const evidence = elements.map(([label, have]) => coverage(label, have, counts.components));
      evidence.push(
        input.sbomAuthor
          ? `author of SBOM data: "${input.sbomAuthor}", from ceproof.config.json`
          : 'author of SBOM data: NOT named. Set manufacturer.name in ceproof.config.json; this tool will not name itself as the author of your SBOM.',
      );
      evidence.push('timestamp: stamped on the document at generation');
      // Two beyond the minimum elements, emitted because they cost nothing and
      // CISA's 2026 update asks for them.
      evidence.push(coverage('component hash (not an NTIA minimum element; CISA 2026 asks for it)', counts.withHash, counts.components));
      evidence.push(coverage('component licence (same)', counts.withLicense, counts.components));
      const complete =
        counts.components > 0 &&
        elements.every(([, have]) => have === counts.components) &&
        input.sbomAuthor !== undefined;
      return {
        status: counts.components === 0 ? 'NEEDS-HUMAN-INPUT' : complete ? 'DERIVED' : 'PARTIAL',
        evidence,
      };
    }

    case 'support-placement':
      return {
        status: 'DERIVED',
        evidence: [
          'The guidance allows the level of support and the end-of-support date either in the SBOM or separately, such as in an addendum.',
          'The paid pack does both: as ceproof:fda:* properties on each component of the CycloneDX document, and as a human-readable addendum section plus a CSV.',
          'This is a property of the pack\'s shape, not of your data, so it is DERIVED for every run.',
        ],
      };

    case 'support-level': {
      const resolved = counts.components - counts.supportUnknown;
      return {
        status: fromCoverage(resolved, counts.components),
        evidence: [
          coverage('a level of support that is not "unknown"', resolved, counts.components),
          coverage('declared by you, which outranks every derived value', counts.supportDeclared, counts.components),
          eolStale
            ? `The bundled end-of-support data is more than ${SNAPSHOT_STALE_AFTER_DAYS} days old, so a component shown as actively maintained may have had an end-of-support date announced since. Refresh it.`
            : 'The bundled end-of-support data is within the freshness threshold.',
          'A level of support is a commitment by whoever maintains the component. Where no dataset answered it, declare it under fda.componentSupport in ceproof.config.json.',
        ],
      };
    }

    case 'end-of-support-date':
      return {
        status: fromCoverage(counts.endOfSupportDates, counts.components),
        evidence: [
          coverage('an end-of-support date', counts.endOfSupportDates, counts.components),
          counts.endOfSupportPassed > 0
            ? `${counts.endOfSupportPassed} of ${counts.endOfSupportDates === 1 ? 'that date' : 'those dates'} ${counts.endOfSupportPassed === 1 ? 'has' : 'have'} already passed as of ${input.asOf}.`
            : `No end-of-support date in this run has passed as of ${input.asOf}.`,
          'This tool never invents a date. A component with none has none here; supply it or state in your submission why the component has no end-of-support date.',
        ],
      };

    case 'unknown-justification': {
      if (counts.supportUnknown === 0) {
        return {
          status: 'DERIVED',
          evidence: ['No component has an unknown level of support in this run, so there is nothing to justify.'],
        };
      }
      const justified = rows.filter((r) => r.support.supportLevel === 'unknown' && r.support.note).length;
      return {
        status: justified === counts.supportUnknown ? 'DERIVED' : 'NEEDS-HUMAN-INPUT',
        evidence: [
          coverage('unknown levels of support carrying your justification', justified, counts.supportUnknown),
          'The guidance asks for a justification where SBOM information cannot be provided. Put it in the declaration\'s `note` so it travels with the component into the output.',
        ],
      };
    }

    case 'all-known-vulnerabilities':
      // Permanently PARTIAL, by construction. See the module comment.
      return {
        status: 'PARTIAL',
        evidence: [
          'FDA asks for ALL known vulnerabilities associated with the device and its software components.',
          'This tool screens the CISA Known Exploited Vulnerabilities Catalog only — the subset FDA names explicitly. It is not a general vulnerability database, and it never will read DERIVED here.',
          `Screened in this run: ${counts.components} components, ${counts.confirmed} confirmed, ${counts.possible} possible, ${counts.notAffected} screened and set aside.`,
          'Identify the rest by other means and carry them into the same table. This screen is one input to that list, not the whole of it.',
        ],
      };

    case 'kev-screen':
      return {
        status: counts.components === 0 ? 'NEEDS-HUMAN-INPUT' : kevStale ? 'PARTIAL' : 'DERIVED',
        evidence: [
          `Screened against CISA KEV catalogue version ${input.kev.snapshotSource.catalogVersion}, released ${input.kev.snapshotSource.dateReleased.slice(0, 10)}, ${input.kev.snapshotSource.upstreamCount} entries.`,
          `Ecosystem advisory ranges captured from OSV on ${input.kev.indexBuiltFrom.osvQueriedAt.slice(0, 10)}.`,
          kevStale
            ? `That catalogue is more than ${SNAPSHOT_STALE_AFTER_DAYS} days old as of ${input.asOf}. A component with no match here may have had one catalogued since. Run \`npm run fetch-kev-snapshot\` or upgrade ceproof, and screen again.`
            : `The catalogue is within the ${SNAPSHOT_STALE_AFTER_DAYS}-day freshness threshold as of ${input.asOf}.`,
          counts.ransomware > 0
            ? `${counts.ransomware} of the findings ${counts.ransomware === 1 ? 'is' : 'are'} flagged by CISA as used in a known ransomware campaign.`
            : 'No finding in this run is flagged by CISA as used in a known ransomware campaign.',
        ],
      };

    case 'how-discovered':
      return {
        status: counts.components === 0 ? 'NEEDS-HUMAN-INPUT' : 'DERIVED',
        evidence: [
          findings === 1
            ? 'The single finding carries one auditable sentence naming what was matched, against which catalogue version, and why its confidence is what it is.'
            : findings > 1
              ? `All ${findings} findings carry one auditable sentence each, naming what was matched, against which catalogue version, and why the confidence is what it is.`
              : 'No finding was produced in this run, so there is nothing to describe — but the method, the catalogue version and the dates are recorded regardless.',
          'This covers only the vulnerabilities THIS screen found. How you discovered any others is yours to describe.',
        ],
      };

    case 'risk-assessment':
      // Permanently NEEDS-HUMAN-INPUT. Not a function of the data.
      return {
        status: 'NEEDS-HUMAN-INPUT',
        evidence: [
          'A safety and security risk assessment of each known vulnerability, including device and system impacts, is one of the two things FDA asks the MANUFACTURER for.',
          'No component scanner can produce it. This tool identifies candidates and records how each was found; the assessment column reads NEEDS-HUMAN-INPUT in every artifact until you write it.',
          findings > 0
            ? `${findings} ${findings === 1 ? 'finding needs' : 'findings need'} one from this screen alone, plus any vulnerability you identified by other means.`
            : 'No finding came out of this screen, which does not remove the obligation for vulnerabilities you identified by other means.',
        ],
      };

    case 'risk-controls':
      return {
        status: 'NEEDS-HUMAN-INPUT',
        evidence: [
          'Details of the applicable safety and security risk controls, including any compensating controls, is the second of the two things FDA asks the MANUFACTURER for.',
          'Same reason as the risk assessment: it is a statement about your device and your design, not about a component.',
        ],
      };

    case 'kev-designed-out':
      // Zero matches is PARTIAL, never DERIVED. See the module comment.
      return {
        status: findings > 0 ? 'NEEDS-HUMAN-INPUT' : 'PARTIAL',
        evidence: [
          findings > 0
            ? `${findings} ${findings === 1 ? 'finding' : 'findings'} matched the bundled KEV catalogue (${counts.confirmed} confirmed, ${counts.possible} possible). The guidance says vulnerabilities in that catalogue should be designed OUT of the device, not mitigated in place.`
            : 'No component matched the bundled KEV catalogue in this run.',
          'Whether a vulnerability has been designed out is a fact about your device that this tool cannot observe.',
          findings > 0
            ? 'Work through the findings and record, for each, whether the affected component was removed, replaced or updated.'
            : 'This reads PARTIAL rather than DERIVED on purpose: nothing matched one catalogue, which is not the same statement as nothing being there.',
        ],
      };

    case 'cyber-device-determination':
      return {
        status: 'NEEDS-HUMAN-INPUT',
        evidence: [
          'Whether your device is a "cyber device" under section 524B of the FD&C Act decides whether an SBOM is a statutory requirement or a recommendation.',
          'That determination depends on the device, its software, its connectivity and its cybersecurity vulnerabilities. It is yours to make, with the guidance\'s section VII.B, and nothing here makes it for you.',
        ],
      };
  }
}

export function computeFdaProfile(input: FdaRenderInput, rows: FdaRow[] = joinRows(input)): FdaProfile {
  const structure = getFdaStructure();
  const counts = countsFor(input, rows);
  const items: FdaGapItem[] = structure.items.map((item: FdaStructureItem) => {
    const { status, evidence } = resolve(item.measure, input, rows, counts);
    return {
      id: item.id,
      measure: item.measure,
      status,
      requirementSummary: item.requirementSummary,
      citation: item.citation,
      evidence,
    };
  });
  return {
    items,
    counts,
    warnings: [...input.mergeWarnings, ...input.support.warnings, ...input.kev.warnings],
    summary: {
      totalItems: items.length,
      derived: items.filter((i) => i.status === 'DERIVED').length,
      partial: items.filter((i) => i.status === 'PARTIAL').length,
      needsHumanInput: items.filter((i) => i.status === 'NEEDS-HUMAN-INPUT').length,
    },
    structureVersion: structure.sourceVersion,
    structureVersionShort: structure.shortVersion,
  };
}
