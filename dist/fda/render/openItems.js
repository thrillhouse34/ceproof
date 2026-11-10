"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.collectOpenItems = collectOpenItems;
exports.renderOpenItemsBody = renderOpenItemsBody;
/**
 * The open-items list: everything the manufacturer still has to supply or
 * check, in the repo's existing honest-gap style.
 *
 * Two groups, and the split matters more than any severity scale would:
 *
 *  - **Content FDA asks for that this pack cannot supply.** A missing level of
 *    support, a missing SBOM author, the dependency relationships. These are
 *    not ceproof's to derive, and the absence of each one is a real gap in the
 *    submission content, not a cosmetic warning.
 *  - **Checks you must make on what this pack does supply.** A product-name-only
 *    KEV match, a version comparison this tool declined to make, two sources
 *    that disagreed, a stale dataset. The pack has an answer in each of these
 *    cases; the answer needs a human to confirm or reject it.
 *
 * Every item is DERIVED from the run's own data, never from matching a warning
 * string, so a reworded engine message can never silently empty this list. The
 * per-finding risk assessment and risk controls appear here as ONE aggregate
 * item pointing at the CSV, not as one item per finding: the table in
 * fda-summary.md and fda-vulnerabilities.csv already enumerate them row by row,
 * and a 500-line open-items file is a file nobody reads.
 */
const kev_1 = require("../kev");
const support_1 = require("../support");
const cyclonedx_1 = require("./cyclonedx");
const input_1 = require("./input");
/** How many component names an item lists before it says "and N more". A 5,000-component device must not produce a 5,000-name paragraph. */
const NAME_LIST_CAP = 25;
function names(rows) {
    return rows.map((row) => (0, input_1.componentLabel)(row.component));
}
function collectOpenItems(input, rows) {
    const items = [];
    const totals = input.kev.totals;
    // --- Content FDA asks for that this pack cannot supply ---
    if (!input.sbomAuthor) {
        items.push({
            id: 'sbom-author-missing',
            group: 'cannot-supply',
            title: 'The SBOM author is not named',
            detail: 'Author of the SBOM data is one of the NTIA minimum elements FDA requires. ceproof cannot know which organisation produced this SBOM, so the field is left out of the enriched document rather than filled with the tool\'s own name.',
            action: 'Set `manufacturer.name` in `ceproof.config.json` and regenerate; it is emitted as CycloneDX `metadata.manufacturer`.',
        });
    }
    const unknownSupport = rows.filter((r) => r.support.supportLevel === 'unknown');
    if (unknownSupport.length > 0) {
        items.push({
            id: 'support-level-unknown',
            group: 'cannot-supply',
            title: `${unknownSupport.length} ${unknownSupport.length === 1 ? 'component has' : 'components have'} an unknown level of support`,
            detail: `FDA asks for the level of support provided through monitoring and maintenance by each component's manufacturer (${support_1.FDA_SOURCE.citation}). ` +
                'That is a commitment made by whoever maintains the component, not something a scanner can observe, and no public dataset answered it for these components.',
            action: 'Declare each one in `ceproof.config.json` under `fda.componentSupport` (`supportLevel`, and `endOfSupportDate` where you have one). Where the information genuinely cannot be provided, FDA asks for a justification — put it in the declaration\'s `note` so it travels with the component.',
            components: names(unknownSupport),
        });
    }
    const noEolDate = rows.filter((r) => !r.support.endOfSupportDate);
    if (noEolDate.length > 0) {
        items.push({
            id: 'end-of-support-date-missing',
            group: 'cannot-supply',
            title: `${noEolDate.length} ${noEolDate.length === 1 ? 'component has' : 'components have'} no end-of-support date`,
            detail: 'FDA asks for each software component\'s end-of-support date. Neither the manufacturer\'s declarations nor the bundled end-of-support data supplied one for these, and this tool never guesses a date.',
            action: 'Supply the date in `ceproof.config.json` under `fda.componentSupport`, or state in your submission why the component has none.',
            components: names(noEolDate),
        });
    }
    if (totals.confirmed + totals.possible > 0) {
        items.push({
            id: 'vulnerability-assessment-missing',
            group: 'cannot-supply',
            title: `${totals.confirmed + totals.possible} vulnerability findings need a risk assessment and risk controls`,
            detail: `For each known vulnerability FDA asks the manufacturer for two things: "${kev_1.MANUFACTURER_SUPPLIED_COLUMNS[0]}" and "${kev_1.MANUFACTURER_SUPPLIED_COLUMNS[1]}". ` +
                'ceproof identifies candidates and records how each was found; it does not and cannot assess them, because both answers need knowledge of the device and system impacts.',
            action: `Fill the last two columns of fda-vulnerabilities.csv, one row per finding. They read ${input_1.NEEDS_HUMAN_INPUT} until you do.`,
        });
    }
    // Dependency relationship is an NTIA minimum element, so the state of the
    // graph is either a gap or it isn't — and which of the two is derived from
    // the graph that was actually carried through, never assumed. A complete
    // graph produces no item at all; the two incomplete shapes produce different
    // items, because "your source SBOM has no graph" and "your source SBOM's
    // graph stops at the top level" need different things done about them.
    const deps = (0, input_1.resolveDependencies)(input, rows);
    if (deps.edges.length === 0) {
        items.push({
            id: 'dependency-relationships-absent',
            group: 'cannot-supply',
            title: 'Dependency relationships are not represented',
            detail: (0, cyclonedx_1.dependencyRelationshipsNote)(deps, rows.length),
            action: 'Regenerate your source SBOM with its dependency data included (syft, cdxgen and Trivy all emit a `dependencies` array; some vendor-supplied SBOMs do not) ' +
                'and re-import it. This tool carries the graph through verbatim and will never infer one.',
        });
    }
    else if (!deps.hasComponentEdges || deps.componentsInGraph < rows.length || deps.unmappedRefs.length > 0) {
        const detail = [(0, cyclonedx_1.dependencyRelationshipsNote)(deps, rows.length)];
        if (deps.unmappedRefs.length > 0) {
            detail.push(`${deps.unmappedRefs.length} ${deps.unmappedRefs.length === 1 ? 'reference' : 'references'} in the source graph pointed at something not in this document ` +
                `(${deps.unmappedRefs.slice(0, 5).join(', ')}${deps.unmappedRefs.length > 5 ? ', …' : ''}) and ${deps.unmappedRefs.length === 1 ? 'that edge was' : 'those edges were'} left out rather than guessed at.`);
        }
        if (deps.unmappedEdgeTargets > 0) {
            detail.push(`${deps.unmappedEdgeTargets} individual dependency ${deps.unmappedEdgeTargets === 1 ? 'target' : 'targets'} named a component this document does not carry and ${deps.unmappedEdgeTargets === 1 ? 'was' : 'were'} omitted from their edge.`);
        }
        items.push({
            id: 'dependency-relationships-incomplete',
            group: 'cannot-supply',
            title: 'Dependency relationships are incomplete in the source SBOM',
            detail: detail.join(' '),
            action: 'Check the dependency graph in your own source SBOM against what you expect, and regenerate it where it is thin — a graph that records only top-level ' +
                'dependencies does not describe the transitive ones FDA would see in the SBOM. This tool carries through whatever the source asserts and adds nothing.',
        });
    }
    items.push({
        id: 'kev-screen-coverage',
        group: 'cannot-supply',
        title: 'Vulnerabilities outside the CISA KEV catalogue are not searched for',
        detail: 'FDA asks for ALL known vulnerabilities associated with the device and its software components. This screen covers the CISA Known Exploited Vulnerabilities Catalog, which is the subset FDA names explicitly — it is not a general vulnerability database.',
        action: 'Identify the rest by other means and carry them into the same table; this pack is one input to that list, not the whole of it.',
    });
    // --- Checks you must make on what this pack does supply ---
    if (totals.productNameOnly > 0) {
        items.push({
            id: 'product-name-only-findings',
            group: 'must-check',
            title: `${totals.productNameOnly} ${totals.productNameOnly === 1 ? 'finding rests' : 'findings rest'} on a product-name match with no corroborating vendor`,
            detail: 'The component name matched a product CISA lists, but the vendor could not be corroborated. Some of these will be a different product that happens to share a name. They are listed rather than filtered because missing a real known-exploited vulnerability is the worse error.',
            action: "Check each row's CISA vendor against the component's real supplier and strike the ones that are a different product.",
        });
    }
    const declined = rows.flatMap((row) => row.findings.filter((f) => (0, input_1.isDeclinedComparison)(row.component, f)).map(() => row));
    if (declined.length > 0) {
        items.push({
            id: 'version-comparison-declined',
            group: 'must-check',
            title: `The version comparison was declined for ${declined.length} ${declined.length === 1 ? 'finding' : 'findings'}`,
            detail: 'An ecosystem advisory names the package and states affected version ranges, but this tool would not compare the component\'s version against them: it only compares plain dotted-numeric versions, because SEMVER and PEP 440 order pre-release and post-release versions differently and a wrong comparison here would put a wrong "not affected" next to a known-exploited vulnerability.',
            action: 'Compare each of these versions against the advisory ranges by hand. The ranges and the advisory id are in the finding\'s evidence line and in fda-vulnerabilities.csv.',
            components: names(declined),
        });
    }
    const noVersion = rows.filter((r) => !r.component.version);
    if (noVersion.length > 0) {
        items.push({
            id: 'component-version-missing',
            group: 'must-check',
            title: `${noVersion.length} ${noVersion.length === 1 ? 'component carries' : 'components carry'} no version`,
            detail: 'Component version is one of the NTIA minimum elements, and without it no finding for that component can ever be version-precise — every advisory match stays "possible".',
            action: 'Add the version in the source SBOM and re-import. This tool will not infer one.',
            components: names(noVersion),
        });
    }
    const noIdentifier = rows.filter((r) => !r.component.purl && !r.component.cpe);
    if (noIdentifier.length > 0) {
        items.push({
            id: 'component-identifier-missing',
            group: 'must-check',
            title: `${noIdentifier.length} ${noIdentifier.length === 1 ? 'component has' : 'components have'} neither a purl nor a CPE`,
            detail: 'Other unique identifiers is an NTIA minimum element, and these two are what every match in this pack is built on: a purl is what reaches the ecosystem-advisory data, a CPE is what reaches the KEV catalogue by vendor and product. A component with neither is matched on its name alone.',
            action: 'Add a purl or a CPE in the source SBOM where you can; expect weaker matches for the components that have neither.',
            components: names(noIdentifier),
        });
    }
    const noSupplier = rows.filter((r) => !r.component.supplier);
    if (noSupplier.length > 0) {
        items.push({
            id: 'component-supplier-missing',
            group: 'must-check',
            title: `${noSupplier.length} ${noSupplier.length === 1 ? 'component has' : 'components have'} no supplier`,
            detail: 'Supplier name is an NTIA minimum element. It is also what corroborates a KEV match: without it, a catalogue match for this component can only ever rest on the product name.',
            action: 'Add the supplier in the source SBOM.',
            components: names(noSupplier),
        });
    }
    const duplicates = rows.filter((r) => r.component.possibleDuplicate);
    if (duplicates.length > 0) {
        items.push({
            id: 'possible-duplicate-components',
            group: 'must-check',
            title: `${duplicates.length} ${duplicates.length === 1 ? 'component may be a duplicate of another entry' : 'components may be duplicates of other entries'}`,
            detail: 'Two sources named the same component but could not be matched on a purl or on name@version, because a version was missing or the two versions differed. They are kept as separate entries: collapsing them would be an assumption a reviewer has no way to see.',
            action: 'Decide whether each pair is one component or two, and fix the version in whichever source is wrong.',
            components: names(duplicates),
        });
    }
    const conflicted = rows.filter((r) => (r.component.conflicts?.length ?? 0) > 0);
    if (conflicted.length > 0) {
        items.push({
            id: 'source-conflicts',
            group: 'must-check',
            title: `${conflicted.length} ${conflicted.length === 1 ? 'component has' : 'components have'} a field two sources disagreed about`,
            detail: 'Where two sources gave different values for the same field, the first value was kept and the other is recorded on the component (and as `ceproof:fda:sourceConflict` in the enriched SBOM) rather than dropped.',
            action: 'Check each conflict and correct the source that is wrong.',
            components: conflicted.map((row) => `${(0, input_1.componentLabel)(row.component)} — ${(row.component.conflicts ?? []).join('; ')}`),
        });
    }
    const coerced = rows.filter((r) => (0, input_1.coercedType)(r.component) !== undefined);
    if (coerced.length > 0) {
        items.push({
            id: 'component-type-coerced',
            group: 'must-check',
            title: `${coerced.length} ${coerced.length === 1 ? 'component declared a type' : 'components declared types'} CycloneDX does not define`,
            detail: 'The enriched SBOM has to validate against the CycloneDX 1.6 schema, whose `type` field is a closed list. These components were emitted as `library` and their original type is named below so the substitution is visible rather than silent.',
            action: 'Use one of the CycloneDX types in the source SBOM if the distinction matters to your submission.',
            components: coerced.map((row) => `${(0, input_1.componentLabel)(row.component)} — declared "${(0, input_1.coercedType)(row.component)}", emitted as "library"`),
        });
    }
    const droppedHashes = rows.filter((r) => (0, input_1.unusableHashes)(r.component).length > 0);
    if (droppedHashes.length > 0) {
        items.push({
            id: 'component-hash-omitted',
            group: 'must-check',
            title: `${droppedHashes.length} ${droppedHashes.length === 1 ? 'component has a hash' : 'components have hashes'} CycloneDX cannot express`,
            detail: 'CycloneDX 1.6 allows a closed list of hash algorithms. These hashes use an algorithm outside it, so they are omitted from the enriched SBOM — relabelling a hash as an algorithm it was not computed with would be a false statement about the component.',
            action: 'Re-emit the hash with one of the CycloneDX algorithms (SHA-256 and friends) in the source SBOM if your submission relies on it.',
            components: droppedHashes.map((row) => `${(0, input_1.componentLabel)(row.component)} — ${(0, input_1.unusableHashes)(row.component).map((h) => h.alg).join(', ')}`),
        });
    }
    // The staleness checks are recomputed here rather than read out of the
    // engines' warning strings, so this list cannot be emptied by a reworded
    // warning. Same single threshold the engines' own warnings use.
    const eolStale = (0, support_1.isSnapshotStale)(input.support.snapshotSource.upstreamGeneratedAt, input.asOf);
    const kevStale = (0, support_1.isSnapshotStale)(input.kev.snapshotSource.dateReleased, input.asOf);
    if (eolStale || kevStale) {
        const stale = [eolStale ? 'The end-of-support data' : undefined, kevStale ? 'the CISA KEV catalogue' : undefined].filter((label) => label !== undefined);
        // Capitalised only when it is the first fragment, so the sentence reads
        // right whichever one (or both) is stale.
        if (!eolStale)
            stale[0] = 'The CISA KEV catalogue';
        items.push({
            id: 'stale-bundled-data',
            group: 'must-check',
            title: 'A bundled dataset is older than the freshness threshold',
            detail: `${stale.join(' and ')} ${stale.length > 1 ? 'are' : 'is'} more than ${support_1.SNAPSHOT_STALE_AFTER_DAYS} days old. ` +
                'A component shown as actively maintained may have had an end-of-support date announced since, and a component shown with no known exploited vulnerability may have had one catalogued since.',
            action: 'Refresh the data and regenerate before relying on this pack, or re-check the affected components against their sources.',
        });
    }
    return items;
}
function renderItem(item) {
    const lines = [`### ${item.title}`, '', item.detail, '', `**What to do:** ${item.action}`];
    if (item.components && item.components.length > 0) {
        const shown = item.components.slice(0, NAME_LIST_CAP);
        lines.push('', ...shown.map((name) => `- ${name}`));
        if (item.components.length > shown.length) {
            lines.push(`- …and ${item.components.length - shown.length} more — the full list is in fda-support-eol.csv and fda-vulnerabilities.csv.`);
        }
    }
    return lines.join('\n');
}
/** The open-items list as its own markdown document body (no title — the caller supplies the heading, so the same body can be embedded in fda-summary.md). */
function renderOpenItemsBody(items) {
    const sections = [];
    const groups = [
        {
            group: 'cannot-supply',
            heading: 'Content FDA asks for that this pack cannot supply',
            blurb: 'Each of these is submission content no tool can derive. Until you supply it, it is missing from your submission, not merely missing from this pack.',
        },
        {
            group: 'must-check',
            heading: 'Checks you must make on what this pack does supply',
            blurb: 'This pack has an answer in each of these cases. Each answer needs a human to confirm or reject it before it goes into a submission.',
        },
    ];
    for (const { group, heading, blurb } of groups) {
        const groupItems = items.filter((item) => item.group === group);
        if (groupItems.length === 0)
            continue;
        sections.push([`## ${heading}`, '', blurb, '', groupItems.map(renderItem).join('\n\n')].join('\n'));
    }
    if (sections.length === 0) {
        return 'No open items were derived from this run. That is unusual: check that the component list is the one you meant to screen.';
    }
    return sections.join('\n\n');
}
//# sourceMappingURL=openItems.js.map