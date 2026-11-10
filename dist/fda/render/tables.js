"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.STALENESS_THRESHOLD_NOTE = exports.VULNERABILITY_CSV_HEADERS = exports.SUPPORT_CSV_HEADERS = void 0;
exports.supportLevelLabel = supportLevelLabel;
exports.identifiedAsOfLine = identifiedAsOfLine;
exports.renderSupportSection = renderSupportSection;
exports.renderSupportAppendix = renderSupportAppendix;
exports.renderVulnerabilitySection = renderVulnerabilitySection;
exports.renderNotAffectedAppendix = renderNotAffectedAppendix;
exports.renderSupportCsv = renderSupportCsv;
exports.renderVulnerabilitiesCsv = renderVulnerabilitiesCsv;
/**
 * The tables: the support/end-of-support addendum, the known-vulnerability
 * section, and the two CSVs.
 *
 * The division of labour is the one FDA's guidance sets out, and it decides the
 * shape of every table here. This tool SCREENS and records how it found each
 * row; the manufacturer ASSESSES. So the vulnerability table carries the two
 * columns the guidance asks the manufacturer for — named once, in
 * MANUFACTURER_SUPPLIED_COLUMNS (src/fda/kev.ts), so no surface paraphrases
 * them — and leaves them reading NEEDS-HUMAN-INPUT. Nothing here may fill them
 * in, and nothing here may imply they were.
 *
 * Layout decisions worth knowing before changing anything:
 *  - `not-affected` rows go in an appendix, not the main table, with their
 *    count stated in the main table's summary line. They are real content — a
 *    reviewer seeing "CVE-2020-11023 considered, version 3.7.1 is outside the
 *    affected range" learns that the screen ran and what it concluded — but on
 *    a device with thousands of components they would bury the actionable rows.
 *  - the per-component support table is also an appendix, for the same reason:
 *    the main body carries the counts and the components that need attention.
 *  - every table states the date the data behind it was captured, not just the
 *    date it was rendered. A reviewer has to be able to tell the difference
 *    between "screened today against a catalogue from last year" and
 *    "screened today against today's catalogue".
 */
const kev_1 = require("../kev");
const support_1 = require("../support");
const input_1 = require("./input");
/** How each support level reads in a document, where the hyphenated enum value would be noise. */
const SUPPORT_LEVEL_LABELS = {
    'actively-maintained': 'actively maintained',
    'no-longer-maintained': 'no longer maintained',
    abandoned: 'abandoned',
    unknown: 'unknown',
};
function supportLevelLabel(level) {
    return SUPPORT_LEVEL_LABELS[level];
}
/**
 * The one line that tells a reviewer when the data behind the vulnerability
 * section was captured — the KEV catalogue's own release date and the date the
 * ecosystem-advisory index was built, both distinct from the run date.
 */
function identifiedAsOfLine(input) {
    const kev = input.kev.snapshotSource;
    const built = input.kev.indexBuiltFrom;
    return (
    // Sliced to the calendar date: CISA's own dateReleased carries a time of
    // day, which is noise on a document people read.
    `**Vulnerabilities identified as of ${kev.dateReleased.slice(0, 10)}** — the release date of CISA KEV catalogue version ${kev.catalogVersion}, ` +
        `which is the newest catalogue this copy of ceproof has. Ecosystem advisory ranges were captured from OSV on ${built.osvQueriedAt.slice(0, 10)}. ` +
        `This document was generated on ${input.asOf}; anything catalogued or published after the two dates above is not reflected here.`);
}
function renderSupportSection(input, rows, appendixLabel) {
    const counts = { 'actively-maintained': 0, 'no-longer-maintained': 0, abandoned: 0, unknown: 0 };
    let withDate = 0;
    let pastDate = 0;
    for (const row of rows) {
        counts[row.support.supportLevel] += 1;
        if (row.support.endOfSupportDate) {
            withDate += 1;
            if (row.support.endOfSupportDate < input.asOf)
                pastDate += 1;
        }
    }
    const summary = (0, input_1.mdTable)(['Level of support', 'Components'], Object.keys(counts).map((level) => [supportLevelLabel(level), String(counts[level])]));
    const lines = [
        `FDA asks for two values per software component beyond the NTIA minimum elements: the level of support provided through monitoring and maintenance by the component's manufacturer, and the component's end-of-support date (${support_1.FDA_SOURCE.citation}).`,
        '',
        summary,
        '',
        `${withDate} of ${rows.length} components have an end-of-support date; ${rows.length - withDate} have none in the data available to this run. ` +
            `${pastDate} ${pastDate === 1 ? 'component has' : 'components have'} an end-of-support date that has already passed as of ${input.asOf}.`,
        '',
        'A level of support is a commitment made by whoever maintains the component, not a property a scanner can observe. Where this run could not resolve one, the row reads `unknown` and says why; declare the real value in `ceproof.config.json` under `fda.componentSupport` and it will be carried through as manufacturer-declared, which outranks every derived value.',
        '',
        `One row per component, with the basis for each value, is in ${appendixLabel}.`,
    ];
    if (counts.unknown > 0) {
        lines.push('', `${counts.unknown} ${counts.unknown === 1 ? 'component has' : 'components have'} an unknown level of support. Where that information genuinely cannot be provided, FDA's guidance asks for a justification — supply it as the \`note\` on the declaration so it travels with the component.`);
    }
    return lines.join('\n');
}
function renderSupportAppendix(rows) {
    return (0, input_1.mdTable)(['Component', 'Version', 'Supplier', 'Identifier', 'Origin', 'Level of support', 'End of support', 'Basis', 'How it was determined'], rows.map((row) => [
        row.component.name,
        row.component.version ?? input_1.NOT_STATED,
        row.component.supplier ?? input_1.NOT_STATED,
        row.component.purl ?? row.component.cpe ?? input_1.NOT_STATED,
        row.component.origins.join(', '),
        supportLevelLabel(row.support.supportLevel),
        row.support.endOfSupportDate ?? input_1.NOT_STATED,
        row.support.basis,
        row.support.evidence,
    ]));
}
function numbered(rows, pick, prefix) {
    const out = [];
    for (const row of rows) {
        for (const finding of pick(row))
            out.push({ ref: `${prefix}${out.length + 1}`, row, finding });
    }
    return out;
}
function ransomwareCell(finding) {
    // CISA's own "Unknown" is absence of evidence, not evidence of absence, so
    // the negative case says exactly that rather than "no".
    return finding.ransomware ? 'yes' : 'not recorded by CISA';
}
function renderVulnerabilitySection(input, rows, notAffectedAppendix) {
    const totals = input.kev.totals;
    const findings = numbered(rows, (r) => r.findings, 'V');
    const lines = [
        identifiedAsOfLine(input),
        '',
        `FDA asks manufacturers to identify all known vulnerabilities associated with the device and its software components, including those in CISA's Known Exploited Vulnerabilities Catalog (${kev_1.FDA_VULN_SOURCE.citation}).`,
        '',
        `This screen covers the CISA KEV catalogue only, offline. It found **${totals.confirmed} confirmed** and **${totals.possible} possible** ${totals.confirmed + totals.possible === 1 ? 'finding' : 'findings'} across ${totals.componentsWithFindings} of ${totals.components} components. ` +
            `${totals.notAffected} ${totals.notAffected === 1 ? 'row was' : 'rows were'} screened and found not to affect the version declared for the component; ${totals.notAffected === 1 ? 'it is' : 'they are'} listed in ${notAffectedAppendix}.` +
            (totals.ransomware > 0 ? ` ${totals.ransomware} of the findings ${totals.ransomware === 1 ? 'is' : 'are'} flagged by CISA as used in a known ransomware campaign.` : ''),
        '',
    ];
    if (findings.length === 0) {
        lines.push('No component matched an entry in the bundled KEV catalogue in this run. That is not a statement that the device is free of known vulnerabilities: the catalogue lists only the vulnerabilities CISA has confirmed as exploited, and the limits below apply in full.', '');
    }
    else {
        lines.push((0, input_1.mdTable)([
            'Ref',
            'Component',
            'Version',
            'CVE',
            'Confidence',
            'Basis',
            "CISA's vendor / product",
            'Added to KEV',
            'Known ransomware use',
            kev_1.MANUFACTURER_SUPPLIED_COLUMNS[0],
            kev_1.MANUFACTURER_SUPPLIED_COLUMNS[1],
        ], findings.map(({ ref, row, finding }) => [
            ref,
            row.component.name,
            row.component.version ?? input_1.NOT_STATED,
            finding.cve,
            finding.confidence,
            finding.basis,
            `${finding.kevVendor} / ${finding.kevProduct}`,
            finding.dateAdded,
            ransomwareCell(finding),
            input_1.NEEDS_HUMAN_INPUT,
            input_1.NEEDS_HUMAN_INPUT,
        ])), '', `The last two columns are the two things FDA asks the MANUFACTURER to provide for each known vulnerability. ceproof does not fill them in and cannot: both need knowledge of the device and system impacts that no component scanner has. They read ${input_1.NEEDS_HUMAN_INPUT} until you write them. The same two columns are the last two columns of fda-vulnerabilities.csv, which is the easier place to work.`, '', '### How each finding was discovered', '', "FDA asks manufacturers to describe how vulnerabilities were discovered. One sentence per finding, naming what was matched, against which catalogue version, and why the confidence is what it is:", '', ...findings.map(({ ref, row, finding }) => `- **${ref} — ${finding.cve}, ${(0, input_1.componentLabel)(row.component)}** (${finding.vulnerabilityName}). ${finding.evidence}${finding.advisory ? ` Advisory: ${finding.advisory} (${finding.advisorySource}).` : ''}`), '');
    }
    lines.push('### What this screen does not cover', '', ...input.kev.limits.map((limit) => `- ${limit}`));
    return lines.join('\n');
}
function renderNotAffectedAppendix(rows) {
    const notAffected = numbered(rows, (r) => r.notAffected, 'N');
    if (notAffected.length === 0) {
        return 'No row reached this appendix: no vulnerability in this run was both matched to a component by an ecosystem advisory and provably outside its affected version ranges.';
    }
    return [
        'Every row here was matched to a component and then set aside, because the version declared for that component falls outside every affected range the advisory states. They are listed so each CVE is visibly considered rather than silently omitted.',
        '',
        (0, input_1.mdTable)(['Ref', 'Component', 'Version', 'CVE', 'Advisory', 'Why it was set aside'], notAffected.map(({ ref, row, finding }) => [
            ref,
            row.component.name,
            row.component.version ?? input_1.NOT_STATED,
            finding.cve,
            finding.advisory ?? input_1.NOT_STATED,
            finding.evidence,
        ])),
    ].join('\n');
}
/**
 * Neither CSV carries the disclaimer, and that is the one disclosed exception
 * to the "every user-facing output states it" doctrine: CSV has no metadata
 * channel, and a line of prose at either end of the file is a malformed row
 * that breaks parsers and shows up as a stray row in the spreadsheet the file
 * exists to be opened in. Both are working copies of tables that appear in
 * full in fda-summary.md, which carries the disclaimer twice.
 * tests/fda/forbiddenClaims.test.ts pins the exception to exactly these two
 * files, so a third artifact can never quietly join them.
 */
exports.SUPPORT_CSV_HEADERS = [
    'component',
    'version',
    'supplier',
    'purl',
    'cpe',
    'type',
    'origin',
    'licenses',
    'hashes',
    'supportLevel',
    'endOfSupportDate',
    'supportBasis',
    'matchedBy',
    'matchedProduct',
    'matchedCycle',
    'howDetermined',
    'manufacturerNote',
    'possibleDuplicate',
    'sourceConflicts',
];
function renderSupportCsv(rows) {
    return (0, input_1.csvRows)(exports.SUPPORT_CSV_HEADERS, rows.map((row) => [
        row.component.name,
        row.component.version ?? '',
        row.component.supplier ?? '',
        row.component.purl ?? '',
        row.component.cpe ?? '',
        row.component.type ?? '',
        row.component.origins.join('; '),
        row.component.licenses.join('; '),
        row.component.hashes.map((h) => `${h.alg}:${h.content}`).join('; '),
        row.support.supportLevel,
        row.support.endOfSupportDate ?? '',
        row.support.basis,
        row.support.matchedBy ?? '',
        row.support.matchedProductId ?? '',
        row.support.matchedCycle ?? '',
        row.support.evidence,
        row.support.note ?? '',
        row.component.possibleDuplicate ? 'yes' : '',
        (row.component.conflicts ?? []).join('; '),
    ]));
}
exports.VULNERABILITY_CSV_HEADERS = [
    'component',
    'version',
    'purl',
    'cpe',
    'cve',
    'vulnerabilityName',
    'confidence',
    'basis',
    'kevVendor',
    'kevProduct',
    'kevDateAdded',
    'kevDueDate',
    'knownRansomwareUse',
    'cwes',
    'advisory',
    'advisorySource',
    'howDiscovered',
    // The two the manufacturer fills in, named exactly as FDA's own two bullets
    // do, so a reviewer can line the column up with the guidance.
    kev_1.MANUFACTURER_SUPPLIED_COLUMNS[0],
    kev_1.MANUFACTURER_SUPPLIED_COLUMNS[1],
];
/**
 * Every finding, including the `not-affected` ones — this file is the complete
 * machine-readable record of the screen, and the `confidence` column is what
 * separates them. The document is where the rows are triaged for a reader.
 */
function renderVulnerabilitiesCsv(rows) {
    const out = [];
    for (const row of rows) {
        for (const finding of [...row.findings, ...row.notAffected]) {
            out.push([
                row.component.name,
                row.component.version ?? '',
                row.component.purl ?? '',
                row.component.cpe ?? '',
                finding.cve,
                finding.vulnerabilityName,
                finding.confidence,
                finding.basis,
                finding.kevVendor,
                finding.kevProduct,
                finding.dateAdded,
                finding.dueDate ?? '',
                finding.ransomware ? 'yes' : '',
                (finding.cwes ?? []).join('; '),
                finding.advisory ?? '',
                finding.advisorySource ?? '',
                finding.evidence,
                // The same marker the document and the CRA gap checklist use, rather
                // than an empty cell: an empty cell in a spreadsheet is ambiguous
                // between "nothing to say" and "nobody has written this yet", and in a
                // premarket submission those are very different things.
                input_1.NEEDS_HUMAN_INPUT,
                input_1.NEEDS_HUMAN_INPUT,
            ]);
        }
    }
    return (0, input_1.csvRows)(exports.VULNERABILITY_CSV_HEADERS, out);
}
/** Named here so the summary and the open-items list quote the same number of days. */
exports.STALENESS_THRESHOLD_NOTE = `Both bundled datasets carry a warning once they are more than ${support_1.SNAPSHOT_STALE_AFTER_DAYS} days old.`;
//# sourceMappingURL=tables.js.map