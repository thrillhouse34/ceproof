"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderSummary = renderSummary;
const picocolors_1 = __importDefault(require("picocolors"));
const branding_1 = require("../branding");
const provenance_1 = require("./provenance");
function colorsFor(enabled) {
    const forced = picocolors_1.default.createColors(enabled);
    return { bold: forced.bold, green: forced.green, yellow: forced.yellow, dim: forced.dim };
}
const INSTRUMENT_ORDER = ['annexVII', 'annexV'];
const INSTRUMENT_LABEL = {
    annexVII: 'Annex VII — Technical Documentation',
    annexV: 'Annex V — EU Declaration of Conformity',
};
// Least-alarming-to-most-actionable reading order — matches the register
// established by licenseproof's UNKNOWN-is-not-alarming precedent: an item
// still needing human input isn't a failure state to color red, it's an
// honest "not yet answered."
const STATUS_ORDER = ['DERIVED', 'PARTIAL', 'NEEDS-HUMAN-INPUT'];
function wrapAt80(text, indent) {
    const words = text.split(' ');
    const lines = [];
    let current = indent;
    for (const word of words) {
        if ((current + word).length > 80 && current.trim().length > 0) {
            lines.push(current.trimEnd());
            current = indent;
        }
        current += word + ' ';
    }
    if (current.trim().length > 0)
        lines.push(current.trimEnd());
    return lines.join('\n');
}
// Every item's `citation` (data/cra-structure.json, traceability-tested —
// never edit that field) is dominated by a shared regulation/consolidation
// preamble ("Regulation (EU) 2024/2847 (Cyber Resilience Act), consolidated
// text 02024R2847-20241120 (base act + Corrigenda 1-3, ...), ") that is
// byte-identical across all 21 items. That preamble is stated once, in full,
// on the header/provenance line instead (see renderSummary below) — printing
// it 21 times buries the part that's actually item-specific: which
// instrument/point (and, for annex7.8 / annex7.2.b, a genuinely item-specific
// "See also" BSI cross-reference) under a wall of repeated text.
//
// This finds where the item-specific part starts and keeps everything from
// there to the end of the string (so any trailing "See also ..." content is
// preserved verbatim, not stripped along with the preamble). The regex
// requires "point" immediately after "Annex VII,"/"Annex V," specifically so
// it does NOT match the preamble's own "...touch Annex V, Annex VII, or
// Articles..." aside, which is never followed by "point". Falls back to the
// full citation, unchanged, if that shape isn't found — this must never
// silently drop information, only shorten it when it safely can.
const CITATION_TAIL_START_RE = /Annex (?:VII|V), point \d/;
function citationTail(citation) {
    const m = citation.match(CITATION_TAIL_START_RE);
    return m && m.index !== undefined ? citation.slice(m.index) : citation;
}
function statusLabel(status, c) {
    if (status === 'DERIVED')
        return c.bold(c.green('DERIVED'));
    if (status === 'PARTIAL')
        return c.bold(c.yellow('PARTIAL'));
    return c.bold('NEEDS-HUMAN-INPUT'); // uncolored — honest, not alarming
}
function renderItem(item, c) {
    const lines = [];
    // Wrap the PLAIN (uncolored) header text first, so the [STATUS] prefix's
    // length is correctly accounted for in the 80-column budget, then colorize
    // only the bracketed status token afterward — ANSI escape codes must never
    // count toward wrap-point decisions (ceproof's terminal rendering must stay
    // within 80 columns of *visible* text, not raw string length).
    const statusPlain = item.status;
    const headerPlain = `[${statusPlain}] ${item.id} — ${item.requirementSummary}`;
    const wrappedHeader = wrapAt80(headerPlain, '  ');
    lines.push(wrappedHeader.replace(`[${statusPlain}]`, `[${statusLabel(item.status, c)}]`));
    lines.push(c.dim(wrapAt80(citationTail(item.citation), '    ')));
    for (const ev of item.evidence) {
        lines.push(c.dim(wrapAt80(`- ${ev}`, '      ')));
    }
    return lines.join('\n');
}
function renderInstrumentSection(instrument, items, c) {
    const lines = [];
    lines.push(c.bold(INSTRUMENT_LABEL[instrument]));
    for (const status of STATUS_ORDER) {
        const inStatus = items.filter((i) => i.status === status);
        for (const item of inStatus)
            lines.push(renderItem(item, c));
    }
    return lines.join('\n');
}
function renderSummary(input) {
    const c = colorsFor(input.colorEnabled);
    const lines = [];
    lines.push(c.bold(`${branding_1.PRODUCT_NAME} scan: ${input.projectName}`));
    // The header line carries a SHORT data identifier only (e.g.
    // "02024R2847-20241120") — the full consolidation sentence (corrigenda
    // verification, BSI supplementary source) is ~300 characters and would
    // dwarf every other header field if printed here. It's stated in full
    // exactly once, directly below, instead of repeated per line or per item
    // (see citationTail() above for the matching per-item fix).
    lines.push(c.dim(`${branding_1.PRODUCT_NAME} ${input.toolVersion} · data ${(0, provenance_1.shortDataVersion)(input.dataVersion)} · scanned ${input.scanTimestamp}`));
    lines.push(c.dim(wrapAt80(`Data source: ${input.dataVersion}`, '  ')));
    lines.push(c.dim(branding_1.DISCLAIMER));
    const counts = {
        derived: input.gapChecklist.filter((i) => i.status === 'DERIVED').length,
        partial: input.gapChecklist.filter((i) => i.status === 'PARTIAL').length,
        needsHumanInput: input.gapChecklist.filter((i) => i.status === 'NEEDS-HUMAN-INPUT').length,
    };
    const total = input.gapChecklist.length;
    lines.push('');
    lines.push(wrapAt80(`${total} CRA item${total === 1 ? '' : 's'} checked — ` +
        `${counts.derived} derived, ${counts.partial} partial, ${counts.needsHumanInput} needs human input`, ''));
    for (const instrument of INSTRUMENT_ORDER) {
        const items = input.gapChecklist.filter((i) => i.instrument === instrument);
        if (items.length === 0)
            continue;
        lines.push('');
        lines.push(renderInstrumentSection(instrument, items, c));
    }
    lines.push('');
    if (!input.configPresent && counts.needsHumanInput > 0) {
        lines.push(c.yellow(wrapAt80(`No ceproof.config.json found. Run "ceproof init" to start answering the ${counts.needsHumanInput} item(s) above that need human input.`, '')));
    }
    else if (input.configPresent && counts.needsHumanInput > 0) {
        lines.push(c.yellow(wrapAt80(`ceproof.config.json found, but ${counts.needsHumanInput} item(s) above still need an answer.`, '')));
    }
    return lines.join('\n');
}
//# sourceMappingURL=summary.js.map