import type { AnnexPackContent, ReportSection } from './annexContent';
import { PRODUCT_NAME, DISCLAIMER } from '../branding';
import { citationTail } from './provenance';

// ─────────────────────────────────────────────────────────────────────────────
// ceproof HTML document renderer (Milestone 2) — the paid centerpiece
// artifact: the Annex VII technical documentation pack and the Annex V
// Declaration of Conformity draft.
//
// A single self-contained `.html` file assembled with template literals (no
// template engine). ALL CSS is inline in one <style> block; there are ZERO
// external references of any kind (no <link>, no <script src>, no remote
// fonts/images/analytics) so the file is fully readable offline, from a
// file:// URL, forever. `tests/report/html.test.ts` greps the rendered output
// to enforce that offline guarantee.
//
// Design is BINDING per the M2 brief's addendum B: reuse licenseproof's
// proven report look VERBATIM — white background, near-black slate text
// (never pure #000), ONE deep-blue accent (#1e3a8a) used only for structure
// (rules, headers, kicker), generous whitespace, no gradients, no marketing
// tone. Every status indicator is a text label plus a plain CSS shape (a
// colored square) — never an emoji or icon-font glyph that could render as
// tofu offline.
//
// CONTENT model is completely different from licenseproof's conflict report:
// this file has no severity buckets or per-package findings. It renders
// `AnnexPackContent` — a flat, already-ordered list of CRA requirement
// sections (`ReportSection`), each carrying its own honest status (DERIVED /
// PARTIAL / NEEDS-HUMAN-INPUT) and either real content or an explicit "not
// yet answered" placeholder. `annexContent.ts` owns WHAT each section says;
// this module owns HOW it's laid out.
//
// PRINT: `page-break-inside: avoid` on `.req` keeps a single CRA item's
// section from splitting across a page break — the addendum B requirement
// that "no item's section splits mid-item". No fixed `@page { size }` is
// declared, so the SAME file prints correctly on both A4 and Letter; the
// content column is capped at ~170mm. The printed footer is STATIC (not
// per-page-numbered): true per-page "page N of M" numbering is the PDF
// renderer's job (pdf.ts) via Puppeteer's `footerTemplate`.
// ─────────────────────────────────────────────────────────────────────────────

// Standard HTML text-content escaping. The apostrophe is deliberately NOT
// escaped: it is only special inside single-quoted attribute values, and no
// dynamic value is ever placed in a single-quoted attribute in this template.
// Leaving it unescaped means vendored/config-supplied prose (which may contain
// apostrophes, e.g. "the manufacturer's registered address") renders
// byte-for-byte verbatim. `"` is still escaped (harmless in text content, and
// defensive if a value ever lands in a double-quoted attribute).
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function plural(n: number, singular: string, pluralForm?: string): string {
  return n === 1 ? singular : (pluralForm ?? `${singular}s`);
}

const STATUS_LABEL: Record<ReportSection['status'], string> = {
  DERIVED: 'Derived',
  PARTIAL: 'Partial',
  'NEEDS-HUMAN-INPUT': 'Needs input',
};

// The chip's visual class is driven primarily by `isOpenItem`, not the raw
// status string: an open item always gets the neutral/muted "not yet" look
// (this codebase's precedent throughout — an unanswered item is an honest
// "not yet" state, never styled as an error/failure), regardless of what its
// underlying status literal happens to be.
function statusChipClass(section: ReportSection): 'derived' | 'partial' | 'open' {
  if (section.isOpenItem) return 'open';
  if (section.status === 'PARTIAL') return 'partial';
  return 'derived';
}

// One requirement section: heading (id + requirement summary), the
// item-specific citation tail (dim; the shared ~150-char regulation preamble
// is stripped per citationTail() in provenance.ts — it's already stated in
// full, once, in the cover header's `cover__data-version` line above, and
// repeating it per item buried the point number and the annex7.8/annex7.2.b
// BSI cross-references under a wall of identical text), a status chip, and
// either the real body paragraphs or an explicit open-item placeholder — an
// open item is NEVER silently blank or omitted. The full untrimmed citation
// stays discoverable via the paragraph's `title` attribute (hover tooltip)
// and, unabridged, in `--format json` output (json.ts renders
// AnnexPackContent verbatim) — never dropped, only deprioritized visually.
function sectionHtml(section: ReportSection): string {
  const chipClass = statusChipClass(section);
  const label = section.isOpenItem ? 'Not yet answered' : STATUS_LABEL[section.status];

  const composedNote = section.composedFromAnnexV
    ? `\n        <p class="req__note">(compiled from the Annex V declaration below)</p>`
    : '';

  const bodyHtml = section.isOpenItem
    ? `        <p class="req__open">This item has not yet been answered. Run <code>ceproof init</code> to supply it.</p>`
    : section.body.map((line) => `        <p>${escapeHtml(line)}</p>`).join('\n');

  return `      <article class="req" id="${escapeHtml(section.id)}" data-status="${escapeHtml(section.status)}">
        <div class="req__head">
          <h2>${escapeHtml(section.id)} — ${escapeHtml(section.requirementSummary)}</h2>
          <span class="chip chip--${chipClass}"><span class="chip__dot"></span>${escapeHtml(label)}</span>
        </div>
        <p class="req__citation" title="${escapeHtml(section.citation)}">${escapeHtml(citationTail(section.citation))}</p>${composedNote}
${bodyHtml}
      </article>`;
}

// A clear, non-alarming statement of how many items still need manufacturer
// input — this codebase's precedent is that NEEDS-HUMAN-INPUT items are not
// failures. Rendered even when the count is zero: the presence or absence of
// open items is itself provenance-relevant information for an audit artifact,
// so this line is never skipped.
function openItemsSummary(content: AnnexPackContent): string {
  const total = content.sections.length;
  const open = content.openItemCount;
  if (open > 0) {
    const verb = open === 1 ? 'still needs' : 'still need';
    return (
      `${open} of ${total} ${plural(total, 'item')} in this pack ${verb} manufacturer input — ` +
      `see the items marked "Not yet answered" below. Run <code>ceproof init</code> to answer them.`
    );
  }
  return `All ${total} ${plural(total, 'item')} in this pack ${total === 1 ? 'has' : 'have'} content — no manufacturer input is currently missing.`;
}

export function renderAnnexHtml(content: AnnexPackContent): string {
  const provenance = content.provenance;

  const sectionsHtml = content.sections.map(sectionHtml).join('\n');

  const provenanceLine =
    `${escapeHtml(PRODUCT_NAME)} ${escapeHtml(provenance.toolVersion)} · ` +
    `CRA data ${escapeHtml(provenance.dataVersion)} · ` +
    `release ${escapeHtml(provenance.release.label)} · ` +
    `generated ${escapeHtml(provenance.scanTimestamp)}`;

  const title = `${content.title} — ${escapeHtml(content.projectName || 'project')}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
:root {
  --ink: #1a1a2e;          /* near-black slate, never pure #000 */
  --muted: #5b6472;        /* secondary text */
  --accent: #1e3a8a;       /* the ONE accent — structure only */
  --rule: #d7dbe3;         /* hairline borders */
  --rule-soft: #eceef2;
  --paper: #ffffff;
  --panel: #f7f8fa;        /* faint neutral panel, not a colored wash */
  --sev-derived: #4b7a53;  /* calm success green — an answered/derived item */
  --sev-partial: #b45309;  /* amber — supported by evidence, needs review */
  --sev-open: #6b7280;     /* neutral muted — "not yet answered", never alarming red */
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 16px;
  line-height: 1.6;
}
.mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; font-size: 0.92em; }
.page { max-width: 900px; margin: 0 auto; padding: 56px 40px 72px; }
a { color: var(--accent); }

/* ---- Cover header ---- */
.cover { border-bottom: 3px solid var(--accent); padding-bottom: 28px; margin-bottom: 32px; }
.cover__kicker { font-size: 0.8rem; letter-spacing: 0.14em; text-transform: uppercase; color: var(--accent); font-weight: 700; margin: 0 0 10px; }
.cover h1 { font-size: 2rem; line-height: 1.25; margin: 0 0 6px; font-weight: 700; }
.cover h1 .project { color: var(--accent); }
.cover__facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 4px 28px; margin: 22px 0 4px; }
.cover__facts .fact { display: flex; flex-direction: column; justify-content: space-between; padding: 6px 0; border-top: 1px solid var(--rule-soft); }
.cover__facts dt { font-size: 0.72rem; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); margin: 0; }
.cover__facts dd { margin: 2px 0 0; font-weight: 600; }
/* The ISO scan timestamp is one indivisible token, but a browser will happily
   break it after a hyphen. Hold it on one line and size it to fit the
   narrowest A4 grid column. */
.cover__facts dd.ts { white-space: nowrap; font-size: 0.88rem; }
/* An honest "no VCS identity detected" or a bare commit hash reads as
   informational, not a headline claim — kept visually quieter than a real
   tagged release, which stays full-weight/full-ink. */
.cover__facts dd.release--none { font-style: italic; font-weight: 500; color: var(--muted); }
.cover__facts dd.release--commit { font-weight: 600; color: var(--muted); }

/* A full provenance sentence (consolidation id + corrigenda findings) — kept
   out of the short-token facts grid above (see the cover header markup) so
   it reads as a normal paragraph instead of overflowing a narrow column. */
.cover__data-version { font-size: 0.82rem; color: var(--muted); margin: 14px 0 0; padding-top: 10px; border-top: 1px solid var(--rule-soft); max-width: 74ch; }
.cover__data-version-label { text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.72rem; font-weight: 700; color: var(--muted); margin-right: 6px; }

/* ---- Callouts (disclaimer + open-items summary) ---- */
.callout { font-size: 1.02rem; font-weight: 600; margin: 18px 0 0; padding: 12px 16px; border-left: 4px solid var(--accent); background: var(--panel); }
.callout--muted { border-left-color: var(--sev-open); font-weight: 500; font-size: 0.98rem; }

/* ---- Sections ---- */
.section { margin: 40px 0; }
.section > h2 { font-size: 1.35rem; margin: 0 0 4px; padding-bottom: 8px; border-bottom: 1px solid var(--rule); font-weight: 700; }
p { margin: 0 0 14px; }

/* ---- Status chips (text label + plain CSS square, never an emoji) ---- */
.chip { display: inline-flex; align-items: center; gap: 7px; font-size: 0.74rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; padding: 3px 10px 3px 8px; border: 1px solid var(--rule); border-radius: 4px; white-space: nowrap; flex: none; }
.chip__dot { width: 10px; height: 10px; border-radius: 2px; background: var(--sev-open); flex: none; }
.chip--derived { color: var(--sev-derived); border-color: var(--sev-derived); }
.chip--derived .chip__dot { background: var(--sev-derived); }
.chip--partial { color: var(--sev-partial); border-color: var(--sev-partial); }
.chip--partial .chip__dot { background: var(--sev-partial); }
.chip--open { color: var(--sev-open); border-color: var(--rule); }
.chip--open .chip__dot { background: var(--sev-open); }

/* ---- Requirement sections ---- */
.req { border: 1px solid var(--rule); border-radius: 8px; padding: 18px 20px; margin: 16px 0; page-break-inside: avoid; break-inside: avoid; }
.req[data-status="DERIVED"] { border-left: 4px solid var(--sev-derived); }
.req[data-status="PARTIAL"] { border-left: 4px solid var(--sev-partial); }
.req[data-status="NEEDS-HUMAN-INPUT"] { border-left: 4px solid var(--sev-open); }
.req__head { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 6px; }
.req__head h2 { font-size: 1.05rem; margin: 0; padding: 0; border: none; font-weight: 700; flex: 1 1 auto; min-width: 0; }
.req__citation { color: var(--muted); font-size: 0.86rem; margin: 0 0 12px; max-width: 74ch; }
.req__note { color: var(--muted); font-size: 0.82rem; font-style: italic; margin: -6px 0 12px; }
.req__open { color: var(--muted); font-style: italic; margin: 0; }

/* ---- Provenance footer ---- */
.provenance { margin-top: 56px; padding-top: 18px; border-top: 1px solid var(--rule); color: var(--muted); font-size: 0.82rem; }
.provenance .mono { color: var(--ink); }

code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88em; background: var(--panel); padding: 1px 5px; border-radius: 3px; }

/* ---- Print ---- */
@media print {
  /* No @page { size } — the same file must print correctly on A4 AND Letter.
     A ~170mm content column fits inside both page widths with margins. */
  @page { margin: 16mm; }
  body { font-size: 11pt; }
  .page { max-width: 170mm; padding: 0; margin: 0; }
  a { color: var(--ink); text-decoration: none; }
  .callout, code { background: transparent !important; }
  .callout { border-left-color: var(--ink); }
  .req, .cover { page-break-inside: avoid; break-inside: avoid; }
  h2 { page-break-after: avoid; }
}
</style>
</head>
<body>
  <main class="page">

    <!-- (1) Cover header -->
    <header class="cover">
      <p class="cover__kicker">${escapeHtml(PRODUCT_NAME.toUpperCase())} — CYBER RESILIENCE ACT COMPLIANCE</p>
      <h1>${escapeHtml(content.title)} for <span class="project">${escapeHtml(content.projectName || 'project')}</span></h1>
      <dl class="cover__facts">
        <div class="fact"><dt>Release</dt><dd class="release--${provenance.release.kind}">${escapeHtml(provenance.release.label)}</dd></div>
        <div class="fact"><dt>Tool version</dt><dd class="mono">${escapeHtml(provenance.toolVersion)}</dd></div>
        <div class="fact"><dt>Scan timestamp</dt><dd class="ts">${escapeHtml(provenance.scanTimestamp)}</dd></div>
      </dl>
      <!-- CRA data version is a full provenance sentence (consolidation id +
           corrigenda findings), not a short token like the facts above — it
           gets its own full-width line rather than being squeezed into a
           190px grid column, which visual review found made the cover
           header look lopsided and cluttered. -->
      <p class="cover__data-version"><span class="cover__data-version-label">CRA data version</span> ${escapeHtml(provenance.dataVersion)}</p>
    </header>

    <!-- (2) Disclaimer — prominent, not buried in the footer -->
    <p class="callout disclaimer">${escapeHtml(DISCLAIMER)}</p>

    <!-- (3) Open-items summary -->
    <p class="callout callout--muted open-items">${openItemsSummary(content)}</p>

    <!-- (4) One section per CRA item, in the order annexContent.ts already established -->
    <section class="section" aria-labelledby="items-h">
      <h2 id="items-h">${escapeHtml(content.title)}</h2>
${sectionsHtml}
    </section>

    <!-- (5) Provenance footer (static — per-page numbering is the PDF's job) -->
    <footer class="provenance">
      <p class="mono">${provenanceLine}</p>
      <p>${escapeHtml(DISCLAIMER)}</p>
    </footer>

  </main>
</body>
</html>
`;
}
