import { describe, it, expect } from 'vitest';
import { renderAnnexHtml } from '../../src/report/html';
import type { AnnexPackContent, ReportSection } from '../../src/report/annexContent';
import type { ProvenanceInfo } from '../../src/report/provenance';

// licenseproof's version of this file tested a severity-chip findings
// section (CONFLICT/AGPL-informational/REVIEW/UNKNOWN cards) over
// `ReportData`. ceproof's M2 renderer (`renderAnnexHtml`) has a completely
// different content model — a flat, already-ordered list of CRA requirement
// sections (`ReportSection`, from `annexContent.ts`), each with an honest
// DERIVED/PARTIAL/NEEDS-HUMAN-INPUT status and either real content or an
// explicit "not yet answered" placeholder. This file was rewritten from
// scratch to match that shape.

function makeProvenance(overrides: Partial<ProvenanceInfo> = {}): ProvenanceInfo {
  return {
    toolVersion: '0.2.0',
    dataVersion: '2026.07.21',
    scanTimestamp: '2026-07-21T12:00:00.000Z',
    release: { kind: 'tag', value: 'v1.2.3', label: 'v1.2.3' },
    ...overrides,
  };
}

function derivedSection(overrides: Partial<ReportSection> = {}): ReportSection {
  return {
    id: 'annex7.1.b',
    requirementSummary: 'General description of the product.',
    citation: 'Regulation (EU) 2024/2847, Annex VII, point 1(b)',
    status: 'DERIVED',
    body: ['Scan evidence: vcs.tag: "v1.2.3"'],
    isOpenItem: false,
    ...overrides,
  };
}

function partialSection(overrides: Partial<ReportSection> = {}): ReportSection {
  return {
    id: 'annex7.2.b',
    requirementSummary: 'Design and development information.',
    citation: 'Regulation (EU) 2024/2847, Annex VII, point 2(b)',
    status: 'PARTIAL',
    body: [
      'Scan evidence: SECURITY.md present at repo root',
      'This item is only partially supported by automated scan evidence — review and supplement before submission.',
    ],
    isOpenItem: false,
    ...overrides,
  };
}

function openSection(overrides: Partial<ReportSection> = {}): ReportSection {
  return {
    id: 'annex7.1.a',
    requirementSummary: 'Name and version of the product.',
    citation: 'Regulation (EU) 2024/2847, Annex VII, point 1(a)',
    status: 'NEEDS-HUMAN-INPUT',
    body: [],
    isOpenItem: true,
    ...overrides,
  };
}

function makeContent(overrides: Partial<AnnexPackContent> = {}): AnnexPackContent {
  const sections = overrides.sections ?? [derivedSection(), partialSection(), openSection()];
  return {
    instrument: 'annexVII',
    title: 'Annex VII — Technical Documentation',
    projectName: 'my-app',
    provenance: makeProvenance(),
    sections,
    openItemCount: sections.filter((s) => s.isOpenItem).length,
    ...overrides,
  };
}

// The section-order markers, in actual render order.
const SECTION_MARKERS = [
  'class="cover"',
  'class="callout disclaimer"',
  'class="callout callout--muted open-items"',
  'id="items-h"',
  'class="provenance"',
];

describe('renderAnnexHtml — document shape', () => {
  it('is a single self-contained HTML document with exactly one <title>', () => {
    const html = renderAnnexHtml(makeContent());
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('<html lang="en">');
    expect(html.trimEnd().endsWith('</html>')).toBe(true);
    expect((html.match(/<title>/g) ?? []).length).toBe(1);
    expect((html.match(/<style>/g) ?? []).length).toBe(1);
  });

  it('renders the five top-level blocks in order', () => {
    const html = renderAnnexHtml(makeContent());
    let last = -1;
    for (const marker of SECTION_MARKERS) {
      const at = html.indexOf(marker);
      expect(at, `marker "${marker}" present`).toBeGreaterThan(-1);
      expect(at, `marker "${marker}" after previous`).toBeGreaterThan(last);
      last = at;
    }
  });

  it('titles the document from content.title and projectName', () => {
    const html = renderAnnexHtml(makeContent({ title: 'Annex V — EU Declaration of Conformity', projectName: 'widget-app' }));
    expect(html).toContain('<title>Annex V — EU Declaration of Conformity — widget-app</title>');
    expect(html).toContain('widget-app');
  });
});

describe('renderAnnexHtml — fully offline', () => {
  it('contains zero external references (no http(s), <link>, <script src>, remote fonts/@import/url())', () => {
    const html = renderAnnexHtml(makeContent());
    expect(html).not.toMatch(/https?:\/\//);
    expect(html).not.toMatch(/<link\b/i);
    expect(html).not.toMatch(/<script\b/i);
    expect(html).not.toMatch(/\bsrc\s*=/i);
    expect(html).not.toMatch(/@import/i);
    expect(html).not.toMatch(/url\(/i);
  });
});

describe('renderAnnexHtml — provenance / cover facts', () => {
  it('states tool version, CRA data version, and scan timestamp', () => {
    const html = renderAnnexHtml(makeContent());
    expect(html).toContain('0.2.0');
    expect(html).toContain('2026.07.21');
    expect(html).toContain('2026-07-21T12:00:00.000Z');
    expect(html).toContain('CRA data version');
  });

  it('renders the release label verbatim for a real-tag release', () => {
    const html = renderAnnexHtml(
      makeContent({ provenance: makeProvenance({ release: { kind: 'tag', value: 'v3.4.5', label: 'v3.4.5' } }) }),
    );
    expect(html).toContain('v3.4.5');
    expect(html).toContain('release--tag');
  });

  it('renders the release label verbatim for a commit-hash fallback, never dressed up as a version', () => {
    const html = renderAnnexHtml(
      makeContent({
        provenance: makeProvenance({
          release: { kind: 'commit', value: 'bf5e50e123456789', label: 'commit bf5e50e12345' },
        }),
      }),
    );
    expect(html).toContain('commit bf5e50e12345');
    expect(html).toContain('release--commit');
  });

  it('renders the release label verbatim for a no-VCS project', () => {
    const html = renderAnnexHtml(
      makeContent({ provenance: makeProvenance({ release: { kind: 'none', label: 'no VCS identity detected' } }) }),
    );
    expect(html).toContain('no VCS identity detected');
    expect(html).toContain('release--none');
  });
});

describe('renderAnnexHtml — disclaimer', () => {
  it('states the "informational — not legal advice" disclaimer prominently near the top AND in the footer', () => {
    const html = renderAnnexHtml(makeContent());
    const disclaimerBlock = html.slice(html.indexOf('class="callout disclaimer"'), html.indexOf('class="callout callout--muted"'));
    expect(disclaimerBlock).toContain('Informational — not legal advice.');
    const occurrences = html.split('Informational — not legal advice.').length - 1;
    expect(occurrences).toBeGreaterThanOrEqual(2);
  });
});

describe('renderAnnexHtml — open-items summary', () => {
  it('states how many items still need manufacturer input when some are open', () => {
    const html = renderAnnexHtml(makeContent());
    const calloutStart = html.indexOf('class="callout callout--muted open-items"');
    const calloutEnd = html.indexOf('</p>', calloutStart);
    const callout = html.slice(calloutStart, calloutEnd);
    expect(callout).toContain('1 of 3 items');
    expect(callout).toContain('manufacturer input');
    expect(callout).toContain('ceproof init');
  });

  it('states plainly that every item has content when there are no open items', () => {
    const sections = [derivedSection(), partialSection()];
    const html = renderAnnexHtml(makeContent({ sections, openItemCount: 0 }));
    const calloutStart = html.indexOf('class="callout callout--muted open-items"');
    const calloutEnd = html.indexOf('</p>', calloutStart);
    const callout = html.slice(calloutStart, calloutEnd);
    expect(callout).toContain('All 2 items');
    expect(callout).not.toContain('still need');
  });
});

describe('renderAnnexHtml — sections', () => {
  it('renders a DERIVED item\'s heading, citation, chip, and body paragraphs', () => {
    const html = renderAnnexHtml(makeContent({ sections: [derivedSection()], openItemCount: 0 }));
    expect(html).toContain('id="annex7.1.b"');
    expect(html).toContain('annex7.1.b — General description of the product.');
    expect(html).toContain('Regulation (EU) 2024/2847, Annex VII, point 1(b)');
    expect(html).toContain('chip--derived');
    expect(html).toContain('Scan evidence: vcs.tag: &quot;v1.2.3&quot;');
    expect(html).not.toContain('This item has not yet been answered');
  });

  it('renders a PARTIAL item with the amber/warning chip and its caveat line', () => {
    const html = renderAnnexHtml(makeContent({ sections: [partialSection()], openItemCount: 0 }));
    expect(html).toContain('chip--partial');
    expect(html).toContain('review and supplement before submission');
  });

  it('renders an open item\'s explicit "not yet answered" placeholder, never blank or omitted', () => {
    const html = renderAnnexHtml(makeContent({ sections: [openSection()], openItemCount: 1 }));
    expect(html).toContain('id="annex7.1.a"');
    expect(html).toContain('This item has not yet been answered.');
    expect(html).toContain('chip--open');
    // The neutral treatment must NOT reuse the alarming vocabulary this
    // codebase avoids for honest not-yet states.
    expect(html.toLowerCase()).not.toContain('error');
    expect(html.toLowerCase()).not.toContain('failed');
  });

  it('shows the composedFromAnnexV note only when the flag is set', () => {
    const composed = derivedSection({ id: 'annex7.7', composedFromAnnexV: true, body: ['x'] });
    const html = renderAnnexHtml(makeContent({ sections: [composed], openItemCount: 0 }));
    expect(html).toContain('compiled from the Annex V declaration below');

    const notComposed = derivedSection({ id: 'annex7.7' });
    const html2 = renderAnnexHtml(makeContent({ sections: [notComposed], openItemCount: 0 }));
    expect(html2).not.toContain('compiled from the Annex V declaration below');
  });

  it('renders sections in the exact order given, and never drops one', () => {
    const html = renderAnnexHtml(makeContent());
    const posB = html.indexOf('id="annex7.1.b"');
    const posPartial = html.indexOf('id="annex7.2.b"');
    const posOpen = html.indexOf('id="annex7.1.a"');
    expect(posB).toBeGreaterThan(-1);
    expect(posPartial).toBeGreaterThan(posB);
    expect(posOpen).toBeGreaterThan(posPartial);
  });
});

describe('renderAnnexHtml — per-item citation trimming (signal-to-noise fix)', () => {
  // Shaped exactly like the real data/cra-structure.json citation strings
  // (see src/report/provenance.ts's citationTail(), and
  // tests/report/summary.test.ts's identically-named describe block for the
  // terminal renderer's version of this same fix).
  const REAL_SHAPED_PREAMBLE =
    'Regulation (EU) 2024/2847 (Cyber Resilience Act), consolidated text 02024R2847-20241120 ' +
    '(base act + Corrigenda 1-3, none of which touch Annex V, Annex VII, or Articles 13/31/33), ';

  it('renders only the item-specific tail in the visible citation paragraph, not the shared preamble', () => {
    const section = derivedSection({ citation: `${REAL_SHAPED_PREAMBLE}Annex VII, point 3.` });
    const html = renderAnnexHtml(makeContent({ sections: [section], openItemCount: 0 }));
    const citationParagraph = html.match(/<p class="req__citation"[^>]*>([^<]*)<\/p>/)?.[1];
    expect(citationParagraph).toBe('Annex VII, point 3.');
  });

  it('keeps the full untrimmed citation discoverable via the title attribute (hover), never dropped', () => {
    const fullCitation = `${REAL_SHAPED_PREAMBLE}Annex VII, point 3.`;
    const section = derivedSection({ citation: fullCitation });
    const html = renderAnnexHtml(makeContent({ sections: [section], openItemCount: 0 }));
    expect(html).toContain(`title="${fullCitation}"`);
  });

  it('does not repeat the shared preamble once per section across many sections', () => {
    const sections = ['1(a)', '1(b)', '2(a)', '3', '4'].map((point, i) =>
      derivedSection({ id: `annex7.${i}`, citation: `${REAL_SHAPED_PREAMBLE}Annex VII, point ${point}.` }),
    );
    const html = renderAnnexHtml(makeContent({ sections, openItemCount: 0 }));
    // The preamble is preserved once per section, but only inside the
    // `title` attribute (full text stays discoverable there) — never in the
    // visible req__citation text itself.
    const visibleCitations = [...html.matchAll(/<p class="req__citation"[^>]*>([^<]*)<\/p>/g)].map((m) => m[1]);
    expect(visibleCitations).toHaveLength(5);
    for (const c of visibleCitations) expect(c).not.toContain('Regulation (EU) 2024/2847 (Cyber Resilience Act)');
  });

  it('preserves the annex7.8-style "See also" BSI cross-reference in the visible trimmed citation', () => {
    const seeAlso =
      'Annex VII, point 8. See also BSI TR-03183-2 v2.1.0 section 4 (SBOM format: CycloneDX >=1.6 or ' +
      'SPDX >=3.0.1 required) and section 5.2.2 (required component fields, including licence information).';
    const section = derivedSection({ id: 'annex7.8', citation: `${REAL_SHAPED_PREAMBLE}${seeAlso}` });
    const html = renderAnnexHtml(makeContent({ sections: [section], openItemCount: 0 }));
    const citationParagraph = html.match(/<p class="req__citation"[^>]*>([^<]*)<\/p>/)?.[1];
    // ">" is HTML-escaped to "&gt;" in text content (escapeHtml), so the
    // rendered text differs from the raw citation only in that respect.
    expect(citationParagraph).toBe(seeAlso.replace(/>/g, '&gt;'));
    expect(citationParagraph).toContain('See also BSI TR-03183-2 v2.1.0 section 4');
  });

  it('preserves the annex7.2.b-style "See also" cross-reference, including the "(b)" after the point number', () => {
    const seeAlso =
      "Annex VII, point 2(b). See also BSI TR-03183-2 v2.1.0 section 5.2.2 (component-level required SBOM " +
      "data fields, including 'Distribution licences') for what counts as SBOM-readiness evidence.";
    const section = partialSection({ id: 'annex7.2.b', citation: `${REAL_SHAPED_PREAMBLE}${seeAlso}` });
    const html = renderAnnexHtml(makeContent({ sections: [section], openItemCount: 0 }));
    const citationParagraph = html.match(/<p class="req__citation"[^>]*>([^<]*)<\/p>/)?.[1];
    expect(citationParagraph).toBe(seeAlso);
  });

  it('falls back to the full citation unchanged (both visible and in title) when the "Annex X, point N" shape is absent', () => {
    const section = derivedSection({ citation: 'An unusually shaped citation with no point number.' });
    const html = renderAnnexHtml(makeContent({ sections: [section], openItemCount: 0 }));
    const citationParagraph = html.match(/<p class="req__citation"[^>]*>([^<]*)<\/p>/)?.[1];
    expect(citationParagraph).toBe('An unusually shaped citation with no point number.');
  });

  it('still shows the full data-version provenance sentence, unchanged, in the cover header', () => {
    // Guards against this fix accidentally touching the cover header's
    // separately-fixed, deliberately-full `cover__data-version` rendering.
    // (The footer's provenance line also carries the full dataVersion —
    // that's pre-existing behavior unrelated to this per-item-citation fix,
    // so this test only asserts the cover header still has it, not a global
    // occurrence count.)
    const dataVersion =
      '32024R2847 consolidated as 02024R2847-20241120 (EN), incorporating Corrigenda 1-3 (OJ L 90780 5.12.2024; ' +
      'OJ L 90555 2.7.2025; OJ L 90828 17.10.2025) -- verified none of the three corrigenda touch Annex V, Annex ' +
      'VII, or Articles 13/31/33. Supplementary source: BSI TR-03183-2 v2.1.0 (2025-08-20).';
    const content = makeContent({ provenance: makeProvenance({ dataVersion }) });
    const html = renderAnnexHtml(content);
    const coverStart = html.indexOf('class="cover"');
    const coverEnd = html.indexOf('</header>');
    expect(html.slice(coverStart, coverEnd)).toContain(dataVersion);
  });
});

describe('renderAnnexHtml — escaping', () => {
  it('escapes HTML-special characters in body text so a <script> value cannot execute', () => {
    const malicious = derivedSection({ body: ['<script>alert(1)</script> & "quoted"'] });
    const html = renderAnnexHtml(makeContent({ sections: [malicious], openItemCount: 0 }));
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&amp;');
    expect(html).toContain('&quot;quoted&quot;');
  });

  it('escapes HTML-special characters in the requirement summary and citation', () => {
    const malicious = derivedSection({
      requirementSummary: '<b>bold</b> & stuff',
      citation: 'Cites <i>Annex VII</i>',
    });
    const html = renderAnnexHtml(makeContent({ sections: [malicious], openItemCount: 0 }));
    expect(html).not.toContain('<b>bold</b>');
    expect(html).not.toContain('<i>Annex VII</i>');
    expect(html).toContain('&lt;b&gt;bold&lt;/b&gt;');
  });

  it('escapes a double quote in the full citation so it cannot break out of the title="" attribute', () => {
    const malicious = derivedSection({ citation: 'Annex VII, point 1(a). "><script>alert(1)</script>' });
    const html = renderAnnexHtml(makeContent({ sections: [malicious], openItemCount: 0 }));
    expect(html).not.toContain('title="Annex VII, point 1(a). ">');
    expect(html).toContain('&quot;&gt;&lt;script&gt;');
  });
});

describe('renderAnnexHtml — print CSS', () => {
  it('avoids splitting a requirement section across a page break, and declares no fixed page size', () => {
    const html = renderAnnexHtml(makeContent());
    expect(html).toContain('@media print');
    expect(html).toMatch(/\.req,\s*\.cover\s*\{[^}]*page-break-inside:\s*avoid/);
    expect(html).toContain('@page { margin');
    expect(html).not.toMatch(/@page[^}]*size\s*:/i);
    expect(html).toContain('body { font-size: 11pt; }');
    expect(html).toMatch(/\.page\s*\{[^}]*max-width:\s*170mm/);
  });

  it('ships no <script>, so there is nothing but CSS driving print behavior', () => {
    const html = renderAnnexHtml(makeContent());
    expect(html).not.toContain('<script');
  });
});
