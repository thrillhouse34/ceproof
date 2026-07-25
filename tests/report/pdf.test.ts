// Real-environment tests: the actual installed browser (if any), the footer
// template, and genuine Chrome-driven renders. The cases that need a
// SIMULATED filesystem (platform gating, first-match-wins, the no-browser
// error) live in pdfNoBrowser.test.ts, which mocks `fs` wholesale.
//
// Real-Chrome-render gating mirrors licenseproof's original approach exactly:
// `findChromeExecutable()`'s real, unmodified result decides whether the
// browser-driven tests run or skip. A sandboxed/containerized CI runner with
// no browser at any standard OS install location (this one included) skips
// them explicitly rather than papering over a missing dependency — a
// legitimate environment-dependent test, not a flaky one. (Separately, this
// renderer WAS exercised end-to-end against Playwright's pre-installed
// Chromium at /opt/pw-browsers/chromium via a throwaway script during
// development — see the M2 completion notes — but that binary is not wired
// into this checked-in suite: doing so would require passing Chrome's
// `--no-sandbox` flag to satisfy this container's root user, which is a
// sandbox-specific workaround, not something that belongs in the shipped
// `findChromeExecutable`/`renderAnnexPdf` code path real users run.)
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { renderAnnexPdf, findChromeExecutable, buildFooterTemplate, NO_BROWSER_MESSAGE } from '../../src/report/pdf';
import { renderAnnexHtml } from '../../src/report/html';
import type { AnnexPackContent } from '../../src/report/annexContent';
import type { ProvenanceInfo } from '../../src/report/provenance';

// Whether THIS machine has a real browser. Every test that actually drives
// Chrome is gated on it, so the suite stays green (with an explicit skip,
// never a silent pass) on a machine or CI runner without one.
const CHROME = findChromeExecutable();

// Real browser launch + print is slower than a normal unit test (cold start
// can take several seconds), so the render tests get their own generous
// timeout rather than relying on the 20s global default.
const RENDER_TIMEOUT = 60_000;

function makeProvenance(overrides: Partial<ProvenanceInfo> = {}): ProvenanceInfo {
  return {
    toolVersion: '0.2.0',
    dataVersion: '2026.07.21',
    scanTimestamp: '2026-07-21T12:00:00.000Z',
    release: { kind: 'tag', value: 'v1.2.3', label: 'v1.2.3' },
    ...overrides,
  };
}

function makeContent(overrides: Partial<AnnexPackContent> = {}): AnnexPackContent {
  const sections = overrides.sections ?? [
    {
      id: 'annex7.1.b',
      requirementSummary: 'General description of the product.',
      citation: 'Regulation (EU) 2024/2847, Annex VII, point 1(b)',
      status: 'DERIVED' as const,
      body: ['Scan evidence: vcs.tag: "v1.2.3"'],
      isOpenItem: false,
    },
    {
      id: 'annex7.1.a',
      requirementSummary: 'Name and version of the product.',
      citation: 'Regulation (EU) 2024/2847, Annex VII, point 1(a)',
      status: 'NEEDS-HUMAN-INPUT' as const,
      body: [],
      isOpenItem: true,
    },
  ];
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

describe('findChromeExecutable', () => {
  it('returns undefined or a path that really exists on disk', () => {
    const found = findChromeExecutable();
    if (found === undefined) return; // no browser on this machine — a valid result
    expect(fs.existsSync(found)).toBe(true);
    expect(path.isAbsolute(found)).toBe(true);
  });
});

describe('NO_BROWSER_MESSAGE', () => {
  it('names Chrome, Chromium and Edge and points at the non-PDF format fallback', () => {
    // The message is a user-facing contract.
    expect(NO_BROWSER_MESSAGE).toContain('Chrome');
    expect(NO_BROWSER_MESSAGE).toContain('Chromium');
    expect(NO_BROWSER_MESSAGE).toContain('Edge');
    expect(NO_BROWSER_MESSAGE).toContain('--format annex7');
    expect(NO_BROWSER_MESSAGE).toContain('--format doc');
  });
});

describe('buildFooterTemplate', () => {
  it('renders the exact required provenance text with a live page-number span', () => {
    const footer = buildFooterTemplate(makeProvenance());

    // The literal required footer text: "ceproof <tool> · CRA data <data> · <timestamp> · page N".
    // `&middot;` is the HTML entity for the separator, and `pageNumber` is the
    // span Puppeteer substitutes the real per-page value into.
    expect(footer).toContain(
      'ceproof 0.2.0 &middot; CRA data 2026.07.21 &middot; 2026-07-21T12:00:00.000Z &middot; page ',
    );
    expect(footer).toContain('<span class="pageNumber"></span>');
  });

  it('sets an explicit font-size (Puppeteer footers default to an invisible size)', () => {
    // Without an explicit font-size the footer renders at effectively 0px and
    // is invisible in the output — a real, easy-to-regress Puppeteer gotcha.
    expect(buildFooterTemplate(makeProvenance())).toMatch(/font-size:\s*\d+px/);
  });

  it('escapes HTML-special characters in the provenance values', () => {
    const footer = buildFooterTemplate(makeProvenance({ toolVersion: '1.0<script>' }));
    expect(footer).toContain('1.0&lt;script&gt;');
    expect(footer).not.toContain('<script>');
  });
});

describe('renderAnnexPdf — real Chrome render', () => {
  it.skipIf(!CHROME)(
    'prints a synthetic pack end-to-end into a valid, multi-page A4 PDF',
    async () => {
      // A pack with many sections so the print genuinely spans multiple
      // pages — that's also what makes the per-page footer meaningful.
      const manySections = Array.from({ length: 20 }, (_, i) => ({
        id: `annex7.${i + 1}`,
        requirementSummary: `Synthetic requirement number ${i + 1}.`,
        citation: `Regulation (EU) 2024/2847, Annex VII, point ${i + 1}`,
        status: 'DERIVED' as const,
        body: [`Scan evidence line for item ${i + 1}.`, `Second paragraph of content for item ${i + 1}.`],
        isOpenItem: false,
      }));
      const content = makeContent({ sections: manySections, openItemCount: 0 });
      const pdf = await renderAnnexPdf(renderAnnexHtml(content), content);

      expect(Buffer.isBuffer(pdf)).toBe(true);

      // Valid PDF magic header + proper end-of-file marker.
      expect(pdf.subarray(0, 5).toString('latin1')).toBe('%PDF-');
      expect(pdf.subarray(-1024).toString('latin1')).toContain('%%EOF');

      // A real rendered document, not a stub.
      expect(pdf.length).toBeGreaterThan(10_000);

      // Plausible page count without a PDF-parsing dependency: the page
      // tree's /Count must be >= 2.
      const raw = pdf.toString('latin1');
      const count = raw.match(/\/Count\s+(\d+)/);
      expect(count, 'PDF declares a page count').not.toBeNull();
      expect(Number(count![1])).toBeGreaterThanOrEqual(2);

      // A4 is 595.28 x 841.89 pt — assert the MediaBox really is A4-sized
      // (proves format:'A4' took effect rather than defaulting to Letter).
      const mediaBox = raw.match(/\/MediaBox\s*\[\s*0\s+0\s+([\d.]+)\s+([\d.]+)\s*\]/);
      expect(mediaBox, 'PDF declares a MediaBox').not.toBeNull();
      expect(Math.round(Number(mediaBox![1]))).toBeGreaterThanOrEqual(595);
      expect(Math.round(Number(mediaBox![1]))).toBeLessThanOrEqual(596);
      expect(Math.round(Number(mediaBox![2]))).toBeGreaterThanOrEqual(841);
      expect(Math.round(Number(mediaBox![2]))).toBeLessThanOrEqual(842);
    },
    RENDER_TIMEOUT,
  );

  it.skipIf(!CHROME)(
    'produces a valid PDF for a pack with a single open item',
    async () => {
      const content = makeContent({
        sections: [
          {
            id: 'annex7.1.a',
            requirementSummary: 'Name and version of the product.',
            citation: 'Regulation (EU) 2024/2847, Annex VII, point 1(a)',
            status: 'NEEDS-HUMAN-INPUT',
            body: [],
            isOpenItem: true,
          },
        ],
        openItemCount: 1,
      });
      const pdf = await renderAnnexPdf(renderAnnexHtml(content), content);
      expect(pdf.subarray(0, 5).toString('latin1')).toBe('%PDF-');
      expect(pdf.length).toBeGreaterThan(1_000);
    },
    RENDER_TIMEOUT,
  );
});
