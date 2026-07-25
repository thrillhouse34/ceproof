import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { REPO_ROOT } from '../../src/paths';
import { getCraStructure } from '../../src/cra/loader';

// Doctrine, non-negotiable (see tests/cra/traceability.test.ts and
// tests/license/noPrivateKeyLeak.test.ts for the same doctrine applied
// elsewhere): a guard that isn't proven non-vacuous proves nothing about the
// next edit. This repo learned that lesson once already with verify-pack.sh,
// which ran as a one-off and was then discarded, so it never caught anything
// after the day it was written. This file is that lesson applied here.
//
// traceability.test.ts's "sourceExcerpt appears verbatim" check only proves
// item.sourceExcerpt occurs SOMEWHERE in the whole vendored source file. That
// is too weak: if two Annex points happen to share (or one's text is a
// substring of another's), an excerpt copy-pasted from the WRONG point would
// still satisfy `content.includes(item.sourceExcerpt)`. This file proves the
// stronger, actually-load-bearing property: item.sourceExcerpt falls within
// the text SPAN of the specific Annex point named by item's OWN citation, not
// just anywhere in the file.
//
// The vendored source (data/sources/celex-02024r2847-20241120-en.txt) marks
// Annex VII / Annex V points with dedicated marker lines: a line containing
// exactly "N." for a top-level point, optionally followed by lines containing
// exactly "(x)" for lettered sub-points (Annex VII points 1 and 2 only —
// Annex VII points 3-8 and all of Annex V are flat, no sub-points). A point's
// text span runs from directly after its marker line to directly before the
// next marker line (top-level or sub-point) or the next "ANNEX ..." heading,
// whichever comes first. This was verified by hand against the real file
// before writing this parser (see the corresponding review notes referenced
// in project history) — the parser below re-derives the same spans from the
// file itself, not from a copy of that manual review.

interface Marker {
  kind: 'top' | 'sub';
  value: string; // e.g. "1" for a top marker, "a" for a sub marker
  lineIndex: number; // index into the file's lines array of the marker line itself
}

interface AnnexIndex {
  markers: Marker[];
  boundEnd: number; // line index the last marker's span is bounded by (next ANNEX heading, or EOF)
}

const ANNEX_BOUNDS: Record<'VII' | 'V', { label: string; next: string }> = {
  VII: { label: 'ANNEX VII', next: 'ANNEX VIII' },
  V: { label: 'ANNEX V', next: 'ANNEX VI' },
};

const TOP_MARKER_RE = /^(\d+)\.$/;
const SUB_MARKER_RE = /^\(([a-z])\)$/;
const CITATION_RE = /Annex (VII|V), point (\d+)(?:\(([a-z])\))?/;

function parseCitationTarget(citation: string): { annex: 'VII' | 'V'; point: string; letter?: string } {
  const m = citation.match(CITATION_RE);
  if (!m) {
    throw new Error(`Could not parse Annex/point out of citation: "${citation}"`);
  }
  return { annex: m[1] as 'VII' | 'V', point: m[2], letter: m[3] };
}

function findAnnexBounds(lines: string[], annexLabel: string, nextAnnexLabel: string): { start: number; end: number } {
  const start = lines.findIndex((l) => l.trim() === annexLabel);
  if (start === -1) {
    throw new Error(`Could not find a line containing exactly "${annexLabel}" in the source file`);
  }
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].trim() === nextAnnexLabel) {
      end = i;
      break;
    }
  }
  return { start, end };
}

function collectMarkers(lines: string[], start: number, end: number): Marker[] {
  const markers: Marker[] = [];
  for (let i = start; i < end; i++) {
    const t = lines[i].trim();
    const topMatch = t.match(TOP_MARKER_RE);
    if (topMatch) {
      markers.push({ kind: 'top', value: topMatch[1], lineIndex: i });
      continue;
    }
    const subMatch = t.match(SUB_MARKER_RE);
    if (subMatch) {
      markers.push({ kind: 'sub', value: subMatch[1], lineIndex: i });
    }
  }
  return markers;
}

function buildAnnexIndex(lines: string[], annex: 'VII' | 'V'): AnnexIndex {
  const { label, next } = ANNEX_BOUNDS[annex];
  const { start, end } = findAnnexBounds(lines, label, next);
  return { markers: collectMarkers(lines, start, end), boundEnd: end };
}

// Locates the marker for `point`/`letter` within `index` and returns the
// text span it owns: everything from directly after its marker line to
// directly before the next marker line (of either kind) or the annex's end
// boundary, whichever comes first.
function spanFor(lines: string[], index: AnnexIndex, point: string, letter: string | undefined): string {
  const { markers, boundEnd } = index;
  const topIdx = markers.findIndex((m) => m.kind === 'top' && m.value === point);
  if (topIdx === -1) {
    throw new Error(`Could not find top-level marker line "${point}." in the annex`);
  }

  let targetIdx = topIdx;
  if (letter) {
    targetIdx = -1;
    for (let j = topIdx + 1; j < markers.length; j++) {
      if (markers[j].kind === 'top') break; // ran into the next top-level point first
      if (markers[j].kind === 'sub' && markers[j].value === letter) {
        targetIdx = j;
        break;
      }
    }
    if (targetIdx === -1) {
      throw new Error(`Could not find sub-point marker "(${letter})" nested under point "${point}."`);
    }
  }

  const marker = markers[targetIdx];
  const spanStartLine = marker.lineIndex + 1;
  const spanEndLine = targetIdx + 1 < markers.length ? markers[targetIdx + 1].lineIndex : boundEnd;
  return lines.slice(spanStartLine, spanEndLine).join('\n');
}

describe('CRA structure data — citation-to-source-span accuracy', () => {
  const structure = getCraStructure();

  // Caches keyed by resolved absolute file path (and, for annex indices,
  // additionally by annex label) so multi-item files are only read/parsed once.
  const lineCache = new Map<string, string[]>();
  const annexIndexCache = new Map<string, AnnexIndex>();

  function getLines(resolved: string): string[] {
    if (!lineCache.has(resolved)) {
      lineCache.set(resolved, fs.readFileSync(resolved, 'utf8').split('\n'));
    }
    return lineCache.get(resolved)!;
  }

  function getAnnexIndex(resolved: string, annex: 'VII' | 'V'): AnnexIndex {
    const key = `${resolved}|${annex}`;
    if (!annexIndexCache.has(key)) {
      annexIndexCache.set(key, buildAnnexIndex(getLines(resolved), annex));
    }
    return annexIndexCache.get(key)!;
  }

  it('every item citation names an Annex point that actually exists in its cited sourceFile', () => {
    // If this fails, either a citation typo'd its point/letter, or the marker
    // convention this parser assumes doesn't hold for that item's sourceFile
    // -- either way, that's a real problem worth surfacing before we even get
    // to comparing excerpts.
    const failures: string[] = [];
    for (const item of structure.items) {
      const resolved = path.join(REPO_ROOT, item.sourceFile);
      try {
        const target = parseCitationTarget(item.citation);
        const index = getAnnexIndex(resolved, target.annex);
        spanFor(getLines(resolved), index, target.point, target.letter);
      } catch (err) {
        failures.push(`${item.id}: ${(err as Error).message}`);
      }
    }
    expect(failures, failures.join('\n')).toEqual([]);
  });

  it('every item sourceExcerpt falls within the specific Annex point span its own citation names (not merely somewhere in the file)', () => {
    const failures: string[] = [];
    for (const item of structure.items) {
      const resolved = path.join(REPO_ROOT, item.sourceFile);
      const target = parseCitationTarget(item.citation);
      const index = getAnnexIndex(resolved, target.annex);
      let span: string;
      try {
        span = spanFor(getLines(resolved), index, target.point, target.letter);
      } catch {
        // Already reported by the previous test; skip here to avoid a
        // confusing double-failure on the same root cause.
        continue;
      }
      const pointLabel = `${target.annex} point ${target.point}${target.letter ? `(${target.letter})` : ''}`;
      if (!span.includes(item.sourceExcerpt)) {
        failures.push(`${item.id}: sourceExcerpt is not within the span of ${pointLabel} (it may belong to a different point)`);
      }
    }
    expect(failures, failures.join('\n')).toEqual([]);
  });

  describe('non-vacuity: span boundaries actually exclude neighboring points', () => {
    // Prove the span logic can't pass by accident (e.g. spans that are
    // secretly "the whole Annex"): pick adjacent points/sub-points that are
    // known to have distinct, non-overlapping real text, and assert neither
    // span contains the other's text. If this ever passed vacuously (spans
    // too wide), these checks would catch it even though every individual
    // item's sourceExcerpt might still look correct.
    const resolved = path.join(REPO_ROOT, 'data/sources/celex-02024r2847-20241120-en.txt');

    it('Annex VII point 1(a) span does not contain point 1(b) span text, and vice versa', () => {
      const index = getAnnexIndex(resolved, 'VII');
      const lines = getLines(resolved);
      const span1a = spanFor(lines, index, '1', 'a');
      const span1b = spanFor(lines, index, '1', 'b');
      expect(span1a.trim().length).toBeGreaterThan(0);
      expect(span1b.trim().length).toBeGreaterThan(0);
      expect(span1a.includes(span1b.trim())).toBe(false);
      expect(span1b.includes(span1a.trim())).toBe(false);
    });

    it('Annex VII point 2(b) span does not contain point 2(c) span text, and vice versa', () => {
      const index = getAnnexIndex(resolved, 'VII');
      const lines = getLines(resolved);
      const span2b = spanFor(lines, index, '2', 'b');
      const span2c = spanFor(lines, index, '2', 'c');
      expect(span2b.trim().length).toBeGreaterThan(0);
      expect(span2c.trim().length).toBeGreaterThan(0);
      expect(span2b.includes(span2c.trim())).toBe(false);
      expect(span2c.includes(span2b.trim())).toBe(false);
    });

    it('Annex VII point 7 span does not contain point 8 span text, and vice versa', () => {
      // Adjacent flat (non-lettered) top-level points, as a second shape of
      // boundary in addition to the lettered sub-point case above.
      const index = getAnnexIndex(resolved, 'VII');
      const lines = getLines(resolved);
      const span7 = spanFor(lines, index, '7', undefined);
      const span8 = spanFor(lines, index, '8', undefined);
      expect(span7.trim().length).toBeGreaterThan(0);
      expect(span8.trim().length).toBeGreaterThan(0);
      expect(span7.includes(span8.trim())).toBe(false);
      expect(span8.includes(span7.trim())).toBe(false);
    });

    it('Annex V point 2 span does not contain point 3 span text, and vice versa', () => {
      const index = getAnnexIndex(resolved, 'V');
      const lines = getLines(resolved);
      const span2 = spanFor(lines, index, '2', undefined);
      const span3 = spanFor(lines, index, '3', undefined);
      expect(span2.trim().length).toBeGreaterThan(0);
      expect(span3.trim().length).toBeGreaterThan(0);
      expect(span2.includes(span3.trim())).toBe(false);
      expect(span3.includes(span2.trim())).toBe(false);
    });

    it("a real sourceExcerpt from a DIFFERENT point would be rejected by this test's own logic", () => {
      // Direct proof that this file's core assertion (the second `it` above)
      // is not vacuous: annex7.1.b's real, verbatim sourceExcerpt is genuine
      // text from Annex VII point 1(b) -- it passes traceability.test.ts's
      // whole-file `content.includes(...)` check fine -- but it must NOT be
      // found within point 1(a)'s span, because it belongs to a different
      // point.
      const index = getAnnexIndex(resolved, 'VII');
      const lines = getLines(resolved);
      const span1a = spanFor(lines, index, '1', 'a');
      const annex7_1_b = structure.items.find((i) => i.id === 'annex7.1.b');
      expect(annex7_1_b).toBeDefined();
      expect(span1a.includes(annex7_1_b!.sourceExcerpt)).toBe(false);
    });
  });
});
