import { describe, it, expect } from 'vitest';
import { renderSummary } from '../../src/report/summary';
import type { GapChecklistItem } from '../../src/gap/types';

// Gap-checklist terminal renderer tests, using synthetic GapChecklistItem
// fixtures constructed inline — never depending on the real (currently
// placeholder) data/cra-structure.json's exact content, since that's liable
// to change once real CRA sources land.

function item(overrides: Partial<GapChecklistItem>): GapChecklistItem {
  return {
    id: 'annex7.1.a',
    instrument: 'annexVII',
    status: 'DERIVED',
    requirementSummary: 'A synthetic test requirement.',
    citation: 'Regulation (EU) 2024/2847, Annex VII, point 1(a)',
    evidence: ['some evidence line'],
    ...overrides,
  };
}

function baseInput(overrides: Partial<Parameters<typeof renderSummary>[0]> = {}) {
  return {
    projectName: 'my-app',
    toolVersion: '0.1.0',
    dataVersion: '2026.07.24',
    scanTimestamp: '2026-07-24T00:00:00.000Z',
    gapChecklist: [] as GapChecklistItem[],
    configPresent: false,
    colorEnabled: false,
    ...overrides,
  };
}

describe('renderSummary', () => {
  it('header includes product name, project name, tool version, data version, scan timestamp, and the disclaimer', () => {
    const output = renderSummary(baseInput());
    expect(output).toContain('ceproof scan: my-app');
    expect(output).toContain('0.1.0');
    expect(output).toContain('2026.07.24');
    expect(output).toContain('2026-07-24T00:00:00.000Z');
    expect(output.toLowerCase()).toContain('not legal advice');
  });

  it('states honest counts of derived/partial/needs-human-input items', () => {
    const output = renderSummary(
      baseInput({
        gapChecklist: [
          item({ id: 'a', status: 'DERIVED' }),
          item({ id: 'b', status: 'PARTIAL' }),
          item({ id: 'c', status: 'NEEDS-HUMAN-INPUT' }),
          item({ id: 'd', status: 'NEEDS-HUMAN-INPUT' }),
        ],
      }),
    );
    expect(output).toContain('4 CRA items checked');
    expect(output).toContain('1 derived');
    expect(output).toContain('1 partial');
    expect(output).toContain('2 needs human input');
  });

  it('singularizes the count line for exactly one item', () => {
    const output = renderSummary(baseInput({ gapChecklist: [item({})] }));
    expect(output).toContain('1 CRA item checked');
  });

  it('groups items under their instrument section', () => {
    const output = renderSummary(
      baseInput({
        gapChecklist: [
          item({ id: 'annex7.1.a', instrument: 'annexVII' }),
          item({ id: 'annex5.1.a', instrument: 'annexV' }),
        ],
      }),
    );
    expect(output).toContain('Annex VII');
    expect(output).toContain('Annex V —');
    const vii = output.indexOf('Annex VII');
    // "Annex V" is a substring of "Annex VII" — search for the disambiguated
    // "Annex V —" heading text, and only after the Annex VII section starts.
    const v = output.indexOf('Annex V —', vii);
    expect(output.slice(vii, v)).toContain('annex7.1.a');
  });

  it('omits an instrument section entirely when it has no items', () => {
    const output = renderSummary(baseInput({ gapChecklist: [item({ instrument: 'annexVII' })] }));
    expect(output).not.toContain('Annex V —');
  });

  it('renders each item with its id, requirement summary, trimmed citation, and evidence lines', () => {
    const output = renderSummary(
      baseInput({
        gapChecklist: [
          item({
            id: 'annex7.9.z',
            requirementSummary: 'A very specific requirement text.',
            citation: 'Regulation (EU) 2024/2847, Annex VII, point 9(z)',
            evidence: ['git tag v1.2.3 detected', 'SECURITY.md present at repo root'],
          }),
        ],
      }),
    );
    expect(output).toContain('annex7.9.z');
    expect(output).toContain('A very specific requirement text.');
    // The item-specific tail is kept...
    expect(output).toContain('Annex VII, point 9(z)');
    // ...but the shared "Regulation (EU) 2024/2847," preamble is NOT repeated
    // per item — it belongs on the header/provenance line instead (see the
    // "citation rendering" describe block below).
    expect(output).not.toContain('Regulation (EU) 2024/2847, Annex VII, point 9(z)');
    expect(output).toContain('git tag v1.2.3 detected');
    expect(output).toContain('SECURITY.md present at repo root');
  });

  it('shows all three status labels distinctly', () => {
    const output = renderSummary(
      baseInput({
        gapChecklist: [
          item({ id: 'a', status: 'DERIVED' }),
          item({ id: 'b', status: 'PARTIAL' }),
          item({ id: 'c', status: 'NEEDS-HUMAN-INPUT' }),
        ],
      }),
    );
    expect(output).toContain('DERIVED');
    expect(output).toContain('PARTIAL');
    expect(output).toContain('NEEDS-HUMAN-INPUT');
  });

  it('suggests "ceproof init" when no config is present and human input is needed', () => {
    const output = renderSummary(
      baseInput({ configPresent: false, gapChecklist: [item({ status: 'NEEDS-HUMAN-INPUT' })] }),
    );
    expect(output).toContain('ceproof init');
  });

  it('notes remaining unanswered items when a config IS present but incomplete', () => {
    const output = renderSummary(
      baseInput({ configPresent: true, gapChecklist: [item({ status: 'NEEDS-HUMAN-INPUT' })] }),
    );
    expect(output.toLowerCase()).toContain('still need an answer');
    expect(output).not.toContain('ceproof init');
  });

  it('prints no follow-up note when everything is derived', () => {
    const output = renderSummary(baseInput({ configPresent: false, gapChecklist: [item({ status: 'DERIVED' })] }));
    expect(output).not.toContain('ceproof init');
    expect(output.toLowerCase()).not.toContain('still need an answer');
  });

  it('respects colorEnabled: false — no ANSI escape codes anywhere', () => {
    const output = renderSummary(baseInput({ gapChecklist: [item({})], colorEnabled: false }));
    // eslint-disable-next-line no-control-regex
    expect(output).not.toMatch(/\x1b\[/);
  });

  it('emits ANSI codes when colorEnabled: true', () => {
    const output = renderSummary(baseInput({ gapChecklist: [item({})], colorEnabled: true }));
    // eslint-disable-next-line no-control-regex
    expect(output).toMatch(/\x1b\[/);
  });

  it('contains zero emoji characters', () => {
    const output = renderSummary(baseInput({ gapChecklist: [item({})], colorEnabled: true }));
    // eslint-disable-next-line no-misleading-character-class
    expect(output).not.toMatch(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u);
  });

  it('wraps long requirement summaries and evidence lines instead of overflowing 80 columns', () => {
    const output = renderSummary(
      baseInput({
        gapChecklist: [
          item({
            requirementSummary:
              'A deliberately very long requirement summary sentence designed to exceed eighty columns of terminal width when rendered on a single line without any wrapping applied at all.',
            evidence: [
              'A deliberately very long evidence line describing exactly what was checked and why it did or did not resolve, also exceeding eighty columns on its own.',
            ],
          }),
        ],
      }),
    );
    for (const line of output.split('\n')) expect(line.length).toBeLessThanOrEqual(80);
  });

  describe('citation and data-version rendering (signal-to-noise fix)', () => {
    // Shaped exactly like the real data/cra-structure.json sourceVersion /
    // item.citation strings (see getCraSourceVersion() and
    // src/report/provenance.ts's shortDataVersion()), without depending on
    // the real file's exact wording — a synthetic fixture in the same shape.
    const REAL_SHAPED_DATA_VERSION =
      '32024R2847 consolidated as 02024R2847-20241120 (EN), incorporating Corrigenda 1-3 (OJ L 90780 5.12.2024; ' +
      'OJ L 90555 2.7.2025; OJ L 90828 17.10.2025) -- verified none of the three corrigenda touch Annex V, Annex ' +
      'VII, or Articles 13/31/33. Supplementary source: BSI TR-03183-2 v2.1.0 (2025-08-20).';
    const REAL_SHAPED_PREAMBLE =
      'Regulation (EU) 2024/2847 (Cyber Resilience Act), consolidated text 02024R2847-20241120 ' +
      '(base act + Corrigenda 1-3, none of which touch Annex V, Annex VII, or Articles 13/31/33), ';

    // wrapAt80 (the "M1 wrapping bug" guard) inserts newlines at word
    // boundaries, so a multi-word phrase that happens to straddle an
    // 80-column wrap point won't appear as one literal substring even though
    // all its words are present and in order. Collapse wrapped whitespace
    // back to single spaces before checking for such phrases — content
    // presence, not raw line layout, is what these tests care about.
    function unwrap(output: string): string {
      return output.replace(/\n\s*/g, ' ');
    }

    it('header line shows only the short data identifier, not the full consolidation sentence', () => {
      const output = renderSummary(baseInput({ dataVersion: REAL_SHAPED_DATA_VERSION, gapChecklist: [] }));
      const headerLine = output.split('\n')[1];
      expect(headerLine).toContain('02024R2847-20241120');
      expect(headerLine).not.toContain('Corrigenda');
      expect(headerLine).not.toContain('BSI TR-03183-2');
    });

    it('states the full data-version detail exactly once, elsewhere in the output', () => {
      const output = renderSummary(baseInput({ dataVersion: REAL_SHAPED_DATA_VERSION, gapChecklist: [] }));
      const occurrences = unwrap(output).split('Supplementary source: BSI TR-03183-2').length - 1;
      expect(occurrences).toBe(1);
      expect(unwrap(output)).toContain('incorporating Corrigenda 1-3');
    });

    it('per-item citation drops the shared preamble but keeps the item-specific instrument/point', () => {
      const output = renderSummary(
        baseInput({
          dataVersion: REAL_SHAPED_DATA_VERSION,
          gapChecklist: [
            item({ id: 'annex7.3', citation: `${REAL_SHAPED_PREAMBLE}Annex VII, point 3.` }),
          ],
        }),
      );
      expect(output).toContain('Annex VII, point 3.');
      expect(output).not.toContain(REAL_SHAPED_PREAMBLE);
      expect(output).not.toContain('base act + Corrigenda');
    });

    it('does not repeat the shared preamble once per item across many items', () => {
      const items = ['1(a)', '1(b)', '2(a)', '3', '4'].map((point, i) =>
        item({ id: `annex7.${i}`, citation: `${REAL_SHAPED_PREAMBLE}Annex VII, point ${point}.` }),
      );
      const output = renderSummary(baseInput({ dataVersion: REAL_SHAPED_DATA_VERSION, gapChecklist: items }));
      const occurrences = output.split('Regulation (EU) 2024/2847 (Cyber Resilience Act)').length - 1;
      expect(occurrences).toBe(0);
    });

    it('preserves a genuinely item-specific "See also" BSI cross-reference (e.g. annex7.8-style items)', () => {
      const seeAlso =
        'Annex VII, point 8. See also BSI TR-03183-2 v2.1.0 section 4 (SBOM format: CycloneDX >=1.6 or ' +
        'SPDX >=3.0.1 required) and section 5.2.2 (required component fields, including licence information).';
      const output = renderSummary(
        baseInput({
          dataVersion: REAL_SHAPED_DATA_VERSION,
          gapChecklist: [item({ id: 'annex7.8', citation: `${REAL_SHAPED_PREAMBLE}${seeAlso}` })],
        }),
      );
      expect(unwrap(output)).toContain('See also BSI TR-03183-2 v2.1.0 section 4');
      expect(unwrap(output)).toContain('required component fields, including licence information');
    });

    it('falls back to the full citation unchanged when the expected "Annex X, point N" shape is absent', () => {
      const output = renderSummary(
        baseInput({ gapChecklist: [item({ citation: 'An unusually shaped citation with no point number.' })] }),
      );
      expect(output).toContain('An unusually shaped citation with no point number.');
    });

    it('falls back to the full data version unchanged on the header line when "consolidated as X" is absent', () => {
      const output = renderSummary(baseInput({ dataVersion: 'some-unrecognized-format', gapChecklist: [] }));
      expect(output.split('\n')[1]).toContain('some-unrecognized-format');
    });

    it('80-column wrapping still holds for the new full-data-version detail line', () => {
      const output = renderSummary(baseInput({ dataVersion: REAL_SHAPED_DATA_VERSION, gapChecklist: [] }));
      for (const line of output.split('\n')) expect(line.length).toBeLessThanOrEqual(80);
    });
  });
});
