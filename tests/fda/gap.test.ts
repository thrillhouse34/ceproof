import { describe, it, expect } from 'vitest';
import { computeFdaProfile } from '../../src/fda/gap';
import { buildFdaProfileJson, renderFdaProfileSummary, type FdaProfileRenderInput } from '../../src/fda/profile';
import { computeExitCode } from '../../src/cli/scan';
import { DISCLAIMER } from '../../src/branding';
import { ASOF, comp, fixtureComponents, fixtureInput } from './renderFixture';
import type { FdaRenderInput } from '../../src/fda/render/input';

const profileOf = (input: FdaRenderInput = fixtureInput()) => computeFdaProfile(input);
const statusOf = (id: string, input?: FdaRenderInput) => profileOf(input).items.find((i) => i.id === id)!.status;
const itemOf = (id: string, input?: FdaRenderInput) => profileOf(input).items.find((i) => i.id === id)!;

/**
 * The free FDA profile. Its whole value is that it is honest about what the
 * paid pack cannot do, so the tests that matter most are the ones asserting a
 * ceiling that no amount of good input can raise. A view that reads better the
 * less the tool finds would be worse than no view.
 */
describe('the permanent ceilings — statuses no input can improve', () => {
  // The best-case input this fixture can produce: every component declared,
  // named author, a full dependency graph.
  const best = () =>
    fixtureInput({
      sbomAuthor: 'Acme Medical Devices Inc.',
      components: [comp({ name: 'nothing-matches-this', version: '1.0', purl: 'pkg:npm/nothing@1.0', supplier: 'Acme', licenses: ['MIT'] })],
    });

  it('"identify ALL known vulnerabilities" is PARTIAL always, because this screens one catalogue', () => {
    expect(statusOf('fda.vuln.identify-all')).toBe('PARTIAL');
    expect(statusOf('fda.vuln.identify-all', best())).toBe('PARTIAL');
    expect(itemOf('fda.vuln.identify-all').evidence.join(' ')).toContain('never will read DERIVED here');
  });

  it('the risk assessment and the risk controls are NEEDS-HUMAN-INPUT always', () => {
    for (const id of ['fda.vuln.risk-assessment', 'fda.vuln.risk-controls']) {
      expect(statusOf(id)).toBe('NEEDS-HUMAN-INPUT');
      // Not even with zero findings: the manufacturer still has to assess the
      // vulnerabilities this screen did not find.
      expect(statusOf(id, best())).toBe('NEEDS-HUMAN-INPUT');
    }
  });

  it('the cyber-device determination is NEEDS-HUMAN-INPUT always — it is not a fact about components', () => {
    expect(statusOf('fda.cyber-device.524b')).toBe('NEEDS-HUMAN-INPUT');
    expect(statusOf('fda.cyber-device.524b', best())).toBe('NEEDS-HUMAN-INPUT');
  });

  it('zero KEV matches is PARTIAL, never DERIVED — nothing matched is not nothing is there', () => {
    expect(statusOf('fda.vuln.kev-designed-out', best())).toBe('PARTIAL');
    expect(itemOf('fda.vuln.kev-designed-out', best()).evidence.join(' ')).toContain('not the same statement as nothing being there');
    // With findings it becomes the manufacturer's to answer, not DERIVED either.
    expect(statusOf('fda.vuln.kev-designed-out')).toBe('NEEDS-HUMAN-INPUT');
  });
});

describe('the coverage-driven items move with the data', () => {
  it('support level reads PARTIAL when some components resolve and some do not', () => {
    expect(statusOf('fda.support.level')).toBe('PARTIAL');
    const evidence = itemOf('fda.support.level').evidence.join(' ');
    expect(evidence).toContain('a level of support that is not "unknown": 3 of 8');
    expect(evidence).toContain('declared by you');
  });

  it('reads NEEDS-HUMAN-INPUT when NOT ONE component resolved — never DERIVED on an empty answer', () => {
    const none = fixtureInput({ components: [comp({ name: 'unknown-thing', version: '9.9.9' })] });
    expect(statusOf('fda.support.level', none)).toBe('NEEDS-HUMAN-INPUT');
    expect(statusOf('fda.support.end-of-support-date', none)).toBe('NEEDS-HUMAN-INPUT');
  });

  it('reads DERIVED only when every component has the value', () => {
    const all = fixtureInput({
      components: [comp({ name: 'openssl', version: '1.1.1', cpe: 'cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*' })],
    });
    expect(statusOf('fda.support.level', all)).toBe('DERIVED');
    expect(statusOf('fda.support.end-of-support-date', all)).toBe('DERIVED');
  });

  it('counts the NTIA minimum elements per component and names the one that is missing', () => {
    const item = itemOf('fda.sbom.ntia-minimum-elements');
    expect(item.status).toBe('PARTIAL');
    const evidence = item.evidence.join('\n');
    expect(evidence).toContain('component name: all 8');
    expect(evidence).toContain('version: 7 of 8');
    expect(evidence).toContain('dependency relationship (in the source SBOM graph): 4 of 8');
    expect(evidence).toContain('author of SBOM data: NOT named');
  });

  it('will not read DERIVED on the minimum elements while the SBOM author is unnamed', () => {
    // Author of SBOM data is an NTIA minimum element and ceproof cannot know
    // it, so a complete-looking component list is still PARTIAL without it.
    const complete = { components: [comp({ name: 'a', version: '1', purl: 'pkg:npm/a@1', supplier: 'Acme', licenses: ['MIT'] })] };
    expect(statusOf('fda.sbom.ntia-minimum-elements', fixtureInput(complete))).toBe('PARTIAL');
  });

  it('states the justification gap only when there is something to justify', () => {
    // The fixture declares FreeRTOS unknown WITH a note, and leaves others
    // unknown with none.
    expect(statusOf('fda.sbom.justification-when-unavailable')).toBe('NEEDS-HUMAN-INPUT');
    const allKnown = fixtureInput({ components: [comp({ name: 'openssl', version: '1.1.1' })] });
    const item = itemOf('fda.sbom.justification-when-unavailable', allKnown);
    expect(item.status).toBe('DERIVED');
    expect(item.evidence.join(' ')).toContain('nothing to justify');
  });

  it('drops the KEV screen to PARTIAL when the bundled catalogue is stale, and names the refresh command', () => {
    expect(statusOf('fda.vuln.kev')).toBe('DERIVED');
    const stale = fixtureInput({ asOf: '2027-06-01' });
    expect(statusOf('fda.vuln.kev', stale)).toBe('PARTIAL');
    expect(itemOf('fda.vuln.kev', stale).evidence.join(' ')).toContain('npm run fetch-kev-snapshot');
  });

  it('reads NEEDS-HUMAN-INPUT on an empty component list rather than DERIVED on nothing', () => {
    // Guarded at the CLI by NoComponentsError, so this can only arise from a
    // caller bug — and the honest answer to "is an SBOM provided" for an empty
    // list is no, not yes.
    const empty = { ...fixtureInput(), support: { ...fixtureInput().support, results: [] } };
    const profile = computeFdaProfile(empty as FdaRenderInput, []);
    expect(profile.items.find((i) => i.id === 'fda.sbom.provided')!.status).toBe('NEEDS-HUMAN-INPUT');
    expect(profile.items.find((i) => i.id === 'fda.sbom.provided')!.evidence.join(' ')).toContain('--sbom');
  });
});

describe('the counts block, which is what makes the problem concrete', () => {
  it('reports what the run found, matching the engines rather than recomputing them', () => {
    const { counts } = profileOf();
    expect(counts.components).toBe(8);
    expect(counts.confirmed).toBe(1);
    expect(counts.possible).toBe(3);
    expect(counts.notAffected).toBe(1);
    expect(counts.inDependencyGraph).toBe(4);
    expect(counts.openItems).toBeGreaterThan(0);
  });

  it('names the number of open items the paid pack would list, so the free view is an honest preview', () => {
    const { counts } = profileOf();
    const summary = renderFdaProfileSummary(renderInput(), false);
    expect(summary).toContain(`open items the paid pack would list: ${counts.openItems}`);
  });
});

function renderInput(input: FdaRenderInput = fixtureInput()): FdaProfileRenderInput {
  const profile = computeFdaProfile(input);
  return {
    profile,
    toolVersion: input.toolVersion,
    generatedAt: input.generatedAt,
    asOf: input.asOf,
    ...(input.subject ? { device: { name: input.subject.name, ...(input.subject.version ? { version: input.subject.version } : {}) } } : {}),
    ...(input.sbomAuthor ? { sbomAuthor: input.sbomAuthor } : {}),
    sboms: input.sbomInputs.map((s) => ({ sourceLabel: s.sourceLabel, specVersion: s.specVersion, componentCount: s.componentCount })),
    fdaData: {
      eolSnapshotGeneratedAt: input.support.snapshotSource.upstreamGeneratedAt,
      eolSnapshotSha256: input.support.snapshotSource.upstreamSha256,
      kevCatalogVersion: input.kev.snapshotSource.catalogVersion,
      kevSnapshotReleased: input.kev.snapshotSource.dateReleased,
      osvQueriedAt: input.kev.indexBuiltFrom.osvQueriedAt,
    },
    limits: input.kev.limits,
  };
}

describe('the two output surfaces', () => {
  it('the terminal summary carries the disclaimer, the counts, the items and the limits', () => {
    const summary = renderFdaProfileSummary(renderInput(), false);
    expect(summary).toContain(DISCLAIMER);
    expect(summary).toContain('13 FDA SBOM content items checked');
    expect(summary).toContain('[NEEDS-HUMAN-INPUT] fda.vuln.risk-assessment');
    expect(summary).toContain('What this view does not cover');
    // The screen's own limits travel with the view, not only with the pack.
    expect(summary).toContain('CISA Known Exploited Vulnerabilities Catalog only');
  });

  it('keeps the 500-character guidance citation out of the terminal header, and the short one in it', () => {
    const summary = renderFdaProfileSummary(renderInput(), false);
    const header = summary.split('\n').slice(0, 4);
    for (const line of header) expect(line.length, `header line too long: ${line}`).toBeLessThanOrEqual(90);
    expect(header[2]).toBe('Guidance: FDA premarket cybersecurity guidance, February 3, 2026');
    // The full version belongs on the machine-readable surface, which is where
    // the docket number and the superseded-edition note are actually useful.
    expect(summary).not.toContain('GUI00001825');
    expect(buildFdaProfileJson(renderInput()).structureVersion).toContain('GUI00001825');
  });

  it('names the paid command once, at the foot, without quoting a price that could go stale', () => {
    const summary = renderFdaProfileSummary(renderInput(), false);
    expect(summary).toContain('report --format fda-pack');
    expect(summary).not.toMatch(/\$\d/);
  });

  it('the JSON carries the same statuses, counts and dataset identifiers as the terminal view', () => {
    const json = buildFdaProfileJson(renderInput());
    expect(json.schemaVersion).toBe(1);
    expect(json.profile).toBe('fda');
    expect(json.asOf).toBe(ASOF);
    expect(json.items.map((i) => i.status)).toEqual(profileOf().items.map((i) => i.status));
    expect(json.counts).toEqual(profileOf().counts);
    expect(json.fdaData.kevCatalogVersion).toBe('2026.10.20');
    expect(json.disclaimer).toBe(DISCLAIMER);
    // Every item says which metric produced it, so two items with the same
    // status are distinguishable in a machine-read pipeline.
    expect(json.items.every((i) => typeof i.measure === 'string')).toBe(true);
  });

  it('leaves the SBOM author out of the JSON rather than naming the tool, when nobody named it', () => {
    expect(buildFdaProfileJson(renderInput()).sbomAuthor).toBeUndefined();
    expect(buildFdaProfileJson(renderInput(fixtureInput({ sbomAuthor: 'Acme' }))).sbomAuthor).toBe('Acme');
  });

  it('is deterministic: the same input renders byte-identically twice', () => {
    expect(JSON.stringify(buildFdaProfileJson(renderInput()))).toBe(JSON.stringify(buildFdaProfileJson(renderInput())));
  });
});

describe('--fail-on over the FDA items', () => {
  const items = () => profileOf().items;

  it('honours the same three thresholds the CRA profile does', () => {
    expect(computeExitCode(items(), 'human-required')).toBe(1);
    expect(computeExitCode(items(), 'partial')).toBe(1);
    expect(computeExitCode(items(), 'never')).toBe(0);
  });

  it('never exits 0 on --fail-on human-required, because three items are permanently human', () => {
    // Deliberate: the risk assessment, the risk controls and the cyber-device
    // determination can never be answered by this tool, so this threshold
    // always reads exit 1 on this profile no matter how good the SBOM is.
    // Which is WHY this profile's default is report-only (`never`) rather
    // than the CRA default — see DEFAULT_FAIL_ON in src/cli/scan.ts and the
    // exit-code tests in tests/cli/fdaGating.test.ts. Asking for this
    // threshold here is opting in to a build that always fails.
    const best = fixtureInput({ sbomAuthor: 'Acme', components: [comp({ name: 'openssl', version: '1.1.1' })] });
    expect(computeExitCode(computeFdaProfile(best).items, 'human-required')).toBe(1);
  });
});

describe('the forbidden wording applies to the free view too', () => {
  // The same bans tests/fda/forbiddenClaims.test.ts enforces on the paid
  // artifacts. A sales-sounding phrase is MORE likely here, because this
  // surface exists partly to sell the pack.
  const FORBIDDEN = [
    /fda[-\s]approved/i,
    /\bcompliant\b/i,
    /\bcompliance\b/i,
    /submission[-\s]ready/i,
    /\bcertified\b/i,
    /meets (?:the )?fda/i,
    /refuse[-\s]to[-\s]accept/i,
    /risk assessment (?:was )?(?:performed|completed|carried out)/i,
    /\bassessed as\b/i,
    /not exploitable/i,
    /\bno risk\b/i,
    /\bno known vulnerabilities\b/i,
  ];

  for (const [label, input] of Object.entries({
    'the awkward fixture': fixtureInput(),
    'a run with nothing to report': fixtureInput({ components: [comp({ name: 'nothing-matches-this', version: '1.0' })] }),
    'a run against stale data': fixtureInput({ asOf: '2027-06-01' }),
    'a complete-looking run': fixtureInput({ sbomAuthor: 'Acme', components: fixtureComponents() }),
  })) {
    it(`${label}: neither surface claims what this tool cannot claim`, () => {
      const rendered = renderFdaProfileSummary(renderInput(input), false) + JSON.stringify(buildFdaProfileJson(renderInput(input)));
      for (const pattern of FORBIDDEN) {
        const match = rendered.match(pattern);
        expect(match, `contains the forbidden phrase "${match?.[0]}"`).toBeNull();
      }
    });
  }
});
