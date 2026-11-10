import { describe, it, expect } from 'vitest';
import { DISCLAIMER, FDA_DISCLAIMER } from '../../src/branding';
import { MANUFACTURER_SUPPLIED_COLUMNS } from '../../src/fda/kev';
import { renderFdaArtifacts } from '../../src/fda/render/artifacts';
import { comp, fixtureInput } from './renderFixture';

/**
 * The wording gate.
 *
 * Two different bans, and they fail for two different reasons:
 *
 *  - A REGULATORY claim ("FDA-approved", "compliant", "submission-ready") is a
 *    claim about the customer's filing. ceproof is in no position to make one,
 *    and a sales-sounding phrase that leaks into a generated artifact is the
 *    kind of thing that ends up quoted back at the customer by a reviewer.
 *  - An ASSESSMENT claim ("risk assessment performed", "not exploitable", "no
 *    risk") would say the tool did the one thing the guidance asks the
 *    manufacturer to do. The whole design of the KEV screen is that it
 *    identifies candidates and leaves the assessment blank; a renderer that
 *    implied otherwise would quietly undo that.
 *
 * Asserted against the RENDERED artifacts, not against the source, so a phrase
 * assembled at runtime out of harmless-looking fragments is caught too. Three
 * inputs are rendered — the awkward fixture, a run with nothing to report, and
 * a run against stale data — because the dangerous wording is most likely to
 * appear in the "nothing found" and "everything is fine" paths.
 */
const FORBIDDEN = [
  // Regulatory claims.
  /fda[-\s]approved/i,
  /\bcompliant\b/i,
  /\bcompliance\b/i,
  /submission[-\s]ready/i,
  /\bcertified\b/i,
  /\bcleared by\b/i,
  /meets (?:the )?fda/i,
  /satisfies (?:the )?fda/i,
  /refuse[-\s]to[-\s]accept/i,
  // Assessment claims.
  /risk assessment (?:was )?(?:performed|completed|carried out)/i,
  /\bwe assessed\b/i,
  /\bassessed as\b/i,
  /not exploitable/i,
  /\bno risk\b/i,
  /\bsafe to ship\b/i,
  /\bno known vulnerabilities\b/i,
];

const INPUTS = {
  'the awkward fixture': fixtureInput(),
  'a run with nothing to report': fixtureInput({ components: [comp({ name: 'nothing-matches-this', version: '1.0' })], sbomAuthor: 'Acme' }),
  'a run against stale data': fixtureInput({ asOf: '2027-06-01' }),
};

describe('no artifact may claim what this tool cannot claim', () => {
  for (const [label, input] of Object.entries(INPUTS)) {
    for (const artifact of renderFdaArtifacts(input)) {
      it(`${artifact.file} (${label}) contains no forbidden claim`, () => {
        for (const pattern of FORBIDDEN) {
          const match = artifact.contents.match(pattern);
          expect(match, `${artifact.file} contains the forbidden phrase "${match?.[0]}"`).toBeNull();
        }
      });
    }
  }
});

/**
 * The two CSVs are the one disclosed exception to "the disclaimer appears on
 * every user-facing output". CSV has no metadata channel: a leading or
 * trailing line of prose is a malformed row that breaks every parser and
 * shows up as a stray row in the spreadsheet the file exists to be opened in.
 * Every other artifact carries it — including the CycloneDX document, because
 * that format DOES have a place for it (`metadata.properties`). The CSVs are
 * working copies of tables that appear in full in fda-summary.md, which
 * carries the disclaimer in its header and again at its foot.
 *
 * The exception is also disclosed IN THE PACK, in DISCLAIMER.md, which names
 * both files and says why — so a customer holding only the output directory
 * learns it from the output rather than from this repo's test suite. The
 * rejected alternative was a repeated `disclaimer` column on every CSV row,
 * which repeats a fixed string thousands of times and makes the working copy
 * worse to work in without telling anyone anything new.
 */
const NO_PROSE_CHANNEL = ['fda-support-eol.csv', 'fda-vulnerabilities.csv'];

describe('every artifact carries the disclaimer', () => {
  for (const artifact of renderFdaArtifacts(fixtureInput()).filter((a) => !NO_PROSE_CHANNEL.includes(a.file))) {
    it(`${artifact.file} carries the standing disclaimer`, () => {
      expect(artifact.contents).toContain(DISCLAIMER);
    });
  }

  it('leaves out only the two CSVs, which have no channel for it', () => {
    const without = renderFdaArtifacts(fixtureInput())
      .filter((a) => !a.contents.includes(DISCLAIMER))
      .map((a) => a.file);
    expect(without).toEqual(NO_PROSE_CHANNEL);
  });

  it('discloses the exception inside the pack, naming both files, not only in this test suite', () => {
    const disclaimer = renderFdaArtifacts(fixtureInput()).find((a) => a.file === 'DISCLAIMER.md')!.contents;
    for (const file of NO_PROSE_CHANNEL) expect(disclaimer).toContain(file);
    expect(disclaimer).toContain('CSV has nowhere to put prose');
  });

  it('carries no disclaimer COLUMN in either CSV: the header set is the data, and nothing else', () => {
    // The rejected alternative to DISCLAIMER.md. Pinned so it cannot arrive by
    // accident — a fixed 32-character string repeated on every row of a
    // 5,000-row file is not a disclosure, it is noise in a working file.
    for (const file of NO_PROSE_CHANNEL) {
      const header = renderFdaArtifacts(fixtureInput()).find((a) => a.file === file)!.contents.split('\r\n')[0];
      expect(header.toLowerCase()).not.toContain('disclaimer');
    }
  });

  it('the human-readable documents carry the FDA-specific disclaimer in full, unmodified', () => {
    const artifacts = renderFdaArtifacts(fixtureInput());
    for (const file of ['fda-summary.md', 'fda-open-items.md', 'fda-provenance.json']) {
      const contents = artifacts.find((a) => a.file === file)!.contents;
      for (const line of FDA_DISCLAIMER) {
        // The provenance file is JSON, so the line is escaped there; compare
        // against the JSON-encoded form for that one.
        expect(contents.includes(line) || contents.includes(JSON.stringify(line).slice(1, -1))).toBe(true);
      }
    }
  });

  it('states that the pack supports but does not replace the manufacturer’s own review', () => {
    const summary = renderFdaArtifacts(fixtureInput()).find((a) => a.file === 'fda-summary.md')!.contents;
    expect(summary).toContain('It supports your own review of your premarket submission; it does not replace it.');
    expect(summary).toContain('has not been reviewed or endorsed by FDA or by CISA');
  });
});

describe('the two manufacturer-supplied columns', () => {
  it('appear verbatim, and are the guidance’s own two bullets rather than a paraphrase', () => {
    const artifacts = renderFdaArtifacts(fixtureInput());
    for (const file of ['fda-summary.md', 'fda-vulnerabilities.csv']) {
      const contents = artifacts.find((a) => a.file === file)!.contents;
      for (const column of MANUFACTURER_SUPPLIED_COLUMNS) expect(contents).toContain(column);
    }
  });

  it('never carry a value this tool produced', () => {
    const csv = renderFdaArtifacts(fixtureInput()).find((a) => a.file === 'fda-vulnerabilities.csv')!.contents;
    for (const line of csv.trim().split('\r\n').slice(1)) {
      expect(line.endsWith('NEEDS-HUMAN-INPUT,NEEDS-HUMAN-INPUT')).toBe(true);
    }
  });
});
