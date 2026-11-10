import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR, REPO_ROOT } from '../../src/paths';
import { loadKevIndex, loadKevSnapshot } from '../../src/fda/kev';

/**
 * The licence gate for everything the FDA mode redistributes under data/.
 *
 * answer-1 Q4 cleared exactly four licences for this mode's vulnerability data:
 * CC0, CC-BY-4.0, MIT and Apache-2.0. That clearance is only worth anything if
 * something enforces it, and a comment in a build script is not something — the
 * build script could be edited, or a new upstream source could change its terms
 * between refreshes. So the assertion lives here, against the files that
 * actually ship.
 *
 * Two distinct things are checked, and both matter:
 *  1. every bundled dataset declares a licence inside the cleared set; and
 *  2. the repo-root NOTICE carries the attribution each of those licences
 *     requires. CC-BY-4.0 in particular requires attribution AND an indication
 *     that the material was modified — and ceproof ships distillations, not
 *     copies, of every one of them.
 *
 * tests/fda/kev.test.ts covers what the data MEANS. This file covers whether we
 * are allowed to ship it.
 */

const CLEARED_LICENCES = ['CC0-1.0', 'CC-BY-4.0', 'MIT', 'Apache-2.0'];

const NOTICE_PATH = path.join(REPO_ROOT, 'NOTICE');
const notice = fs.readFileSync(NOTICE_PATH, 'utf8');
/** NOTICE wraps at 76 columns, so a one-line attribution string appears in it across several lines. Compare on collapsed whitespace; everything else must still match character for character. */
const noticeFlat = notice.replace(/\s+/g, ' ');

describe('the bundled KEV catalogue snapshot', () => {
  const snapshot = loadKevSnapshot();

  it('declares a licence inside the cleared set', () => {
    expect(CLEARED_LICENCES).toContain(snapshot.source.license);
  });

  it('records where that licence can be read, so the claim is checkable rather than remembered', () => {
    expect(snapshot.source.licenseUrl).toMatch(/^https:\/\//);
  });

  it('is attributed in NOTICE, naming the file, the source and the licence', () => {
    expect(notice).toContain('data/kev-snapshot.json');
    expect(notice).toContain(snapshot.source.name);
    expect(notice).toContain(snapshot.source.license);
    expect(notice).toContain(snapshot.source.licenseUrl);
  });

  it('carries CISA’s no-endorsement condition into NOTICE, since that is a real constraint on how the data may be presented', () => {
    // CC0 asks for no attribution at all, so this is the part of CISA's licence
    // text that actually binds us: nothing may imply CISA or DHS endorsement.
    expect(notice).toContain('endorsement by CISA or DHS');
  });
});

describe('the bundled KEV ecosystem-advisory index', () => {
  const index = loadKevIndex();

  it('declares at least one source, and every one is inside the cleared set', () => {
    expect(index.sources.length).toBeGreaterThan(0);
    for (const source of index.sources) {
      expect(CLEARED_LICENCES, `${source.name} is licensed ${source.license}, which is not cleared for this mode`).toContain(source.license);
      expect(source.licenseUrl, `${source.name} has no licence URL`).toMatch(/^https:\/\//);
    }
  });

  it('states the modification CC-BY-4.0 requires us to indicate, for every CC-BY source', () => {
    const ccBy = index.sources.filter((s) => s.license === 'CC-BY-4.0');
    expect(ccBy.length).toBeGreaterThan(0);
    for (const source of ccBy) {
      expect(source.attribution, `${source.name} does not indicate that the material was modified`).toContain('Modified:');
    }
  });

  it('attributes every source in NOTICE, with its licence and the modification statement', () => {
    expect(notice).toContain('data/kev-index.json');
    for (const source of index.sources) {
      expect(notice, `${source.name} is not attributed in NOTICE`).toContain(source.name);
      expect(notice, `${source.name}'s licence URL is not in NOTICE`).toContain(source.licenseUrl);
      if (source.license === 'CC-BY-4.0') {
        expect(noticeFlat, `${source.name}'s modification statement is not in NOTICE`).toContain(source.attribution.replace(/\s+/g, ' '));
      }
    }
  });

  it('contains no entry whose advisory source is not one of the declared sources', () => {
    // The actual leak path: the build script filters by upstream database, so a
    // record from an uncleared database would arrive with an advisorySource that
    // no entry in `sources` accounts for. That is what this catches on the
    // shipped file, independently of the script that wrote it.
    const declared = new Set(index.sources.map((s) => s.name));
    for (const entry of index.entries) {
      expect(declared, `${entry.advisory} came from "${entry.advisorySource}", which is not a declared source`).toContain(entry.advisorySource);
    }
  });

  it('ships only package names and version ranges — no advisory prose that would carry more of the upstream work', () => {
    // The CC-BY attribution says the modification is that only names and ranges
    // are retained. If summaries, details or references ever start shipping, the
    // NOTICE statement becomes false, which is a licence problem and not just a
    // size one.
    const raw = fs.readFileSync(path.join(DATA_DIR, 'kev-index.json'), 'utf8');
    for (const field of ['"summary"', '"details"', '"references"', '"severity"', '"versions"', '"database_specific"']) {
      expect(raw, `${field} should not be in the vendored index`).not.toContain(field);
    }
  });
});

describe('NOTICE as the single record of everything data/ redistributes', () => {
  it('still accounts for the end-of-support snapshot that milestone 2 added', () => {
    // A guard against a future edit rewriting NOTICE around the new KEV entries
    // and dropping the MIT attribution the endoflife.date data requires.
    expect(notice).toContain('data/eol-snapshot.json');
    expect(notice).toContain('endoflife.date');
    expect(notice).toContain('MIT');
  });

  it('ships in the published package, because attribution that stays in the repo reaches nobody', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
    expect(pkg.files).toContain('NOTICE');
  });

  it('has an entry for every .json file bundled under data/ that came from a third party', () => {
    // The scar this guards against is the one in CLAUDE.md: a new file lands in
    // data/, nothing forces anyone to think about packaging or attribution, and
    // it ships unattributed. Anything added to data/ either gets a NOTICE entry
    // or gets added to this list with a reason.
    const ceproofsOwn = new Set([
      'manifest.json', // written by this repo
      'cra-structure.json', // this repo's own extraction of EU regulation text (not copyrightable as such)
      // This repo's own extraction of FDA guidance text — a US Government
      // work, not subject to domestic copyright. NOTICE still describes it,
      // under the data/sources/ entry, because the source it was extracted
      // from and the NTIA document it refers to both need naming.
      'fda-structure.json',
      'license-categories.json', // this repo's own classification
      'classifier-to-spdx.json', // this repo's own mapping
    ]);
    const bundled = fs
      .readdirSync(DATA_DIR)
      .filter((f) => f.endsWith('.json'))
      .filter((f) => !ceproofsOwn.has(f));
    expect(bundled.length).toBeGreaterThan(0);
    for (const file of bundled) {
      expect(notice, `data/${file} is bundled but has no NOTICE entry`).toContain(`data/${file}`);
    }
  });
});
