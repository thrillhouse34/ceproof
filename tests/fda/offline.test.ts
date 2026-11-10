import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { REPO_ROOT } from '../../src/paths';

/**
 * The fully-offline doctrine, as a test instead of as a grep someone remembers
 * to run.
 *
 * Every milestone of the FDA mode has been checked by hand ("I grepped
 * src/fda/ to confirm no new code path touches https") and that is exactly the
 * kind of check that holds until the one session that forgets. The mode's whole
 * value proposition for a medical-device manufacturer is that it runs inside
 * their network and sends nothing anywhere; a single `fetch` in a renderer
 * would undo that silently, because a network call that succeeds looks like
 * nothing at all.
 *
 * The build-time scripts (scripts/fetch-*.ts, scripts/build-kev-index.ts) DO
 * fetch, by design — they are how the vendored snapshots are produced, they
 * never ship in the npm tarball, and nothing in src/ invokes them. They are
 * outside this test's scope on purpose.
 */
const NETWORK_PATTERNS: { pattern: RegExp; what: string }[] = [
  { pattern: /\bfetch\s*\(/, what: 'a fetch() call' },
  { pattern: /require\(\s*['"](https?|net|dns|tls|dgram|http2)['"]\s*\)/, what: 'a require of a network module' },
  { pattern: /from\s+['"](node:)?(https?|net|dns|tls|dgram|http2)['"]/, what: 'an import of a network module' },
  { pattern: /\bXMLHttpRequest\b/, what: 'an XMLHttpRequest' },
  { pattern: /\bnew WebSocket\b/, what: 'a WebSocket' },
  { pattern: /\baxios\b/, what: 'an HTTP client' },
  { pattern: /\bgot\s*\(/, what: 'an HTTP client' },
];

function sourceFiles(dir: string): string[] {
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) return sourceFiles(full);
      return entry.isFile() && entry.name.endsWith('.ts') ? [full] : [];
    });
}

describe('the FDA mode is fully offline at runtime', () => {
  const files = sourceFiles(path.join(REPO_ROOT, 'src', 'fda'));

  it('covers every file under src/fda, including the renderers', () => {
    // A test that silently stops finding files is worse than no test. These
    // two must be in the list for the assertion below to mean anything.
    expect(files.length).toBeGreaterThanOrEqual(10);
    expect(files.some((f) => f.endsWith(path.join('fda', 'kev.ts')))).toBe(true);
    expect(files.some((f) => f.includes(path.join('fda', 'render')))).toBe(true);
  });

  for (const file of files) {
    const relative = path.relative(REPO_ROOT, file);
    it(`${relative} makes no network call`, () => {
      const source = fs.readFileSync(file, 'utf8');
      for (const { pattern, what } of NETWORK_PATTERNS) {
        const match = source.match(pattern);
        expect(match, `${relative} appears to contain ${what}: "${match?.[0]}"`).toBeNull();
      }
    });
  }

  it('resolves every bundled dataset through DATA_DIR rather than an assembled path', () => {
    // importSbom.ts is the one file that reads a path the USER gave it — that
    // is its whole job. Everything else that reads a file in this mode is
    // reading a vendored snapshot, and a snapshot path assembled some other way
    // is how "bundled" data turns into data read out of someone's home
    // directory.
    const readsUserInput = path.join('fda', 'importSbom.ts');
    const readers = files.filter(
      (file) => !file.endsWith(readsUserInput) && /readFileSync/.test(fs.readFileSync(file, 'utf8')),
    );
    expect(readers.length).toBeGreaterThan(0);
    for (const file of readers) {
      expect(fs.readFileSync(file, 'utf8'), `${path.relative(REPO_ROOT, file)} reads a file without going through DATA_DIR`).toContain('DATA_DIR');
    }
  });
});
