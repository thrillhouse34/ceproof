import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { collectRepoFacts } from '../../src/detect/index';

const REPO_ROOT = path.join(__dirname, '..', '..');

const tmpDirs: string[] = [];

function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-detect-index-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('collectRepoFacts', () => {
  it('assembles plausible facts against this repo\'s own root', () => {
    const facts = collectRepoFacts(REPO_ROOT);

    // ecosystems: this repo is an npm project.
    expect(facts.ecosystems.detected).toContain('npm');

    // vcs: this repo is a real git working tree with commits.
    expect(facts.vcs.isGitRepo).toBe(true);
    expect(facts.vcs.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(typeof facts.vcs.dirty).toBe('boolean');

    // projectLicense: repo root carries a LICENSE file.
    expect(facts.projectLicense.rootLicenseFilePresent).toBe(true);
    expect(facts.projectLicense.rootLicenseFilePath).toBeTruthy();

    // runtimes: package.json declares an engines.node constraint, or is
    // honestly absent — either way this must not throw and must be a
    // string when present.
    if (facts.runtimes.node !== undefined) {
      expect(typeof facts.runtimes.node).toBe('string');
    }

    // security / updateMechanism: shape sanity (presence facts are booleans,
    // paths is always an array, never a missing key).
    expect(typeof facts.security.securityMdPresent).toBe('boolean');
    expect(typeof facts.security.securityTxtPresent).toBe('boolean');
    expect(typeof facts.security.vulnDisclosurePolicyPresent).toBe('boolean');
    expect(Array.isArray(facts.security.paths)).toBe(true);
    expect(typeof facts.updateMechanism.dependabotPresent).toBe('boolean');
    expect(typeof facts.updateMechanism.renovatePresent).toBe('boolean');
  });

  it('degrades cleanly against a bare empty temp dir, never throws', () => {
    const dir = makeTmpDir();

    let facts;
    expect(() => {
      facts = collectRepoFacts(dir);
    }).not.toThrow();

    expect(facts).toBeDefined();
    const f = facts!;

    expect(f.ecosystems.detected).toEqual([]);
    expect(f.vcs).toEqual({ isGitRepo: false });
    expect(f.projectLicense.rootLicenseFilePresent).toBe(false);
    expect(f.projectLicense.rootLicenseFilePath).toBeUndefined();
    expect(f.projectLicense.declaredLicenseId).toBeUndefined();
    expect(f.runtimes).toEqual({});
    expect(f.security).toEqual({
      securityMdPresent: false,
      securityTxtPresent: false,
      vulnDisclosurePolicyPresent: false,
      paths: [],
    });
    expect(f.updateMechanism).toEqual({
      dependabotPresent: false,
      renovatePresent: false,
    });
  });
});
