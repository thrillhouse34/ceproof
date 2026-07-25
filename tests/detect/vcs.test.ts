import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { vcsDetector } from '../../src/detect/vcs';

const tmpDirs: string[] = [];

function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-vcs-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** Runs a git command in `cwd`, throwing if it fails — test setup helper only. */
function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

/** Initializes a real git repo at `dir` with local user config and one commit. */
function initRepoWithCommit(dir: string): void {
  git(dir, ['init', '--initial-branch=main']);
  git(dir, ['config', 'user.email', 'test@example.com']);
  git(dir, ['config', 'user.name', 'Test User']);
  fs.writeFileSync(path.join(dir, 'README.md'), '# test repo\n');
  git(dir, ['add', 'README.md']);
  git(dir, ['commit', '-m', 'initial commit']);
}

describe('vcsDetector', () => {
  it('reports id "vcs"', () => {
    expect(vcsDetector.id).toBe('vcs');
  });

  it('degrades cleanly to isGitRepo:false with no throw for a non-git directory', () => {
    const dir = makeTmpDir();

    let facts;
    expect(() => {
      facts = vcsDetector.run(dir);
    }).not.toThrow();

    expect(facts).toEqual({ isGitRepo: false });
  });

  it('degrades cleanly to isGitRepo:false for a directory that does not exist', () => {
    const dir = path.join(os.tmpdir(), 'ceproof-vcs-does-not-exist-xyz');

    let facts;
    expect(() => {
      facts = vcsDetector.run(dir);
    }).not.toThrow();

    expect(facts).toEqual({ isGitRepo: false });
  });

  it('reports isGitRepo:true with commit and branch after a real init + commit', () => {
    const dir = makeTmpDir();
    initRepoWithCommit(dir);

    const facts = vcsDetector.run(dir);
    const expectedCommit = git(dir, ['rev-parse', 'HEAD']);

    expect(facts.isGitRepo).toBe(true);
    expect(facts.commit).toBe(expectedCommit);
    expect(facts.branch).toBe('main');
    expect(facts.dirty).toBe(false);
  });

  it('reports tagIsRealTag:false when the tag field is only the --always commit-hash fallback', () => {
    const dir = makeTmpDir();
    initRepoWithCommit(dir);

    const facts = vcsDetector.run(dir);

    // No real tag exists, so `describe --tags --always` falls back to the
    // abbreviated commit hash — `tag` is present, but must not be mistaken
    // for a human-meaningful release version.
    expect(facts.isGitRepo).toBe(true);
    expect(facts.tag).toBeDefined();
    expect(facts.tagIsRealTag).toBe(false);
  });

  it('surfaces the tag for a tagged commit, with tagIsRealTag:true', () => {
    const dir = makeTmpDir();
    initRepoWithCommit(dir);
    git(dir, ['tag', 'v1.2.3']);

    const facts = vcsDetector.run(dir);

    expect(facts.isGitRepo).toBe(true);
    expect(facts.tag).toBe('v1.2.3');
    expect(facts.tagIsRealTag).toBe(true);
  });

  it('reports dirty:true after an uncommitted change', () => {
    const dir = makeTmpDir();
    initRepoWithCommit(dir);
    fs.writeFileSync(path.join(dir, 'README.md'), '# test repo, modified\n');

    const facts = vcsDetector.run(dir);

    expect(facts.isGitRepo).toBe(true);
    expect(facts.dirty).toBe(true);
  });

  it('reports dirty:true for a new untracked file', () => {
    const dir = makeTmpDir();
    initRepoWithCommit(dir);
    fs.writeFileSync(path.join(dir, 'untracked.txt'), 'not added\n');

    const facts = vcsDetector.run(dir);

    expect(facts.isGitRepo).toBe(true);
    expect(facts.dirty).toBe(true);
  });
});
