import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runtimesDetector } from '../../src/detect/runtimes';

const tmpDirs: string[] = [];

function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-runtimes-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('runtimesDetector', () => {
  it('reports id "runtimes"', () => {
    expect(runtimesDetector.id).toBe('runtimes');
  });

  it('reads engines.node from package.json when present', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', engines: { node: '>=18.0.0' } }));

    const facts = runtimesDetector.run(dir);

    expect(facts.node).toBe('>=18.0.0');
    expect(facts.python).toBeUndefined();
  });

  it('reads requires-python from pyproject.toml [project] when present', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'pyproject.toml'), '[project]\nname = "x"\nrequires-python = ">=3.10"\n');

    const facts = runtimesDetector.run(dir);

    expect(facts.python).toBe('>=3.10');
    expect(facts.node).toBeUndefined();
  });

  it('falls back to setup.cfg [options] python_requires when pyproject.toml does not declare requires-python', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(
      path.join(dir, 'setup.cfg'),
      '[metadata]\nname = x\n\n[options]\npackages = find:\npython_requires = >=3.8\n',
    );

    const facts = runtimesDetector.run(dir);

    expect(facts.python).toBe('>=3.8');
    expect(facts.node).toBeUndefined();
  });

  it('prefers pyproject.toml requires-python over setup.cfg python_requires when both are present', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'pyproject.toml'), '[project]\nname = "x"\nrequires-python = ">=3.11"\n');
    fs.writeFileSync(path.join(dir, 'setup.cfg'), '[options]\npython_requires = >=3.6\n');

    const facts = runtimesDetector.run(dir);

    expect(facts.python).toBe('>=3.11');
  });

  it('falls back to setup.cfg when pyproject.toml exists but has no [project] requires-python', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'pyproject.toml'), '[project]\nname = "x"\n');
    fs.writeFileSync(path.join(dir, 'setup.cfg'), '[options]\npython_requires = >=3.9\n');

    const facts = runtimesDetector.run(dir);

    expect(facts.python).toBe('>=3.9');
  });

  it('reports both node and python set when both are declared', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', engines: { node: '>=20' } }));
    fs.writeFileSync(path.join(dir, 'pyproject.toml'), '[project]\nname = "x"\nrequires-python = ">=3.12"\n');

    const facts = runtimesDetector.run(dir);

    expect(facts.node).toBe('>=20');
    expect(facts.python).toBe('>=3.12');
  });

  it('leaves both fields undefined (not a crash) when neither manifest is present', () => {
    const dir = makeTmpDir();

    let facts;
    expect(() => {
      facts = runtimesDetector.run(dir);
    }).not.toThrow();

    expect(facts).toEqual({});
  });

  it('leaves node undefined when package.json exists but has no engines.node', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x' }));

    const facts = runtimesDetector.run(dir);

    expect(facts.node).toBeUndefined();
  });

  it('leaves python undefined when setup.cfg exists but has no [options] python_requires', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'setup.cfg'), '[metadata]\nname = x\n');

    const facts = runtimesDetector.run(dir);

    expect(facts.python).toBeUndefined();
  });

  it('does not crash and returns {} for a project with neither package.json nor pyproject.toml/setup.cfg', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'README.md'), 'hello\n');

    let facts;
    expect(() => {
      facts = runtimesDetector.run(dir);
    }).not.toThrow();

    expect(facts).toEqual({});
  });

  it('does not crash for a directory that does not exist', () => {
    const dir = path.join(os.tmpdir(), 'ceproof-runtimes-does-not-exist-xyz');

    let facts;
    expect(() => {
      facts = runtimesDetector.run(dir);
    }).not.toThrow();

    expect(facts).toEqual({});
  });

  it('does not crash on malformed package.json and still reads python from pyproject.toml', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'package.json'), '{ not valid json');
    fs.writeFileSync(path.join(dir, 'pyproject.toml'), '[project]\nname = "x"\nrequires-python = ">=3.7"\n');

    const facts = runtimesDetector.run(dir);

    expect(facts.node).toBeUndefined();
    expect(facts.python).toBe('>=3.7');
  });
});
