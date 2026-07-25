import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { updateMechanismDetector } from '../../src/detect/updateMechanism';

const tmpDirs: string[] = [];

function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-updateMechanism-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('updateMechanismDetector', () => {
  it('reports id "update-mechanism"', () => {
    expect(updateMechanismDetector.id).toBe('update-mechanism');
  });

  it('finds .github/dependabot.yml and marks only dependabotPresent', () => {
    const dir = makeTmpDir();
    fs.mkdirSync(path.join(dir, '.github'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.github', 'dependabot.yml'), 'version: 2\nupdates: []\n');

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(true);
    expect(facts.renovatePresent).toBe(false);
  });

  it('finds .github/dependabot.yaml (the .yaml extension variant) too', () => {
    const dir = makeTmpDir();
    fs.mkdirSync(path.join(dir, '.github'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.github', 'dependabot.yaml'), 'version: 2\nupdates: []\n');

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(true);
    expect(facts.renovatePresent).toBe(false);
  });

  it('finds renovate.json and marks only renovatePresent', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'renovate.json'), '{"extends": ["config:base"]}\n');

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(false);
    expect(facts.renovatePresent).toBe(true);
  });

  it('finds .renovaterc and marks renovatePresent', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, '.renovaterc'), '{"extends": ["config:base"]}\n');

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(false);
    expect(facts.renovatePresent).toBe(true);
  });

  it('finds a "renovate" key embedded in package.json and marks renovatePresent', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ name: 'x', version: '1.0.0', renovate: { extends: ['config:base'] } }),
    );

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(false);
    expect(facts.renovatePresent).toBe(true);
  });

  it('does not mark renovatePresent when package.json exists but has no "renovate" key', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(false);
    expect(facts.renovatePresent).toBe(false);
  });

  it('reports both false when neither dependabot nor renovate config is present', () => {
    const dir = makeTmpDir();

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(false);
    expect(facts.renovatePresent).toBe(false);
  });

  it('detects both dependabot and renovate when both are present', () => {
    const dir = makeTmpDir();
    fs.mkdirSync(path.join(dir, '.github'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.github', 'dependabot.yml'), 'version: 2\nupdates: []\n');
    fs.writeFileSync(path.join(dir, 'renovate.json'), '{"extends": ["config:base"]}\n');

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(true);
    expect(facts.renovatePresent).toBe(true);
  });

  it('does not crash on a malformed package.json and treats it as no embedded renovate config', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'package.json'), '{ this is not valid JSON ');

    expect(() => updateMechanismDetector.run(dir)).not.toThrow();

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(false);
    expect(facts.renovatePresent).toBe(false);
  });

  it('still detects a standalone renovate.json file even when package.json is malformed', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'package.json'), '{ this is not valid JSON ');
    fs.writeFileSync(path.join(dir, 'renovate.json'), '{"extends": ["config:base"]}\n');

    const facts = updateMechanismDetector.run(dir);

    expect(facts.dependabotPresent).toBe(false);
    expect(facts.renovatePresent).toBe(true);
  });
});
