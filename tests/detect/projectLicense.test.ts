import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { projectLicenseDetector } from '../../src/detect/projectLicense';

describe('projectLicenseDetector', () => {
  let scratch: string;

  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-project-license-'));
  });

  afterEach(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  describe('root license file detection', () => {
    it('reports rootLicenseFilePresent + rootLicenseFilePath when LICENSE is present', () => {
      fs.writeFileSync(path.join(scratch, 'LICENSE'), 'MIT License text');
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.rootLicenseFilePresent).toBe(true);
      expect(facts.rootLicenseFilePath).toBe('LICENSE');
    });

    it('recognizes LICENSE.md, LICENSE.txt, COPYING, and COPYING.md', () => {
      const variants = ['LICENSE.md', 'LICENSE.txt', 'COPYING', 'COPYING.md'];
      for (const name of variants) {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-project-license-'));
        fs.writeFileSync(path.join(dir, name), 'license text');
        const facts = projectLicenseDetector.run(dir);
        expect(facts.rootLicenseFilePresent).toBe(true);
        expect(facts.rootLicenseFilePath).toBe(name);
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it('matches license filenames case-insensitively, preserving the on-disk casing', () => {
      fs.writeFileSync(path.join(scratch, 'license.md'), 'license text');
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.rootLicenseFilePresent).toBe(true);
      expect(facts.rootLicenseFilePath).toBe('license.md');
    });

    it('reports rootLicenseFilePresent: false and no path when no license file exists', () => {
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.rootLicenseFilePresent).toBe(false);
      expect(facts.rootLicenseFilePath).toBeUndefined();
    });

    it('does not crash on an empty/nonexistent directory', () => {
      const missing = path.join(scratch, 'does-not-exist');
      expect(() => projectLicenseDetector.run(missing)).not.toThrow();
      const facts = projectLicenseDetector.run(missing);
      expect(facts.rootLicenseFilePresent).toBe(false);
    });
  });

  describe('declared license id', () => {
    it('reads declaredLicenseId from package.json alone', () => {
      fs.writeFileSync(path.join(scratch, 'package.json'), JSON.stringify({ name: 'x', license: 'MIT' }));
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.declaredLicenseId).toBe('MIT');
    });

    it('reads declaredLicenseId from pyproject.toml alone (PEP 621 string form)', () => {
      fs.writeFileSync(path.join(scratch, 'pyproject.toml'), '[project]\nname = "x"\nlicense = "Apache-2.0"\n');
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.declaredLicenseId).toBe('Apache-2.0');
    });

    it('reads declaredLicenseId from pyproject.toml table form (license = { text = "..." })', () => {
      fs.writeFileSync(
        path.join(scratch, 'pyproject.toml'),
        '[project]\nname = "x"\nlicense = { text = "BSD-3-Clause" }\n',
      );
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.declaredLicenseId).toBe('BSD-3-Clause');
    });

    it('prefers package.json over pyproject.toml when both declare a license (npm wins)', () => {
      fs.writeFileSync(path.join(scratch, 'package.json'), JSON.stringify({ name: 'x', license: 'MIT' }));
      fs.writeFileSync(path.join(scratch, 'pyproject.toml'), '[project]\nname = "x"\nlicense = "Apache-2.0"\n');
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.declaredLicenseId).toBe('MIT');
    });

    it('leaves declaredLicenseId undefined when neither manifest declares one (never crashes)', () => {
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.declaredLicenseId).toBeUndefined();
    });

    it('leaves declaredLicenseId undefined when package.json exists but has no license field', () => {
      fs.writeFileSync(path.join(scratch, 'package.json'), JSON.stringify({ name: 'x' }));
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.declaredLicenseId).toBeUndefined();
    });

    it('leaves declaredLicenseId undefined when pyproject.toml has a license = { file = "..." } table', () => {
      fs.writeFileSync(
        path.join(scratch, 'pyproject.toml'),
        '[project]\nname = "x"\nlicense = { file = "LICENSE" }\n',
      );
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.declaredLicenseId).toBeUndefined();
    });

    it('does not crash on a malformed package.json, falling through to pyproject.toml', () => {
      fs.writeFileSync(path.join(scratch, 'package.json'), '{ not valid json');
      fs.writeFileSync(path.join(scratch, 'pyproject.toml'), '[project]\nname = "x"\nlicense = "MIT"\n');
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.declaredLicenseId).toBe('MIT');
    });
  });

  describe('combined', () => {
    it('reports both license-file presence and declared id together', () => {
      fs.writeFileSync(path.join(scratch, 'LICENSE'), 'MIT License text');
      fs.writeFileSync(path.join(scratch, 'package.json'), JSON.stringify({ name: 'x', license: 'MIT' }));
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.rootLicenseFilePresent).toBe(true);
      expect(facts.rootLicenseFilePath).toBe('LICENSE');
      expect(facts.declaredLicenseId).toBe('MIT');
    });

    it('reports neither field set when the directory has nothing relevant', () => {
      fs.writeFileSync(path.join(scratch, 'README.md'), 'hello');
      const facts = projectLicenseDetector.run(scratch);
      expect(facts.rootLicenseFilePresent).toBe(false);
      expect(facts.rootLicenseFilePath).toBeUndefined();
      expect(facts.declaredLicenseId).toBeUndefined();
    });
  });
});
