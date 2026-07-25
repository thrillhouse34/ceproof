import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { securityDetector } from '../../src/detect/security';

const tmpDirs: string[] = [];

function makeTmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ceproof-security-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('securityDetector', () => {
  it('reports id "security"', () => {
    expect(securityDetector.id).toBe('security');
  });

  it('finds SECURITY.md and marks only securityMdPresent', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'SECURITY.md'), '# Security Policy\n');

    const facts = securityDetector.run(dir);

    expect(facts.securityMdPresent).toBe(true);
    expect(facts.securityTxtPresent).toBe(false);
    expect(facts.vulnDisclosurePolicyPresent).toBe(false);
    expect(facts.paths).toEqual(['SECURITY.md']);
  });

  it('finds a SECURITY file with no extension and marks only securityMdPresent', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'SECURITY'), 'Report vulnerabilities to security@example.com\n');

    const facts = securityDetector.run(dir);

    expect(facts.securityMdPresent).toBe(true);
    expect(facts.securityTxtPresent).toBe(false);
    expect(facts.vulnDisclosurePolicyPresent).toBe(false);
    expect(facts.paths).toEqual(['SECURITY']);
  });

  it('finds .well-known/security.txt and marks securityTxtPresent + vulnDisclosurePolicyPresent', () => {
    const dir = makeTmpDir();
    fs.mkdirSync(path.join(dir, '.well-known'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.well-known', 'security.txt'), 'Contact: mailto:security@example.com\n');

    const facts = securityDetector.run(dir);

    expect(facts.securityMdPresent).toBe(false);
    expect(facts.securityTxtPresent).toBe(true);
    expect(facts.vulnDisclosurePolicyPresent).toBe(true);
    expect(facts.paths).toEqual(['.well-known/security.txt']);
  });

  it('finds a root security.txt and marks securityTxtPresent + vulnDisclosurePolicyPresent', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'security.txt'), 'Contact: mailto:security@example.com\n');

    const facts = securityDetector.run(dir);

    expect(facts.securityMdPresent).toBe(false);
    expect(facts.securityTxtPresent).toBe(true);
    expect(facts.vulnDisclosurePolicyPresent).toBe(true);
    expect(facts.paths).toEqual(['security.txt']);
  });

  it('reports all false with empty paths when nothing is present', () => {
    const dir = makeTmpDir();

    const facts = securityDetector.run(dir);

    expect(facts.securityMdPresent).toBe(false);
    expect(facts.securityTxtPresent).toBe(false);
    expect(facts.vulnDisclosurePolicyPresent).toBe(false);
    expect(facts.paths).toEqual([]);
  });

  it('reports every present variant when multiple files exist at once', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'SECURITY.md'), '# Security Policy\n');
    fs.writeFileSync(path.join(dir, 'SECURITY'), 'Report vulnerabilities to security@example.com\n');
    fs.mkdirSync(path.join(dir, '.well-known'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.well-known', 'security.txt'), 'Contact: mailto:security@example.com\n');
    fs.writeFileSync(path.join(dir, 'security.txt'), 'Contact: mailto:security@example.com\n');

    const facts = securityDetector.run(dir);

    expect(facts.securityMdPresent).toBe(true);
    expect(facts.securityTxtPresent).toBe(true);
    expect(facts.vulnDisclosurePolicyPresent).toBe(true);
    expect(facts.paths).toEqual(['SECURITY.md', 'SECURITY', '.well-known/security.txt', 'security.txt']);
  });
});
