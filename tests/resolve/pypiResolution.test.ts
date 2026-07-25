import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { pypiEcosystem } from '../../src/ecosystems/pypi';
import { resolveProject } from '../../src/resolve/resolveProject';

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');

async function scanAndResolve(fixtureName: string, projectLicenseId: string) {
  const dir = path.join(FIXTURES, fixtureName);
  const scanResult = await pypiEcosystem.scan(dir, { productionOnly: false });
  return resolveProject(dir, scanResult, projectLicenseId).packages;
}

describe('PyPI license resolution pipeline (Task 6) — end-to-end through resolveProject', () => {
  it('PEP 639: resolves a clean License-Expression field, source "expression", no false disagreement with an agreeing classifier', async () => {
    const resolved = await scanAndResolve('pypi-pep639', 'proprietary');
    const pkg = resolved.find((p) => p.name === 'cleanpkg')!;
    expect(pkg.source).toBe('expression');
    expect(pkg.license).toBe('MIT');
    expect(pkg.category).toBe('permissive');
  });

  it('classifier-only: falls to a mapped Trove classifier when License is unparseable ("UNKNOWN"), source "classifier"', async () => {
    const resolved = await scanAndResolve('pypi-classifier-only', 'proprietary');
    const pkg = resolved.find((p) => p.name === 'classifierpkg')!;
    expect(pkg.source).toBe('classifier');
    expect(pkg.license).toBe('BSD-3-Clause'); // "License :: OSI Approved :: BSD License" -> BSD-3-Clause
    expect(pkg.category).toBe('permissive');
    expect(pkg.confidence).toBe('medium');
  });

  // licenseproof also ran a metadata-vs-classifier disagreement check here
  // (conflict.level/explanationKey bumped to REVIEW on a genuine cross-signal
  // disagreement, suppressed for same-family variants — see
  // src/rules/categories.ts's sameLicenseFamily). ceproof has no conflict
  // concept, so that disagreement/suppression logic and its dedicated tests
  // were removed along with src/rules/conflicts.ts. Primary-signal selection
  // (License field wins over classifier) is unchanged and still covered by
  // resolveLicenseForPackage's own PyPI-branch tests.
  it('disagreement case: primary signal is License (more specific field), not the classifier', async () => {
    const resolved = await scanAndResolve('pypi-license-classifier-disagreement', 'proprietary');
    const pkg = resolved.find((p) => p.name === 'disagreepkg')!;
    expect(pkg.source).toBe('metadata');
    expect(pkg.license).toBe('MIT');
    expect(pkg.licenseIds).toEqual(['MIT']);
    expect(pkg.category).toBe('permissive');
  });

  it('same-family variant: License-Expression:BSD-2-Clause + generic "BSD License" classifier (maps to BSD-3-Clause) still resolves via the expression', async () => {
    const resolved = await scanAndResolve('pypi-bsd-variant-classifier', 'proprietary');
    const pkg = resolved.find((p) => p.name === 'bsdvariantpkg')!;
    expect(pkg.source).toBe('expression');
    expect(pkg.license).toBe('BSD-2-Clause');
    expect(pkg.licenseIds).toEqual(['BSD-2-Clause']);
    expect(pkg.category).toBe('permissive');
  });

  it('same-family variant holds across a copyleft family too: License-Expression:GPL-2.0-only + generic "GPL" classifier (maps to GPL-3.0-only) still resolves via the expression', async () => {
    const resolved = await scanAndResolve('pypi-gpl-variant-classifier', 'GPL-3.0-only');
    const pkg = resolved.find((p) => p.name === 'gplvariantpkg')!;
    expect(pkg.source).toBe('expression');
    expect(pkg.license).toBe('GPL-2.0-only');
    expect(pkg.licenseIds).toEqual(['GPL-2.0-only']);
    expect(pkg.category).toBe('strong-copyleft');
  });
});
