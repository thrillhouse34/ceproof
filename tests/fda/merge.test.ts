import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { componentsFromScan, mergeComponents } from '../../src/fda/merge';
import { importSbomFile } from '../../src/fda/importSbom';
import { buildReportData } from '../../src/report/reportData';
import type { FdaComponent } from '../../src/fda/types';

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');
const sbom = (name: string) => importSbomFile(path.join(FIXTURES, 'sbom-import', name));

function comp(partial: Partial<FdaComponent> & { name: string }): FdaComponent {
  return { licenses: [], hashes: [], properties: {}, origins: ['scan'], ...partial };
}

describe('componentsFromScan — the only bridge from the scan pipeline', () => {
  it('adapts resolved npm/PyPI packages, purls included, origin "scan"', async () => {
    const data = await buildReportData(path.join(FIXTURES, 'mixed-npm-pypi-full'), { productionOnly: false });
    const components = componentsFromScan(data.packages);
    expect(components).toHaveLength(data.packages.length);
    expect(components.every((c) => c.origins.length === 1 && c.origins[0] === 'scan')).toBe(true);
    expect(components.every((c) => c.purl?.startsWith('pkg:'))).toBe(true);
    // Scan components carry no hashes or properties — nothing is invented to fill the shape.
    expect(components.every((c) => c.hashes.length === 0)).toBe(true);
  });

  it('omits the license entirely when none was resolved, rather than asserting "UNKNOWN"', () => {
    const resolved = [
      { name: 'a', version: '1.0.0', ecosystem: 'npm', direct: true, dev: false, paths: [], pathCountAtLeast: 1, installPath: 'node_modules/a', license: 'MIT', licenseIds: ['MIT'], category: 'permissive', confidence: 'high', source: 'metadata' },
      { name: 'b', version: '2.0.0', ecosystem: 'npm', direct: true, dev: false, paths: [], pathCountAtLeast: 1, installPath: 'node_modules/b', license: 'UNKNOWN', licenseIds: [], category: 'unknown', confidence: 'low', source: 'none' },
    ] as Parameters<typeof componentsFromScan>[0];
    const [a, b] = componentsFromScan(resolved);
    expect(a.licenses).toEqual(['MIT']);
    expect(b.licenses).toEqual([]);
  });
});

describe('mergeComponents — dedupe keys', () => {
  it('merges on the normalized purl even when the two sources used different qualifiers', () => {
    const syft = sbom('syft-cyclonedx-1.6.json');
    const cdxgen = sbom('cdxgen-cyclonedx-1.5.json');
    const { components } = mergeComponents([syft.components, cdxgen.components]);
    // openssl appears in both, with ?arch=arm64 vs ?arch=amd64 qualifiers.
    const openssl = components.filter((c) => c.name === 'openssl');
    expect(openssl).toHaveLength(1);
    expect(openssl[0].origins).toEqual(['sbom:syft-cyclonedx-1.6.json', 'sbom:cdxgen-cyclonedx-1.5.json']);
    // Union of both sources' hashes; the first source's supplier is kept.
    expect(openssl[0].hashes.map((h) => h.alg)).toEqual(['SHA-256', 'SHA-512']);
    expect(openssl[0].supplier).toBe('Debian OpenSSL Team');
    expect(components).toHaveLength(4); // openssl, zlib1g, busybox, left-pad
  });

  it('merges on case-insensitive name@version when neither side has a purl', () => {
    const { components, warnings } = mergeComponents([
      [comp({ name: 'FreeRTOS', version: '10.4.6', supplier: 'Amazon' })],
      [comp({ name: 'freertos', version: '10.4.6', origins: ['sbom:vendor.json'], licenses: ['MIT'] })],
    ]);
    expect(components).toHaveLength(1);
    expect(components[0].name).toBe('FreeRTOS');
    expect(components[0].licenses).toEqual(['MIT']);
    expect(components[0].origins).toEqual(['scan', 'sbom:vendor.json']);
    expect(warnings).toEqual([]);
  });

  it('does NOT merge on name alone: a missing version keeps both entries and flags them', () => {
    const { components, warnings } = mergeComponents([
      [comp({ name: 'openssl', version: '3.0.11', origins: ['sbom:a.json'] })],
      [comp({ name: 'openssl', origins: ['sbom:b.json'] })],
    ]);
    expect(components).toHaveLength(2);
    expect(components.every((c) => c.possibleDuplicate === true)).toBe(true);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/Possible duplicate, unresolved: "openssl"/);
    expect(warnings[0]).toMatch(/neither was merged/);
  });

  it('does NOT merge two different versions of the same name, and does not flag them either', () => {
    const { components, warnings } = mergeComponents([
      [comp({ name: 'openssl', version: '1.1.1', purl: 'pkg:generic/openssl@1.1.1', origins: ['sbom:a.json'] })],
      [comp({ name: 'openssl', version: '3.0.11', purl: 'pkg:generic/openssl@3.0.11', origins: ['sbom:b.json'] })],
    ]);
    expect(components).toHaveLength(2);
    // Same name, genuinely different versions: two real components, flagged so a
    // reviewer can confirm the device really ships both.
    expect(components.every((c) => c.possibleDuplicate === true)).toBe(true);
    expect(warnings).toHaveLength(1);
  });

  it('warns once per ambiguous name, not once per occurrence', () => {
    const { warnings } = mergeComponents([
      [comp({ name: 'zlib', origins: ['sbom:a.json'] })],
      [comp({ name: 'zlib', origins: ['sbom:b.json'] })],
      [comp({ name: 'zlib', origins: ['sbom:c.json'] })],
    ]);
    expect(warnings.filter((w) => /zlib/.test(w))).toHaveLength(1);
  });

  it('indexes a purl contributed by a later source so a third source still matches', () => {
    const { components } = mergeComponents([
      [comp({ name: 'musl', version: '1.2.5', origins: ['sbom:a.json'] })],
      [comp({ name: 'musl', version: '1.2.5', purl: 'pkg:apk/alpine/musl@1.2.5', origins: ['sbom:b.json'] })],
      [comp({ name: 'musl-c', version: '9.9.9', purl: 'pkg:apk/alpine/musl@1.2.5', origins: ['sbom:c.json'] })],
    ]);
    expect(components).toHaveLength(1);
    expect(components[0].origins).toEqual(['sbom:a.json', 'sbom:b.json', 'sbom:c.json']);
  });
});

describe('mergeComponents — conflicts are recorded, never silently dropped', () => {
  it('keeps the first source value and records the loser with both origins named', () => {
    const { components, warnings } = mergeComponents([
      [comp({ name: 'openssl', version: '3.0.11', purl: 'pkg:generic/openssl@3.0.11', supplier: 'Debian', origins: ['sbom:a.json'] })],
      [comp({ name: 'openssl', version: '3.0.11', purl: 'pkg:generic/openssl@3.0.11', supplier: 'OpenSSL Foundation', origins: ['sbom:b.json'] })],
    ]);
    expect(components[0].supplier).toBe('Debian');
    expect(components[0].conflicts).toEqual([
      'supplier: kept "Debian" (sbom:a.json), also reported as "OpenSSL Foundation" (sbom:b.json)',
    ]);
    expect(warnings.some((w) => /1 field conflict/.test(w))).toBe(true);
  });

  it('records a conflicting property value and keeps the first', () => {
    const { components } = mergeComponents([
      [comp({ name: 'a', version: '1', properties: { 'ceproof:fda:supportLevel': 'actively-maintained' }, origins: ['sbom:a.json'] })],
      [comp({ name: 'a', version: '1', properties: { 'ceproof:fda:supportLevel': 'abandoned' }, origins: ['sbom:b.json'] })],
    ]);
    expect(components[0].properties['ceproof:fda:supportLevel']).toBe('actively-maintained');
    expect(components[0].conflicts?.[0]).toMatch(/property ceproof:fda:supportLevel: kept "actively-maintained"/);
  });

  it('fills an absent scalar from a later source without calling it a conflict', () => {
    const { components, warnings } = mergeComponents([
      [comp({ name: 'a', version: '1', origins: ['scan'] })],
      [comp({ name: 'a', version: '1', supplier: 'ACME', cpe: 'cpe:2.3:a:acme:a:1:*:*:*:*:*:*:*', origins: ['sbom:b.json'] })],
    ]);
    expect(components[0].supplier).toBe('ACME');
    expect(components[0].cpe).toBe('cpe:2.3:a:acme:a:1:*:*:*:*:*:*:*');
    expect(components[0].conflicts).toBeUndefined();
    expect(warnings).toEqual([]);
  });
});

describe('mergeComponents — repo scan plus imported SBOMs', () => {
  it('is additive: a Node app scan and two firmware SBOMs all contribute', async () => {
    const data = await buildReportData(path.join(FIXTURES, 'mixed-npm-pypi-full'), { productionOnly: false });
    const scan = componentsFromScan(data.packages);
    const a = sbom('firmware-no-purls.json');
    const b = sbom('nested-components.json');
    const { components } = mergeComponents([scan, a.components, b.components]);
    expect(components.length).toBe(scan.length + a.components.length + b.components.length);
    expect(components.some((c) => c.origins.includes('scan'))).toBe(true);
    expect(components.some((c) => c.name === 'FreeRTOS')).toBe(true);
    expect(components.some((c) => c.name === 'musl-utils')).toBe(true);
  });

  it('accumulates source refs instead of treating two documents’ bom-refs as a conflict', () => {
    // A bom-ref is a document-local identifier, not a fact about the software,
    // so two documents naming the same component differently is not a
    // disagreement — and BOTH refs have to survive, or the dependency edges
    // from whichever document merged second would be unmappable.
    const { components, warnings } = mergeComponents([
      [comp({ name: 'openssl', version: '1.1.1', origins: ['sbom:a.json'], sourceRefs: ['sbom:a.json|ossl'] })],
      [comp({ name: 'openssl', version: '1.1.1', origins: ['sbom:b.json'], sourceRefs: ['sbom:b.json|openssl-1'] })],
    ]);
    expect(components).toHaveLength(1);
    expect(components[0].sourceRefs).toEqual(['sbom:a.json|ossl', 'sbom:b.json|openssl-1']);
    expect(warnings.join(' ')).not.toContain('sourceRefs');
    expect(components[0].conflicts).toBeUndefined();
  });

  it('does not duplicate a source ref when the same document contributes twice', () => {
    const { components } = mergeComponents([
      [comp({ name: 'a', version: '1', origins: ['sbom:a.json'], sourceRefs: ['sbom:a.json|x'] })],
      [comp({ name: 'a', version: '1', origins: ['sbom:a.json'], sourceRefs: ['sbom:a.json|x'] })],
    ]);
    expect(components[0].sourceRefs).toEqual(['sbom:a.json|x']);
  });

  it('never mutates the caller lists', () => {
    const source = [comp({ name: 'a', version: '1', origins: ['scan'] })];
    const snapshot = JSON.stringify(source);
    mergeComponents([source, [comp({ name: 'a', version: '1', supplier: 'ACME', origins: ['sbom:b.json'] })]]);
    expect(JSON.stringify(source)).toBe(snapshot);
  });
});
