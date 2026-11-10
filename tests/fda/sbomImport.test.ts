import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { createHash } from 'crypto';
import * as fs from 'fs';
import {
  importSbomFile,
  parseCycloneDx,
  normalizePurl,
  SbomImportError,
  SUPPORTED_CYCLONEDX_VERSIONS,
} from '../../src/fda/importSbom';

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures', 'sbom-import');
const fixture = (name: string) => path.join(FIXTURES, name);

describe('importSbomFile — CycloneDX JSON acceptance', () => {
  it('imports a syft-style CycloneDX 1.6 SBOM with purls, hashes, licenses and supplier', () => {
    const sbom = importSbomFile(fixture('syft-cyclonedx-1.6.json'));
    expect(sbom.format).toBe('cyclonedx');
    expect(sbom.specVersion).toBe('1.6');
    expect(sbom.sourceLabel).toBe('syft-cyclonedx-1.6.json');
    expect(sbom.components).toHaveLength(3);

    const openssl = sbom.components.find((c) => c.name === 'openssl');
    expect(openssl).toBeDefined();
    // Qualifiers stripped from the purl so the same component matches across sources.
    expect(openssl!.purl).toBe('pkg:deb/debian/openssl@3.0.11-1~deb12u2');
    expect(openssl!.cpe).toBe('cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*');
    expect(openssl!.supplier).toBe('Debian OpenSSL Team'); // from `publisher`
    expect(openssl!.licenses).toEqual(['Apache-2.0']);
    expect(openssl!.hashes).toEqual([
      { alg: 'SHA-256', content: '3f2d1d4f0c9b8a7e6d5c4b3a29180f7e6d5c4b3a29180f7e6d5c4b3a29180f7e' },
    ]);
    expect(openssl!.properties['syft:package:foundBy']).toBe('dpkg-db-cataloger');
    expect(openssl!.origins).toEqual(['sbom:syft-cyclonedx-1.6.json']);

    // A non-SPDX license NAME survives as a string; an expression survives whole.
    expect(sbom.components.find((c) => c.name === 'zlib1g')!.licenses).toEqual(['Zlib-like (vendor modified)']);
    const busybox = sbom.components.find((c) => c.name === 'busybox')!;
    expect(busybox.licenses).toEqual(['GPL-2.0-only AND bzip2-1.0.6']);
    expect(busybox.supplier).toBe('BusyBox Project'); // supplier.name wins over publisher/author
  });

  it('captures metadata.component as the BOM subject, not as a dependency', () => {
    const sbom = importSbomFile(fixture('syft-cyclonedx-1.6.json'));
    expect(sbom.subject).toMatchObject({
      name: 'acme-infusion-pump-firmware',
      version: '4.2.1',
      type: 'firmware',
    });
    expect(sbom.components.map((c) => c.name)).not.toContain('acme-infusion-pump-firmware');
  });

  it('stamps the SHA-256 of the exact bytes read, for the provenance artifact', () => {
    const file = fixture('syft-cyclonedx-1.6.json');
    const expected = createHash('sha256').update(fs.readFileSync(file, 'utf8'), 'utf8').digest('hex');
    expect(importSbomFile(file).sha256).toBe(expected);
  });

  it('accepts a cdxgen-style 1.5 SBOM and keeps ceproof:fda:* properties already present', () => {
    const sbom = importSbomFile(fixture('cdxgen-cyclonedx-1.5.json'));
    expect(sbom.specVersion).toBe('1.5');
    const leftPad = sbom.components.find((c) => c.name === 'left-pad')!;
    expect(leftPad.properties['ceproof:fda:supportLevel']).toBe('no-longer-maintained');
    expect(leftPad.properties['ceproof:fda:endOfSupportDate']).toBe('2024-01-01');
    expect(leftPad.supplier).toBe('azer'); // from `author`
  });

  it('accepts the older 1.4 spec version', () => {
    const sbom = importSbomFile(fixture('cyclonedx-1.4-minimal.json'));
    expect(sbom.specVersion).toBe('1.4');
    expect(sbom.components).toEqual([
      { name: 'mbedtls', version: '2.28.5', type: 'library', licenses: [], hashes: [], properties: {}, origins: ['sbom:cyclonedx-1.4-minimal.json'] },
    ]);
  });

  it('supports exactly the documented spec versions', () => {
    expect(SUPPORTED_CYCLONEDX_VERSIONS).toEqual(['1.4', '1.5', '1.6']);
  });
});

describe('importSbomFile — thin firmware SBOMs (the real C/C++ case)', () => {
  it('imports components with no purl, keeping the CPE and leaving a missing version absent', () => {
    const sbom = importSbomFile(fixture('firmware-no-purls.json'));
    expect(sbom.components).toHaveLength(4);
    const openssl = sbom.components.find((c) => c.name === 'openssl')!;
    expect(openssl.purl).toBeUndefined();
    expect(openssl.cpe).toBe('cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*');
    // A fuzzy version is carried through verbatim, never "completed" to 1.1.1w.
    expect(openssl.version).toBe('1.1.1');
    // No version is UNKNOWN, i.e. absent — never defaulted to "0.0.0" or "latest".
    const lwip = sbom.components.find((c) => c.name === 'lwip')!;
    expect(lwip.version).toBeUndefined();
    expect(lwip.licenses).toEqual([]);
    expect(sbom.components.find((c) => c.name === 'Yocto')!.type).toBe('operating-system');
  });

  it('flattens nested components and warns rather than silently dropping a nameless one', () => {
    const sbom = importSbomFile(fixture('nested-components.json'));
    expect(sbom.components.map((c) => c.name)).toEqual(['alpine', 'musl', 'musl-utils']);
    expect(sbom.warnings.some((w) => /no name/.test(w))).toBe(true);
  });

  it('warns on an SBOM with no components instead of reporting a clean empty import', () => {
    const sbom = parseCycloneDx('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', 'empty.json');
    expect(sbom.components).toEqual([]);
    expect(sbom.warnings.some((w) => /no components/.test(w))).toBe(true);
  });
});

describe('importSbomFile — refusals name the real problem', () => {
  const cases: { file: string; match: RegExp }[] = [
    { file: 'cyclonedx-xml.xml', match: /CycloneDX XML/ },
    { file: 'spdx-tag-value.spdx', match: /SPDX tag-value/ },
    { file: 'spdx-2.3-tiny.json', match: /SPDX JSON document \(SPDX-2\.3\)/ },
    { file: 'truncated.json', match: /not valid JSON/ },
    { file: 'not-an-sbom.json', match: /not a CycloneDX SBOM/ },
    { file: 'cyclonedx-1.3-too-old.json', match: /CycloneDX 1\.3 is not supported/ },
  ];

  for (const { file, match } of cases) {
    it(`refuses ${file} with a message that says what it actually is`, () => {
      expect(() => importSbomFile(fixture(file))).toThrow(SbomImportError);
      expect(() => importSbomFile(fixture(file))).toThrow(match);
      // The message always names the file, so a multi---sbom run says which one failed.
      expect(() => importSbomFile(fixture(file))).toThrow(new RegExp(file.replace(/\./g, '\\.')));
    });
  }

  it('refuses a missing file without leaking a raw stack', () => {
    expect(() => importSbomFile(fixture('does-not-exist.json'))).toThrow(SbomImportError);
    expect(() => importSbomFile(fixture('does-not-exist.json'))).toThrow(/cannot read file/);
  });

  it('refuses a CycloneDX document with no specVersion', () => {
    expect(() => parseCycloneDx('{"bomFormat":"CycloneDX"}', 'x.json')).toThrow(/declares no "specVersion"/);
  });

  it('refuses a JSON root that is not an object', () => {
    expect(() => parseCycloneDx('[1,2,3]', 'x.json')).toThrow(/the JSON root is not an object/);
  });
});

/**
 * Dependency relationship is an NTIA minimum element, and the importer is the
 * only place it can enter this mode. Every assertion here is about carrying
 * the producer's graph through unchanged — and about qualifying its refs, which
 * is what stops two SBOMs that both call their root "1" from cross-wiring.
 */
describe('importSbomFile — the dependency graph', () => {
  it('carries the source dependencies array through verbatim, with every ref qualified by origin', () => {
    const sbom = importSbomFile(fixture('syft-cyclonedx-1.6.json'));
    const o = 'sbom:syft-cyclonedx-1.6.json';
    expect(sbom.dependencies).toEqual([
      { ref: `${o}|device-image`, dependsOn: [`${o}|pkg:deb/debian/openssl@3.0.11-1~deb12u2`, `${o}|pkg:generic/busybox@1.36.1`] },
      { ref: `${o}|pkg:deb/debian/openssl@3.0.11-1~deb12u2`, dependsOn: [`${o}|pkg:deb/debian/zlib1g@1.2.13`] },
      { ref: `${o}|pkg:deb/debian/zlib1g@1.2.13`, dependsOn: [] },
      // An entry with no dependsOn at all is legal CycloneDX and means
      // "recorded, and there are none" — it keeps its entry, empty.
      { ref: `${o}|pkg:generic/busybox@1.36.1`, dependsOn: [] },
    ]);
  });

  it('records each component’s own bom-ref so the graph can be mapped onto the emitted refs', () => {
    const sbom = importSbomFile(fixture('syft-cyclonedx-1.6.json'));
    expect(sbom.components.find((c) => c.name === 'openssl')!.sourceRefs).toEqual([
      'sbom:syft-cyclonedx-1.6.json|pkg:deb/debian/openssl@3.0.11-1~deb12u2',
    ]);
    // The subject carries one too: a source graph is normally rooted at it.
    expect(sbom.subject!.sourceRefs).toEqual(['sbom:syft-cyclonedx-1.6.json|device-image']);
  });

  it('leaves sourceRefs absent on a component the source gave no bom-ref, rather than inventing one', () => {
    const sbom = importSbomFile(fixture('firmware-no-purls.json'));
    expect(sbom.components.every((c) => c.sourceRefs === undefined)).toBe(true);
  });

  it('reports an empty graph as empty — a vendor SBOM with no dependencies array is the common real case', () => {
    expect(importSbomFile(fixture('firmware-no-purls.json')).dependencies).toEqual([]);
  });

  it('warns rather than silently dropping a dependencies entry with no ref', () => {
    const sbom = parseCycloneDx(
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        components: [{ 'bom-ref': 'a', type: 'library', name: 'a', version: '1.0' }],
        dependencies: [{ ref: 'a', dependsOn: ['b'] }, { dependsOn: ['a'] }, 'not-an-object'],
      }),
      'broken-deps.json',
    );
    expect(sbom.dependencies).toEqual([{ ref: 'sbom:broken-deps.json|a', dependsOn: ['sbom:broken-deps.json|b'] }]);
    expect(sbom.warnings.join(' ')).toContain('2 entries in the SBOM\'s dependencies array had no "ref"');
  });

  it('ignores a dependencies value that is not an array at all, without throwing', () => {
    const sbom = parseCycloneDx(
      JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ type: 'library', name: 'a' }], dependencies: 'nope' }),
      'odd.json',
    );
    expect(sbom.dependencies).toEqual([]);
  });

  it('qualifies refs per file, so two SBOMs that both call their root "1" cannot cross-wire', () => {
    const doc = (name: string) =>
      parseCycloneDx(
        JSON.stringify({
          bomFormat: 'CycloneDX',
          specVersion: '1.6',
          components: [{ 'bom-ref': '1', type: 'library', name, version: '1.0' }],
          dependencies: [{ ref: '1', dependsOn: [] }],
        }),
        name,
      );
    expect(doc('a.json').dependencies[0].ref).toBe('sbom:a.json|1');
    expect(doc('b.json').dependencies[0].ref).toBe('sbom:b.json|1');
    expect(doc('a.json').components[0].sourceRefs).not.toEqual(doc('b.json').components[0].sourceRefs);
  });
});

describe('normalizePurl', () => {
  it('strips qualifiers and subpaths and keeps the identifying part', () => {
    expect(normalizePurl('pkg:deb/debian/openssl@3.0.11?arch=arm64&distro=debian-12')).toBe('pkg:deb/debian/openssl@3.0.11');
    expect(normalizePurl('pkg:golang/github.com/a/b@v1.2.3#sub/dir')).toBe('pkg:golang/github.com/a/b@v1.2.3');
    expect(normalizePurl('pkg:npm/%40babel/core@7.24.0')).toBe('pkg:npm/%40babel/core@7.24.0');
  });
});

describe('importSbomFile — a firmware-sized SBOM', () => {
  it('imports 5,000 components in well under the per-test budget', () => {
    // Generated in memory rather than committed: a ~1 MB fixture buys nothing
    // a generated one doesn't, and the repo doesn't need the weight.
    const components = Array.from({ length: 5000 }, (_, i) => ({
      type: 'library',
      name: `component-${i}`,
      version: `1.0.${i}`,
      purl: `pkg:generic/component-${i}@1.0.${i}`,
      licenses: [{ license: { id: 'MIT' } }],
    }));
    const text = JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components });
    const started = Date.now();
    const sbom = parseCycloneDx(text, 'big.json');
    expect(sbom.components).toHaveLength(5000);
    expect(Date.now() - started).toBeLessThan(5000);
  });
});
