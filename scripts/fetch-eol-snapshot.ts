// scripts/fetch-eol-snapshot.ts
//
// Build-time-only vendoring script for the FDA mode's end-of-support data
// (data/eol-snapshot.json). Same shape and doctrine as
// scripts/fetch-cra-sources.ts and scripts/fetch-spdx-data.ts: never invoked by
// tests, never wired into "npm run build", and fully offline-intolerant in the
// safe direction — a failed, blocked, empty or structurally-unexpected fetch
// prints a clear error, exits non-zero, and leaves the existing snapshot
// untouched. It never fabricates content and never leaves a partial file behind.
//
//   npm run fetch-eol-snapshot
//
// SOURCE: endoflife.date's v1 "full" products endpoint. The project (code and
// release data) is MIT-licensed — github.com/endoflife-date/endoflife.date —
// which is inside the license set cleared for this mode (CC0, CC-BY-4.0, MIT,
// Apache-2.0). The attribution it requires lives in the repo-root NOTICE file,
// which ships in the published package (package.json "files"). If this source
// is ever swapped, NOTICE has to be updated in the same commit.
//
// WHY NO PINNED expectedSha256, unlike fetch-cra-sources.ts: the CRA regulation
// text is a frozen document, so drift there means something is wrong. This
// dataset changes every day by design (new releases, newly-announced EOL dates),
// so a pinned hash would fail on every legitimate refresh. The integrity
// evidence recorded instead is the SHA-256 of the exact upstream bytes this
// snapshot was distilled from, plus upstream's own `generated_at`, both written
// into the snapshot header so a rendered FDA artifact can cite precisely which
// upstream state it reflects.
//
// WHAT IS DROPPED, and why the snapshot is a distillation rather than a copy:
// the upstream payload is ~3 MB and carries per-release changelog links, latest
// patch numbers, codenames, release dates, LTS flags, icons and free-text custom
// fields that the support/EOL engine never reads. Only the fields
// src/fda/support.ts actually consumes are kept, because data/ ships inside the
// npm tarball. Formatting is one line per product rather than fully
// pretty-printed for the same reason: a 487-line diff is still reviewable, and
// it is a third of the bytes.

import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import * as crypto from 'crypto';
import { REPO_ROOT } from '../src/paths';
import { EOL_SNAPSHOT_SCHEMA, normalizeCpeKey, normalizePurlKey } from '../src/fda/support';
import type { EolProduct, EolRelease, EolSnapshot } from '../src/fda/support';

const SOURCE_URL = 'https://endoflife.date/api/v1/products/full/';
const OUTPUT_PATH = 'data/eol-snapshot.json';

/**
 * Floor on the number of products a run must produce before it is allowed to
 * overwrite the vendored snapshot. The whole failure mode this guards against
 * is silent: if upstream changes its response shape, every selector below
 * returns nothing, the snapshot becomes near-empty, and the FDA output then
 * reports "unknown" for every single component with no visible cause — a
 * plausible-looking artifact built on no data at all. Upstream carried 487
 * products when this was written; 300 leaves room for real shrinkage while
 * still catching a shape change.
 */
const MIN_PRODUCTS = 300;

function fetchBuffer(url: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'ceproof-build-script', Accept: 'application/json' } }, (res) => {
        const wafAction = res.headers['x-amzn-waf-action'];
        if (wafAction) {
          res.resume();
          reject(new Error(`GET ${url} was intercepted by a WAF bot-challenge (x-amzn-waf-action: ${wafAction}, status ${res.statusCode}) — not a real success`));
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`GET ${url} failed: HTTP ${res.statusCode} ${res.statusMessage ?? ''}`.trim()));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : undefined;
}

/** Upstream uses `null` for "no such date"; keep that as absent, never as a guessed date. */
function dateOrUndefined(v: unknown): string | undefined {
  const s = str(v);
  return s && /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : undefined;
}

function releaseFrom(raw: unknown): EolRelease | undefined {
  if (!isRecord(raw)) return undefined;
  const cycle = str(raw.name);
  if (!cycle) return undefined;
  const release: EolRelease = { cycle };
  const eolFrom = dateOrUndefined(raw.eolFrom);
  if (eolFrom) release.eolFrom = eolFrom;
  const eoasFrom = dateOrUndefined(raw.eoasFrom);
  if (eoasFrom) release.eoasFrom = eoasFrom;
  const eoesFrom = dateOrUndefined(raw.eoesFrom);
  if (eoesFrom) release.eoesFrom = eoesFrom;
  // The boolean upstream computed at ITS generation time. Kept only as the
  // fallback for cycles that carry no date at all (upstream's `eol: true`
  // boolean form), and labelled as "as of the snapshot date" wherever used —
  // see resolveSupport() in src/fda/support.ts, which prefers recomputing from
  // the dates so a vendored snapshot doesn't quietly go stale.
  //
  // Upstream's `isMaintained` is NOT kept: it is redundant with `isEol` in
  // every one of the 9309 release cycles in the payload, except for the 202
  // where it flags that paid extended support outlives standard support — which
  // `eoesFrom` already carries, with a date attached.
  if (typeof raw.isEol === 'boolean') release.isEolAtSnapshot = raw.isEol;
  return release;
}

function productFrom(raw: unknown): EolProduct | undefined {
  if (!isRecord(raw)) return undefined;
  const id = str(raw.name);
  if (!id) return undefined;

  const releases: EolRelease[] = [];
  if (Array.isArray(raw.releases)) {
    for (const r of raw.releases) {
      const release = releaseFrom(r);
      if (release) releases.push(release);
    }
  }
  if (releases.length === 0) return undefined; // a product with no release cycles can never answer a version question

  const purls: string[] = [];
  const cpes: string[] = [];
  if (Array.isArray(raw.identifiers)) {
    for (const ident of raw.identifiers) {
      if (!isRecord(ident)) continue;
      const value = str(ident.id);
      if (!value) continue;
      if (ident.type === 'purl') {
        const key = normalizePurlKey(value);
        if (key && !purls.includes(key)) purls.push(key);
      } else if (ident.type === 'cpe') {
        // Both the 2.3 formatted form and the legacy cpe:/ URI form appear
        // upstream for the same product; normalizeCpeKey collapses them to one
        // vendor:product key, so the dedupe below is doing real work.
        const key = normalizeCpeKey(value);
        if (key && !cpes.includes(key)) cpes.push(key);
      }
      // `repology` identifiers are deliberately dropped: nothing in the FDA
      // mode can produce a repology id to match against.
    }
  }

  const aliases: string[] = [];
  if (Array.isArray(raw.aliases)) {
    for (const a of raw.aliases) {
      const alias = str(a);
      if (alias) aliases.push(alias.toLowerCase());
    }
  }

  const product: EolProduct = { id, releases };
  const label = str(raw.label);
  if (label) product.label = label;
  if (aliases.length > 0) product.aliases = aliases;
  if (purls.length > 0) product.purls = purls;
  if (cpes.length > 0) product.cpes = cpes;
  const links = raw.links;
  if (isRecord(links)) {
    // The component manufacturer's OWN published release/support policy. Worth
    // the bytes: FDA asks for the level of support provided *by the software
    // component manufacturer*, so citing their own policy page is much stronger
    // evidence in the addendum than citing an aggregator.
    const releasePolicy = str(links.releasePolicy);
    if (releasePolicy) product.releasePolicyUrl = releasePolicy;
    const html = str(links.html);
    if (html) product.pageUrl = html;
  }
  return product;
}

async function main(): Promise<void> {
  let body: Buffer;
  try {
    body = await fetchBuffer(SOURCE_URL);
  } catch (err) {
    console.error(`FAILED: ${(err as Error).message}`);
    console.error(`\nThe existing ${OUTPUT_PATH} (if any) was left untouched. Nothing was written.`);
    process.exitCode = 1;
    return;
  }

  if (body.length === 0) {
    console.error(`FAILED: GET ${SOURCE_URL} returned an empty body (even though it claimed 200). Nothing was written.`);
    process.exitCode = 1;
    return;
  }

  const upstreamSha256 = crypto.createHash('sha256').update(body).digest('hex');

  let doc: unknown;
  try {
    doc = JSON.parse(body.toString('utf8'));
  } catch (err) {
    console.error(`FAILED: upstream response is not valid JSON (${(err as Error).message}). Nothing was written.`);
    process.exitCode = 1;
    return;
  }

  if (!isRecord(doc) || !Array.isArray(doc.result)) {
    console.error('FAILED: upstream response has no "result" array — the API shape changed. Nothing was written.');
    process.exitCode = 1;
    return;
  }

  const products: EolProduct[] = [];
  for (const raw of doc.result) {
    const product = productFrom(raw);
    if (product) products.push(product);
  }

  if (products.length < MIN_PRODUCTS) {
    console.error(
      `FAILED: only ${products.length} usable products distilled from ${doc.result.length} upstream entries, ` +
        `below the floor of ${MIN_PRODUCTS}. That means the upstream response shape changed and the selectors in ` +
        'this script no longer find what they expect. Nothing was written — a near-empty snapshot would make every ' +
        'component report an unexplained "unknown" support level.',
    );
    process.exitCode = 1;
    return;
  }

  products.sort((a, b) => a.id.localeCompare(b.id));

  const snapshot: EolSnapshot = {
    schema: EOL_SNAPSHOT_SCHEMA,
    source: {
      name: 'endoflife.date',
      url: SOURCE_URL,
      license: 'MIT',
      licenseUrl: 'https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE',
      copyright: 'Copyright 2020 endoflife.date contributors',
      upstreamSchemaVersion: str(doc.schema_version) ?? 'unknown',
      upstreamGeneratedAt: str(doc.generated_at) ?? 'unknown',
      upstreamSha256,
    },
    fetchedAt: new Date().toISOString(),
    products,
  };

  // Hand-assembled rather than JSON.stringify(_, null, 2): the header stays
  // readable, and the 487 products get one line each so a refresh produces a
  // diff a human can actually review, without paying for 9309 indented release
  // objects.
  const { products: _products, ...header } = snapshot;
  const headerJson = JSON.stringify(header, null, 2).replace(/\n\}$/, '');
  const productLines = products.map((p) => `    ${JSON.stringify(p)}`).join(',\n');
  const outputAbsPath = path.join(REPO_ROOT, OUTPUT_PATH);
  fs.writeFileSync(outputAbsPath, `${headerJson},\n  "products": [\n${productLines}\n  ]\n}\n`, 'utf8');

  const releaseCount = products.reduce((n, p) => n + p.releases.length, 0);
  const bytes = fs.statSync(outputAbsPath).size;
  console.log(
    `Vendored ${OUTPUT_PATH}: ${products.length} products, ${releaseCount} release cycles, ${bytes} bytes ` +
      `(distilled from ${body.length} upstream bytes, sha256 ${upstreamSha256}, upstream generated_at ${snapshot.source.upstreamGeneratedAt}).`,
  );
  console.log(
    'Now update data/manifest.json\'s eolSnapshotGeneratedAt to the upstream generated_at above, and re-run scripts/verify-pack.sh (this changed what data/ contains).',
  );
}

void main();
