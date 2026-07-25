// scripts/fetch-cra-sources.ts
//
// Build-time-only source-vendoring script for ceproof's CRA reference material
// (the EU Cyber Resilience Act regulation text and the BSI TR-03183-2 technical
// guideline). Mirrors the pattern in scripts/fetch-spdx-data.ts: never invoked
// by tests, never wired into "npm run build", fully offline-tolerant (a failed
// or blocked fetch prints a clear error and exits non-zero — it never fabricates
// content and never leaves a partial/empty file behind).
//
// STATUS (M1 Task T9): both sources are now vendored in data/sources/, supplied
// directly by Mark rather than fetched by this script (EUR-Lex's AWS WAF
// bot-challenge and an unresolved BSI subdomain-allowlist gap blocked automated
// fetching — see M1-COMPLETION-REPORT.md). Each SOURCES entry below pins the
// URL (where known) and the exact SHA-256 of the vendored bytes, so this script
// can VERIFY the already-vendored files' integrity even though it still cannot
// fetch: run it with no network access and it checks data/sources/*'s hashes
// against these pinned values and reports drift, rather than only being useful
// once fetching works. If a source's bytes are ever re-vendored (e.g. Mark
// supplies an updated corrigendum-incorporating version), update its
// expectedSha256 here deliberately — a silent mismatch must never pass.
//
// Once EUR-Lex/BSI become fetchable from this environment, re-run:
//   npm run fetch-cra-sources
// A clean fetch-and-verify run vendors fresh bytes into data/sources/, checks
// them against expectedSha256, and writes data/sources/manifest.json recording
// the exact URL, SHA-256, and fetch time for each source.

import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import * as crypto from 'crypto';
import { REPO_ROOT } from '../src/paths';

interface CraSource {
  id: string;
  /** null = no confirmed fetchable URL; see `pendingReason`. Never a guessed/placeholder network address. */
  url: string | null;
  description: string;
  /** Path relative to REPO_ROOT, under data/sources/. */
  outputPath: string;
  /** The exact SHA-256 of the currently-vendored bytes at outputPath, pinned for integrity verification. */
  expectedSha256: string;
  /** Set only when `url` is null — explains why this source has no confirmed fetch URL. */
  pendingReason?: string;
}

const SOURCES: CraSource[] = [
  {
    id: 'celex-02024r2847-20241120-en',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02024R2847-20241120',
    description:
      'Regulation (EU) 2024/2847 (Cyber Resilience Act), consolidated text CELEX 02024R2847, ' +
      'point-in-time 20241120, EUR-Lex EN HTML view. Incorporates Corrigenda 1-3 (OJ L 90780 ' +
      '5.12.2024; OJ L 90555 2.7.2025; OJ L 90828 17.10.2025) — verified none of the three touch ' +
      'Annex V, Annex VII, or Articles 13/31/33 (see M1-COMPLETION-REPORT.md). Blocked by an AWS ' +
      'WAF bot-challenge (x-amzn-waf-action: challenge) as of this vendoring; supplied directly by ' +
      'Mark rather than fetched by this script.',
    outputPath: 'data/sources/celex-02024r2847-20241120-en.html',
    expectedSha256: '10d4b544a348d275762394b17a5515e555d91bfd062ab0494dd477ac28e3bbb5',
  },
  {
    id: 'bsi-tr-03183-2-v2.1.0',
    url: null,
    description:
      'BSI Technical Guideline TR-03183-2 v2.1.0, dated 2025-08-20 (Cyber Resilience Requirements ' +
      'for Manufacturers and Products, Part 2: Software Bill of Materials).',
    outputPath: 'data/sources/bsi-tr-03183-2-v2.1.0.pdf',
    expectedSha256: 'dda0ccd9b6148571d1d12241a1618b30027f22bc15e24248fdd21a011e62845c',
    pendingReason:
      "exact download URL not confirmed — BSI's TR-03183 index page " +
      '(https://www.bsi.bund.de/dok/TR-03183-en, or wherever it currently resolves to) needs to be ' +
      'checked to locate the current, stable TR-03183-2 v2.1.0 PDF link. This specific copy was ' +
      "supplied directly by Mark, not fetched — www.bsi.bund.de wasn't allowlisted at vendoring time " +
      '(only the bare bsi.bund.de domain was, which redirects to www but the redirect target itself ' +
      'was then rejected by the network policy).',
  },
];

interface ManifestEntry {
  id: string;
  url: string;
  sha256: string;
  fetchedAt: string;
}

interface SourcesManifest {
  sources: ManifestEntry[];
}

/**
 * Fetches `url` and resolves with the raw response body as a Buffer.
 * Rejects (never resolves with partial data) on:
 *   - a transport-level error,
 *   - any non-200 status code (including 202/403, the shapes an AWS WAF
 *     bot-challenge typically takes — those are not treated as success even
 *     though they carry a body),
 *   - an explicit WAF-challenge response header.
 */
function fetchBinary(url: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'ceproof-build-script' } }, (res) => {
        const wafAction = res.headers['x-amzn-waf-action'];
        if (wafAction) {
          res.resume(); // drain so the socket can close cleanly
          reject(
            new Error(
              `GET ${url} was intercepted by a WAF bot-challenge (x-amzn-waf-action: ${wafAction}, ` +
                `status ${res.statusCode}) — not a real success, no content will be written`,
            ),
          );
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

function sha256Hex(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

type SourceResult =
  | { id: string; status: 'verified'; entry: ManifestEntry }
  | { id: string; status: 'fetched'; entry: ManifestEntry }
  | { id: string; status: 'error'; error: string };

/**
 * For each source: if the vendored file already exists on disk, VERIFY its
 * hash against expectedSha256 (works with no network access at all — this is
 * the "verify integrity even though it can't fetch" mode). Only attempt a
 * live fetch when the file is missing locally. Either path ends with the same
 * hash check, so a source can never silently pass with drifted content.
 */
async function processOne(source: CraSource): Promise<SourceResult> {
  const outputAbsPath = path.join(REPO_ROOT, source.outputPath);

  if (fs.existsSync(outputAbsPath)) {
    const body = fs.readFileSync(outputAbsPath);
    const sha256 = sha256Hex(body);
    if (sha256 !== source.expectedSha256) {
      return {
        id: source.id,
        status: 'error',
        error:
          `already-vendored file at ${source.outputPath} does not match the pinned expectedSha256 ` +
          `(expected ${source.expectedSha256}, got ${sha256}) — the file changed since it was pinned; ` +
          'investigate before trusting it, never silently accept drifted content',
      };
    }
    console.log(`Verified ${source.id} -> ${source.outputPath} (${body.length} bytes, sha256 matches pinned value)`);
    return {
      id: source.id,
      status: 'verified',
      entry: { id: source.id, url: source.url ?? '(no confirmed URL — see pendingReason)', sha256, fetchedAt: '(not re-fetched; verified against already-vendored bytes)' },
    };
  }

  if (source.url === null) {
    return { id: source.id, status: 'error', error: `not vendored locally and no confirmed URL yet — ${source.pendingReason ?? 'unresolved'}` };
  }

  let body: Buffer;
  try {
    body = await fetchBinary(source.url);
  } catch (err) {
    return { id: source.id, status: 'error', error: (err as Error).message };
  }

  if (body.length === 0) {
    // Never write an empty file, even if the server claimed 200.
    return { id: source.id, status: 'error', error: `GET ${source.url} returned an empty body` };
  }

  const sha256 = sha256Hex(body);
  if (sha256 !== source.expectedSha256) {
    return {
      id: source.id,
      status: 'error',
      error:
        `freshly-fetched content does not match the pinned expectedSha256 (expected ${source.expectedSha256}, ` +
        `got ${sha256}) — the upstream document changed; update expectedSha256 deliberately after reviewing ` +
        'what changed, never silently accept it',
    };
  }

  fs.mkdirSync(path.dirname(outputAbsPath), { recursive: true });
  fs.writeFileSync(outputAbsPath, body);

  const fetchedAt = new Date().toISOString();
  console.log(`Vendored ${source.id} -> ${source.outputPath} (${body.length} bytes, sha256 ${sha256})`);
  return { id: source.id, status: 'fetched', entry: { id: source.id, url: source.url, sha256, fetchedAt } };
}

async function main(): Promise<void> {
  const results = await Promise.all(SOURCES.map(processOne));

  const succeeded: ManifestEntry[] = [];
  const failed: { id: string; error: string }[] = [];
  for (const r of results) {
    if (r.status === 'error') failed.push({ id: r.id, error: r.error });
    else succeeded.push(r.entry);
  }

  for (const f of failed) {
    console.error(`FAILED: source "${f.id}" — ${f.error}`);
  }

  if (failed.length > 0) {
    console.error(
      `\n${failed.length}/${SOURCES.length} source(s) failed to fetch/verify. No manifest.json was written ` +
        '(the CRA source manifest only records complete, verified runs). Re-run once the failures above ' +
        'are resolved.',
    );
    process.exitCode = 1;
    return;
  }

  const manifest: SourcesManifest = { sources: succeeded };
  const manifestPath = path.join(REPO_ROOT, 'data', 'sources', 'manifest.json');
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  console.log(`Wrote ${manifestPath} (${succeeded.length} source(s)).`);
}

main().catch((err) => {
  console.error('fetch-cra-sources failed unexpectedly:', (err as Error).message);
  process.exitCode = 1;
});
