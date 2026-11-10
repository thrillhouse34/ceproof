// scripts/fetch-kev-snapshot.ts
//
// Build-time-only vendoring script for the FDA mode's known-exploited-
// vulnerability data (data/kev-snapshot.json). Same shape and doctrine as
// scripts/fetch-eol-snapshot.ts, fetch-cra-sources.ts and fetch-spdx-data.ts:
// never invoked by tests, never wired into "npm run build", and intolerant of
// failure in the safe direction — a failed, blocked, empty or structurally
// unexpected fetch prints a clear error, exits non-zero, and leaves the
// existing snapshot untouched. It never fabricates content and never leaves a
// partial file behind.
//
//   npm run fetch-kev-snapshot
//
// Then run `npm run build-kev-index`, which joins this catalogue against OSV to
// produce the version-range index, and re-run scripts/verify-pack.sh, because
// this changed what data/ contains.
//
// SOURCE: CISA's Known Exploited Vulnerabilities Catalog JSON feed.
//
// LICENCE: CC0-1.0, verified by reading CISA's own licence file at
// https://www.cisa.gov/sites/default/files/licenses/kev/license.txt (linked as
// "License" from the catalogue page) rather than from memory. Its first line:
//
//   "The KEV database is distributed under the Creative Commons 0 1.0 License.
//    You may use this data in any legal manner but note that information
//    provided at any 3rd party links included in the KEV database are bound by
//    the policies and licenses of those 3rd party websites. Use of the
//    information does not authorize you to use the CISA Logo or DHS Seal, nor
//    should such use be interpreted as an endorsement by CISA or DHS."
//
// CC0 is inside the licence set cleared for this mode (CC0, CC-BY-4.0, MIT,
// Apache-2.0). CC0 imposes no attribution requirement, but the entry in the
// repo-root NOTICE is kept anyway: the no-endorsement sentence above is a real
// constraint on how this data may be presented, and the file is where the
// provenance of everything under data/ is recorded.
//
// WHY NO PINNED expectedSha256, unlike fetch-cra-sources.ts: the CRA regulation
// text is frozen, so drift there means something is wrong. CISA adds entries to
// this catalogue continuously, so a pinned hash would fail on every legitimate
// refresh. The integrity evidence recorded instead is the SHA-256 of the exact
// upstream bytes, CISA's own catalogVersion and dateReleased, and their own
// `count` — all in the snapshot header, so a rendered FDA artifact can cite
// precisely which catalogue state it reflects.
//
// WHAT IS DROPPED, and why the snapshot is a distillation rather than a copy
// (data/ ships inside the npm tarball, so every byte is a byte every user
// downloads):
//   - shortDescription: ~300 characters of prose per entry, ~500 kB in total.
//     vulnerabilityName is kept instead — it names the weakness class and the
//     product in one line, which is what a vulnerability table needs.
//   - requiredAction: CISA's remediation instruction to federal agencies. Long,
//     near-boilerplate, and directed at agency asset owners rather than device
//     manufacturers.
//   - notes: third-party advisory links. CISA's own licence text says those
//     links are bound by other sites' licences, so they are the one part of the
//     feed worth not redistributing.
//   - forensicTriage: a BOD 26-04 obligation on federal agencies, not a
//     property of the vulnerability.
// knownRansomwareCampaignUse is narrowed to a boolean set only on "Known":
// CISA's "Unknown" is absence of evidence, not evidence of absence, so it is
// recorded as an absent field rather than as false.
//
// The vendor/product comparison keys are deliberately NOT precomputed here.
// They are derived at load time by normalizeKevKey() in src/fda/kev.ts, so
// there is exactly one implementation of that rule and no way for a stale
// snapshot's keys to disagree with the matcher that uses them.

import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import * as crypto from 'crypto';
import { REPO_ROOT } from '../src/paths';
import { KEV_SNAPSHOT_SCHEMA } from '../src/fda/kev';
import type { KevCatalogEntry, KevSnapshot } from '../src/fda/kev';

const SOURCE_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const LICENSE_URL = 'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt';
const OUTPUT_PATH = 'data/kev-snapshot.json';

/**
 * Floor on the number of entries a run must produce before it is allowed to
 * overwrite the vendored snapshot. The failure mode this guards against is the
 * worst one this tool has: if the feed's shape changes, every selector below
 * returns nothing, the snapshot goes near-empty, and the FDA output then reports
 * "no known exploited vulnerabilities" for every component — a clean-looking
 * artifact built on no data at all. The catalogue held 1766 entries when this
 * was written and has only ever grown; 1000 leaves room for a re-scoping while
 * still catching a shape change. (src/fda/kev.ts refuses to load a zero-entry
 * snapshot at runtime too; this is the earlier of the two gates.)
 */
const MIN_ENTRIES = 1000;

function fetchBuffer(url: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'ceproof-build-script', Accept: 'application/json' } }, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          res.resume();
          reject(new Error(`GET ${url} redirected to ${res.headers.location ?? 'an unstated location'} — the feed moved; update SOURCE_URL rather than following it blindly`));
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`GET ${url} failed: HTTP ${res.statusCode} ${res.statusMessage ?? ''}`.trim()));
          return;
        }
        const type = String(res.headers['content-type'] ?? '');
        if (type && !/json/i.test(type)) {
          res.resume();
          reject(new Error(`GET ${url} returned content-type "${type}" rather than JSON — this is probably an interstitial or error page, not the feed`));
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

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

function entryFrom(raw: unknown): KevCatalogEntry | undefined {
  if (!isRecord(raw)) return undefined;
  const cve = str(raw.cveID);
  const vendor = str(raw.vendorProject);
  const product = str(raw.product);
  const vulnerabilityName = str(raw.vulnerabilityName);
  const dateAdded = str(raw.dateAdded);
  // All five are required for an entry to be usable: without vendor and product
  // there is nothing to match a component against, and without the CVE there is
  // nothing to report. A partial entry is dropped rather than half-kept, and the
  // MIN_ENTRIES floor is what catches it if that starts happening at scale.
  if (!cve || !vendor || !product || !vulnerabilityName || !dateAdded || !ISO_DATE.test(dateAdded)) return undefined;

  const entry: KevCatalogEntry = { cve, vendor, product, vulnerabilityName, dateAdded };
  const dueDate = str(raw.dueDate);
  if (dueDate && ISO_DATE.test(dueDate)) entry.dueDate = dueDate;
  if (str(raw.knownRansomwareCampaignUse) === 'Known') entry.ransomware = true;
  if (Array.isArray(raw.cwes)) {
    const cwes = raw.cwes.map(str).filter((c): c is string => c !== undefined);
    if (cwes.length > 0) entry.cwes = cwes;
  }
  return entry;
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

  if (!isRecord(doc) || !Array.isArray(doc.vulnerabilities)) {
    console.error('FAILED: upstream response has no "vulnerabilities" array — the feed shape changed. Nothing was written.');
    process.exitCode = 1;
    return;
  }

  const entries: KevCatalogEntry[] = [];
  const seen = new Set<string>();
  for (const raw of doc.vulnerabilities) {
    const entry = entryFrom(raw);
    if (!entry || seen.has(entry.cve)) continue;
    seen.add(entry.cve);
    entries.push(entry);
  }

  if (entries.length < MIN_ENTRIES) {
    console.error(
      `FAILED: only ${entries.length} usable entries distilled from ${doc.vulnerabilities.length} upstream entries, ` +
        `below the floor of ${MIN_ENTRIES}. That means the feed's shape changed and the selectors in this script no ` +
        'longer find what they expect. Nothing was written — a near-empty catalogue would make every component report ' +
        'no known exploited vulnerabilities, which is the most dangerous output this tool can produce.',
    );
    process.exitCode = 1;
    return;
  }

  const upstreamCount = typeof doc.count === 'number' ? doc.count : entries.length;
  if (upstreamCount !== entries.length) {
    // Not fatal — CISA's own count has disagreed with the array length before,
    // and a few unusable entries are a legitimate reason — but it must be said
    // out loud, not swallowed.
    console.warn(`NOTE: CISA's own count is ${upstreamCount} but ${entries.length} entries were kept (${doc.vulnerabilities.length} were offered). Check the difference if it is large.`);
  }

  // Newest first, matching the order CISA publishes in: a reviewer reading the
  // diff of a refresh cares about what was just added.
  entries.sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || a.cve.localeCompare(b.cve));

  const snapshot: KevSnapshot = {
    schema: KEV_SNAPSHOT_SCHEMA,
    source: {
      name: 'CISA Known Exploited Vulnerabilities Catalog',
      url: SOURCE_URL,
      license: 'CC0-1.0',
      licenseUrl: LICENSE_URL,
      licenseStatement:
        'The KEV database is distributed under the Creative Commons 0 1.0 License. Use of the information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS.',
      catalogVersion: str(doc.catalogVersion) ?? 'unknown',
      dateReleased: str(doc.dateReleased) ?? 'unknown',
      upstreamCount,
      upstreamSha256,
    },
    fetchedAt: new Date().toISOString(),
    entries,
  };

  // Hand-assembled rather than JSON.stringify(_, null, 2): the header stays
  // readable and each entry gets one line, so a refresh produces a diff a human
  // can actually review (the new CVEs appear as added lines at the top) at a
  // fraction of the bytes of a fully indented file.
  const { entries: _entries, ...header } = snapshot;
  const headerJson = JSON.stringify(header, null, 2).replace(/\n\}$/, '');
  const entryLines = entries.map((e) => `    ${JSON.stringify(e)}`).join(',\n');
  const outputAbsPath = path.join(REPO_ROOT, OUTPUT_PATH);
  fs.writeFileSync(outputAbsPath, `${headerJson},\n  "entries": [\n${entryLines}\n  ]\n}\n`, 'utf8');

  const bytes = fs.statSync(outputAbsPath).size;
  const ransomware = entries.filter((e) => e.ransomware).length;
  console.log(
    `Vendored ${OUTPUT_PATH}: ${entries.length} entries (${ransomware} flagged as used in known ransomware campaigns), ${bytes} bytes ` +
      `(distilled from ${body.length} upstream bytes, sha256 ${upstreamSha256}, catalogue version ${snapshot.source.catalogVersion}, released ${snapshot.source.dateReleased}).`,
  );
  console.log('Next: "npm run build-kev-index" (the index is built from this file), then update data/manifest.json and re-run scripts/verify-pack.sh.');
}

void main();
