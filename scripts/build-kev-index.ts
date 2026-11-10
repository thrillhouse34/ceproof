// scripts/build-kev-index.ts
//
// Build-time-only script that produces data/kev-index.json: the version-range
// index that lets the KEV screen say `confirmed` instead of `possible`.
//
//   npm run fetch-kev-snapshot   # first — this script reads that file
//   npm run build-kev-index
//
// Then re-run scripts/verify-pack.sh, because this changed what data/ contains.
//
// WHAT IT IS. data/kev-snapshot.json tells you that a CVE is being actively
// exploited; it does not tell you which versions of which package are affected,
// because CISA's catalogue carries no version data at all. This script takes
// every CVE in that snapshot, asks OSV whether an npm or PyPI advisory exists
// for it, and keeps the affected version ranges when one does. The result is
// small — most of the catalogue is Microsoft, Cisco, Apple and Adobe product
// vulnerabilities with no package-ecosystem identity whatsoever — and that is
// the point: it is the thin slice where this tool can be version-precise.
//
// WHAT IT IS NOT. This is not an NVD/CPE layer (explicitly out of scope for
// this version). It maps advisories to package versions, so it can only ever
// refine findings for components that have an npm or PyPI identity — the two
// ecosystems ceproof's own scanner produces. A C/C++ component gets nothing
// from this file, which is exactly why src/fda/kev.ts caps those at `possible`
// and says so in each row's evidence.
//
// WHY THE API RATHER THAN THE BULK EXPORTS. OSV publishes per-ecosystem archives
// (osv-vulnerabilities.storage.googleapis.com/{npm,PyPI}/all.zip), but those are
// ~220 MB and ~38 MB respectively — a quarter of a gigabyte of download and
// temporary disk to extract a file that ends up a few tens of kilobytes. The
// per-CVE API path is bounded by the catalogue size instead (one request per KEV
// CVE, plus one per advisory alias found), needs no temp storage, and reads
// exactly what it uses.
//
// WHY TWO HOPS PER CVE. OSV's CVE-id records come from the CVE-to-OSV conversion
// and carry only GIT and CPE ranges — no package ecosystem — so they cannot
// answer "which npm version". The ecosystem data lives in the records those CVE
// records alias to (GHSA-* from the GitHub Advisory Database, PYSEC-* from the
// PyPA Advisory Database), which is why this fetches the CVE record first and
// then its aliases.
//
// LICENCES, all verified by reading each project's own LICENSE through the
// GitHub API rather than from memory, and all inside the set cleared for this
// mode (CC0, CC-BY-4.0, MIT, Apache-2.0):
//   - OSV.dev (google/osv.dev), the API this queries:            Apache-2.0
//   - GitHub Advisory Database (github/advisory-database):       CC-BY-4.0
//   - PyPA Advisory Database (pypa/advisory-database):           CC-BY-4.0
// CC-BY-4.0 requires attribution and an indication that the material was
// modified. Both live in the repo-root NOTICE, which ships in the published
// package, and the per-source attribution strings are written into this file's
// own `sources` block as well so an artifact can cite them offline. If this
// script ever starts keeping a record from a database outside that set,
// tests/fda/kevIndexLicensing.test.ts fails — that check is the gate, not this
// comment.
//
// WHAT IS DROPPED. OSV's enumerated `versions` arrays (hundreds of strings per
// advisory; the ranges express the same thing in a few bytes), summaries,
// details, references, severity scores and CWE lists — the KEV snapshot already
// carries the name and CWEs, and the risk assessment is the manufacturer's to
// write, so a bundled CVSS score would only invite it to be mistaken for one.

import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import { REPO_ROOT } from '../src/paths';
import { KEV_INDEX_SCHEMA, loadKevSnapshot } from '../src/fda/kev';
import type { KevIndex, KevIndexEntry, KevIndexRange, KevIndexSource } from '../src/fda/kev';
// The same normalizer the matcher uses, so both sides of a lookup are produced
// by one function and a purl spelling difference can never silently miss.
import { normalizePurlKey } from '../src/fda/support';

const OUTPUT_PATH = 'data/kev-index.json';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';

/** The only ecosystems ceproof's own scanner can produce, so the only ones a bundled range can ever be matched against. */
const KEPT_ECOSYSTEMS: Record<string, 'npm' | 'PyPI'> = { npm: 'npm', PyPI: 'PyPI' };

/**
 * Advisory databases this script is allowed to keep records from, keyed by the
 * host-and-org prefix of OSV's own `database_specific.source` URL. A record from
 * anywhere else is dropped with a message rather than quietly bundled, because
 * "we only ship CC0/CC-BY-4.0/MIT/Apache-2.0 data" has to be enforced by code,
 * not by intention — OSV aggregates databases under licences outside that set.
 */
const ALLOWED_SOURCES: { match: string; source: KevIndexSource }[] = [
  {
    match: 'https://github.com/github/advisory-database/',
    source: {
      name: 'GitHub Advisory Database',
      url: 'https://github.com/github/advisory-database',
      license: 'CC-BY-4.0',
      licenseUrl: 'https://github.com/github/advisory-database/blob/main/LICENSE.md',
      attribution:
        'GitHub Advisory Database (github/advisory-database), licensed CC-BY-4.0. Modified: only the affected package names and version ranges for CVEs in the CISA KEV catalogue are retained; all other advisory content is omitted.',
    },
  },
  {
    match: 'https://github.com/pypa/advisory-database/',
    source: {
      name: 'PyPA Advisory Database',
      url: 'https://github.com/pypa/advisory-database',
      license: 'CC-BY-4.0',
      licenseUrl: 'https://github.com/pypa/advisory-database/blob/main/LICENSE',
      attribution:
        'PyPA Advisory Database (pypa/advisory-database), licensed CC-BY-4.0. Modified: only the affected package names and version ranges for CVEs in the CISA KEV catalogue are retained; all other advisory content is omitted.',
    },
  },
];

/** The API itself, recorded as a source because it is how the join was performed even though it contributes no bundled text of its own. */
const OSV_SOURCE: KevIndexSource = {
  name: 'OSV.dev',
  url: 'https://osv.dev/',
  license: 'Apache-2.0',
  licenseUrl: 'https://github.com/google/osv.dev/blob/master/LICENSE',
  attribution: 'Advisory-to-package resolution performed via the OSV.dev API (google/osv.dev, Apache-2.0). Individual advisory records remain under their own databases’ licences, listed alongside.',
};

/** Concurrent OSV requests. Modest on purpose: this is a free public API being asked ~2000 questions. */
const CONCURRENCY = 12;

interface OsvRecord {
  id?: string;
  aliases?: string[];
  affected?: {
    package?: { name?: string; ecosystem?: string; purl?: string };
    ranges?: { type?: string; events?: Record<string, string>[] }[];
    database_specific?: { source?: string };
  }[];
}

function getJson(url: string): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'ceproof-build-script', Accept: 'application/json' } }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode === 404) {
            resolve({ status: 404, body: undefined });
            return;
          }
          if (res.statusCode !== 200) {
            reject(new Error(`GET ${url} failed: HTTP ${res.statusCode} ${res.statusMessage ?? ''}`.trim()));
            return;
          }
          try {
            resolve({ status: 200, body: JSON.parse(text) });
          } catch (err) {
            reject(new Error(`GET ${url} returned non-JSON (${(err as Error).message})`));
          }
        });
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

/**
 * Fetch one OSV record. A 404 is a normal, expected answer (most KEV CVEs have
 * no OSV record at all), so it returns undefined. A transport error is retried
 * twice and then thrown — a silently-skipped fetch would shrink the index
 * without anything saying so, and this script's whole value is that the index
 * is complete for the catalogue it was built from.
 */
async function fetchOsv(id: string): Promise<OsvRecord | undefined> {
  let lastError: Error | undefined;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const { status, body } = await getJson(`${OSV_VULN_URL}${encodeURIComponent(id)}`);
      if (status === 404) return undefined;
      return body as OsvRecord;
    } catch (err) {
      lastError = err as Error;
      await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
    }
  }
  throw new Error(`OSV lookup for ${id} failed after 3 attempts: ${lastError?.message ?? 'unknown error'}`);
}

/** Map `fn` over `items` with a fixed concurrency ceiling, preserving order. */
async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

function rangesFrom(events: Record<string, string>[] | undefined): KevIndexRange[] {
  if (!Array.isArray(events)) return [];
  // OSV expresses one range as a flat list of single-key event objects
  // ({introduced}, {fixed}, ...). They are collapsed into one KevIndexRange per
  // OSV range here; src/fda/kev.ts sorts the bounds by version when evaluating,
  // so their order in the file carries no meaning and none is implied.
  const range: KevIndexRange = {};
  for (const event of events) {
    if (typeof event.introduced === 'string') range.introduced = event.introduced;
    if (typeof event.fixed === 'string') range.fixed = event.fixed;
    if (typeof event.last_affected === 'string') range.lastAffected = event.last_affected;
    if (typeof event.limit === 'string') range.limit = event.limit;
  }
  return Object.keys(range).length > 0 ? [range] : [];
}

interface Collected {
  entries: KevIndexEntry[];
  usedSources: Set<string>;
  rejected: Map<string, number>;
}

function collectFrom(cve: string, advisoryId: string, record: OsvRecord, into: Collected): void {
  for (const affected of record.affected ?? []) {
    const pkg = affected.package;
    const ecosystemRaw = pkg?.ecosystem;
    const name = pkg?.name;
    if (!ecosystemRaw || !name) continue;
    // OSV qualifies some ecosystems with a release ("Debian:11"); only the part
    // before the colon identifies the package namespace.
    const ecosystem = KEPT_ECOSYSTEMS[ecosystemRaw.split(':')[0]];
    if (!ecosystem) continue;

    const sourceUrl = affected.database_specific?.source ?? '';
    const allowed = ALLOWED_SOURCES.find((s) => sourceUrl.startsWith(s.match));
    if (!allowed) {
      // Licence gate, not a parsing nicety: the bundled index may only contain
      // data from the cleared licence set.
      // Report the database, not the individual advisory path.
      const key = sourceUrl ? sourceUrl.split('/').slice(0, 5).join('/') : '(no source url)';
      into.rejected.set(key, (into.rejected.get(key) ?? 0) + 1);
      continue;
    }

    const purl = pkg.purl ?? (ecosystem === 'npm' ? `pkg:npm/${name}` : `pkg:pypi/${name.toLowerCase().replace(/_/g, '-')}`);
    const purlKey = normalizePurlKey(purl);
    if (!purlKey) continue;

    for (const range of affected.ranges ?? []) {
      const ranges = rangesFrom(range.events);
      if (ranges.length === 0) continue;
      into.usedSources.add(allowed.source.name);
      into.entries.push({
        cve,
        advisory: advisoryId,
        advisorySource: allowed.source.name,
        ecosystem,
        package: name,
        purlKey,
        rangeType: range.type ?? 'unspecified',
        ranges,
      });
    }
  }
}

async function main(): Promise<void> {
  const snapshot = loadKevSnapshot();
  const cves = snapshot.entries.map((e) => e.cve);
  console.log(`Reading ${cves.length} CVEs from data/kev-snapshot.json (catalogue version ${snapshot.source.catalogVersion}).`);
  console.log(`Querying OSV for each one (${CONCURRENCY} at a time). This takes a couple of minutes.`);

  let cveRecords: (OsvRecord | undefined)[];
  try {
    cveRecords = await mapLimit(cves, CONCURRENCY, (cve) => fetchOsv(cve));
  } catch (err) {
    console.error(`FAILED: ${(err as Error).message}`);
    console.error(`\nThe existing ${OUTPUT_PATH} (if any) was left untouched. Nothing was written.`);
    process.exitCode = 1;
    return;
  }

  const withRecord = cveRecords.filter((r) => r !== undefined).length;
  console.log(`${withRecord} of ${cves.length} KEV CVEs have an OSV record.`);

  // The ecosystem data lives in the advisories the CVE records alias to, so
  // gather those next. One alias can cover several CVEs; fetch each once.
  const aliasToCves = new Map<string, Set<string>>();
  cveRecords.forEach((record, i) => {
    for (const alias of record?.aliases ?? []) {
      if (alias.startsWith('CVE-')) continue;
      const existing = aliasToCves.get(alias);
      if (existing) existing.add(cves[i]);
      else aliasToCves.set(alias, new Set([cves[i]]));
    }
  });
  const aliasIds = [...aliasToCves.keys()].sort();
  console.log(`Fetching ${aliasIds.length} aliased advisory records for their affected version ranges.`);

  let aliasRecords: (OsvRecord | undefined)[];
  try {
    aliasRecords = await mapLimit(aliasIds, CONCURRENCY, (id) => fetchOsv(id));
  } catch (err) {
    console.error(`FAILED: ${(err as Error).message}`);
    console.error(`\nThe existing ${OUTPUT_PATH} (if any) was left untouched. Nothing was written.`);
    process.exitCode = 1;
    return;
  }

  const collected: Collected = { entries: [], usedSources: new Set(), rejected: new Map() };
  aliasRecords.forEach((record, i) => {
    if (!record) return;
    const id = aliasIds[i];
    for (const cve of aliasToCves.get(id) ?? []) collectFrom(cve, id, record, collected);
  });

  if (collected.rejected.size > 0) {
    console.log('Advisory records dropped because their upstream database is outside the cleared licence set:');
    for (const [source, count] of [...collected.rejected].sort((a, b) => b[1] - a[1])) {
      console.log(`  ${count} from ${source}`);
    }
  }

  // Deduplicate: the same (cve, package, range) can arrive through two aliases.
  const seen = new Set<string>();
  const entries = collected.entries
    .filter((e) => {
      const key = `${e.cve}|${e.ecosystem}|${e.purlKey}|${JSON.stringify(e.ranges)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) => a.cve.localeCompare(b.cve) || a.purlKey.localeCompare(b.purlKey) || JSON.stringify(a.ranges).localeCompare(JSON.stringify(b.ranges)));

  // No MIN_ENTRIES floor, unlike fetch-kev-snapshot.ts, and the asymmetry is
  // deliberate: an empty catalogue would make the tool report "no known
  // exploited vulnerabilities" for everything, but an empty index only costs
  // `confirmed` rows — every match simply falls back to `possible`, which is
  // visible in the output and warned about at runtime by screenKev(). A floor
  // here would block a legitimate run in which no KEV CVE happens to have an
  // npm or PyPI advisory.
  if (entries.length === 0) {
    console.warn('NOTE: no npm or PyPI advisories were found for any CVE in the catalogue. The index will be empty and every finding will be reported as "possible".');
  }

  const sources: KevIndexSource[] = [OSV_SOURCE, ...ALLOWED_SOURCES.filter((s) => collected.usedSources.has(s.source.name)).map((s) => s.source)];

  const index: KevIndex = {
    schema: KEV_INDEX_SCHEMA,
    sources,
    builtFrom: {
      kevCatalogVersion: snapshot.source.catalogVersion,
      kevSha256: snapshot.source.upstreamSha256,
      kevEntryCount: snapshot.entries.length,
      osvQueriedAt: new Date().toISOString(),
      cvesQueried: cves.length,
      cvesWithOsvRecord: withRecord,
    },
    entries,
  };

  const { entries: _entries, ...header } = index;
  const headerJson = JSON.stringify(header, null, 2).replace(/\n\}$/, '');
  const entryLines = entries.map((e) => `    ${JSON.stringify(e)}`).join(',\n');
  const outputAbsPath = path.join(REPO_ROOT, OUTPUT_PATH);
  fs.writeFileSync(outputAbsPath, `${headerJson},\n  "entries": [\n${entryLines}\n  ]\n}\n`, 'utf8');

  const npm = entries.filter((e) => e.ecosystem === 'npm').length;
  const pypi = entries.filter((e) => e.ecosystem === 'PyPI').length;
  const distinctCves = new Set(entries.map((e) => e.cve)).size;
  const distinctPackages = new Set(entries.map((e) => e.purlKey)).size;
  console.log(
    `Vendored ${OUTPUT_PATH}: ${entries.length} ranges (${npm} npm, ${pypi} PyPI) across ${distinctPackages} packages and ${distinctCves} KEV CVEs, ` +
      `${fs.statSync(outputAbsPath).size} bytes. Sources: ${sources.map((s) => `${s.name} (${s.license})`).join(', ')}.`,
  );
  console.log('Next: update data/manifest.json, check the NOTICE entries still match the sources above, and re-run scripts/verify-pack.sh.');
}

void main();
