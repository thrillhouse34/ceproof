import { expect } from 'vitest';

// The forbidden-marker set for the "internal artifact leaks into
// customer-facing text" guard, shared by its two halves: the public one
// (tests/report/noInternalArtifactLeak.test.ts — scan/report output, --help,
// README) and the private one (tests/private/fulfillmentEmailLeak.test.ts —
// the license-fulfillment email, whose template lives in the never-shipped
// scripts/keygen/ tooling that the public mirror excludes). One list, so the
// two halves cannot drift apart.
//
// Not a *.test.ts file on purpose: vitest only collects tests/**/*.test.ts, so
// importing this costs nothing and runs no tests of its own.
//
// "placeholder" is deliberately NOT in the list below, even though the task
// that added this guard specifically called it out to check. It was checked:
// `ceproof init`'s real output says "This file was generated with placeholder
// values only — nothing was assumed on your behalf," which is a correct,
// intentional, helpful customer-facing message (it tells the customer the
// config needs filling in) — not a leftover internal marker. Banning the word
// outright would make this test fail on legitimate, desired copy, which is
// worse than not checking it at all.

interface Marker {
  label: string;
  pattern: RegExp;
}

export const FORBIDDEN_MARKERS: Marker[] = [
  { label: '"completion report" (internal-only doc, no customer access)', pattern: /completion report/i },
  { label: '"milestone" (internal planning vocabulary)', pattern: /\bmilestones?\b/i },
  { label: 'bare M1-M6 milestone shorthand', pattern: /(?<![A-Za-z0-9])M[1-6](?![A-Za-z0-9])/ },
  { label: '"brief" as in an internal planning-doc reference', pattern: /\bbriefs?\b/i },
  { label: '"subagent" (internal tooling vocabulary)', pattern: /\bsubagents?\b/i },
  { label: '"TODO" marker', pattern: /\bTODO\b/ },
  { label: '"FIXME" marker', pattern: /\bFIXME\b/ },
  { label: 'internal path .claude/', pattern: /\.claude\// },
  { label: 'internal path scripts/keygen/', pattern: /scripts\/keygen\// },
  { label: 'internal path docs/plans/', pattern: /docs\/plans\// },
];

export function findHits(label: string, content: string): string[] {
  const hits: string[] = [];
  for (const marker of FORBIDDEN_MARKERS) {
    const m = content.match(marker.pattern);
    if (m) {
      const idx = m.index ?? 0;
      const start = Math.max(0, idx - 40);
      const end = Math.min(content.length, idx + m[0].length + 40);
      hits.push(`[${label}] ${marker.label}: ...${content.slice(start, end).replace(/\n/g, '\\n')}...`);
    }
  }
  return hits;
}

export function expectClean(label: string, content: string): void {
  const hits = findHits(label, content);
  expect(hits, hits.join('\n')).toEqual([]);
}
