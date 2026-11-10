import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR } from '../paths';

export interface DataManifest {
  /**
   * Version of the CRA/SPDX reference data the CRA product stamps into every
   * rendered Annex VII / Annex V artifact. Deliberately NOT a version of
   * everything under data/: the FDA mode's end-of-support snapshot refreshes on
   * its own cadence (daily upstream) and carries its own identifiers below, so
   * folding it into dataVersion would churn the CRA provenance line on every
   * EOL refresh and make two unrelated datasets look like one.
   */
  dataVersion: string;
  spdxListVersion: string;
  generatedAt: string;
  /** The exact CRA consolidation identifier the vendored data/sources/ and data/cra-structure.json reflect. See src/cra/loader.ts's getCraSourceVersion() for the value the gap-checklist engine actually uses. */
  craSourceVersion?: string;
  /** Where data/eol-snapshot.json came from and under what licence. Mirrors its own `source` block; see NOTICE. */
  eolSnapshotSource?: string;
  /** Upstream's own `generated_at` for the vendored end-of-support snapshot — the date the FDA mode's staleness warning is measured from. */
  eolSnapshotGeneratedAt?: string;
  /** Where data/kev-snapshot.json came from and under what licence. Mirrors its own `source` block; see NOTICE. */
  kevSnapshotSource?: string;
  /** CISA's own catalogue version and release date for the vendored KEV snapshot — what the FDA mode's staleness warning is measured from. Separate from eolSnapshotGeneratedAt because the two datasets refresh on unrelated cadences. */
  kevSnapshotReleased?: string;
}

let cached: DataManifest | undefined;
function load(): DataManifest {
  if (!cached) cached = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'manifest.json'), 'utf8'));
  return cached!;
}

export function getDataManifest(): DataManifest {
  return load();
}

export function getDataVersion(): string {
  return load().dataVersion;
}
