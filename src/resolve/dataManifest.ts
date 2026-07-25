import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR } from '../paths';

export interface DataManifest {
  dataVersion: string;
  spdxListVersion: string;
  generatedAt: string;
  /** The exact CRA consolidation identifier the vendored data/sources/ and data/cra-structure.json reflect. See src/cra/loader.ts's getCraSourceVersion() for the value the gap-checklist engine actually uses. */
  craSourceVersion?: string;
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
