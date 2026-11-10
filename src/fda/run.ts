/**
 * One run of the FDA mode: inputs in, a joined `FdaRenderInput` out.
 *
 * Both CLI surfaces need exactly this — `scan --profile fda` renders the free
 * gap view from it, `report --format fda-pack` renders the paid artifacts from
 * it — and they must agree about what was found, or the free view becomes a
 * sales pitch for a different document. So the assembly happens once, here,
 * and neither command owns any part of it.
 *
 * It lives under src/fda rather than src/cli so that
 * `tests/fda/offline.test.ts` covers it: this is the file that would be most
 * tempting to "just fetch the latest KEV data" from, and it is the one place
 * in the mode where a network call would look reasonable. It makes none. The
 * only I/O is reading the user's SBOM files (through `importSbomFile`) and the
 * vendored snapshots (through `resolveSupport`/`screenKev`, both of which
 * resolve `DATA_DIR` themselves).
 *
 * `NoProjectFoundError` is DOWNGRADED to a warning when an SBOM was supplied.
 * That is the whole point of the mode: a device-firmware repo is C/C++, has no
 * lockfile, and is not a scannable project — refusing to run there would make
 * the import path unreachable for exactly the customers it exists for. With
 * neither an SBOM nor a scannable project, the run fails with a usage error
 * that says so.
 */
import * as path from 'path';
import { getToolVersion } from '../toolVersion';
import { buildReportData, NoProjectFoundError } from '../report/reportData';
import { readConfigFile, resolveConfigPath } from '../config/write';
import { validateConfig } from '../config/validate';
import type { CeproofConfig } from '../config/types';
import { importSbomFile, SbomImportError } from './importSbom';
import { componentsFromScan, mergeComponents } from './merge';
import { resolveSupport } from './support';
import { screenKev } from './kev';
import { joinRows, type FdaRenderInput, type FdaRow } from './render/input';
import type { FdaComponent, FdaDependency } from './types';

export { SbomImportError };

/** Nothing to screen. Exit 2 at the CLI, with nothing written. */
export class NoComponentsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NoComponentsError';
  }
}

export interface FdaRunOptions {
  /** Project path to scan for npm/PyPI dependencies. A repo scan contributes components alongside any imported SBOM. */
  path: string;
  /** `--sbom <file>`, repeatable. CycloneDX JSON only in this version. */
  sbomPaths: string[];
  productionOnly: boolean;
  configPath?: string;
  /** Injected by tests so an artifact can be regenerated for a fixed date and compared. Defaults to today. */
  asOf?: string;
  /** Injected by tests for the same reason. Defaults to now. */
  generatedAt?: string;
}

export interface FdaRunResult {
  input: FdaRenderInput;
  rows: FdaRow[];
  /** The resolved config, so the caller can report whether one was present without reading it twice. */
  config: CeproofConfig | null;
}

function readConfig(configPath: string): CeproofConfig | null {
  const read = readConfigFile(configPath);
  if (!read.present || 'parseError' in read) return null;
  const result = validateConfig(read.raw);
  return result.valid ? result.config : null;
}

/**
 * The device the pack is about. An imported SBOM's own `metadata.component`
 * is authoritative — it is the producer's statement about what they built —
 * and the config's `product.name` is the fallback. Never the scanned
 * directory's name: a directory is not a device.
 *
 * The FIRST imported SBOM's subject wins when several name one, and the
 * disagreement is warned about rather than resolved silently.
 */
function resolveSubject(
  subjects: { label: string; subject: FdaComponent }[],
  config: CeproofConfig | null,
  warnings: string[],
): FdaComponent | undefined {
  if (subjects.length > 1) {
    const names = subjects.map((s) => `"${s.subject.name}" (${s.label})`);
    const distinct = new Set(subjects.map((s) => s.subject.name));
    if (distinct.size > 1) {
      warnings.push(
        `More than one imported SBOM names a different subject: ${names.join(', ')}. ` +
          `The first was used as the device this pack describes. If that is wrong, run them separately or set product.name in ceproof.config.json.`,
      );
    }
  }
  if (subjects.length > 0) return subjects[0].subject;
  if (config?.product?.name) {
    return {
      name: config.product.name,
      type: 'device',
      licenses: [],
      hashes: [],
      properties: {},
      origins: ['override'],
    };
  }
  return undefined;
}

export async function runFda(options: FdaRunOptions): Promise<FdaRunResult> {
  const asOf = options.asOf ?? new Date().toISOString().slice(0, 10);
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const config = readConfig(resolveConfigPath(options.path, options.configPath));
  const warnings: string[] = [];

  // SBOMs first: an SbomImportError is a usage error about a file the user
  // named, and there is no reason to make them wait through a dependency scan
  // to hear about a typo'd path or an SPDX file.
  const sources: FdaComponent[][] = [];
  const dependencies: FdaDependency[] = [];
  const subjects: { label: string; subject: FdaComponent }[] = [];
  const sbomInputs: FdaRenderInput['sbomInputs'] = [];
  for (const sbomPath of options.sbomPaths) {
    const imported = importSbomFile(sbomPath);
    sources.push(imported.components);
    dependencies.push(...imported.dependencies);
    if (imported.subject) subjects.push({ label: imported.sourceLabel, subject: imported.subject });
    sbomInputs.push({
      sourceLabel: imported.sourceLabel,
      specVersion: imported.specVersion,
      ...(imported.sha256 ? { sha256: imported.sha256 } : {}),
      componentCount: imported.components.length,
    });
    warnings.push(...imported.warnings);
  }

  let scanPath: string | undefined;
  try {
    const data = await buildReportData(options.path, { productionOnly: options.productionOnly });
    const scanned = componentsFromScan(data.packages);
    if (scanned.length > 0) {
      sources.push(scanned);
      scanPath = path.resolve(options.path);
    }
    warnings.push(...data.warnings);
  } catch (err) {
    if (!(err instanceof NoProjectFoundError)) throw err;
    if (sbomInputs.length === 0) {
      throw new NoComponentsError(
        `${err.message}. For device firmware there is usually no lockfile to scan — supply your own SBOM with --sbom <file.json> (CycloneDX JSON, spec 1.4-1.6).`,
      );
    }
    // Expected, not exceptional: this is the firmware case.
    warnings.push(
      `No npm or PyPI project was found at ${path.resolve(options.path)}, so no components came from a repo scan. ` +
        `Everything in this run came from the imported SBOM${sbomInputs.length === 1 ? '' : 's'}.`,
    );
  }

  const merged = mergeComponents(sources);
  if (merged.components.length === 0) {
    throw new NoComponentsError(
      'No software components were found to screen. An imported SBOM with no components, and no scannable project, leaves nothing to report on.',
    );
  }

  const support = resolveSupport(merged.components, { asOf, ...(config?.fda ? { fda: config.fda } : {}) });
  const kev = screenKev(merged.components, { asOf });

  const input: FdaRenderInput = {
    asOf,
    generatedAt,
    toolVersion: getToolVersion(),
    ...(() => {
      const subject = resolveSubject(subjects, config, warnings);
      return subject ? { subject } : {};
    })(),
    // "Author of the SBOM data" is an NTIA minimum element and only the
    // manufacturer can supply it. Absent stays absent.
    ...(config?.manufacturer?.name ? { sbomAuthor: config.manufacturer.name } : {}),
    support,
    kev,
    mergeWarnings: [...warnings, ...merged.warnings],
    sbomInputs,
    ...(scanPath ? { scanPath } : {}),
    ...(dependencies.length > 0 ? { dependencies } : {}),
  };

  return { input, rows: joinRows(input), config };
}
