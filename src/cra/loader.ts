import * as fs from 'fs';
import * as path from 'path';
import { DATA_DIR } from '../paths';
import type { CraDerivability, CraInstrument, CraStructureFile, CraStructureItem } from './types';

const VALID_INSTRUMENTS: CraInstrument[] = ['annexVII', 'annexV'];
const VALID_DERIVABILITY: CraDerivability[] = ['derivable', 'partial', 'human-required', 'boilerplate'];

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

function assertString(value: unknown, field: string, itemLabel: string): void {
  if (!isNonEmptyString(value)) {
    throw new Error(`Malformed CRA structure data: ${itemLabel} field "${field}" must be a non-empty string`);
  }
}

function validateItem(raw: unknown, index: number): CraStructureItem {
  const itemLabel = `items[${index}]`;
  if (typeof raw !== 'object' || raw === null) {
    throw new Error(`Malformed CRA structure data: ${itemLabel} must be an object`);
  }
  const item = raw as Record<string, unknown>;

  assertString(item.id, 'id', itemLabel);
  assertString(item.requirementSummary, 'requirementSummary', itemLabel);
  assertString(item.citation, 'citation', itemLabel);
  assertString(item.sourceFile, 'sourceFile', itemLabel);
  assertString(item.sourceExcerpt, 'sourceExcerpt', itemLabel);

  if (typeof item.instrument !== 'string' || !VALID_INSTRUMENTS.includes(item.instrument as CraInstrument)) {
    throw new Error(
      `Malformed CRA structure data: ${itemLabel} field "instrument" must be one of ${VALID_INSTRUMENTS.join(', ')}`
    );
  }
  if (typeof item.derivability !== 'string' || !VALID_DERIVABILITY.includes(item.derivability as CraDerivability)) {
    throw new Error(
      `Malformed CRA structure data: ${itemLabel} field "derivability" must be one of ${VALID_DERIVABILITY.join(', ')}`
    );
  }
  if (!Array.isArray(item.evidenceKeys) || !item.evidenceKeys.every((k) => typeof k === 'string')) {
    throw new Error(`Malformed CRA structure data: ${itemLabel} field "evidenceKeys" must be an array of strings`);
  }

  if (item.derivability === 'boilerplate') {
    assertString(item.boilerplateText, 'boilerplateText', itemLabel);
  } else if (item.boilerplateText !== undefined) {
    throw new Error(
      `Malformed CRA structure data: ${itemLabel} has "boilerplateText" set but derivability is not "boilerplate"`
    );
  }

  return {
    id: item.id as string,
    instrument: item.instrument as CraInstrument,
    requirementSummary: item.requirementSummary as string,
    citation: item.citation as string,
    sourceFile: item.sourceFile as string,
    sourceExcerpt: item.sourceExcerpt as string,
    derivability: item.derivability as CraDerivability,
    evidenceKeys: item.evidenceKeys as string[],
    ...(item.boilerplateText !== undefined ? { boilerplateText: item.boilerplateText as string } : {}),
  };
}

export function parseCraStructure(raw: unknown): CraStructureFile {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Malformed CRA structure data: expected a top-level object');
  }
  const data = raw as Record<string, unknown>;

  assertString(data.sourceVersion, 'sourceVersion', 'root');
  assertString(data.generatedAt, 'generatedAt', 'root');

  if (!Array.isArray(data.items)) {
    throw new Error('Malformed CRA structure data: field "items" must be an array');
  }

  const items = data.items.map((item, index) => validateItem(item, index));

  return {
    sourceVersion: data.sourceVersion as string,
    generatedAt: data.generatedAt as string,
    items,
  };
}

let cached: CraStructureFile | undefined;

function load(): CraStructureFile {
  if (!cached) {
    const filePath = path.join(DATA_DIR, 'cra-structure.json');
    let raw: unknown;
    try {
      raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (err) {
      throw new Error(`Failed to read/parse CRA structure data at ${filePath}: ${(err as Error).message}`);
    }
    cached = parseCraStructure(raw);
  }
  return cached;
}

export function getCraStructure(): CraStructureFile {
  return load();
}

export function getCraSourceVersion(): string {
  return load().sourceVersion;
}
