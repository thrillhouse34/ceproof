import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runActivate } from '../../src/cli/activate';

const REAL_KEY =
  'eyJwcm9kdWN0IjoiY2Vwcm9vZiIsInRpZXIiOiJpbmRpdmlkdWFsIiwibGljZW5zZUlkIjoiNzZaNTJOVzRHVSIsImlzc3VlZEF0IjoiMjAyNi0wNy0yNFQwNToyOTozOC4xMzRaIiwidXBkYXRlc1VudGlsIjoiMjAyNy0wNy0yNFQwNToyOTozOC4xMzRaIn0.1_Ji7XgwqBTNxY5zdG_0aBWrv5Z8QmXyn0z5ui3EFTw-4FA2f5kViCHuie7MLLLIqSrv1btxHZwkDI8-1nWhDw';

describe('runActivate', () => {
  let scratch: string;
  let keyFile: string;

  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'lp-activate-'));
    keyFile = path.join(scratch, 'nested', 'ceproof', 'license.key');
  });

  afterEach(() => {
    fs.rmSync(scratch, { recursive: true, force: true });
  });

  it('stores a valid key, names the tier, confirms unlock, exit 0, creates the dir tree', () => {
    const result = runActivate(REAL_KEY, { keyFilePath: keyFile });
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('individual'); // names the tier
    expect(result.output.toLowerCase()).toContain('unlock');
    expect(fs.existsSync(keyFile)).toBe(true);
    expect(fs.readFileSync(keyFile, 'utf8')).toBe(REAL_KEY);
  });

  it('trims surrounding whitespace before storing (stores the clean key)', () => {
    const result = runActivate(`  ${REAL_KEY}\n`, { keyFilePath: keyFile });
    expect(result.exitCode).toBe(0);
    expect(fs.readFileSync(keyFile, 'utf8')).toBe(REAL_KEY);
  });

  it('rejects an empty key with exit 2, writes nothing', () => {
    const result = runActivate('   ', { keyFilePath: keyFile });
    expect(result.exitCode).toBe(2);
    expect(fs.existsSync(keyFile)).toBe(false);
  });

  it('rejects a malformed key (no separator) with a format-specific message, exit 2, nothing written', () => {
    const result = runActivate('this-is-not-a-key', { keyFilePath: keyFile });
    expect(result.exitCode).toBe(2);
    expect(result.output.toLowerCase()).toContain('does not look like a license key');
    expect(fs.existsSync(keyFile)).toBe(false);
  });

  it('rejects a tampered key (bad signature) with the generic verification message, exit 2, nothing written', () => {
    const lastDot = REAL_KEY.lastIndexOf('.');
    const s = REAL_KEY.slice(lastDot + 1);
    const tampered = REAL_KEY.slice(0, lastDot + 1) + (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
    const result = runActivate(tampered, { keyFilePath: keyFile });
    expect(result.exitCode).toBe(2);
    expect(result.output.toLowerCase()).toContain('could not be verified');
    expect(fs.existsSync(keyFile)).toBe(false);
  });

  it('does not overwrite/ create the file on any failure', () => {
    runActivate('garbage.garbage', { keyFilePath: keyFile });
    expect(fs.existsSync(keyFile)).toBe(false);
  });
});
