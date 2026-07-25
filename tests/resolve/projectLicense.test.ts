import { describe, it, expect } from 'vitest';
import { resolveProjectLicenseContext } from '../../src/resolve/projectLicense';

describe('resolveProjectLicenseContext', () => {
  it('uses the manifest license when no CLI override is given', () => {
    expect(resolveProjectLicenseContext('MIT', undefined)).toEqual({ displayId: 'MIT', modeId: 'MIT', wasUnspecified: false });
  });

  it('CLI override wins over the manifest license', () => {
    expect(resolveProjectLicenseContext('MIT', 'GPL-3.0-only')).toEqual({ displayId: 'GPL-3.0-only', modeId: 'GPL-3.0-only', wasUnspecified: false });
  });

  it('treats an absent manifest license and no override as unspecified, strictest mode', () => {
    expect(resolveProjectLicenseContext(undefined, undefined)).toEqual({ displayId: 'unspecified', modeId: 'proprietary', wasUnspecified: true });
  });

  it('treats an unparseable manifest license as unspecified', () => {
    expect(resolveProjectLicenseContext('not a real license expression OR', undefined)).toEqual({ displayId: 'unspecified', modeId: 'proprietary', wasUnspecified: true });
  });

  it('treats whitespace-only as unspecified', () => {
    expect(resolveProjectLicenseContext('   ', undefined)).toEqual({ displayId: 'unspecified', modeId: 'proprietary', wasUnspecified: true });
  });

  // licenseproof also tested that resolveProjectLicenseContext's modeId fed
  // correctly into deriveProjectLicenseMode (conflict-mode derivation).
  // ceproof has no conflict concept, so that derivation function and its
  // OR-expression test block were removed along with src/rules/conflicts.ts;
  // resolveProjectLicenseContext itself (tested above) is unchanged.
});
