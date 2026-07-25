/**
 * Detects presence of security-disclosure artifacts at a project root:
 * SECURITY.md, SECURITY (no extension), .well-known/security.txt, and
 * security.txt.
 *
 * Facts-only: this detector makes no judgment about whether a found policy
 * is well-formed or adequate (e.g. it does not parse security.txt per RFC
 * 9116) — it only reports presence and repo-relative paths.
 *
 * A "vulnerability disclosure policy" is treated as present whenever either
 * security.txt variant (.well-known/security.txt or security.txt) is found:
 * RFC 9116 security.txt is itself the vulnerability-disclosure-policy
 * mechanism, so the two concepts are the same artifact family in practice.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { Detector, SecurityFacts } from './types';

/** Candidate repo-relative paths, in the order they're checked. */
const SECURITY_MD_CANDIDATES = ['SECURITY.md', 'SECURITY'];
const SECURITY_TXT_CANDIDATES = [path.join('.well-known', 'security.txt'), 'security.txt'];

function findExisting(projectPath: string, candidates: string[]): string[] {
  const found: string[] = [];
  for (const candidate of candidates) {
    if (fs.existsSync(path.join(projectPath, candidate))) {
      found.push(candidate.split(path.sep).join('/'));
    }
  }
  return found;
}

function run(projectPath: string): SecurityFacts {
  const mdPaths = findExisting(projectPath, SECURITY_MD_CANDIDATES);
  const txtPaths = findExisting(projectPath, SECURITY_TXT_CANDIDATES);

  const securityMdPresent = mdPaths.length > 0;
  const securityTxtPresent = txtPaths.length > 0;

  return {
    securityMdPresent,
    securityTxtPresent,
    vulnDisclosurePolicyPresent: securityTxtPresent,
    paths: [...mdPaths, ...txtPaths],
  };
}

export const securityDetector: Detector<SecurityFacts> = { id: 'security', run };
