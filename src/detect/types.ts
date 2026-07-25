/**
 * Shared data model for repo-level fact detection (CRA compliance-posture
 * scanning), plus the Detector<T> interface individual detectors implement.
 *
 * Doctrine for everything in this file (binding for all detector
 * implementations, not just the types):
 *  - Fully offline at runtime: detectors must never make network calls.
 *  - Honest UNKNOWNs: an absent/unknown fact is an explicit field value
 *    (omit an optional field, or set a boolean to `false` when the thing
 *    was actively checked-for-and-not-found), never a missing key that
 *    silently drops information. Never guess or fabricate a value.
 *  - `run()` is synchronous and must not throw for the "nothing found"
 *    case — "not present" is a normal, representable fact, not an error.
 *
 * Path convention: every `*Path` / `paths` field in this file holds
 * repo-relative paths (relative to the `projectPath` passed to `run()`),
 * using forward slashes, matching the convention already used for
 * ScannedPackage.installPath in src/ecosystems/types.ts.
 */

/**
 * A single-purpose fact detector. `T` is whichever `*Facts` shape (or
 * sub-piece of RepoFacts) this detector produces.
 *
 * `id` should be a short, stable, kebab-case identifier (e.g. 'security',
 * 'vcs') — it's for logging/diagnostics, not for lookup keying into
 * RepoFacts (the orchestrator wires detector output to RepoFacts fields
 * explicitly, it does not key off `id`).
 */
export interface Detector<T> {
  id: string;
  run(projectPath: string): T;
}

/**
 * Presence of security-disclosure artifacts (SECURITY.md, security.txt,
 * or an equivalent vulnerability disclosure policy).
 */
export interface SecurityFacts {
  securityMdPresent: boolean;
  securityTxtPresent: boolean;
  vulnDisclosurePolicyPresent: boolean;
  /** Repo-relative paths of whichever of the above were found (empty array, never omitted, when none were found). */
  paths: string[];
}

/**
 * Facts about the scanned project's own declared license (distinct from
 * dependency license facts, which live under src/license/ and
 * src/ecosystems/ — this is only about the root project itself).
 */
export interface ProjectLicenseFacts {
  rootLicenseFilePresent: boolean;
  /** Repo-relative path to the root LICENSE file. Present if and only if rootLicenseFilePresent is true. */
  rootLicenseFilePath?: string;
  /** Declared license identifier/expression from package.json "license" or pyproject.toml, if present as a plain string. Absent means UNKNOWN/not declared, not "no license". */
  declaredLicenseId?: string;
}

/** Which package ecosystems were detected at the project root. */
export interface EcosystemFacts {
  detected: Array<'npm' | 'pypi'>;
}

/**
 * Declared runtime version constraints. Each field is absent when UNKNOWN
 * (not declared, or the manifest couldn't be read) — never defaulted to a
 * fabricated value.
 */
export interface RuntimeFacts {
  /** engines.node from package.json, if present. */
  node?: string;
  /** python_requires (setup.cfg/setup.py) or requires-python (pyproject.toml), if present. */
  python?: string;
}

/** Version-control facts, resolved via git only when the project is actually a git repo. */
export interface VcsFacts {
  isGitRepo: boolean;
  /**
   * Only set when isGitRepo is true and `git describe --tags --always`
   * resolved. This is a display-oriented identifier: when no reachable tag
   * exists, `--always` falls back to the abbreviated commit hash, so a
   * present `tag` value is NOT on its own evidence of a human-meaningful
   * release version — see `tagIsRealTag`, which distinguishes the two
   * cases explicitly rather than letting a bare commit hash pass as a tag.
   */
  tag?: string;
  /**
   * Only set when isGitRepo is true. True iff `tag` came from an actual
   * reachable git tag (`git describe --tags`, without `--always`,
   * succeeded) rather than the commit-hash fallback `--always` produces
   * when no tag exists. Exists so consumers can require a real release
   * version rather than accepting a bare commit hash as one.
   */
  tagIsRealTag?: boolean;
  /** Only set when isGitRepo is true and a commit resolved. */
  commit?: string;
  /** Only set when isGitRepo is true and a branch resolved. */
  branch?: string;
  /** Only set when isGitRepo is true and dirty-state could be determined. */
  dirty?: boolean;
}

/** Presence of automated dependency-update tooling configuration. */
export interface UpdateMechanismFacts {
  dependabotPresent: boolean;
  renovatePresent: boolean;
}

/**
 * The full set of repo-level facts gathered for CRA compliance-posture
 * scanning. These six top-level keys are a stable contract shared across
 * multiple detector implementations and the orchestrator/report layer —
 * do not rename, remove, or restructure them without updating every
 * consumer.
 */
export interface RepoFacts {
  security: SecurityFacts;
  projectLicense: ProjectLicenseFacts;
  ecosystems: EcosystemFacts;
  runtimes: RuntimeFacts;
  vcs: VcsFacts;
  updateMechanism: UpdateMechanismFacts;
}
