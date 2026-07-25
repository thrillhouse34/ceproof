"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
//# sourceMappingURL=types.js.map