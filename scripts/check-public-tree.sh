#!/usr/bin/env bash
#
# check-public-tree.sh — prove that the PUBLIC file selection still typechecks
# and tests green, before it becomes a public commit.
#
# Why this exists: scripts/publish-mirror.sh correctly excludes the private
# key-generation tooling (scripts/keygen/**) from the public mirror, and the
# test suite is included. So any test with a STATIC import of an excluded
# module typechecks fine here and fails `tsc -p tsconfig.test.json` with
# TS2307 there — `npm test` exits 2 in the published mirror while being green
# in this repo, and nothing notices until someone runs it in the mirror. That
# happened twice (tests/report/noInternalArtifactLeak.test.ts shipped broken
# at 0.3.5, tests/license/keyFormat.test.ts joined it at 0.4.0).
#
# What it does: builds the same file selection publish-mirror.sh would copy
# (`git ls-files` minus its EXCLUDE_RE — read out of that script, not restated
# here), into a throwaway temp directory, then runs the repo's real `npm test`
# inside it.
#
# It does NOT build dist/, create a git remote, push, or write anything to
# ../ceproof-public. Nothing in this repo's working tree is touched. The temp
# directory is removed on exit, including on failure.
#
# Usage: npm run test:public-tree   (or: bash scripts/check-public-tree.sh)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MIRROR_SCRIPT="$REPO_ROOT/scripts/publish-mirror.sh"

# --- Reuse the mirror's own exclusion rule -----------------------------------
# Lift publish-mirror.sh's single EXCLUDE_RE assignment verbatim and eval it,
# so the public/private boundary is defined in exactly one place. Same
# source-of-truth trick tests/repo/publicMirrorNoDanglingRefs.test.ts already
# uses against the same anchored line shape; a check that restated the list
# would pass happily while the real mirror excluded something else.
EXCLUDE_LINE="$(grep -E "^EXCLUDE_RE='.+'\$" "$MIRROR_SCRIPT" || true)"
if [ "$(printf '%s' "$EXCLUDE_LINE" | grep -c .)" -ne 1 ]; then
  echo "FAIL: expected exactly one single-line EXCLUDE_RE='...' assignment in $MIRROR_SCRIPT" >&2
  echo "      (has the script's shape changed? this check and" >&2
  echo "       tests/repo/publicMirrorNoDanglingRefs.test.ts both read that line)" >&2
  exit 1
fi
eval "$EXCLUDE_LINE"

# Non-vacuity: if the pattern ever stops matching the keygen tooling, this
# check would be "passing" on a tree that still contains it, and the TS2307
# class of bug would be invisible again.
if ! printf '%s' 'scripts/keygen/issue.mjs' | grep -Eq "$EXCLUDE_RE"; then
  echo "FAIL: EXCLUDE_RE no longer excludes scripts/keygen/ — refusing to run a vacuous check" >&2
  exit 1
fi

# Built as a SIBLING of this repo, not under $TMPDIR, because that is where the
# real mirror goes (../ceproof-public) and two test groups resolve the private
# signing key relative to the tree they run from (`../ceproof-signing-key` —
# tests/license/verify.test.ts, tests/cli/reportGating.test.ts). From $TMPDIR
# they would skip themselves, and the check would quietly cover less than a real
# mirror run does. Nothing is written inside this repo, and the directory is
# removed on exit.
TMP="$(mktemp -d "$(cd "$REPO_ROOT/.." && pwd)/ceproof-public-tree-XXXXXX")"
cleanup() {
  chmod -R u+w "$TMP" 2>/dev/null || true
  rm -rf "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

# --- Same include list the mirror copies from --------------------------------
echo "==> Building the public file selection at: $TMP"
copied=0
excluded=0
while IFS= read -r -d '' f; do
  if printf '%s' "$f" | grep -Eq "$EXCLUDE_RE"; then
    excluded=$((excluded + 1))
    continue
  fi
  mkdir -p "$TMP/$(dirname "$f")"
  cp -p "$f" "$TMP/$f"
  copied=$((copied + 1))
done < <(git ls-files -z)
echo "==> Copied $copied tracked files, excluded $excluded internal files"

# The mirror is a real single-commit git repo, and several tests read the tree
# through git (`git ls-files`) or the VCS detector, so make this one a repo
# too — before the node_modules symlink below, which must not be added.
git -C "$TMP" init -q
git -C "$TMP" add -A
git -C "$TMP" -c user.name=ceproof -c user.email=ceproof@localhost \
  commit -q -m "public tree under test"

# dist/ is deliberately NOT built here: no test reads it, and this check is
# about the source selection. publish-mirror.sh builds it for the real mirror.

# node_modules is gitignored in both trees and installed, not copied. Symlink
# the already-installed one rather than reinstalling — `npm test` resolves
# tsc/vitest/tsx through it.
ln -s "$REPO_ROOT/node_modules" "$TMP/node_modules"

echo "==> Running the real \`npm test\` (tsc -p tsconfig.test.json && vitest run) in the public tree"
cd "$TMP"
npm test
echo "==> Public tree passes typecheck and tests"
