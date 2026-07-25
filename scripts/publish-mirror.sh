#!/usr/bin/env bash
#
# publish-mirror.sh — build a clean, PUBLIC-ready single-commit git repo at
# ../ceproof-public from this private development repo.
#
# What it does:
#   - Copies every git-tracked file EXCEPT internal working documents and the
#     private key-generation tooling (see EXCLUDE_RE below), plus the built
#     dist/ tree (gitignored in this dev repo, but a required part of the
#     runnable public package: bin -> dist/cli/index.js).
#   - Initializes the target as a FRESH single-commit git repo. This is the
#     public mirror's own origin story, NOT a copy of this repo's private
#     development history.
#
# What it deliberately does NOT do (these are manual launch steps for Mark):
#   - Create a GitHub repo, add a git remote, or push anything anywhere.
#
# Idempotent: each run fully wipes and regenerates the target directory, so
# running it twice in a row produces the same clean result — never an
# accumulation of stale files from a previous run.
#
# It never reads from, writes to, or otherwise touches the sibling
# ../ceproof-private directory (itself — N/A, this IS that repo) or the
# sibling ../ceproof-signing-key directory, which holds the real private
# signing key entirely outside this repo's working tree (see
# scripts/keygen/generateSigningKey.mjs). The safety rails below refuse to
# run at all if TARGET is ever misconfigured to overlap either.
#
# data/sources/ decision: INCLUDED in the mirror (not excluded). It's the
# vendored EU primary-source text (EUR-Lex CRA consolidated text, BSI
# TR-03183-2) that every citation in the product traces back to — the
# traceability tests read it, and a source-available audit of "does this
# citation actually say what the tool claims" is impossible without it. It's
# already public EU regulatory text (zero sensitivity, unlike the signing
# key), and small: ~2.5MB across 5 files as of this writing, trivial for a
# git repo. Its exclusion from the *npm tarball* (package.json's "files"
# allowlist has "!data/sources") is a separate, unrelated packaging decision
# — nobody running `npx ceproof scan` needs a bundled copy of the regulation
# text on every install — and has no bearing on what the public source mirror
# should contain.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET="$(cd .. && pwd)/ceproof-public"

# --- Safety rails -----------------------------------------------------------
# Never let the target resolve to this repo, or to the real private-key
# directory (a genuine sibling of this repo — see comment above).
case "$TARGET" in
  *ceproof-private*)
    echo "refusing: target path overlaps this repo ($TARGET)" >&2
    exit 1
    ;;
  *ceproof-signing-key*)
    echo "refusing: target path overlaps the private signing-key directory ($TARGET)" >&2
    exit 1
    ;;
esac
if [ "$TARGET" = "$REPO_ROOT" ]; then
  echo "refusing: target path is the repo itself ($TARGET)" >&2
  exit 1
fi

# --- Build ------------------------------------------------------------------
echo "==> Building dist/ (npm run build)"
npm run build >/dev/null

# --- Regenerate a clean tree ------------------------------------------------
echo "==> Regenerating clean public tree at: $TARGET"
# This Mac's ~/Documents is iCloud-synced, and a previous run's target tree can
# pick up permission-restricted iCloud conflict-copy artifacts (e.g. a
# ".git 3" or "fixtures 3" directory dropped in read-only). A plain `rm -rf`
# can fail ("Directory not empty") against those and, under `set -e`, abort
# mid-wipe — leaving a broken half-regenerated mirror behind. Restore write
# permissions recursively first, and retry the removal once more before
# giving up, so re-running this script stays truly idempotent even when the
# previous target has stuck sync-conflict leftovers.
if [ -e "$TARGET" ]; then
  chmod -R u+w "$TARGET" 2>/dev/null || true
  rm -rf "$TARGET" 2>/dev/null || true
  if [ -e "$TARGET" ]; then
    chmod -R u+w "$TARGET" 2>/dev/null || true
    rm -rf "$TARGET"
  fi
fi
mkdir -p "$TARGET"

# Files to EXCLUDE from the public mirror, matched (anchored, full-path) against
# each git-tracked path with POSIX ERE:
#   milestone*_brief.md          — internal milestone briefs (business/planning)
#   foundations_addendum.md      — internal binding-decisions doc
#   M<N>-COMPLETION-REPORT.md    — internal per-milestone completion reports
#   scripts/keygen/**            — PRIVATE key-generation tooling. NEVER shipped.
#   docs/plans/**                — internal implementation-planning documents
#   .superpowers/**              — subagent-driven-development ledger/tooling
#                                  (internal process tooling, not the product;
#                                  not git-tracked today, guard for the future)
#
# NOT excluded (deliberate calls, not oversights):
#   CLAUDE.md, README-DEV.md     — dev-process/doctrine docs, same treatment as
#                                  licenseproof-public's README-DEV.md: public
#                                  transparency about how the tool is built and
#                                  verified is on-brand for a source-available,
#                                  audit-it-yourself compliance tool.
#   data/sources/**              — see the file-header comment above.
EXCLUDE_RE='^(milestone[^/]*_brief\.md|foundations_addendum\.md|M[0-9]+-COMPLETION-REPORT\.md|scripts/keygen/.*|docs/plans/.*|\.superpowers/.*)$'

# Copy every git-tracked file except the excluded ones, preserving structure.
copied=0
excluded=0
while IFS= read -r -d '' f; do
  if printf '%s' "$f" | grep -Eq "$EXCLUDE_RE"; then
    excluded=$((excluded + 1))
    continue
  fi
  mkdir -p "$TARGET/$(dirname "$f")"
  cp -p "$f" "$TARGET/$f"
  copied=$((copied + 1))
done < <(git ls-files -z)

# dist/ is gitignored in this dev repo but ships in the public package.
if [ -d dist ]; then
  cp -Rp dist "$TARGET/dist"
fi

echo "==> Copied $copied tracked files, excluded $excluded internal files, plus dist/"

# --- Defense-in-depth: refuse to publish if any key-shaped material made it
# into the copied tree. This repo has already paid once for a signing-key
# leak (repo deletion + key rotation) — the mirror gets the same non-vacuous
# guard as tests/license/noPrivateKeyLeak.test.ts, applied to the actual
# artifact about to become a public commit, not just to this dev repo's tree.
echo "==> Scanning copied tree for private-key material before committing"
if grep -rIl --exclude-dir=.git -E -- '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----' "$TARGET" >/tmp/ceproof-mirror-key-scan 2>/dev/null; then
  echo "refusing: PEM private-key block found in the copied tree:" >&2
  cat /tmp/ceproof-mirror-key-scan >&2
  rm -f /tmp/ceproof-mirror-key-scan
  exit 1
fi
rm -f /tmp/ceproof-mirror-key-scan

# --- Fresh single-commit git repo -------------------------------------------
cd "$TARGET"
rm -rf .git
git init -q
git add -A
# dist/ is listed in the copied .gitignore; force it in — the public repo ships
# a ready-to-run build.
git add -f dist
git commit -q -m "ceproof — EU Cyber Resilience Act compliance-posture scanner, offline CLI"

echo "==> Done. Clean single-commit public mirror at: $TARGET"
git log --oneline
