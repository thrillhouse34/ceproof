#!/usr/bin/env bash
# Verifies that `npm pack` + a real install actually ships a working CLI —
# specifically that data/ (including cra-structure.json, the SPDX license
# texts the reused dependency-resolution engine still uses, etc.) is present
# in the tarball and gets loaded from node_modules/ceproof/data/ at runtime,
# not accidentally resolved via a dev-tree path.
#
# Also verifies the published-artifact side of the private-material safety
# story (a meaningfully different check from tests/license/noPrivateKeyLeak.
# test.ts, which scans the git-tracked REPO tree — this script scans the
# actual packed tarball + a real post-install tree, what a real
# `npm install ceproof` produces):
#   - the tarball ships nothing under scripts/keygen/
#   - the tarball ships nothing under data/sources/ (the M2 packaging
#     decision: full vendored primary-source text is build-time-only, never
#     published — only the distilled data/cra-structure.json ships)
#   - the installed tree contains no PEM private-key material
#   - the installed tree contains none of the internal planning docs
#
# M2 added `report` (Annex VII pack, Annex V DoC draft, SBOM formats) to the
# `scan`/`init` M1 shipped. M3 gates the narrative formats (annex7/
# annex7-pdf/doc/doc-pdf) behind a license key and registers `activate`/
# `deactivate` — this script verifies real gating against the installed CLI:
# the free SBOM format succeeds with no key, a gated format refuses with
# exit 3 and writes nothing.
#
# Usage: bash scripts/verify-pack.sh
# Exits non-zero on any verification failure.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "==> Building..."
npm run build

echo "==> Packing..."
npm pack --pack-destination /tmp

TARBALL=$(ls -t /tmp/ceproof-*.tgz | head -1)
echo "==> Tarball: $TARBALL"

# Captured ONCE into a variable and grepped via here-strings (<<<) everywhere
# below, rather than repeatedly piping `tar -tzf "$TARBALL" | grep -q ...`.
# That live-pipe form is a real, latent bug under `set -o pipefail`: `grep -q`
# exits the instant it finds a match, closing its stdin; `tar`, still writing
# to that now-closed pipe, dies from SIGPIPE; `pipefail` then reports the
# WHOLE pipeline as failed even though grep found exactly what it was looking
# for. It's a race (tar sometimes finishes first), so it doesn't always
# reproduce — which is exactly why it went unnoticed in licenseproof's
# original version of this script, which this one was adapted from. A
# here-string has no live producer process to receive a SIGPIPE at all.
TAR_LISTING=$(tar -tzf "$TARBALL")

echo "==> Confirming data/ is present inside the tarball..."
if ! grep -q '^package/data/manifest\.json$' <<<"$TAR_LISTING"; then
  echo "FAIL: data/manifest.json not found in tarball contents" >&2
  exit 1
fi
if ! grep -q '^package/data/cra-structure\.json$' <<<"$TAR_LISTING"; then
  echo "FAIL: data/cra-structure.json not found in tarball contents" >&2
  exit 1
fi

echo "==> Confirming the packed package.json still ships a real bin.ceproof entry..."
# npm's package.json normalizer (@npmcli/package-json's secureAndUnixifyPath)
# silently rewrites bin values it considers non-canonical -- e.g. a leading
# "./" -- and prints a misleadingly-worded "invalid and removed" warning even
# though it just reassigns the corrected value rather than deleting the bin
# entry. That warning going unnoticed on a real publish is exactly the recur-
# rence this guards against: assert the PACKED metadata still resolves to a
# real file in the tarball, not just that `npm publish` exited 0.
PACKED_PKG_JSON=$(tar -xzOf "$TARBALL" package/package.json)
BIN_VALUE=$(node -e '
  let s = "";
  process.stdin.on("data", d => s += d);
  process.stdin.on("end", () => {
    const pkg = JSON.parse(s);
    process.stdout.write((pkg.bin && pkg.bin.ceproof) || "");
  });
' <<<"$PACKED_PKG_JSON")
if [ -z "$BIN_VALUE" ]; then
  echo "FAIL: packed package.json has no bin.ceproof entry" >&2
  exit 1
fi
echo "==> Packed bin.ceproof = $BIN_VALUE"
if ! grep -qF "package/$BIN_VALUE" <<<"$TAR_LISTING"; then
  echo "FAIL: packed bin.ceproof points at '$BIN_VALUE', which is not a file in the tarball" >&2
  exit 1
fi

echo "==> Confirming the tarball ships nothing under scripts/keygen/..."
if grep -q '^package/scripts/keygen/' <<<"$TAR_LISTING"; then
  echo "FAIL: scripts/keygen/ found in the packed tarball" >&2
  grep '^package/scripts/keygen/' <<<"$TAR_LISTING" >&2
  exit 1
fi

echo "==> Confirming the tarball ships nothing under scripts/ at all..."
if grep -q '^package/scripts/' <<<"$TAR_LISTING"; then
  echo "FAIL: scripts/ found in the packed tarball" >&2
  grep '^package/scripts/' <<<"$TAR_LISTING" >&2
  exit 1
fi

echo "==> Confirming the tarball ships nothing under data/sources/ (M2 packaging decision: build-time-only primary-source text, never published)..."
if grep -q '^package/data/sources/' <<<"$TAR_LISTING"; then
  echo "FAIL: data/sources/ found in the packed tarball" >&2
  grep '^package/data/sources/' <<<"$TAR_LISTING" >&2
  exit 1
fi

TEMP_INSTALL_DIR=$(mktemp -d)
echo "==> Installing into a clean temp dir: $TEMP_INSTALL_DIR"
(
  cd "$TEMP_INSTALL_DIR"
  npm init -y >/dev/null
  npm install "$TARBALL" >/dev/null
)

echo "==> Confirming node_modules/ceproof/data/ exists on disk post-install..."
if [ ! -f "$TEMP_INSTALL_DIR/node_modules/ceproof/data/manifest.json" ]; then
  echo "FAIL: node_modules/ceproof/data/manifest.json missing after install" >&2
  exit 1
fi
if [ ! -f "$TEMP_INSTALL_DIR/node_modules/ceproof/data/cra-structure.json" ]; then
  echo "FAIL: node_modules/ceproof/data/cra-structure.json missing after install" >&2
  exit 1
fi

echo "==> Confirming node_modules/.bin/ceproof exists and is executable after a real install..."
# Proves the bin entry survived packing AND that npm actually wired the
# command on install, not just that the packed package.json contains the
# field. Bash's [ -x ] follows symlinks, so this checks the real target's
# executable bit, not just the symlink's own mode.
if [ ! -e "$TEMP_INSTALL_DIR/node_modules/.bin/ceproof" ]; then
  echo "FAIL: node_modules/.bin/ceproof does not exist after install" >&2
  exit 1
fi
if [ ! -x "$TEMP_INSTALL_DIR/node_modules/.bin/ceproof" ]; then
  echo "FAIL: node_modules/.bin/ceproof exists but is not executable" >&2
  exit 1
fi

INSTALLED_PKG_DIR="$TEMP_INSTALL_DIR/node_modules/ceproof"

echo "==> Scanning the installed package tree for private-key material..."
# Same style of check as tests/license/noPrivateKeyLeak.test.ts's repo-tree
# scan, but applied to the REAL installed post-npm-install tree instead of the
# git-tracked working tree — a private key could in principle leak into the
# published artifact even if it never touches the repo (e.g. via a stray
# "files" glob), so this is a distinct assertion, not a duplicate.
#
# The marker string is built from two halves at runtime (never written
# contiguously below) so this script's OWN source text never contains the
# literal substring tests/license/noPrivateKeyLeak.test.ts scans for — this
# script is a git-tracked file too, and would otherwise trip its own guard.
PEM_MARKER_PART1="PRIVATE"
PEM_MARKER_PART2="KEY"
PEM_BLOCK_REGEX="-----BEGIN ([A-Z0-9]+ )*${PEM_MARKER_PART1} ${PEM_MARKER_PART2}-----"
GENERIC_MARKER="${PEM_MARKER_PART1} ${PEM_MARKER_PART2}"

PEM_BLOCK_HITS=$(grep -rlE -- "$PEM_BLOCK_REGEX" "$INSTALLED_PKG_DIR" 2>/dev/null || true)
if [ -n "$PEM_BLOCK_HITS" ]; then
  echo "FAIL: PEM private-key block found in the installed package:" >&2
  echo "$PEM_BLOCK_HITS" >&2
  exit 1
fi
GENERIC_MARKER_HITS=$(grep -rlF -- "$GENERIC_MARKER" "$INSTALLED_PKG_DIR" 2>/dev/null || true)
if [ -n "$GENERIC_MARKER_HITS" ]; then
  echo "FAIL: generic private-key marker found in the installed package:" >&2
  echo "$GENERIC_MARKER_HITS" >&2
  exit 1
fi

echo "==> Confirming no internal planning docs shipped in the installed package..."
# The trailing "-iname '*report.md'" is deliberately broad and
# case-insensitive: it's meant to catch completion-report docs regardless of
# naming convention. This repo itself names its milestone reports
# 'M1-COMPLETION-REPORT.md', 'M2-COMPLETION-REPORT.md', etc. — uppercase,
# hyphenated, no underscore before "REPORT" — which the old case-sensitive
# '*_report.md' glob (inherited from licenseproof-private, which this repo
# was bootstrapped from) would have missed entirely. Any filename ending in
# "report.md", in any case or separator style, is caught by this single
# suffix match. Checked against `npm pack --dry-run --json`: the only *.md
# this package ships is README.md, which does not end in "report.md", so
# this stays non-flagging for real shipped docs.
FORBIDDEN_DOCS=$(find "$INSTALLED_PKG_DIR" -type f \( \
  -name 'milestone*_brief.md' -o \
  -name 'foundations_addendum.md' -o \
  -iname '*report.md' \
  \) 2>/dev/null || true)
if [ -n "$FORBIDDEN_DOCS" ]; then
  echo "FAIL: internal planning docs found in the installed package:" >&2
  echo "$FORBIDDEN_DOCS" >&2
  exit 1
fi

echo "==> Setting up a minimal scan target (a package.json with a real dependency, no node_modules or lockfile needed)..."
PACK_VERIFY_PROJECT=$(mktemp -d)
cat > "$PACK_VERIFY_PROJECT/package.json" <<'EOF'
{"name":"pack-verify-target","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}
EOF

BIN="$TEMP_INSTALL_DIR/node_modules/.bin/ceproof"

echo "==> Running the packed CLI (--format json) against the scan target..."
set +e
JSON_OUTPUT=$(node "$BIN" scan "$PACK_VERIFY_PROJECT" --format json --fail-on never)
JSON_EXIT=$?
set -e
echo "$JSON_OUTPUT"
echo "(exit code: $JSON_EXIT)"
if [ "$JSON_EXIT" -ne 0 ]; then
  echo "FAIL: packed scan --fail-on never exited $JSON_EXIT, expected 0" >&2
  exit 1
fi

echo "==> Checking for module-resolution errors..."
if grep -qiE 'cannot find module|enoent' <<<"$JSON_OUTPUT"; then
  echo "FAIL: output references a module-resolution error" >&2
  exit 1
fi

echo "==> Checking dataVersion and schemaVersion are populated (proves data/ loaded from the packed location)..."
if ! grep -q '"schemaVersion": *1' <<<"$JSON_OUTPUT"; then
  echo "FAIL: schemaVersion missing or not 1 in JSON output" >&2
  exit 1
fi
if ! grep -q '"dataVersion": *"[^"]\+"' <<<"$JSON_OUTPUT"; then
  echo "FAIL: dataVersion missing or empty in JSON output" >&2
  exit 1
fi
if ! grep -q '"gapChecklist"' <<<"$JSON_OUTPUT"; then
  echo "FAIL: gapChecklist missing from JSON output" >&2
  exit 1
fi

echo "==> Confirming --help resolves through the installed bin (shebang + bin wiring intact)..."
node "$BIN" --help >/dev/null

echo "==> Confirming ceproof init works through the installed bin..."
INIT_TARGET=$(mktemp -d)
node "$BIN" init "$INIT_TARGET" >/dev/null
if [ ! -f "$INIT_TARGET/ceproof.config.json" ]; then
  echo "FAIL: ceproof init did not write ceproof.config.json via the installed bin" >&2
  exit 1
fi
rm -rf "$INIT_TARGET"

# --- M3: real gating check against the packed + installed binary ---
#
# The installed CLI's key discovery reads `CEPROOF_KEY` from the process
# environment and, failing that, `~/.config/ceproof/license.key` from the
# REAL home directory. To guarantee a genuinely clean slate regardless of
# what's active on this machine, run the installed binary with CEPROOF_KEY
# unset AND HOME pointed at a fresh, empty scratch directory — this makes
# `~/.config/ceproof/license.key` resolve to a path guaranteed not to exist,
# without ever touching the real ~/.config/ceproof/ directory.
NOKEY_HOME=$(mktemp -d)
REPORT_OUT_DIR=$(mktemp -d)

echo "==> Verifying gating on the installed CLI with NO license key present anywhere (HOME=$NOKEY_HOME, CEPROOF_KEY unset)..."

echo "==> ceproof report --format sbom-cyclonedx (free format, no key) must succeed with a real written file..."
CYCLONE_OUT="$REPORT_OUT_DIR/sbom.cyclonedx.json"
set +e
CYCLONE_STDOUT=$(env -u CEPROOF_KEY HOME="$NOKEY_HOME" node "$BIN" report "$PACK_VERIFY_PROJECT" --format sbom-cyclonedx --out "$CYCLONE_OUT" 2>&1)
CYCLONE_EXIT=$?
set -e
echo "$CYCLONE_STDOUT"
echo "(exit code: $CYCLONE_EXIT)"
if [ "$CYCLONE_EXIT" -ne 0 ]; then
  echo "FAIL: sbom-cyclonedx (free, no key) exited $CYCLONE_EXIT, expected 0" >&2
  exit 1
fi
if [ ! -s "$CYCLONE_OUT" ]; then
  echo "FAIL: sbom-cyclonedx output file missing or empty at $CYCLONE_OUT" >&2
  exit 1
fi
if ! grep -q '"bomFormat"' "$CYCLONE_OUT"; then
  echo "FAIL: sbom-cyclonedx output at $CYCLONE_OUT does not look like real CycloneDX content" >&2
  exit 1
fi

echo "==> ceproof report --format annex7 (gated format, no key) must refuse politely with exit 3 and write nothing..."
ANNEX7_OUT="$REPORT_OUT_DIR/annex7.html"
set +e
ANNEX7_STDOUT=$(env -u CEPROOF_KEY HOME="$NOKEY_HOME" node "$BIN" report "$PACK_VERIFY_PROJECT" --format annex7 --out "$ANNEX7_OUT" 2>&1)
ANNEX7_EXIT=$?
set -e
echo "$ANNEX7_STDOUT"
echo "(exit code: $ANNEX7_EXIT)"
if [ "$ANNEX7_EXIT" -ne 3 ]; then
  echo "FAIL: annex7 (gated, no key) exited $ANNEX7_EXIT, expected 3" >&2
  exit 1
fi
if ! grep -q '\$99' <<<"$ANNEX7_STDOUT"; then
  echo "FAIL: unlicensed refusal message is missing the individual price (\$99)" >&2
  exit 1
fi
if ! grep -q '\$299' <<<"$ANNEX7_STDOUT"; then
  echo "FAIL: unlicensed refusal message is missing the agency price (\$299)" >&2
  exit 1
fi
if ! grep -q 'ceproof\.dev' <<<"$ANNEX7_STDOUT"; then
  echo "FAIL: unlicensed refusal message is missing ceproof.dev" >&2
  exit 1
fi
if [ -e "$ANNEX7_OUT" ]; then
  echo "FAIL: annex7 output file was written despite no license key being present: $ANNEX7_OUT" >&2
  exit 1
fi

rm -rf "$REPORT_OUT_DIR" "$NOKEY_HOME"

echo "==> Cleaning up..."
rm -rf "$TEMP_INSTALL_DIR" "$PACK_VERIFY_PROJECT" "$TARBALL"

echo "PASS: npm pack + install verification succeeded — data/ (including cra-structure.json) is packed, installed, and loaded correctly; keygen tooling, vendored primary-source text, and internal docs are excluded from the published artifact; scan, init, and report (free sbom-cyclonedx works keyless, gated annex7 refuses with exit 3) all work against the installed CLI."
