#!/usr/bin/env bash
set -euo pipefail

# scripts/make-demo-project.sh
#
# Deterministically rebuilds the "Northgate FlowMeter Agent" demo project —
# the fictional example manufacturer (Northgate Devices GmbH) used to
# generate the flagship marketing samples shipped at ../ceproof-site/
# report-sample.html and doc-sample.html. Before this script existed, that
# demo lived ad hoc under /tmp, was never committed anywhere, and could not
# be regenerated after a CRA data update or a report-rendering fix without
# manually re-deriving every detail from scratch.
#
# Built to be a realistic, best-case repo — real `npm install`, a real git
# history with a real annotated release tag, a real security-disclosure
# contact, and a real root LICENSE file — so ceproof's scan resolves as much
# as an honest best-case repo actually can. (An earlier ad hoc build of this
# same demo skipped `npm install` entirely, which left both of its
# dependencies unresolved — "2 of 2 resolved package(s) have an unknown
# license category" in the shipped sample pack. That's the wrong demo to put
# in front of a prospective buyer, and is exactly the kind of drift this
# script exists to make impossible to reintroduce.)
#
# Usage:
#   scripts/make-demo-project.sh [target-dir]
#
# If target-dir is omitted, a fresh directory is created under mktemp -d.
# If target-dir is given, it is wiped and rebuilt from scratch -- safe to
# re-run any time the demo needs regenerating.
#
# The demo directory ships its own ceproof.config.json (copied in from
# fixtures/ceproof.config.filled.json below, not hand-duplicated -- that
# fixture stays the single source of truth, and this script just re-copies
# whatever it currently contains), so the demo is fully self-contained: no
# separate --config flag pointing back into this dev repo is needed to
# regenerate the samples from it.
#
# The final project directory path is printed as the LAST line of stdout, so
# a caller can capture it with: DIR=$(scripts/make-demo-project.sh | tail -1)
#
# To regenerate the shipped samples from this demo:
#   DIR=$(scripts/make-demo-project.sh | tail -1)
#   ceproof report "$DIR" --key <a valid ceproof key> --format annex7 \
#     > /path/to/report-sample.html
#   ceproof report "$DIR" --key <a valid ceproof key> --format doc \
#     > /path/to/doc-sample.html
# (then re-apply the site's sample-bar wrapper — see M4-COMPLETION-REPORT.md)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${1:-}"

if [[ -z "$TARGET_DIR" ]]; then
  TARGET_DIR="$(mktemp -d -t ceproof-demo)"
else
  rm -rf "$TARGET_DIR"
  mkdir -p "$TARGET_DIR"
fi

echo "ceproof demo project (Northgate FlowMeter Agent) -> $TARGET_DIR" >&2

if ! command -v npm >/dev/null 2>&1; then
  echo "error: 'npm' is not installed or not on PATH." >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "error: 'git' is not installed or not on PATH." >&2
  exit 1
fi

# --- package.json -----------------------------------------------------------
# A small, realistic industrial-IoT product: two well-known, permissively
# (MIT) licensed dependencies. Deliberately minimal (2 deps, not 20) — the
# sample pack's job is to show what a COMPLETE, well-evidenced pack looks
# like, not to stress-test dependency-tree scale (fixtures/ already covers
# that for the test suite).
cat > "$TARGET_DIR/package.json" <<'EOF'
{
  "name": "northgate-flowmeter-agent",
  "version": "2.4.0",
  "description": "Modbus flow-meter telemetry agent for plant SCADA integration.",
  "license": "MIT",
  "dependencies": {
    "left-pad": "^1.3.0",
    "commander": "^12.1.0"
  }
}
EOF

# --- Root LICENSE file --------------------------------------------------
# Matches package.json's declared "license": "MIT" above -- a real repo
# claiming MIT normally has the text at its root, and ceproof's
# projectLicense detector checks for exactly that file's presence.
cat > "$TARGET_DIR/LICENSE" <<'EOF'
MIT License

Copyright (c) 2026 Northgate Devices GmbH

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
EOF

# --- Vulnerability-disclosure contact ---------------------------------------
# security@northgate-devices.example uses the RFC 2606 reserved ".example"
# TLD -- guaranteed to never resolve to a real mailbox, consistent with
# Northgate Devices GmbH being an explicitly fictional example manufacturer
# throughout the marketing site.
mkdir -p "$TARGET_DIR/.well-known"
cat > "$TARGET_DIR/.well-known/security.txt" <<'EOF'
Contact: mailto:security@northgate-devices.example
EOF

# --- Real npm install ---------------------------------------------------
# Real install (not a hand-authored lockfile) so ceproof resolves both
# dependencies' actual declared licenses from their real package metadata,
# the same way it would against a real customer repo.
echo "-- npm install (real, in $TARGET_DIR) --" >&2
(cd "$TARGET_DIR" && npm install --no-audit --no-fund >&2)

# --- Filled config (the human-required answers) -----------------------------
# Copied from the fixture, not hand-duplicated, so the fixture stays the one
# place this content is authored. Named ceproof.config.json to match the CLI's
# own default `--config ./ceproof.config.json` lookup -- callers don't need
# to pass --config at all to regenerate a fully-answered pack from this demo.
FILLED_CONFIG="$HERE/fixtures/ceproof.config.filled.json"
if [[ ! -f "$FILLED_CONFIG" ]]; then
  echo "error: fixture not found: $FILLED_CONFIG" >&2
  exit 1
fi
cp "$FILLED_CONFIG" "$TARGET_DIR/ceproof.config.json"

# --- Real git history, tagged release ---------------------------------------
# ceproof's VCS detector (src/detect/vcs.ts) only treats a project as having
# a real release identity when `git describe --tags` succeeds outright (not
# just `--always`, which falls back to a bare commit hash) -- see that
# file's comments. An annotated tag on a real commit is what makes the
# sample pack's release-identity fact genuine rather than fabricated copy.
(
  cd "$TARGET_DIR"
  git init -q
  git config user.name "Demo"
  git config user.email "demo@example.com"
  git add -A
  git commit -q -m "release v2.4.0"
  git tag -a v2.4.0 -m "v2.4.0"
)

echo "Demo project ready at: $TARGET_DIR" >&2
echo "  npm:    package.json + node_modules/ + package-lock.json (real install)" >&2
echo "  git:    real repo, tagged v2.4.0" >&2
echo "  root:   LICENSE (MIT), .well-known/security.txt" >&2
echo "  config: ceproof.config.json (filled, copied from fixtures/ceproof.config.filled.json)" >&2

# Last line of stdout is the path itself, so `DIR=$(script | tail -1)` works.
echo "$TARGET_DIR"
