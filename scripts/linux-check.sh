#!/usr/bin/env bash
# Builds the shared logic of the Mac app and runs its tests on Linux/WSL (the app itself needs a Mac):
#   wsl -d Ubuntu-24.04 -u root -- bash /mnt/g/slmtune-macos/scripts/linux-check.sh
# With SING_BOX=/path/to/sing-box it also checks the configs tools/ConfigDump writes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK_DIR:-$HOME/slmmac}"
. "${SWIFTLY_HOME_DIR:-$HOME/.local/share/swiftly}/env.sh" 2>/dev/null || true
rm -rf "$WORK/Sources" "$WORK/Tests" "$WORK/tools"
mkdir -p "$WORK"
cp -r "$ROOT/Package.swift" "$ROOT/Sources" "$ROOT/Tests" "$ROOT/tools" "$WORK/"
cd "$WORK"
echo "== build"
swift build 2>&1 | grep -E "error|warning: " || true
echo "== tests"
swift test 2>&1 | grep -E "error|failed|Executed .* tests" | tail -12
if [ -n "${SING_BOX:-}" ]; then
  echo "== sing-box check of generated configs"
  rm -rf configs && swift run ConfigDump configs >/dev/null 2>&1
  for f in configs/singbox-*.json; do "$SING_BOX" check -c "$f" && echo "ok $f" || echo "FAIL $f"; done
fi
