#!/usr/bin/env bash
# Downloads every core for both Mac architectures from their official releases, checks the SHA-256 the
# publisher gives (GitHub's asset digest; Tor's sha256sums file), and makes universal binaries with lipo.
#   scripts/fetch-cores.sh <out-dir>        (macOS; GITHUB_TOKEN avoids the API rate limit)
set -euo pipefail
OUT="${1:?out dir}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT/tor"
AUTH=()
[ -n "${GITHUB_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN")

# asset <repo> <regex> <file>: the latest release's asset, checked against its digest.
asset() {
  local repo="$1" re="$2" dest="$3"
  curl -fsSL "${AUTH[@]}" -o "$WORK/rel.json" "https://api.github.com/repos/$repo/releases/latest"
  local line; line="$(python3 -c '
import json, re, sys
rel = json.load(open(sys.argv[2]))
for a in rel["assets"]:
    if re.search(sys.argv[1], a["name"]):
        print(a["browser_download_url"], (a.get("digest") or "").replace("sha256:", ""), rel["tag_name"]); break
' "$re" "$WORK/rel.json")"
  [ -n "$line" ] || { echo "no asset $re in $repo" >&2; exit 1; }
  set -- $line
  [ -n "${2:-}" ] || { echo "no digest for $1" >&2; exit 1; }
  curl -fsSL -o "$dest" "$1"
  echo "$2  $dest" | shasum -a 256 -c - >/dev/null || { echo "SHA-256 mismatch: $1" >&2; exit 1; }
  echo "  $repo $3 ← $(basename "$1")"
}

universal() { # universal <out> <arm64 file> <x86_64 file>
  lipo -create "$2" "$3" -output "$1"
  chmod 755 "$1"
}

echo "== sing-box"
for a in arm64 amd64; do
  asset SagerNet/sing-box "^sing-box-[0-9.]+-darwin-$a\\.tar\\.gz$" "$WORK/sb-$a.tgz"
  mkdir -p "$WORK/sb-$a" && tar -xzf "$WORK/sb-$a.tgz" -C "$WORK/sb-$a"
done
universal "$OUT/sing-box" "$(find "$WORK/sb-arm64" -name sing-box -type f)" "$(find "$WORK/sb-amd64" -name sing-box -type f)"

echo "== Xray"
asset XTLS/Xray-core '^Xray-macos-arm64-v8a\.zip$' "$WORK/x-arm.zip"
asset XTLS/Xray-core '^Xray-macos-64\.zip$' "$WORK/x-x64.zip"
mkdir -p "$WORK/x-arm" "$WORK/x-x64"
unzip -q "$WORK/x-arm.zip" -d "$WORK/x-arm"; unzip -q "$WORK/x-x64.zip" -d "$WORK/x-x64"
universal "$OUT/xray" "$WORK/x-arm/xray" "$WORK/x-x64/xray"

echo "== mihomo"
asset MetaCubeX/mihomo '^mihomo-darwin-arm64-v[0-9.]+\.gz$' "$WORK/m-arm.gz"
asset MetaCubeX/mihomo '^mihomo-darwin-amd64-compatible-v[0-9.]+\.gz$' "$WORK/m-x64.gz"
gunzip -c "$WORK/m-arm.gz" > "$WORK/m-arm"; gunzip -c "$WORK/m-x64.gz" > "$WORK/m-x64"
universal "$OUT/mihomo" "$WORK/m-arm" "$WORK/m-x64"

echo "== Hysteria 2"
asset apernet/hysteria '^hysteria-darwin-arm64$' "$WORK/h-arm"
asset apernet/hysteria '^hysteria-darwin-amd64$' "$WORK/h-x64"
universal "$OUT/hysteria" "$WORK/h-arm" "$WORK/h-x64"

echo "== NaiveProxy"
asset klzgrad/naiveproxy '^naiveproxy-v[0-9.]+-[0-9]+-mac-arm64-arm64\.tar\.xz$' "$WORK/n-arm.txz"
asset klzgrad/naiveproxy '^naiveproxy-v[0-9.]+-[0-9]+-mac-x64-x64\.tar\.xz$' "$WORK/n-x64.txz"
mkdir -p "$WORK/n-arm" "$WORK/n-x64"
tar -xf "$WORK/n-arm.txz" -C "$WORK/n-arm"; tar -xf "$WORK/n-x64.txz" -C "$WORK/n-x64"
universal "$OUT/naive" "$(find "$WORK/n-arm" -name naive -type f)" "$(find "$WORK/n-x64" -name naive -type f)"

echo "== TrustTunnel"
asset TrustTunnel/TrustTunnelClient '^trusttunnel_client-v[0-9.]+-macos-universal\.tar\.gz$' "$WORK/tt.tgz"
mkdir -p "$WORK/tt" && tar -xzf "$WORK/tt.tgz" -C "$WORK/tt"
install -m 755 "$(find "$WORK/tt" -name trusttunnel_client -type f | head -1)" "$OUT/trusttunnel_client"

echo "== Zapret (tpws)"
asset bol-van/zapret '^zapret-v[0-9.]+\.tar\.gz$' "$WORK/z.tgz"
mkdir -p "$WORK/z" && tar -xzf "$WORK/z.tgz" -C "$WORK/z"
install -m 755 "$(find "$WORK/z" -path '*binaries/mac64/tpws' -type f | head -1)" "$OUT/tpws"

echo "== Tor Expert Bundle"
V="$(curl -fsSL https://aus1.torproject.org/torbrowser/update_3/release/downloads.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
BASE="https://archive.torproject.org/tor-package-archive/torbrowser/$V"
curl -fsSL -o "$WORK/sums.txt" "$BASE/sha256sums-signed-build.txt"
for a in aarch64 x86_64; do
  f="tor-expert-bundle-macos-$a-$V.tar.gz"
  curl -fsSL -o "$WORK/$f" "$BASE/$f"
  (cd "$WORK" && grep "  $f\$" sums.txt | shasum -a 256 -c - >/dev/null) || { echo "Tor SHA-256 mismatch" >&2; exit 1; }
  mkdir -p "$WORK/tor-$a" && tar -xzf "$WORK/$f" -C "$WORK/tor-$a"
  echo "  Tor $V ← $f"
done
# Same layout in both: tor/, data/; every Mach-O becomes universal, the rest is copied.
A="$WORK/tor-aarch64"; X="$WORK/tor-x86_64"
(cd "$A" && find . -type f) | while read -r rel; do
  dest="$OUT/tor/$(echo "$rel" | sed -e 's#^\./tor/#./#' -e 's#^\./##')"
  mkdir -p "$(dirname "$dest")"
  if file "$A/$rel" | grep -q Mach-O && [ -f "$X/$rel" ]; then universal "$dest" "$A/$rel" "$X/$rel"; else cp "$A/$rel" "$dest"; fi
done
ls -la "$OUT" "$OUT/tor"
