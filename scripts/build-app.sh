#!/usr/bin/env bash
# Builds SLMtune.app (universal: Apple Silicon + Intel) with all cores and the helper, signs it ad hoc and
# packs SLMtune.dmg. Runs on macOS with Xcode (GitHub Actions: .github/workflows/macos.yml).
#   scripts/build-app.sh [version]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-4.1}"
BUILD="${BUILD_NUMBER:-1}"
DIST="$ROOT/dist"
APP="$DIST/SLMtune.app"
cd "$ROOT"

echo "== swift build (arm64 + x86_64)"
swift build -c release --arch arm64 --arch x86_64 --product SLMtune
swift build -c release --arch arm64 --arch x86_64 --product SLMtuneHelper
BIN="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)"

rm -rf "$DIST" && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/helper" "$APP/Contents/Resources/cores"
cp "$BIN/SLMtune" "$APP/Contents/MacOS/SLMtune"
cp "$BIN/SLMtuneHelper" "$APP/Contents/Resources/helper/SLMtuneHelper"
# SwiftPM resource bundles of the dependencies (if any) next to the executable.
find "$BIN" -maxdepth 1 -name '*.bundle' -exec cp -R {} "$APP/Contents/Resources/" \;

echo "== cores"
if [ -n "${CORES_DIR:-}" ] && [ -d "$CORES_DIR" ]; then cp -R "$CORES_DIR/." "$APP/Contents/Resources/cores/"
else bash "$ROOT/scripts/fetch-cores.sh" "$APP/Contents/Resources/cores"; fi

echo "== resources"
cp -R Resources/en.lproj Resources/ru.lproj "$APP/Contents/Resources/"
cp Resources/server/*.sh Resources/logo.png "$APP/Contents/Resources/"
# Tor's built-in bridges: the bundle's own list when it has one (fresher), else ours.
PT="$APP/Contents/Resources/cores/tor/pluggable_transports/pt_config.json"
if [ -f "$PT" ]; then cp "$PT" "$APP/Contents/Resources/pt_config.json"; else cp Resources/pt_config.json "$APP/Contents/Resources/"; fi
ICON="$DIST/AppIcon.iconset"; mkdir -p "$ICON"
for s in 16 32 128 256 512; do
  sips -z $s $s Resources/icon-1024.png --out "$ICON/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) Resources/icon-1024.png --out "$ICON/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICON" -o "$APP/Contents/Resources/AppIcon.icns" && rm -rf "$ICON"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>SLMtune</string>
  <key>CFBundleDisplayName</key><string>SLMtune</string>
  <key>CFBundleIdentifier</key><string>com.slmtune.mac</string>
  <key>CFBundleExecutable</key><string>SLMtune</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$BUILD</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleDevelopmentRegion</key><string>ru</string>
  <key>CFBundleLocalizations</key><array><string>ru</string><string>en</string></array>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>SLMtune · GPL-3.0</string>
  <key>NSLocationWhenInUseUsageDescription</key><string>macOS показывает название сети Wi-Fi только с доступом к геолокации: оно нужно для правил «дома без VPN».</string>
  <key>NSLocationUsageDescription</key><string>macOS показывает название сети Wi-Fi только с доступом к геолокации: оно нужно для правил «дома без VPN».</string>
  <key>NSAppleEventsUsageDescription</key><string>Чтобы установить помощник с паролем администратора.</string>
  <key>CFBundleURLTypes</key><array><dict>
    <key>CFBundleURLName</key><string>SLMtune link</string>
    <key>CFBundleURLSchemes</key><array><string>slmtune</string></array>
  </dict></array>
</dict></plist>
EOF

echo "== sign (ad hoc)"
# Inner binaries first, then the app. Ad hoc: no Apple account; Gatekeeper asks once (right click → Open).
find "$APP/Contents/Resources" -type f \( -perm -u+x -o -name '*.dylib' \) -print0 | while IFS= read -r -d '' f; do
  file "$f" | grep -q Mach-O && codesign --force --sign - --timestamp=none "$f"
done
codesign --force --sign - --timestamp=none "$APP"
codesign --verify --deep --strict "$APP"

echo "== dmg"
STAGE="$DIST/dmg"; mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "SLMtune $VERSION" -srcfolder "$STAGE" -ov -format UDZO "$DIST/SLMtune.dmg" >/dev/null
rm -rf "$STAGE"
shasum -a 256 "$DIST/SLMtune.dmg"
du -sh "$APP" "$DIST/SLMtune.dmg"
