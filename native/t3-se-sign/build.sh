#!/usr/bin/env bash
# Builds the desktop's Touch ID approver into <out>/T3 Code.app (default out: dist/).
#
#   ./build.sh [--out DIR] [--arch arm64|x64|universal] [--icon FILE.icns]
#
# The binary sits in its own bundle named "T3 Code", because macOS names the caller on the
# Touch ID sheet ("T3 Code is trying to approve an admin request"); a bare binary would show its
# file name. Needs swiftc and the macOS SDK (Xcode Command Line Tools). Ad hoc signed, no
# entitlements: the key is a CryptoKit blob in a file, not a keychain item.
set -euo pipefail
cd "$(dirname "$0")"

out=dist
arch=universal
icon=
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --arch) arch="$2"; shift 2 ;;
    --icon) icon="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
case "$arch" in
  arm64) targets=(arm64) ;;
  x64) targets=(x86_64) ;;
  universal) targets=(arm64 x86_64) ;;
  *) echo "unknown arch $arch" >&2; exit 2 ;;
esac

bundle="$out/T3 Code.app"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rm -rf "$bundle"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"

slices=()
for target in "${targets[@]}"; do
  xcrun swiftc -O -target "$target-apple-macos13.0" -o "$work/$target" main.swift
  slices+=("$work/$target")
done
lipo -create "${slices[@]}" -output "$bundle/Contents/MacOS/T3 Code"

icon_entry=
if [ -n "$icon" ]; then
  cp "$icon" "$bundle/Contents/Resources/icon.icns"
  icon_entry="<key>CFBundleIconFile</key><string>icon</string>"
fi
cat > "$bundle/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.t3tools.t3code.touch-id</string>
  <key>CFBundleName</key><string>T3 Code</string>
  <key>CFBundleDisplayName</key><string>T3 Code</string>
  <key>CFBundleExecutable</key><string>T3 Code</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleShortVersionString</key><string>1</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  $icon_entry
</dict>
</plist>
PLIST
plutil -lint "$bundle/Contents/Info.plist" >/dev/null
codesign --force --sign - "$bundle"
echo "built $bundle" >&2
