#!/bin/zsh
set -eu
cd "${0:A:h}"
version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' Resources/Info.plist)
minimum_os=$(/usr/libexec/PlistBuddy -c 'Print LSMinimumSystemVersion' Resources/Info.plist)
work=$(mktemp -d "${TMPDIR:-/tmp}/cisco-release.XXXXXX")
trap 'rm -rf "$work"' EXIT
app="$work/Cisco Config Cleaner.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" releases
for arch in arm64 x86_64; do
    swiftc -target "$arch-apple-macos$minimum_os" -module-cache-path "$work/cache-$arch" AddressScheme.swift IdentityOptions.swift CoverageTests.swift SchemeTests.swift main.swift -o "$work/$arch"
done
"$work/$(uname -m)" --self-test
lipo -create "$work/arm64" "$work/x86_64" -output "$app/Contents/MacOS/CiscoConfigCleaner"
cp Resources/Info.plist "$app/Contents/Info.plist"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
codesign --force --deep --sign - "$app"
codesign --verify --deep "$app"
archive="releases/Cisco-Config-Cleaner-$version-macOS-universal.zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$archive"
(cd releases && shasum -a 256 "${archive:t}" > SHA256SUMS.txt)
