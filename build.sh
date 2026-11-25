#!/bin/zsh
set -eu
cd "${0:A:h}"
app='Config Cleaner.app'
minimum_os=$(/usr/libexec/PlistBuddy -c 'Print LSMinimumSystemVersion' Resources/Info.plist)
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
swiftc -target "$(uname -m)-apple-macos$minimum_os" -module-cache-path "${TMPDIR:-/tmp}/cisco-cleaner-module-cache" AddressScheme.swift IdentityOptions.swift CoverageTests.swift SchemeTests.swift main.swift -o ConfigCleaner-next
version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' Resources/Info.plist)
build=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' Resources/Info.plist)
[[ "$(./ConfigCleaner-next --version)" == "v$version (build $build)" ]] || { print -u2 'Executable and bundle versions disagree'; exit 1; }
./ConfigCleaner-next --self-test
cp Resources/Info.plist "$app/Contents/Info.plist"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
# Include the license and notices in the signed application bundle.
cp LICENSE "$app/Contents/Resources/LICENSE.txt"
cp THIRD-PARTY-NOTICES.md "$app/Contents/Resources/THIRD-PARTY-NOTICES.txt"
mv ConfigCleaner-next "$app/Contents/MacOS/ConfigCleaner"
codesign --force --deep --sign - "$app"
codesign --verify --deep "$app"
