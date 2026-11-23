#!/bin/zsh
set -eu
cd "${0:A:h}"
app='Cisco Config Cleaner.app'
minimum_os=$(/usr/libexec/PlistBuddy -c 'Print LSMinimumSystemVersion' Resources/Info.plist)
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
swiftc -target "$(uname -m)-apple-macos$minimum_os" -module-cache-path "${TMPDIR:-/tmp}/cisco-cleaner-module-cache" AddressScheme.swift IdentityOptions.swift CoverageTests.swift SchemeTests.swift main.swift -o CiscoConfigCleaner-next
version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' Resources/Info.plist)
build=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' Resources/Info.plist)
[[ "$(./CiscoConfigCleaner-next --version)" == "v$version (build $build)" ]] || { print -u2 'Executable and bundle versions disagree'; exit 1; }
./CiscoConfigCleaner-next --self-test
cp Resources/Info.plist "$app/Contents/Info.plist"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
mv CiscoConfigCleaner-next "$app/Contents/MacOS/CiscoConfigCleaner"
codesign --force --deep --sign - "$app"
codesign --verify --deep "$app"
