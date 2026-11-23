#!/bin/zsh
set -eu
cd "${0:A:h}"
app='Cisco Config Cleaner.app'
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
swiftc -module-cache-path "${TMPDIR:-/tmp}/cisco-cleaner-module-cache" AddressScheme.swift IdentityOptions.swift CoverageTests.swift SchemeTests.swift main.swift -o CiscoConfigCleaner-next
./CiscoConfigCleaner-next --self-test
cp Resources/Info.plist "$app/Contents/Info.plist"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
mv CiscoConfigCleaner-next "$app/Contents/MacOS/CiscoConfigCleaner"
codesign --force --deep --sign - "$app"
codesign --verify --deep "$app"
