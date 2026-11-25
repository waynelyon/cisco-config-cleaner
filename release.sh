#!/bin/zsh
set -eu
cd "${0:A:h}"
version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' Resources/Info.plist)
minimum_os=$(/usr/libexec/PlistBuddy -c 'Print LSMinimumSystemVersion' Resources/Info.plist)
work=$(mktemp -d "${TMPDIR:-/tmp}/cisco-release.XXXXXX")
trap 'rm -rf "$work"' EXIT
app="$work/Config Cleaner.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" releases
for arch in arm64 x86_64; do
    swiftc -target "$arch-apple-macos$minimum_os" -module-cache-path "$work/cache-$arch" AddressScheme.swift IdentityOptions.swift CoverageTests.swift SchemeTests.swift main.swift -o "$work/$arch"
done
version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' Resources/Info.plist)
build=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' Resources/Info.plist)
[[ "$("$work/$(uname -m)" --version)" == "v$version (build $build)" ]] || { print -u2 'Executable and bundle versions disagree'; exit 1; }
"$work/$(uname -m)" --self-test
lipo -create "$work/arm64" "$work/x86_64" -output "$app/Contents/MacOS/ConfigCleaner"
cp Resources/Info.plist "$app/Contents/Info.plist"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
# Include the license and notices in the signed application bundle.
cp LICENSE "$app/Contents/Resources/LICENSE.txt"
cp THIRD-PARTY-NOTICES.md "$app/Contents/Resources/THIRD-PARTY-NOTICES.txt"
signing_identity="${SIGNING_IDENTITY:-}"
notary_profile="${NOTARY_PROFILE:-}"
if [[ -n "$notary_profile" && -z "$signing_identity" ]]; then
    print -u2 'NOTARY_PROFILE requires SIGNING_IDENTITY'; exit 1
fi
if [[ -n "$signing_identity" ]]; then
    codesign --force --options runtime --timestamp --sign "$signing_identity" "$app"
else
    codesign --force --sign - "$app"
fi
codesign --verify --deep --strict "$app"
archive="releases/Config-Cleaner-$version-macOS-universal.zip"
if [[ -n "$notary_profile" ]]; then
    submission="$work/notarization.zip"
    ditto -c -k --sequesterRsrc --keepParent "$app" "$submission"
    xcrun notarytool submit "$submission" --keychain-profile "$notary_profile" --wait
    xcrun stapler staple "$app"
    xcrun stapler validate "$app"
    spctl --assess --type execute --verbose "$app"
fi
# Stage fresh archive in the temporary directory; avoid retaining stale ZIP entries.
ditto -c -k --sequesterRsrc --keepParent "$app" "$work/archive.zip"
mv -f "$work/archive.zip" "$archive"
(cd releases && shasum -a 256 "${archive:t}" > SHA256SUMS.txt)
