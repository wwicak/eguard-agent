#!/bin/bash
set -euo pipefail

# Build macOS .pkg installer for eGuard Agent.
#
# Signing / notarization (all optional — absent env => unsigned dev build):
#   Code signing identities must already be in the keychain search list
#   (the CI workflow imports them from base64 secrets; see release-agent.yml).
#     DEVELOPER_ID_APPLICATION   Developer ID Application identity (codesign the binary)
#     DEVELOPER_ID_INSTALLER     Developer ID Installer identity   (productsign the .pkg)
#   Notarization (prefers App Store Connect API key, falls back to Apple ID):
#     NOTARY_KEY_P8 / NOTARY_KEY_ID / NOTARY_ISSUER_ID   (ASC API key path + ids)
#     APPLE_ID / APPLE_TEAM_ID / APPLE_APP_PASSWORD      (legacy app-specific pw)
#
# Endpoint Security entitlement:
#   The agent collects telemetry via Apple's /usr/bin/eslogger, so the binary
#   does NOT need com.apple.developer.endpoint-security.client to function.
#   A bare Mach-O cannot embed a provisioning profile, and a Developer ID binary
#   that claims that restricted entitlement WITHOUT an authorizing profile is
#   killed by AMFI at launch on a normal (SIP-on) Mac. Therefore the entitlement
#   is applied ONLY when SIGN_ES_ENTITLEMENT=1 (used for SIP/AMFI-disabled test
#   VMs, or once the agent ships as a .systemextension bundle with a granted
#   provisioning profile). Default: OFF => safe, launches everywhere.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${VERSION:-0.1.0}"
IDENTIFIER="com.eguard.agent"
# Signing identifier for the ES client (matches the App ID registered for the
# endpoint-security entitlement). Overridable for other bundle ids.
CODESIGN_IDENTIFIER="${CODESIGN_IDENTIFIER:-id.eguard.agent.sysext}"
INSTALL_LOCATION="/usr/local/bin"
ARTIFACTS_DIR="${REPO_ROOT}/artifacts/macos"
BUILD_DMG="${BUILD_DMG:-1}"

mkdir -p "$ARTIFACTS_DIR"

# Use a unique temp directory to avoid symlink attacks on shared runners.
PKG_ROOT="$(mktemp -d)"
trap 'rm -rf "$PKG_ROOT" /tmp/eguard-agent-component.pkg /tmp/Distribution-versioned.xml' EXIT

mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"
mkdir -p "$PKG_ROOT/Library/Application Support/eGuard/logs"

# Copy binary (assumes universal binary already built)
cp "${REPO_ROOT}/eguard-agent" "$PKG_ROOT/usr/local/bin/eguard-agent"
chmod 755 "$PKG_ROOT/usr/local/bin/eguard-agent"

# Copy LaunchDaemon plist
cp "$SCRIPT_DIR/com.eguard.agent.plist" "$PKG_ROOT/Library/LaunchDaemons/"

# ---------------------------------------------------------------------------
# Code-sign the agent binary (Developer ID Application + hardened runtime).
# Notarization requires a hardened-runtime, Developer ID signature.
# ---------------------------------------------------------------------------
if [ -n "${DEVELOPER_ID_APPLICATION:-}" ]; then
    CODESIGN_ARGS=(
        --force --timestamp --options runtime
        --identifier "$CODESIGN_IDENTIFIER"
        --sign "$DEVELOPER_ID_APPLICATION"
    )
    if [ "${SIGN_ES_ENTITLEMENT:-0}" = "1" ]; then
        echo "WARNING: signing with endpoint-security entitlement (SIGN_ES_ENTITLEMENT=1)."
        echo "         This binary will be killed by AMFI on a normal SIP-enabled Mac"
        echo "         unless it is a .systemextension bundle with a granted profile."
        CODESIGN_ARGS+=(--entitlements "$SCRIPT_DIR/entitlements.plist")
    fi
    codesign "${CODESIGN_ARGS[@]}" "$PKG_ROOT/usr/local/bin/eguard-agent"
    codesign --verify --strict --verbose=2 "$PKG_ROOT/usr/local/bin/eguard-agent"
    echo "Signed binary entitlements:"
    codesign -d --entitlements :- "$PKG_ROOT/usr/local/bin/eguard-agent" 2>/dev/null || true
fi

# Build component package
pkgbuild \
    --root "$PKG_ROOT" \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --scripts "$SCRIPT_DIR/scripts" \
    --install-location / \
    /tmp/eguard-agent-component.pkg

# Substitute version into Distribution.xml so installer metadata is accurate.
sed "s/version=\"0.1.0\"/version=\"${VERSION}\"/" \
    "$SCRIPT_DIR/Distribution.xml" > /tmp/Distribution-versioned.xml

# Build product archive
productbuild \
    --distribution /tmp/Distribution-versioned.xml \
    --package-path /tmp \
    "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg"

# Sign the installer package (Developer ID Installer)
if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
    productsign \
        --sign "$DEVELOPER_ID_INSTALLER" \
        "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg" \
        "$ARTIFACTS_DIR/eguard-agent-${VERSION}-signed.pkg"
    mv "$ARTIFACTS_DIR/eguard-agent-${VERSION}-signed.pkg" \
       "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg"
fi

# ---------------------------------------------------------------------------
# Notarize (prefer App Store Connect API key, else Apple ID app-specific pw).
# ---------------------------------------------------------------------------
PKG_PATH="$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg"
if [ -n "${NOTARY_KEY_P8:-}" ] && [ -n "${NOTARY_KEY_ID:-}" ] && [ -n "${NOTARY_ISSUER_ID:-}" ]; then
    echo "Notarizing via App Store Connect API key ${NOTARY_KEY_ID}…"
    xcrun notarytool submit "$PKG_PATH" \
        --key "$NOTARY_KEY_P8" \
        --key-id "$NOTARY_KEY_ID" \
        --issuer "$NOTARY_ISSUER_ID" \
        --wait
    xcrun stapler staple "$PKG_PATH"
elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    echo "Notarizing via Apple ID ${APPLE_ID}…"
    xcrun notarytool submit "$PKG_PATH" \
        --apple-id "$APPLE_ID" \
        --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait
    xcrun stapler staple "$PKG_PATH"
fi

echo "Package built: $PKG_PATH"

if [[ "$BUILD_DMG" == "1" ]]; then
    "$SCRIPT_DIR/scripts/build-dmg.sh" \
        --pkg "$PKG_PATH" \
        --out "$ARTIFACTS_DIR/eguard-agent-${VERSION}.dmg"
    echo "DMG built: $ARTIFACTS_DIR/eguard-agent-${VERSION}.dmg"
fi

# Cleanup handled by EXIT trap
