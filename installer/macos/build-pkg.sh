#!/bin/bash
set -euo pipefail

# Build macOS .pkg installer for eGuard Agent
# Requires: Xcode command line tools, Developer ID certificate

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${VERSION:-0.1.0}"
IDENTIFIER="com.eguard.agent"
INSTALL_LOCATION="/usr/local/bin"
ARTIFACTS_DIR="${REPO_ROOT}/artifacts/macos"

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

# Sign if certificate is available
if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
    productsign \
        --sign "$DEVELOPER_ID_INSTALLER" \
        "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg" \
        "$ARTIFACTS_DIR/eguard-agent-${VERSION}-signed.pkg"
    mv "$ARTIFACTS_DIR/eguard-agent-${VERSION}-signed.pkg" \
       "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg"
fi

# Notarize if all credentials are available
if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    xcrun notarytool submit \
        "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg" \
        --apple-id "$APPLE_ID" \
        --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait
    xcrun stapler staple "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg"
fi

echo "Package built: $ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg"
# Cleanup handled by EXIT trap
