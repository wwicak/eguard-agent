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
mkdir -p /tmp/eguard-pkg-root/usr/local/bin
mkdir -p /tmp/eguard-pkg-root/Library/LaunchDaemons
mkdir -p "/tmp/eguard-pkg-root/Library/Application Support/eGuard/logs"

# Copy binary (assumes universal binary already built)
cp "${REPO_ROOT}/eguard-agent" /tmp/eguard-pkg-root/usr/local/bin/eguard-agent
chmod 755 /tmp/eguard-pkg-root/usr/local/bin/eguard-agent

# Copy LaunchDaemon plist
cp "$SCRIPT_DIR/com.eguard.agent.plist" /tmp/eguard-pkg-root/Library/LaunchDaemons/

# Build component package
pkgbuild \
    --root /tmp/eguard-pkg-root \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --scripts "$SCRIPT_DIR/scripts" \
    --install-location / \
    /tmp/eguard-agent-component.pkg

# Build product archive
productbuild \
    --distribution "$SCRIPT_DIR/Distribution.xml" \
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

# Notarize if credentials are available
if [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ]; then
    xcrun notarytool submit \
        "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg" \
        --apple-id "$APPLE_ID" \
        --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait
    xcrun stapler staple "$ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg"
fi

echo "Package built: $ARTIFACTS_DIR/eguard-agent-${VERSION}.pkg"

# Cleanup
rm -rf /tmp/eguard-pkg-root /tmp/eguard-agent-component.pkg
