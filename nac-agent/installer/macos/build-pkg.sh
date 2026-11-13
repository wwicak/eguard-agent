#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=${VERSION:-0.0.0-dev}
[[ "$VERSION" =~ ^[0-9][A-Za-z0-9.+-]*$ ]] || exit 2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/root/Library/eGuard NAC" "$WORK/root/Library/LaunchDaemons" dist/unix
# Build stamped universal payload unless the publisher provides one explicitly.
if [[ -z "${BINARY:-}" ]]; then
 GO=${GO:-go}
 for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH=$arch "$GO" build -trimpath -ldflags "-X eguard-nac-agent/buildinfo.Version=$VERSION" -o "$WORK/nac-$arch" ./cmd/nac-service
 done
 lipo -create "$WORK/nac-amd64" "$WORK/nac-arm64" -output "$WORK/universal"
 BINARY="$WORK/universal"
fi
mkdir -p "$WORK/scripts"
cp installer/macos/scripts/* "$WORK/scripts/"
{
 printf '#!/bin/sh\nNAC_NEW_VERSION=%s\nNAC_INSTALLED_BINARY="/Library/eGuard NAC/eguard-nac-service"\n' "$VERSION"
 cat packaging/version-policy.sh installer/macos/scripts/preinstall
} > "$WORK/scripts/preinstall"
chmod 755 "$WORK/scripts/"*
cp "$BINARY" "$WORK/root/Library/eGuard NAC/eguard-nac-service"
chmod 755 "$WORK/root/Library/eGuard NAC/eguard-nac-service"
cp installer/macos/id.eguard.nac.plist "$WORK/root/Library/LaunchDaemons/"
if [[ -n "${DEVELOPER_ID_APPLICATION:-}" ]]; then
 codesign --force --timestamp --options runtime --identifier id.eguard.nac --sign "$DEVELOPER_ID_APPLICATION" "$WORK/root/Library/eGuard NAC/eguard-nac-service"
 codesign --verify --strict "$WORK/root/Library/eGuard NAC/eguard-nac-service"
fi
pkgbuild --root "$WORK/root" --identifier id.eguard.nac --version "$VERSION" --scripts "$WORK/scripts" --install-location / "$WORK/component.pkg"
sed "s/@VERSION@/$VERSION/g" installer/macos/Distribution.xml > "$WORK/Distribution.xml"
PKG="dist/unix/eGuard-NAC-$VERSION.pkg"
productbuild --distribution "$WORK/Distribution.xml" --package-path "$WORK" "$PKG"
if [[ -n "${DEVELOPER_ID_INSTALLER:-}" ]]; then
 productsign --sign "$DEVELOPER_ID_INSTALLER" "$PKG" "$WORK/signed.pkg"
 mv "$WORK/signed.pkg" "$PKG"
 pkgutil --check-signature "$PKG"
fi
if [[ -n "${DEVELOPER_ID_APPLICATION:-}" && -n "${DEVELOPER_ID_INSTALLER:-}" ]]; then
 if [[ -n "${NOTARY_KEY_P8:-}" && -n "${NOTARY_KEY_ID:-}" && -n "${NOTARY_ISSUER_ID:-}" ]]; then
  xcrun notarytool submit "$PKG" --key "$NOTARY_KEY_P8" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID" --wait
  xcrun stapler staple "$PKG"
 elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" ]]; then
  xcrun notarytool submit "$PKG" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD" --wait
  xcrun stapler staple "$PKG"
 fi
fi
