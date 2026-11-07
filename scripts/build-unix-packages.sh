#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
GO=${GO:-/usr/local/go/bin/go}
VERSION=${1:-0.0.0-dev}
[[ "$VERSION" =~ ^[0-9][A-Za-z0-9.+-]*$ ]] || { echo 'Invalid version' >&2; exit 2; }
OUT=dist/unix
mkdir -p "$OUT"
for os in linux darwin; do
 for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch "$GO" build -trimpath -o "$OUT/eguard-nac-${os}-${arch}" ./cmd/nac-service
 done
done
for arch in amd64 arm64; do
 config="$OUT/nfpm-${arch}.yaml"
 printf '%s\n' "name: eguard-nac-agent" "arch: $arch" "platform: linux" "version: $VERSION" 'maintainer: eGuard' 'description: NAC-only posture, inventory and status agent (evaluation build)' 'license: Proprietary' 'contents:' > "$config"
 printf '  - src: %s\n    dst: %s\n' "$OUT/eguard-nac-linux-$arch" /usr/lib/eguard-nac/eguard-nac-service >> "$config"
 printf '  - src: %s\n    dst: %s\n    type: symlink\n' /usr/lib/eguard-nac/eguard-nac-service /usr/bin/eguard-nac >> "$config"
 printf '  - src: %s\n    dst: %s\n' packaging/systemd/eguard-nac.service /usr/lib/systemd/system/eguard-nac.service >> "$config"
 printf '%s\n' 'scripts:' '  postinstall: packaging/postinstall.sh' '  preremove: packaging/preremove.sh' '  postremove: packaging/postremove.sh' >> "$config"
 if command -v nfpm >/dev/null; then
  for format in deb rpm; do nfpm package --config "$config" --packager "$format" --target "$OUT/"; done
 else
  echo "nfpm unavailable; generated binaries and $config only (no download attempted)."
 fi
done
