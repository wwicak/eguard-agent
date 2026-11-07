#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
GO=${GO:-go}
export VERSION=${1:-0.0.0-dev}
[[ "$VERSION" =~ ^[0-9][A-Za-z0-9.+-]*$ ]] || { echo 'Invalid version' >&2; exit 2; }
export GPG_KEY_FILE=${GPG_KEY_FILE:-}
OUT=dist/unix
mkdir -p "$OUT"
for os in linux darwin; do
 for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch "$GO" build -trimpath -o "$OUT/eguard-nac-${os}-${arch}" ./cmd/nac-service
 done
done
NFPM=${NFPM:-$(command -v nfpm || true)}
if [[ -z "$NFPM" && -x "$HOME/go/bin/nfpm" ]]; then NFPM="$HOME/go/bin/nfpm"; fi
if [[ -z "$NFPM" ]]; then echo 'nfpm unavailable; binaries only.'; exit 0; fi
for ARCH in amd64 arm64; do
 export ARCH
 config="$OUT/nfpm-$ARCH.yaml"
 python3 -c 'import os; print(os.path.expandvars(open("packaging/nfpm.yaml").read()))' > "$config"
 rpmarch=x86_64; [[ "$ARCH" != arm64 ]] || rpmarch=aarch64
 "$NFPM" package --config "$config" --packager deb --target "$OUT/eguard-nac-agent_${VERSION}_${ARCH}.deb"
 "$NFPM" package --config "$config" --packager rpm --target "$OUT/eguard-nac-agent-${VERSION}-1.${rpmarch}.rpm"
done
