#!/usr/bin/env bash
# Build eGuard NAC installer (not code-signed). Usage:
#   NAC_BOOTSTRAP_PIN=<64 hex ed25519 pubkey> scripts/build-installer.sh [version]
# The pin is the enrollment-signing public key the agent trusts; it is compiled in
# and never read from disk. No signing is performed (no certificate available).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-0.2.0}"
PIN="${NAC_BOOTSTRAP_PIN:?NAC_BOOTSTRAP_PIN (64 lowercase hex) required}"
[[ "$PIN" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid NAC_BOOTSTRAP_PIN" >&2; exit 2; }
GO=${GO:-/usr/local/go/bin/go}
OUT=dist
PAY=$OUT/payload
rm -rf "$PAY"; mkdir -p "$PAY"
ENROLL_URL="${NAC_ENROLL_URL:-}"; ENROLL_CA="${NAC_ENROLL_CA_B64:-}"
if [[ -n "$ENROLL_URL" ]]; then [[ "$ENROLL_URL" =~ ^https://[A-Za-z0-9.:-]+$ && -n "$ENROLL_CA" ]] || { echo "NAC_ENROLL_URL needs https://host:port and NAC_ENROLL_CA_B64" >&2; exit 2; }; fi
LD="-X eguard-nac-agent/buildinfo.Version=$VERSION -s -w -X eguard-nac-agent/provision.BootstrapPinHex=$PIN -X eguard-nac-agent/selfenroll.ServerURL=$ENROLL_URL -X eguard-nac-agent/selfenroll.ServerCAB64=$ENROLL_CA"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
$GO build -trimpath -ldflags "$LD" -o "$PAY/eguard-nac-service.exe" ./cmd/nac-service
$GO build -trimpath -ldflags "$LD" -o "$PAY/nac-setup.exe" ./cmd/nac-setup
unset GOOS GOARCH CGO_ENABLED
cat > "$PAY/NOTICE.txt" <<EOF
eGuard NAC Agent ${VERSION}

This agent collects device posture for network access policy only: network
adapters (MAC/IP), device identity, domain membership, antivirus and firewall
status, with timestamps. It does not monitor user activity, browse history,
files, or run remote commands. It is not an EDR.

Unknown evidence is reported as Unknown. Access decisions are made by the eGuard
server and network devices, not by this agent.

Temporary enrollments are removed automatically after the server-defined expiry
while the device is running, or at the next boot.

This build is not Authenticode code-signed.
Third-party licenses: see docs/third-party-notices.md in the source distribution.
EOF
makensis -V2 -DVERSION="$VERSION" -DPAYLOAD="../../$PAY" installer/windows/eguard-nac.nsi
EXE="$OUT/eGuard-NAC-Setup-${VERSION}-x64.exe"
python3 scripts/gen-sbom.py "$GO" "$VERSION" "$OUT/eguard-nac-agent-${VERSION}.cdx.json" "$PAY/eguard-nac-service.exe" "$PAY/nac-setup.exe"
( cd "$OUT" && sha256sum "$(basename "$EXE")" payload/eguard-nac-service.exe payload/nac-setup.exe "eguard-nac-agent-${VERSION}.cdx.json" > SHA256SUMS )
echo "built $EXE"
cat "$OUT/SHA256SUMS"
