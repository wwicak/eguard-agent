#!/usr/bin/env bash
set -euo pipefail

SERVER="${EGUARD_SERVER:-}"
VERSION=""
CHECKSUM=""
PACKAGE_URL=""
FORMAT="deb"
UPDATE_DIR="/var/lib/eguard-agent/update"

usage() {
  cat <<'EOF'
Usage: apply-agent-update.sh --server <host[:port]> --version <X.Y.Z> --checksum <sha256> [--url <package-url>] [--format deb|rpm]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      SERVER="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --checksum)
      CHECKSUM="${2:-}"
      shift 2
      ;;
    --url)
      PACKAGE_URL="${2:-}"
      shift 2
      ;;
    --format)
      FORMAT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${SERVER}" || -z "${VERSION}" || -z "${CHECKSUM}" ]]; then
  echo "error: --server, --version and --checksum are required" >&2
  usage >&2
  exit 1
fi

if [[ "${FORMAT}" != "deb" && "${FORMAT}" != "rpm" ]]; then
  echo "error: --format must be deb or rpm" >&2
  exit 1
fi

if [[ -z "${PACKAGE_URL}" ]]; then
  PACKAGE_URL="https://${SERVER}/api/v1/agent-install/linux-${FORMAT}?version=${VERSION}"
fi

install -d -m 0755 "${UPDATE_DIR}"
pkg_path="${UPDATE_DIR}/eguard-agent-${VERSION}.${FORMAT}"

curl -fsSL "${PACKAGE_URL}" -o "${pkg_path}"
echo "${CHECKSUM}  ${pkg_path}" | sha256sum --check --status

if [[ "${FORMAT}" == "deb" ]]; then
  dpkg -i "${pkg_path}"
else
  rpm -Uvh "${pkg_path}"
fi

echo "updated eguard-agent to ${VERSION}; next heartbeat reports updated agent_version"
