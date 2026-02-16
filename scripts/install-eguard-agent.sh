#!/usr/bin/env bash
set -euo pipefail

SERVER="${EGUARD_SERVER:-}"
TOKEN=""
PACKAGE_URL=""

usage() {
  cat <<'EOF'
Usage: install-eguard-agent.sh --server <host[:port]> [--token <token>] [--url <package-url>]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      SERVER="${2:-}"
      shift 2
      ;;
    --token)
      TOKEN="${2:-}"
      shift 2
      ;;
    --url)
      PACKAGE_URL="${2:-}"
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

if [[ -z "${SERVER}" ]]; then
  echo "error: --server is required" >&2
  exit 1
fi

if [[ -f /etc/debian_version ]]; then
  PKG_FORMAT="deb"
  INSTALL_CMD=(dpkg -i)
elif [[ -f /etc/redhat-release ]]; then
  PKG_FORMAT="rpm"
  INSTALL_CMD=(rpm -i)
else
  echo "unsupported os: expected debian- or redhat-based linux" >&2
  exit 1
fi

if [[ -z "${PACKAGE_URL}" ]]; then
  PACKAGE_URL="https://${SERVER}/api/v1/agent-install/linux-${PKG_FORMAT}"
fi

tmpfile="$(mktemp "/tmp/eguard-agent.XXXXXX.${PKG_FORMAT}")"
trap 'rm -f "${tmpfile}"' EXIT
curl -fsSL "${PACKAGE_URL}" -o "${tmpfile}"

"${INSTALL_CMD[@]}" "${tmpfile}"

if [[ -n "${TOKEN}" ]]; then
  install -d -m 0755 /etc/eguard-agent
  cat > /etc/eguard-agent/bootstrap.conf <<EOF
[server]
address = ${SERVER}
grpc_port = 50052
enrollment_token = ${TOKEN}
EOF
fi

systemctl enable eguard-agent
systemctl start eguard-agent

echo "eguard-agent installed from ${PACKAGE_URL}"
