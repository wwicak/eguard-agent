#!/bin/bash

set -euo pipefail

EGUARD_SERVER="${EGUARD_SERVER:-}"
ENROLLMENT_TOKEN="${EGUARD_ENROLLMENT_TOKEN:-}"
EGUARD_GRPC_PORT="${EGUARD_GRPC_PORT:-}"
DEFAULT_GRPC_PORT="${EGUARD_GRPC_PORT:-50053}"
PACKAGE_URL=""
DEFAULT_SERVER="${EGUARD_SERVER:-}"

usage() {
    cat <<'EOF'
Usage: install-eguard-agent.sh --server <host[:port]> [--token <token>] [--grpc-port <port>] [--url <package-url>]
EOF
}

has_url_scheme() {
    local value="$1"
    [[ "$value" == http://* || "$value" == https://* ]]
}

probe_server_base() {
    local raw_server="$1"
    local hostport="$raw_server"
    local probe_path="/api/v1/endpoint/ping"

    if has_url_scheme "$hostport"; then
        echo "$hostport"
        return 0
    fi

    local https_base="https://${hostport}"
    local http_base="http://${hostport}"

    if curl -fsSL --connect-timeout 5 --max-time 10 "${https_base}${probe_path}" -o /dev/null; then
        echo "$https_base"
        return 0
    fi

    if curl -fsSL --connect-timeout 5 --max-time 10 "${http_base}${probe_path}" -o /dev/null; then
        echo "$http_base"
        return 0
    fi

    echo "$https_base"
    return 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)
            EGUARD_SERVER="$2"
            shift 2
            ;;
        --token)
            ENROLLMENT_TOKEN="$2"
            shift 2
            ;;
        --grpc-port)
            EGUARD_GRPC_PORT="$2"
            shift 2
            ;;
        --url)
            PACKAGE_URL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$EGUARD_SERVER" && -n "$DEFAULT_SERVER" ]]; then
    EGUARD_SERVER="$DEFAULT_SERVER"
fi

if [[ -z "$EGUARD_SERVER" ]]; then
    echo "Error: --server is required" >&2
    exit 1
fi

if [[ -z "$EGUARD_GRPC_PORT" ]]; then
    EGUARD_GRPC_PORT="$DEFAULT_GRPC_PORT"
fi

if [[ -z "$EGUARD_GRPC_PORT" ]]; then
    EGUARD_GRPC_PORT="50053"
fi

if [[ -f /etc/debian_version ]]; then
    PKG_FORMAT="deb"
    INSTALL_CMD="dpkg -i"
elif [[ -f /etc/redhat-release ]] || [[ -f /etc/fedora-release ]]; then
    PKG_FORMAT="rpm"
    if command -v dnf5 >/dev/null 2>&1; then
        INSTALL_CMD="dnf5 install -y"
    elif command -v dnf >/dev/null 2>&1; then
        INSTALL_CMD="dnf install -y"
    elif command -v yum >/dev/null 2>&1; then
        INSTALL_CMD="yum install -y"
    else
        INSTALL_CMD="rpm -ivh --force"
    fi
else
    echo "Unsupported OS. This installer supports Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, and Fedora." >&2
    exit 1
fi

SERVER_BASE="$(probe_server_base "$EGUARD_SERVER")"

if [[ -z "$PACKAGE_URL" ]]; then
    PACKAGE_URL="${SERVER_BASE}/api/v1/agent-install/linux-${PKG_FORMAT}"
fi

SUDO=""
if [[ -n "${MOCK_LOG:-}" ]]; then
    SUDO=""
elif [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "Error: root privileges are required (run as root or install sudo)." >&2
        exit 1
    fi
fi

TMPFILE="$(mktemp "/tmp/eguard-agent.XXXXXX.${PKG_FORMAT}")"
trap 'rm -f "$TMPFILE"' EXIT

if [[ -n "$ENROLLMENT_TOKEN" ]]; then
    curl -fsSL "$PACKAGE_URL" -H "X-Enrollment-Token: ${ENROLLMENT_TOKEN}" -o "$TMPFILE"
else
    curl -fsSL "$PACKAGE_URL" -o "$TMPFILE"
fi

set +e
$SUDO sh -c "$INSTALL_CMD \"$TMPFILE\""
INSTALL_RC=$?
set -e

if [[ "$INSTALL_RC" -ne 0 ]]; then
    if ! command -v eguard-agent >/dev/null 2>&1 && ! [[ -x /usr/bin/eguard-agent ]]; then
        echo "Error: package installation failed (exit code $INSTALL_RC)" >&2
        exit 1
    fi
    echo "Package installed (postinst service restart returned $INSTALL_RC — expected with RefuseManualStop)"
fi

SERVER_ADDRESS="${EGUARD_SERVER#https://}"
SERVER_ADDRESS="${SERVER_ADDRESS#http://}"
SERVER_ADDRESS="${SERVER_ADDRESS%%/*}"
SERVER_HOST="$SERVER_ADDRESS"
if [[ "$SERVER_HOST" == \[*\]* ]]; then
    SERVER_HOST="${SERVER_HOST#[}"
    SERVER_HOST="${SERVER_HOST%%]*}"
elif [[ "$SERVER_HOST" == *:* ]]; then
    SERVER_HOST="${SERVER_HOST%%:*}"
fi

$SUDO install -d -m 0755 /etc/eguard-agent

GRPC_ADDR="${SERVER_HOST}:${EGUARD_GRPC_PORT}"
TOKEN_LINE=""
if [[ -n "$ENROLLMENT_TOKEN" ]]; then
    TOKEN_LINE="enrollment_token = \"${ENROLLMENT_TOKEN}\""
fi

$SUDO tee /etc/eguard-agent/agent.conf >/dev/null <<CONF
[agent]
id = ""
server_addr = "${GRPC_ADDR}"
${TOKEN_LINE}
mode = "active"

[transport]
mode = "grpc"

[response]
autonomous_response = true
dry_run = false

[response.definite]
kill = true
quarantine = true
capture_script = true

[response.very_high]
kill = true
quarantine = true
capture_script = true

[response.high]
kill = true
quarantine = false
capture_script = true

[response.medium]
kill = false
quarantine = false
capture_script = false

[response.rate_limit]
max_kills_per_minute = 10
max_quarantines_per_minute = 5
cooldown_secs = 60

[response.auto_isolation]
enabled = false
min_incidents_in_window = 3
window_secs = 300
max_isolations_per_hour = 2

[response.protected]
process_patterns = ["^systemd", "sshd", "dbus-daemon", "journald", "eguard-agent", "containerd", "dockerd"]
paths = ["/usr/bin", "/usr/sbin", "/usr/lib", "/lib", "/boot", "/usr/local/eg"]

[storage]
backend = "sqlite"
path = "/var/lib/eguard-agent/offline-events.db"
cap_mb = 100

[control_plane]
policy_refresh_interval_secs = 300
CONF

service_unit_exists() {
    local unit_name="$1"
    systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "${unit_name}.service"
}

detect_agent_binary() {
    local candidates=()
    if command -v eguard-agent >/dev/null 2>&1; then
        candidates+=("$(command -v eguard-agent)")
    fi
    candidates+=("/usr/local/bin/eguard-agent" "/usr/bin/eguard-agent")

    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    # Fall back to the standard package path when running in mocked or partially
    # upgraded environments where the package manager succeeded but the binary is
    # not yet visible on PATH.
    printf '%s\n' "/usr/bin/eguard-agent"
    return 0
}

write_fallback_unit() {
    local unit_name="$1"
    local binary_path="$2"

    $SUDO install -d -m 0755 /etc/systemd/system
    $SUDO tee "/etc/systemd/system/${unit_name}.service" >/dev/null <<UNIT
[Unit]
Description=eGuard Endpoint Agent
After=network-online.target
Wants=network-online.target
RefuseManualStop=yes
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
ExecStart=${binary_path}
Restart=always
RestartSec=1
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
TimeoutStopSec=5s

[Install]
WantedBy=multi-user.target
UNIT
    $SUDO systemctl daemon-reload
}

SYSTEMD_UNIT="${EGUARD_AGENT_SYSTEMD_UNIT:-eguard-agent}"
if ! service_unit_exists "$SYSTEMD_UNIT"; then
    if service_unit_exists "eguard-agent-server"; then
        SYSTEMD_UNIT="eguard-agent-server"
    else
        AGENT_BINARY="$(detect_agent_binary || true)"
        if [[ -z "$AGENT_BINARY" ]]; then
            echo "Error: no executable eguard-agent binary found to build fallback systemd unit." >&2
            exit 1
        fi
        SYSTEMD_UNIT="eguard-agent"
        write_fallback_unit "$SYSTEMD_UNIT" "$AGENT_BINARY"
    fi
fi

$SUDO systemctl enable "${SYSTEMD_UNIT}"
$SUDO systemctl restart "${SYSTEMD_UNIT}"

echo "eGuard Agent installed and enrolling with ${EGUARD_SERVER}"
