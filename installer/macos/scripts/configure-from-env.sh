#!/bin/bash

set -euo pipefail

PLIST_PATH="/Library/LaunchDaemons/com.eguard.agent.plist"
BOOTSTRAP_DIR="/Library/Application Support/eGuard"
BOOTSTRAP_FILE="${BOOTSTRAP_DIR}/bootstrap.conf"
TMP_ENV_FILE=""
BOOTSTRAP_TMP=""

cleanup() {
    if [[ -n "$TMP_ENV_FILE" && -f "$TMP_ENV_FILE" ]]; then
        rm -f "$TMP_ENV_FILE"
    fi
    if [[ -n "$BOOTSTRAP_TMP" && -f "$BOOTSTRAP_TMP" ]]; then
        rm -f "$BOOTSTRAP_TMP"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: configure-from-env.sh [--env-file <path>] [--interactive]

Provide eGuard installer config as newline-separated EGUARD_* entries, for example:
EGUARD_SERVER_ADDR='https://server:1443'
EGUARD_ENROLLMENT_TOKEN='token'
EGUARD_TRANSPORT_MODE='grpc'
EGUARD_TLS_INSECURE_SKIP_VERIFY='true'
EOF
}

is_truthy() {
    local raw
    raw="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$raw" in
        1|true|yes|on|enabled|y) return 0 ;;
        *) return 1 ;;
    esac
}

contains_unsafe_chars() {
    local value="$1"
    [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]
}

trim_quotes() {
    local value="$1"
    value="${value%$'\r'}"
    value="${value#${value%%[![:space:]]*}}"
    value="${value%${value##*[![:space:]]}}"
    if [[ "$value" =~ ^\'.*\'$ || "$value" =~ ^\".*\"$ ]]; then
        value="${value:1:${#value}-2}"
    fi
    printf '%s' "$value"
}

is_valid_port() {
    local value="$1"
    [[ "$value" =~ ^[0-9]{1,5}$ ]] || return 1
    ((value >= 1 && value <= 65535))
}

extract_host_from_server() {
    local raw="$1"
    local without_scheme authority

    without_scheme="${raw#https://}"
    without_scheme="${without_scheme#http://}"
    authority="${without_scheme%%/*}"

    if [[ "$authority" == \[*\]* ]]; then
        authority="${authority#[}"
        authority="${authority%%]*}"
        printf '%s' "$authority"
        return
    fi

    if [[ "$authority" == *:* ]]; then
        printf '%s' "${authority%%:*}"
        return
    fi

    printf '%s' "$authority"
}

extract_port_from_server() {
    local raw="$1"
    local without_scheme authority

    without_scheme="${raw#https://}"
    without_scheme="${without_scheme#http://}"
    authority="${without_scheme%%/*}"

    if [[ "$authority" == \[*\]*:* ]]; then
        printf '%s' "${authority##*:}"
        return
    fi

    if [[ "$authority" == *:* ]]; then
        printf '%s' "${authority##*:}"
        return
    fi

    printf '%s' "50053"
}

validate_key() {
    case "$1" in
        EGUARD_SERVER_ADDR|EGUARD_SERVER|EGUARD_SERVER_HOST|EGUARD_ENROLLMENT_TOKEN|EGUARD_TRANSPORT_MODE|EGUARD_GRPC_PORT|EGUARD_TLS_INSECURE_SKIP_VERIFY|EGUARD_POLICY_REFRESH_INTERVAL_SECS|EGUARD_COMPLIANCE_CHECK_INTERVAL_SECS|EGUARD_COMPLIANCE_AUTO_REMEDIATE|EGUARD_INVENTORY_INTERVAL_SECS|EGUARD_DEVICE_OWNERSHIP|EGUARD_MEMORY_SCAN_ENABLED|EGUARD_MEMORY_SCAN_INTERVAL_SECS|EGUARD_KERNEL_INTEGRITY_ENABLED|EGUARD_KERNEL_INTEGRITY_INTERVAL_SECS|EGUARD_AUTONOMOUS_RESPONSE|EGUARD_RESPONSE_DRY_RUN)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

load_env_file() {
    local source_file="$1"
    local line key value

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        line="${line#${line%%[![:space:]]*}}"
        line="${line%${line##*[![:space:]]}}"
        [[ -z "$line" || "$line" == \#* ]] && continue

        if [[ "$line" != *=* ]]; then
            echo "Error: invalid config line: $line" >&2
            exit 1
        fi

        key="${line%%=*}"
        value="${line#*=}"
        key="${key#export }"
        key="${key#${key%%[![:space:]]*}}"
        key="${key%${key##*[![:space:]]}}"
        value="$(trim_quotes "$value")"

        if ! validate_key "$key"; then
            echo "Error: unsupported config key: $key" >&2
            exit 1
        fi
        if contains_unsafe_chars "$value"; then
            echo "Error: unsupported control characters in value for $key" >&2
            exit 1
        fi

        export "$key=$value"
    done < "$source_file"
}

prompt_for_env_file() {
    TMP_ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/eguard-installer-env.XXXXXX")"
    cat <<'EOF'
Paste your eGuard installer config block below, then press Ctrl-D:
EOF
    cat > "$TMP_ENV_FILE"
    load_env_file "$TMP_ENV_FILE"
}

ensure_plist_env_dict() {
    cat > "$PLIST_PATH" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.eguard.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/eguard-agent</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/usr/local/bin</string>
    <key>EnvironmentVariables</key>
    <dict/>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/eguard-agent.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/eguard-agent.err.log</string>
</dict>
</plist>
EOF
}

set_plist_env() {
    local key="$1"
    local value="$2"
    /usr/bin/plutil -replace "EnvironmentVariables.${key}" -string "$value" "$PLIST_PATH" 2>/dev/null \
        || /usr/bin/plutil -insert "EnvironmentVariables.${key}" -string "$value" "$PLIST_PATH"
}

ENV_FILE=""
INTERACTIVE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)
            ENV_FILE="$2"
            shift 2
            ;;
        --interactive)
            INTERACTIVE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -n "$ENV_FILE" ]]; then
    if [[ ! -f "$ENV_FILE" ]]; then
        echo "Error: env file not found: $ENV_FILE" >&2
        exit 1
    fi
    load_env_file "$ENV_FILE"
elif [[ "$INTERACTIVE" == "1" ]]; then
    prompt_for_env_file
else
    usage >&2
    exit 1
fi

SERVER_ADDR="${EGUARD_SERVER_ADDR:-${EGUARD_SERVER:-}}"
SERVER_HOST_OVERRIDE="${EGUARD_SERVER_HOST:-}"
TOKEN="${EGUARD_ENROLLMENT_TOKEN:-}"

if [[ -z "$SERVER_ADDR" ]]; then
    echo "Error: EGUARD_SERVER_ADDR is required" >&2
    exit 1
fi

if [[ -z "$TOKEN" ]]; then
    echo "Error: EGUARD_ENROLLMENT_TOKEN is required" >&2
    exit 1
fi

GRPC_PORT="${EGUARD_GRPC_PORT:-}"
if [[ -z "$GRPC_PORT" ]]; then
    GRPC_PORT="50053"
fi
if ! is_valid_port "$GRPC_PORT"; then
    echo "Error: invalid EGUARD_GRPC_PORT (must be 1-65535)" >&2
    exit 1
fi

SERVER_HOST="${SERVER_HOST_OVERRIDE:-$(extract_host_from_server "$SERVER_ADDR")}"
if [[ -z "$SERVER_HOST" ]] || contains_unsafe_chars "$SERVER_HOST"; then
    echo "Error: invalid EGUARD_SERVER_ADDR" >&2
    exit 1
fi

mkdir -p "$BOOTSTRAP_DIR"
chmod 700 "$BOOTSTRAP_DIR"

ensure_plist_env_dict

set_plist_env "EGUARD_ENROLLMENT_TOKEN" "$TOKEN"

for key in \
    EGUARD_TRANSPORT_MODE \
    EGUARD_GRPC_PORT \
    EGUARD_TLS_INSECURE_SKIP_VERIFY \
    EGUARD_POLICY_REFRESH_INTERVAL_SECS \
    EGUARD_COMPLIANCE_CHECK_INTERVAL_SECS \
    EGUARD_COMPLIANCE_AUTO_REMEDIATE \
    EGUARD_INVENTORY_INTERVAL_SECS \
    EGUARD_DEVICE_OWNERSHIP \
    EGUARD_MEMORY_SCAN_ENABLED \
    EGUARD_MEMORY_SCAN_INTERVAL_SECS \
    EGUARD_KERNEL_INTEGRITY_ENABLED \
    EGUARD_KERNEL_INTEGRITY_INTERVAL_SECS \
    EGUARD_AUTONOMOUS_RESPONSE \
    EGUARD_RESPONSE_DRY_RUN; do
    value="${!key:-}"
    if [[ -n "$value" ]]; then
        set_plist_env "$key" "$value"
    fi
done

BOOTSTRAP_TMP="$(mktemp "${TMPDIR:-/tmp}/eguard-bootstrap.XXXXXX")"
(umask 077; {
    printf '[server]\n'
    printf 'address = %s\n' "$SERVER_HOST"
    printf 'grpc_port = %s\n' "$GRPC_PORT"
    printf 'enrollment_token = %s\n' "$TOKEN"
} > "$BOOTSTRAP_TMP")
install -m 600 "$BOOTSTRAP_TMP" "$BOOTSTRAP_FILE"

/usr/sbin/chown root:wheel "$PLIST_PATH"
/bin/chmod 644 "$PLIST_PATH"
/usr/bin/plutil -lint "$PLIST_PATH" >/dev/null

launchctl bootout system/com.eguard.agent 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH"
launchctl enable system/com.eguard.agent
launchctl kickstart -k system/com.eguard.agent

echo "eGuard Agent configured and started."
