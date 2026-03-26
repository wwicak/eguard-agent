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

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

open_fda_settings() {
    if have_cmd open; then
        /usr/bin/open "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles" >/dev/null 2>&1 || true
    fi
}

show_fda_popup() {
    local message="$1"

    if ! have_cmd osascript; then
        return 0
    fi

    osascript - "$message" <<'APPLESCRIPT' >/dev/null 2>&1 || true
on run argv
    set alertMessage to item 1 of argv
    try
        display dialog alertMessage with title "eGuard Installer" buttons {"Later", "Open Settings"} default button "Open Settings" with icon caution
        if button returned of result is "Open Settings" then
            do shell script "/usr/bin/open 'x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles'"
        end if
    end try
end run
APPLESCRIPT
}

check_full_disk_access() {
    local out_file err_file rc stderr_text

    if [[ ! -x /usr/bin/eslogger ]]; then
        return 2
    fi

    out_file="$(mktemp "${TMPDIR:-/tmp}/eguard-eslogger-out.XXXXXX")"
    err_file="$(mktemp "${TMPDIR:-/tmp}/eguard-eslogger-err.XXXXXX")"

    rc=0
    if ! /bin/bash -lc '
        out_file="$1"
        err_file="$2"
        /usr/bin/eslogger --format json exec >"$out_file" 2>"$err_file" &
        pid=$!
        sleep 1
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            exit 0
        fi
        wait "$pid"
    ' -- "$out_file" "$err_file"; then
        rc=$?
    fi

    stderr_text="$(tr -d '\r' < "$err_file" 2>/dev/null || true)"
    rm -f "$out_file" "$err_file"

    if printf '%s' "$stderr_text" | grep -qiE 'NOT_PERMITTED|Full Disk Access'; then
        return 1
    fi

    if [[ "$rc" -ne 0 ]]; then
        return 2
    fi

    return 0
}

notify_fda_requirement() {
    local message
    message="Full Disk Access is not enabled for /usr/local/bin/eguard-agent. The agent will run in degraded process-only mode until you grant it in System Settings > Privacy & Security > Full Disk Access."

    echo "Warning: $message" >&2
    echo "Opening the Full Disk Access settings page..." >&2
    open_fda_settings
    show_fda_popup "$message"
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
    <string>/Library/Application Support/eGuard</string>
    <key>EnvironmentVariables</key>
    <dict/>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>Nice</key>
    <integer>5</integer>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>8192</integer>
    </dict>
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

case "$(check_full_disk_access; printf '%s' "$?")" in
    1)
        notify_fda_requirement
        ;;
    2)
        echo "Warning: unable to verify Full Disk Access automatically; check /usr/local/bin/eguard-agent in System Settings > Privacy & Security > Full Disk Access if telemetry looks degraded." >&2
        ;;
esac
