#!/bin/bash
set -euo pipefail

# eGuard Agent macOS installer
# Usage: curl -fsSL https://<server>/install-macos.sh | bash -s -- --server <url> (--token <token> | --token-file <file>) [--grpc-port <port>] [--sha256 <hash>]
#   or:  bash install.sh --server <url> (--token <token> | --token-file <file>) [--grpc-port <port>] [--sha256 <hash>]

SERVER_URL=""
TOKEN=""
TOKEN_FILE="${EGUARD_ENROLLMENT_TOKEN_FILE:-}"
EGUARD_GRPC_PORT="${EGUARD_GRPC_PORT:-}"
EXPECTED_SHA256=""
TOKEN_HEADER_FILE=""
ALLOW_INSECURE_HTTP_INSTALL="${EGUARD_ALLOW_INSECURE_HTTP_INSTALL:-0}"
REQUIRE_PKG_SIGNATURE="${EGUARD_REQUIRE_PKG_SIGNATURE:-0}"
MAX_PACKAGE_BYTES="${EGUARD_MAX_INSTALL_PKG_BYTES:-268435456}" # 256 MiB default

umask 077

contains_unsafe_chars() {
    local value="$1"
    [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]
}

is_truthy() {
    local raw
    raw="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$raw" in
        1|true|yes|on|enabled|y) return 0 ;;
        *) return 1 ;;
    esac
}

is_non_negative_int() {
    [[ "${1:-}" =~ ^[0-9]+$ ]]
}

is_valid_port() {
    local value="$1"
    [[ "$value" =~ ^[0-9]{1,5}$ ]] || return 1
    ((value >= 1 && value <= 65535))
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command not found: $cmd" >&2
        exit 1
    fi
}

validate_url_scheme() {
    local label="$1"
    local url="$2"

    if [[ "$url" == https://* ]]; then
        return 0
    fi

    if [[ "$url" == http://* ]]; then
        if is_truthy "$ALLOW_INSECURE_HTTP_INSTALL"; then
            echo "Warning: using insecure HTTP for ${label}; set EGUARD_ALLOW_INSECURE_HTTP_INSTALL=0 to enforce HTTPS" >&2
            return 0
        fi
        echo "Error: ${label} must use https:// (or set EGUARD_ALLOW_INSECURE_HTTP_INSTALL=1 for explicit insecure HTTP)" >&2
        exit 1
    fi

    echo "Error: invalid ${label} URL scheme (expected http:// or https://): ${url}" >&2
    exit 1
}

prepare_token_header_file() {
    local token_value="$1"
    local destination="$2"

    if [[ -z "$token_value" ]]; then
        return 0
    fi

    if contains_unsafe_chars "$token_value"; then
        echo "Error: enrollment token contains unsupported control characters" >&2
        exit 1
    fi

    printf 'X-Enrollment-Token: %s\n' "$token_value" > "$destination"
}

extract_host_from_url() {
    local raw="$1"
    local without_scheme
    local authority

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

read_token_from_file() {
    local token_path="$1"

    if [[ -z "$token_path" ]]; then
        return 0
    fi
    if contains_unsafe_chars "$token_path"; then
        echo "Error: token file path contains unsupported control characters" >&2
        exit 1
    fi
    if [[ ! -f "$token_path" ]]; then
        echo "Error: token file not found: $token_path" >&2
        exit 1
    fi

    TOKEN="$(tr -d '\r\n' < "$token_path")"
}

curl_fetch_file() {
    local url="$1"
    local output_path="$2"
    local token_header_path="${3:-}"

    local -a opts=(
        --fail
        --show-error
        --silent
        --location
        --retry 3
        --retry-delay 1
        --connect-timeout 10
        --max-time 180
    )

    if [[ "$url" == https://* ]]; then
        opts+=(--proto "=https" --tlsv1.2)
    else
        opts+=(--proto "=http,https")
    fi

    if [[ -n "$token_header_path" ]]; then
        opts+=( -H "@${token_header_path}" )
    fi

    curl "${opts[@]}" -o "$output_path" "$url"
}

curl_fetch_text() {
    local url="$1"
    local token_header_path="${2:-}"

    local -a opts=(
        --fail
        --show-error
        --silent
        --location
        --retry 3
        --retry-delay 1
        --connect-timeout 10
        --max-time 120
    )

    if [[ "$url" == https://* ]]; then
        opts+=(--proto "=https" --tlsv1.2)
    else
        opts+=(--proto "=http,https")
    fi

    if [[ -n "$token_header_path" ]]; then
        opts+=( -H "@${token_header_path}" )
    fi

    curl "${opts[@]}" "$url"
}

compute_sha256() {
    local file_path="$1"

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file_path" | awk '{print tolower($1)}'
        return
    fi

    if command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file_path" | awk '{print tolower($NF)}'
        return
    fi

    echo "Error: neither shasum nor openssl is available for SHA-256 verification" >&2
    exit 1
}

extract_sha256_from_json() {
    local json="$1"

    if command -v jq >/dev/null 2>&1; then
        jq -r '.sha256 // empty' <<<"$json" | tr 'A-F' 'a-f'
        return
    fi

    printf '%s' "$json" | tr -d '\n\r' | sed -nE 's/.*"sha256"[[:space:]]*:[[:space:]]*"([0-9a-fA-F]{64})".*/\1/p' | tr 'A-F' 'a-f'
}

verify_pkg_signature_if_required() {
    local pkg_path="$1"

    if ! is_truthy "$REQUIRE_PKG_SIGNATURE"; then
        return 0
    fi

    require_cmd pkgutil
    if ! pkgutil --check-signature "$pkg_path" >/dev/null 2>&1; then
        echo "Error: package signature verification failed for $pkg_path" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)
            SERVER_URL="${2:?--server requires a value}"
            shift 2
            ;;
        --token)
            TOKEN="${2:?--token requires a value}"
            shift 2
            ;;
        --token-file)
            TOKEN_FILE="${2:?--token-file requires a value}"
            shift 2
            ;;
        --grpc-port)
            EGUARD_GRPC_PORT="${2:?--grpc-port requires a value}"
            shift 2
            ;;
        --sha256)
            EXPECTED_SHA256="${2:?--sha256 requires a value}"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: install.sh --server <server_url> (--token <enrollment_token> | --token-file <path>) [--grpc-port <port>] [--sha256 <expected_sha256>]" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$SERVER_URL" ]]; then
    echo "Usage: install.sh --server <server_url> (--token <enrollment_token> | --token-file <path>) [--grpc-port <port>] [--sha256 <expected_sha256>]" >&2
    exit 1
fi

if [[ -n "$TOKEN" && -n "$TOKEN_FILE" ]]; then
    echo "Error: --token and --token-file are mutually exclusive" >&2
    exit 1
fi

if [[ -n "$TOKEN_FILE" ]]; then
    read_token_from_file "$TOKEN_FILE"
fi

if [[ -z "$TOKEN" ]]; then
    echo "Usage: install.sh --server <server_url> (--token <enrollment_token> | --token-file <path>) [--grpc-port <port>] [--sha256 <expected_sha256>]" >&2
    exit 1
fi

if contains_unsafe_chars "$SERVER_URL"; then
    echo "Error: server URL contains unsupported control characters" >&2
    exit 1
fi

if [[ "$SERVER_URL" != http://* && "$SERVER_URL" != https://* ]]; then
    SERVER_URL="https://${SERVER_URL}"
fi

validate_url_scheme "server" "$SERVER_URL"

if [[ -z "$EGUARD_GRPC_PORT" ]]; then
    EGUARD_GRPC_PORT="50052"
fi
if ! is_valid_port "$EGUARD_GRPC_PORT"; then
    echo "Error: invalid --grpc-port (must be 1-65535)" >&2
    exit 1
fi

require_cmd curl
require_cmd awk
require_cmd sed
require_cmd tr
require_cmd mktemp
require_cmd install
require_cmd installer
require_cmd wc

if ! is_non_negative_int "$MAX_PACKAGE_BYTES" || ((MAX_PACKAGE_BYTES < 1024)); then
    echo "Error: EGUARD_MAX_INSTALL_PKG_BYTES must be an integer >= 1024" >&2
    exit 1
fi

echo "Installing eGuard Agent..."
echo "Server: $SERVER_URL"

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "Error: root privileges are required (run as root or install sudo)." >&2
        exit 1
    fi
fi

PKG_PATH="$(mktemp "${TMPDIR:-/tmp}/eguard-agent.XXXXXX.pkg")"
BOOTSTRAP_TMP="$(mktemp "${TMPDIR:-/tmp}/eguard-bootstrap.XXXXXX")"
TOKEN_HEADER_FILE="$(mktemp "${TMPDIR:-/tmp}/eguard-token-header.XXXXXX")"
trap 'rm -f "$PKG_PATH" "$BOOTSTRAP_TMP" "$TOKEN_HEADER_FILE"' EXIT

prepare_token_header_file "$TOKEN" "$TOKEN_HEADER_FILE"

# Download package
curl_fetch_file "${SERVER_URL}/api/v1/agent-install/macos" "$PKG_PATH" "$TOKEN_HEADER_FILE"

PKG_SIZE_BYTES="$(wc -c < "$PKG_PATH" | tr -d '[:space:]')"
if ! is_non_negative_int "$PKG_SIZE_BYTES" || ((PKG_SIZE_BYTES == 0)); then
    echo "Error: downloaded package is empty or unreadable" >&2
    exit 1
fi
if ((PKG_SIZE_BYTES > MAX_PACKAGE_BYTES)); then
    echo "Error: downloaded package size (${PKG_SIZE_BYTES} bytes) exceeds cap (${MAX_PACKAGE_BYTES} bytes)" >&2
    exit 1
fi

if [[ -z "$EXPECTED_SHA256" ]]; then
    SHA256_JSON="$(curl_fetch_text "${SERVER_URL}/api/v1/agent-install/macos/sha256" "$TOKEN_HEADER_FILE")"
    EXPECTED_SHA256="$(extract_sha256_from_json "$SHA256_JSON")"
fi

if [[ ! "$EXPECTED_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "Error: invalid expected SHA-256 hash" >&2
    exit 1
fi

EXPECTED_SHA256="$(printf '%s' "$EXPECTED_SHA256" | tr 'A-F' 'a-f')"
ACTUAL_SHA256="$(compute_sha256 "$PKG_PATH")"

if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    echo "Error: package SHA-256 mismatch (expected $EXPECTED_SHA256, got $ACTUAL_SHA256)" >&2
    exit 1
fi

verify_pkg_signature_if_required "$PKG_PATH"

# Write bootstrap config with restrictive permissions (contains enrollment token)
BOOTSTRAP_DIR="/Library/Application Support/eGuard"
BOOTSTRAP_FILE="${BOOTSTRAP_DIR}/bootstrap.conf"
SERVER_HOST="$(extract_host_from_url "$SERVER_URL")"

if [[ -z "$SERVER_HOST" ]] || contains_unsafe_chars "$SERVER_HOST"; then
    echo "Error: unable to derive safe server host from --server" >&2
    exit 1
fi

(umask 077; {
    printf '[server]\n'
    printf 'address = %s\n' "$SERVER_HOST"
    printf 'grpc_port = %s\n' "$EGUARD_GRPC_PORT"
    printf 'enrollment_token = %s\n' "$TOKEN"
} > "$BOOTSTRAP_TMP")

$SUDO mkdir -p "$BOOTSTRAP_DIR"
$SUDO chmod 700 "$BOOTSTRAP_DIR"
$SUDO install -m 600 "$BOOTSTRAP_TMP" "$BOOTSTRAP_FILE"

# Install package
$SUDO installer -pkg "$PKG_PATH" -target /

echo "eGuard Agent installed successfully."
