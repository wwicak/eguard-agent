#!/bin/bash
set -euo pipefail

# eGuard Agent macOS installer
# Usage: curl -fsSL https://<server>/install-macos.sh | bash -s -- --server <url> --token <token>
#   or:  bash install.sh --server <url> --token <token>

SERVER_URL=""
TOKEN=""

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
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: install.sh --server <server_url> --token <enrollment_token>" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$SERVER_URL" ]] || [[ -z "$TOKEN" ]]; then
    echo "Usage: install.sh --server <server_url> --token <enrollment_token>" >&2
    exit 1
fi

echo "Installing eGuard Agent..."
echo "Server: $SERVER_URL"

# Download package
curl -fsSL \
    -H "X-Enrollment-Token: ${TOKEN}" \
    -o /tmp/eguard-agent.pkg \
    "${SERVER_URL}/api/v1/agent-install/macos"

# Write bootstrap config with restrictive permissions (contains enrollment token)
mkdir -p "/Library/Application Support/eGuard"
chmod 700 "/Library/Application Support/eGuard"
# Use single-quoted heredoc to avoid shell interpretation of special chars,
# and jq-style printf to produce valid JSON regardless of input content.
printf '{"server_url":"%s","enrollment_token":"%s"}\n' \
    "$(printf '%s' "$SERVER_URL" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    "$(printf '%s' "$TOKEN" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    > "/Library/Application Support/eGuard/bootstrap.conf"
chmod 600 "/Library/Application Support/eGuard/bootstrap.conf"

# Install package
sudo installer -pkg /tmp/eguard-agent.pkg -target /

# Cleanup
rm -f /tmp/eguard-agent.pkg

echo "eGuard Agent installed successfully."
