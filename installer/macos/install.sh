#!/bin/bash
set -euo pipefail

# eGuard Agent macOS installer
# Usage: curl -fsSL https://<server>/install-macos.sh | bash -s -- <server_url> <enrollment_token>

SERVER_URL="${1:?Usage: install.sh <server_url> <enrollment_token>}"
TOKEN="${2:?Usage: install.sh <server_url> <enrollment_token>}"

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
(umask 077 && cat > "/Library/Application Support/eGuard/bootstrap.conf" <<EOF
{"server_url":"${SERVER_URL}","enrollment_token":"${TOKEN}"}
EOF
)
chmod 600 "/Library/Application Support/eGuard/bootstrap.conf"

# Install package
sudo installer -pkg /tmp/eguard-agent.pkg -target /

# Cleanup
rm -f /tmp/eguard-agent.pkg

echo "eGuard Agent installed successfully."
