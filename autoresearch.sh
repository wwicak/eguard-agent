#!/usr/bin/env bash
# Windows AI-era autoresearch harness
# Lives in eguard-agent/ to avoid conflicting with the macOS agent's
# autoresearch.sh in fe_eguard/.
set -euo pipefail

FE_EGUARD="/home/dimas/fe_eguard"
SERVER_HOST="${EGUARD_SERVER_HOST:-192.168.122.25}"
SERVER_PASS="${EGUARD_SERVER_PASS:-Eguard123}"

# ═══════════════════════════════════════════════════════
# Phase 0: Build + deploy server binary from fe_eguard source
# ═══════════════════════════════════════════════════════
echo "=== BUILD SERVER BINARY ==="
cd "$FE_EGUARD/go"
go build -o /tmp/eg-agent-server-candidate ./cmd/eg-agent-server
cd "$OLDPWD"

echo "=== DEPLOY SERVER BINARY ==="
LOCAL_HASH="$(sha256sum /tmp/eg-agent-server-candidate | awk '{print $1}')"
REMOTE_HASH="$(sshpass -p "$SERVER_PASS" ssh -o StrictHostKeyChecking=no root@"$SERVER_HOST" 'sha256sum /usr/local/eg/sbin/eg-agent-server 2>/dev/null' | awk '{print $1}')"

if [ "$LOCAL_HASH" != "$REMOTE_HASH" ]; then
  echo "Binary changed ($LOCAL_HASH vs $REMOTE_HASH), deploying..."
  cat /tmp/eg-agent-server-candidate | sshpass -p "$SERVER_PASS" ssh -o StrictHostKeyChecking=no root@"$SERVER_HOST" \
    'cat > /tmp/eg-agent-server-new && chmod +x /tmp/eg-agent-server-new && cp /usr/local/eg/sbin/eg-agent-server /usr/local/eg/sbin/eg-agent-server.bak && systemctl stop eguard-agent-server.service && cp /tmp/eg-agent-server-new /usr/local/eg/sbin/eg-agent-server && systemctl start eguard-agent-server.service && sleep 2 && systemctl is-active eguard-agent-server.service'
  echo "=== WAITING FOR STABILIZATION (30s) ==="
  sleep 30
else
  SERVER_MEM="$(sshpass -p "$SERVER_PASS" ssh -o StrictHostKeyChecking=no root@"$SERVER_HOST" \
    'systemctl show eguard-agent-server.service --property=MemoryCurrent 2>/dev/null' | awk -F= '{print $2}' | tr -d '[:space:]')"
  SERVER_MEM_MB=$((${SERVER_MEM:-0} / 1048576))
  if [ "${SERVER_MEM_MB}" -gt 200 ]; then
    echo "Server memory high (${SERVER_MEM_MB}MB > 200MB), restarting..."
    sshpass -p "$SERVER_PASS" ssh -o StrictHostKeyChecking=no root@"$SERVER_HOST" \
      'systemctl restart eguard-agent-server.service && sleep 2 && systemctl is-active eguard-agent-server.service'
    echo "=== WAITING FOR STABILIZATION (30s) ==="
    sleep 30
  else
    echo "Binary unchanged, server memory OK (${SERVER_MEM_MB}MB), skipping restart"
  fi
fi

# ═══════════════════════════════════════════════════════
# Phase 1: Run Windows AI-era adversarial battery (W1-W40)
# The battery script derives ROOT_DIR from its own path inside fe_eguard/.
# ═══════════════════════════════════════════════════════
echo "=== RUNNING WINDOWS AI-ERA BATTERY (W1-W40) ==="
bash "$FE_EGUARD/scripts/windows-attack-battery.sh"
