#!/bin/sh
set -e

legacy_unit=/etc/systemd/system/eguard-agent.service
if [ -f "$legacy_unit" ] && [ ! -L "$legacy_unit" ]; then
    if grep -q '^Description=eGuard Endpoint Agent$' "$legacy_unit" \
        && grep -q '^ExecStart=/usr/bin/eguard-agent$' "$legacy_unit"; then
        sed -i 's/^TimeoutStopSec=.*/TimeoutStopSec=15s/' "$legacy_unit" || true
    fi
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable eguard-agent.service || true
    systemctl reset-failed eguard-agent.service || true
    systemctl start eguard-agent.service || systemctl restart eguard-agent.service || true
fi
