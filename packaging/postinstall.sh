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
    recover_cmd='sleep 2; systemctl daemon-reload || true; systemctl enable eguard-agent.service || true; systemctl reset-failed eguard-agent.service || true; systemctl restart eguard-agent.service || systemctl start eguard-agent.service || true'
    if command -v systemd-run >/dev/null 2>&1; then
        systemd-run --unit "eguard-agent-postinstall-$(date +%s)" --collect /bin/sh -c "$recover_cmd" >/dev/null 2>&1 || /bin/sh -c "$recover_cmd"
    else
        /bin/sh -c "$recover_cmd"
    fi
fi
