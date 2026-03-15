#!/bin/sh
set -e

legacy_unit=/etc/systemd/system/eguard-agent.service
if [ -f "$legacy_unit" ] && [ ! -L "$legacy_unit" ]; then
    if grep -q '^Description=eGuard Endpoint Agent$' "$legacy_unit" \
        && grep -q '^ExecStart=/usr/bin/eguard-agent$' "$legacy_unit"; then
        sed -i 's/^TimeoutStopSec=.*/TimeoutStopSec=15s/' "$legacy_unit" || true
    fi
fi

# Ensure nf_tables kernel module loads at boot (needed for nftables-based
# network isolation on Fedora/RHEL 9+ where iptables-legacy may be blocked).
if [ -d /etc/modules-load.d ]; then
    echo "nf_tables" > /etc/modules-load.d/eguard-agent.conf 2>/dev/null || true
fi
modprobe nf_tables 2>/dev/null || true

# Protect agent config from tampering via immutable flag.
if [ -f /etc/eguard-agent/agent.conf ]; then
    chattr +i /etc/eguard-agent/agent.conf 2>/dev/null || true
fi

if [ -d /run/systemd/system ]; then
    recover_cmd='sleep 2; systemctl daemon-reload || true; systemctl enable eguard-agent.service || true; systemctl reset-failed eguard-agent.service || true; systemctl restart eguard-agent.service || systemctl start eguard-agent.service || true'
    if command -v systemd-run >/dev/null 2>&1; then
        systemd-run --unit "eguard-agent-postinstall-$(date +%s)" --collect /bin/sh -c "$recover_cmd" >/dev/null 2>&1 || /bin/sh -c "$recover_cmd"
    else
        /bin/sh -c "$recover_cmd"
    fi
fi
