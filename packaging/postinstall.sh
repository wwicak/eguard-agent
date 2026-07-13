#!/bin/sh
set -e

legacy_unit=/etc/systemd/system/eguard-agent.service
if [ -f "$legacy_unit" ] && [ ! -L "$legacy_unit" ]; then
    if grep -q '^Description=eGuard Endpoint Agent$' "$legacy_unit" \
        && grep -q '^ExecStart=/usr/bin/eguard-agent$' "$legacy_unit"; then
        sed -i 's/^TimeoutStopSec=.*/TimeoutStopSec=15s/' "$legacy_unit" || true
    fi
fi

if [ -d /etc/modules-load.d ]; then
    echo "nf_tables" > /etc/modules-load.d/eguard-agent.conf 2>/dev/null || true
fi
modprobe nf_tables 2>/dev/null || true

# Clear legacy immutability before ownership changes or enrollment's atomic rename.
if [ -f /etc/eguard-agent/agent.conf ]; then
    chattr -i /etc/eguard-agent/agent.conf 2>/dev/null || true
    chown root:root /etc/eguard-agent/agent.conf
    chmod 0600 /etc/eguard-agent/agent.conf
fi

restart_agent() {
    old_pid=$(systemctl show -p MainPID --value eguard-agent.service 2>/dev/null || true)
    target_version=$( (unset EGUARD_AGENT_VERSION; timeout 10 /usr/bin/eguard-agent --version 2>/dev/null | head -n 1) || true)
    if systemctl is-active --quiet eguard-agent.service; then
        systemctl kill --kill-who=main -s TERM eguard-agent.service
    else
        systemctl start eguard-agent.service
    fi
    i=0
    while [ "$i" -lt 30 ]; do
        pid=$(systemctl show -p MainPID --value eguard-agent.service 2>/dev/null || true)
        if [ -n "$pid" ] && [ "$pid" != 0 ] && [ "$pid" != "$old_pid" ] \
            && systemctl is-active --quiet eguard-agent.service \
            && [ "/proc/$pid/exe" -ef /usr/bin/eguard-agent ]; then
            live_version=$( (unset EGUARD_AGENT_VERSION; timeout 10 "/proc/$pid/exe" --version 2>/dev/null | head -n 1) || true)
            if [ -z "$target_version" ] || [ -z "$live_version" ] || [ "$live_version" = "$target_version" ]; then
                return 0
            fi
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || echo "agent postinstall: daemon-reload failed" >&2
    systemctl enable eguard-agent.service || echo "agent postinstall: enable failed" >&2
    if ! restart_agent; then
        echo "agent postinstall: restart could not be verified on the installed binary" >&2
    fi
fi
exit 0
