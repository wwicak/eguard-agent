#!/bin/sh
set -e

action="${1:-}"
case "$action" in
    upgrade|failed-upgrade|1)
        exit 0
        ;;
esac

# Remove immutable flag so package manager can clean up config.
chattr -i /etc/eguard-agent/agent.conf 2>/dev/null || true

if [ -d /run/systemd/system ]; then
    systemctl stop eguard-agent.service || true
    systemctl disable eguard-agent.service || true
fi
