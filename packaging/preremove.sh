#!/bin/sh
set -e

action="${1:-}"
case "$action" in
    upgrade|failed-upgrade|1)
        exit 0
        ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl stop eguard-agent.service || true
    systemctl disable eguard-agent.service || true
fi
