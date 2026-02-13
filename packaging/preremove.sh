#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl stop eguard-agent.service || true
    systemctl disable eguard-agent.service || true
fi
