#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable eguard-agent.service
    systemctl start eguard-agent.service || true
fi
