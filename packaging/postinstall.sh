#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable eguard-agent.service || true
    systemctl reset-failed eguard-agent.service || true
    systemctl start eguard-agent.service || systemctl restart eguard-agent.service || true
fi
