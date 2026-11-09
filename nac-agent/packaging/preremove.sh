#!/bin/sh
set -eu
# Fail closed while enrolled: uninstall CLI enforces the signed anti-tamper
# selection and performs the authorization handoff before package removal.
if [ -e /var/lib/eguard-nac/state.json ]; then
 echo 'Run sudo eguard-nac uninstall [--token TOKEN | --authorization FILE] before removing this package.' >&2
 exit 1
fi
systemctl stop eguard-nac.service || true
systemctl disable eguard-nac.service || true
