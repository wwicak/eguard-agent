#!/bin/sh
set -eu
# nfpm: Debian passes upgrade; RPM passes remaining package count.
case "${1:-}" in
 upgrade) systemctl stop eguard-nac.service || true; exit 0 ;;
 *[!0-9]*|'') ;;
 *) if [ "$1" -ge 1 ]; then systemctl stop eguard-nac.service || true; exit 0; fi ;;
esac
# Test-only state override; production always uses the fixed provisioning root.
if [ -e "${EGUARD_NAC_TEST_STATE:-/var/lib/eguard-nac/state.json}" ]; then
 echo 'Run sudo eguard-nac uninstall [--token TOKEN | --authorization FILE] before removing this package.' >&2
 exit 1
fi
systemctl stop eguard-nac.service || true
systemctl disable eguard-nac.service || true
