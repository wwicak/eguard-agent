#!/bin/sh
set -eu
systemctl daemon-reload
systemctl enable eguard-nac.service
if [ -e "${EGUARD_NAC_TEST_STATE:-/var/lib/eguard-nac/state.json}" ]; then
 systemctl start eguard-nac.service
fi
# A fresh installation remains stopped until enrollment.
