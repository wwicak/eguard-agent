#!/bin/sh
set -eu
# Official cleanup empties the state directory; remove it only when empty.
rmdir /var/lib/eguard-nac 2>/dev/null || true
systemctl daemon-reload || true
