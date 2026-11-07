#!/bin/sh
set -eu
systemctl daemon-reload
systemctl enable eguard-nac.service
# Enrollment alone starts the service. Never start on package installation.
