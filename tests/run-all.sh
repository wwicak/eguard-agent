#!/usr/bin/env bash
set -euo pipefail

echo "[tst] enrollment + heartbeat"
echo "[tst] known malware hash (EICAR)"
echo "[tst] sigma webshell"
echo "[tst] c2 domain"
echo "[tst] kernel module load"
echo "[tst] reverse shell"
echo "[tst] entropy anomaly"
echo "[tst] compliance failure"
echo "[tst] agent tamper"
echo "[tst] offline buffering + reconnect drain"
echo "[tst] rule hot-reload + emergency push"
echo "[tst] protected process + rate limiter"
echo "[tst] quarantine + restore"
echo "[tst] lsm execution block"
echo "[tst] fleet correlation + z-score anomaly"

SIMULATE_CMD="${EGUARD_SIMULATE_CMD:-/usr/local/bin/tests/malware-sim/simulate.sh}"
"${SIMULATE_CMD}" all

cargo test -p response kill_process_tree_orders_children_before_parent -- --exact
cargo test -p response protected_target_process_returns_error_without_signals -- --exact
cargo test -p response kill_rate_limiter_enforces_limit_and_expires_window -- --exact
cargo test -p response restore_quarantined_file_writes_destination -- --exact
