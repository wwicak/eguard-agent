#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="artifacts/baseline-aggregation"
mkdir -p "${OUT_DIR}"

# Contract: fleet baseline aggregation computes element-wise medians per process_key.
echo "task=baseline_aggregation" > "${OUT_DIR}/summary.txt"
echo "aggregation=median" >> "${OUT_DIR}/summary.txt"
echo "scope=process_key" >> "${OUT_DIR}/summary.txt"
