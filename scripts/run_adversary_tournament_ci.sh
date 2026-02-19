#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/adversary-tournament"
OUT_JSON="${OUT_DIR}/metrics.json"

mkdir -p "${OUT_DIR}"

# Tournament workflow owns regression decisions via check_adversary_tournament_gate.py.
# Keep detection-quality trend/adversary score checks in observation mode here to avoid
# coupling against pre-existing local trend files.
export EGUARD_DQ_TREND_FAIL_ON_REGRESSION="${EGUARD_DQ_TREND_FAIL_ON_REGRESSION:-0}"
export EGUARD_ADV_FAIL_ON_SCORE_DROP="${EGUARD_ADV_FAIL_ON_SCORE_DROP:-0}"

run_stage() {
  local label="$1"
  local command="$2"
  echo "[adversary-tournament] $(date -u +%Y-%m-%dT%H:%M:%SZ) :: ${label}"
  bash -c "${command}"
}

run_stage "detection quality + adversary score" "bash ${ROOT_DIR}/scripts/run_detection_quality_gate_ci.sh"
run_stage "detection latency benchmark" "bash ${ROOT_DIR}/scripts/run_detection_benchmark_ci.sh"
run_stage "runtime tick slo" "bash ${ROOT_DIR}/scripts/run_runtime_tick_slo_ci.sh"
run_stage "replay determinism" "bash ${ROOT_DIR}/scripts/run_replay_determinism_ci.sh"
run_stage "rule-push slo" "bash ${ROOT_DIR}/scripts/run_rule_push_slo_ci.sh"
run_stage "ebpf resource budget" "bash ${ROOT_DIR}/scripts/run_ebpf_resource_budget_ci.sh"

python3 - <<'PY' "${ROOT_DIR}" "${OUT_JSON}"
from __future__ import annotations

import json
import os
import pathlib
import sys
from datetime import datetime, timezone
from typing import Any

root = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])


def load_json(relative: str) -> dict[str, Any]:
    path = root / relative
    if not path.is_file():
        raise FileNotFoundError(f"missing required artifact: {relative}")
    return json.loads(path.read_text(encoding="utf-8"))


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    if value < low:
        return low
    if value > high:
        return high
    return value


def inverse_budget_score(value: float, budget: float) -> float:
    if budget <= 0.0:
        return 0.0
    return clamp(1.0 - (max(value, 0.0) / budget))


detection_quality = load_json("artifacts/detection-quality-gate/metrics.json")
adversary_score = load_json("artifacts/detection-quality-gate/adversary-emulation-score.json")
detection_benchmark = load_json("artifacts/detection-benchmark/metrics.json")
runtime_tick = load_json("artifacts/runtime-tick-slo/metrics.json")
replay = load_json("artifacts/replay-determinism/metrics.json")
rule_push = load_json("artifacts/rule-push-slo/metrics.json")
ebpf_budget = load_json("artifacts/ebpf-resource-budget/metrics.json")

measured_quality = detection_quality.get("measured", {})
if not isinstance(measured_quality, dict):
    measured_quality = {}

adversary_scores = adversary_score.get("scores", {})
if not isinstance(adversary_scores, dict):
    adversary_scores = {}

rule_push_measured = rule_push.get("measured", {})
if not isinstance(rule_push_measured, dict):
    rule_push_measured = {}

ebpf_measured = ebpf_budget.get("measured", {})
if not isinstance(ebpf_measured, dict):
    ebpf_measured = {}

adversary_final = as_float(adversary_scores.get("final_score"), 0.0)
adversary_focus = as_float(adversary_scores.get("focus_score"), 0.0)
false_alarm_upper = as_float(measured_quality.get("false_alarm_upper_bound"), 1.0)

detection_wall_ms = as_int(detection_benchmark.get("wall_clock_ms"), 0)
runtime_tick_wall_ms = as_int(runtime_tick.get("wall_clock_ms"), 0)
replay_wall_ms = as_int(replay.get("wall_clock_ms"), 0)
rule_push_transfer_seconds = as_float(rule_push_measured.get("transfer_seconds_at_link_rate"), 0.0)
rule_push_rollout_seconds = as_float(rule_push_measured.get("fleet_rollout_seconds"), 0.0)
ebpf_release_build_wall_ms = as_int(ebpf_measured.get("release_build_wall_ms"), 0)
ebpf_binary_size_mb = as_float(ebpf_measured.get("binary_size_mb"), 0.0)

thresholds = {
    "target_false_alarm_upper_bound": as_float(
        os.environ.get("EGUARD_TOURNAMENT_TARGET_FAR_MAX", "0.20"),
        0.20,
    ),
    "max_detection_wall_clock_ms": as_float(
        os.environ.get("EGUARD_TOURNAMENT_MAX_DETECTION_WALL_MS", "60000"),
        60000.0,
    ),
    "max_rule_push_rollout_seconds": as_float(
        os.environ.get("EGUARD_TOURNAMENT_MAX_RULE_PUSH_ROLLOUT_SECONDS", "30"),
        30.0,
    ),
    "max_ebpf_release_build_wall_ms": as_float(
        os.environ.get("EGUARD_TOURNAMENT_MAX_EBPF_BUILD_MS", "300000"),
        300000.0,
    ),
}

components = {
    "adversary_final": clamp(adversary_final / 100.0),
    "adversary_focus": clamp(adversary_focus / 100.0),
    "false_alarm": inverse_budget_score(false_alarm_upper, thresholds["target_false_alarm_upper_bound"]),
    "detection_wall": inverse_budget_score(float(detection_wall_ms), thresholds["max_detection_wall_clock_ms"]),
    "rule_push_rollout": inverse_budget_score(
        rule_push_rollout_seconds,
        thresholds["max_rule_push_rollout_seconds"],
    ),
    "ebpf_build_wall": inverse_budget_score(
        float(ebpf_release_build_wall_ms),
        thresholds["max_ebpf_release_build_wall_ms"],
    ),
}

weights = {
    "adversary_final": 0.40,
    "adversary_focus": 0.15,
    "false_alarm": 0.15,
    "detection_wall": 0.15,
    "rule_push_rollout": 0.10,
    "ebpf_build_wall": 0.05,
}

weighted = 0.0
weight_total = 0.0
for key, weight in weights.items():
    weight_total += weight
    weighted += components.get(key, 0.0) * weight

resilience_index = 0.0
if weight_total > 0.0:
    resilience_index = 100.0 * (weighted / weight_total)

report = {
    "suite": "adversary_tournament",
    "recorded_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "thresholds": thresholds,
    "scores": {
        "resilience_index": round(resilience_index, 6),
        "adversary_final_score": adversary_final,
        "adversary_focus_score": adversary_focus,
    },
    "score_components": {
        "normalized": components,
        "weights": weights,
    },
    "measurements": {
        "false_alarm_upper_bound": false_alarm_upper,
        "detection_benchmark_wall_clock_ms": detection_wall_ms,
        "runtime_tick_wall_clock_ms": runtime_tick_wall_ms,
        "replay_determinism_wall_clock_ms": replay_wall_ms,
        "rule_push_transfer_seconds": rule_push_transfer_seconds,
        "rule_push_rollout_seconds": rule_push_rollout_seconds,
        "ebpf_release_build_wall_ms": ebpf_release_build_wall_ms,
        "ebpf_binary_size_mb": ebpf_binary_size_mb,
    },
    "sources": {
        "detection_quality": "artifacts/detection-quality-gate/metrics.json",
        "adversary_emulation_score": "artifacts/detection-quality-gate/adversary-emulation-score.json",
        "detection_benchmark": "artifacts/detection-benchmark/metrics.json",
        "runtime_tick_slo": "artifacts/runtime-tick-slo/metrics.json",
        "replay_determinism": "artifacts/replay-determinism/metrics.json",
        "rule_push_slo": "artifacts/rule-push-slo/metrics.json",
        "ebpf_resource_budget": "artifacts/ebpf-resource-budget/metrics.json",
    },
}

out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f"wrote adversary tournament metrics to {out_path}")
PY
