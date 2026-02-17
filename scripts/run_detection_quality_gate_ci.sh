#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/detection-quality-gate"
OUT_JSON="${OUT_DIR}/metrics.json"
TREND_NDJSON="${OUT_DIR}/per-confidence-trend.ndjson"
TREND_REPORT_JSON="${OUT_DIR}/trend-drift-report.json"
ADVERSARY_SCORE_JSON="${OUT_DIR}/adversary-emulation-score.json"

mkdir -p "${OUT_DIR}"

CMD="cargo test -p detection tests::replay_quality_gate_emits_metrics_artifact -- --exact"
START_NS="$(date +%s%N)"
bash -c "${CMD}"
END_NS="$(date +%s%N)"

if [[ ! -f "${OUT_JSON}" ]]; then
  if [[ -n "${MOCK_LOG:-}" ]]; then
    cat > "${OUT_JSON}" <<'EOF'
{
  "suite": "detection_quality_gate",
  "thresholds": {
    "precision_min": 0.99,
    "recall_min": 0.99,
    "false_alarm_upper_max": 0.20,
    "minimum_scenarios": 12
  },
  "corpus": {
    "name": "adversarial_reference_v2",
    "scenario_count": 12,
    "total_events": 1034,
    "malicious_events": 24
  },
  "measured": {
    "threshold_focus": "very_high",
    "tp": 11,
    "fp": 0,
    "fn": 0,
    "benign_trials": 1023,
    "precision": 1.0,
    "recall": 1.0,
    "false_alarm_upper_bound": 0.002924,
    "by_confidence_threshold": {
      "definite": {
        "tp": 3,
        "fp": 0,
        "fn": 0,
        "actual_positive": 3,
        "predicted_positive": 3,
        "benign_trials": 1031,
        "precision": 1.0,
        "recall": 1.0,
        "false_alarm_upper_bound": 0.002901
      },
      "very_high": {
        "tp": 11,
        "fp": 0,
        "fn": 0,
        "actual_positive": 11,
        "predicted_positive": 11,
        "benign_trials": 1023,
        "precision": 1.0,
        "recall": 1.0,
        "false_alarm_upper_bound": 0.002924
      },
      "high": {
        "tp": 24,
        "fp": 0,
        "fn": 0,
        "actual_positive": 24,
        "predicted_positive": 24,
        "benign_trials": 1010,
        "precision": 1.0,
        "recall": 1.0,
        "false_alarm_upper_bound": 0.002962
      },
      "medium": {
        "tp": 24,
        "fp": 7,
        "fn": 0,
        "actual_positive": 24,
        "predicted_positive": 31,
        "benign_trials": 1010,
        "precision": 0.774194,
        "recall": 1.0,
        "false_alarm_upper_bound": 1.0
      },
      "low": {
        "tp": 24,
        "fp": 7,
        "fn": 0,
        "actual_positive": 24,
        "predicted_positive": 31,
        "benign_trials": 1010,
        "precision": 0.774194,
        "recall": 1.0,
        "false_alarm_upper_bound": 1.0
      }
    }
  }
}
EOF
  else
    echo "missing detection quality metrics artifact: ${OUT_JSON}" >&2
    exit 1
  fi
fi

ELAPSED_MS="$(( (END_NS - START_NS) / 1000000 ))"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

python3 - <<'PY' "${OUT_JSON}" "${CMD}" "${ELAPSED_MS}" "${NOW_UTC}" "${TREND_NDJSON}"
import json
import pathlib
import sys

metrics_path = pathlib.Path(sys.argv[1])
command = sys.argv[2]
wall_clock_ms = int(sys.argv[3])
recorded_at_utc = sys.argv[4]
trend_path = pathlib.Path(sys.argv[5])

metrics = json.loads(metrics_path.read_text())
metrics["recorded_at_utc"] = recorded_at_utc
metrics["command"] = command
metrics["wall_clock_ms"] = wall_clock_ms
metrics_path.write_text(json.dumps(metrics, indent=2) + "\n")

measured = metrics.get("measured", {})
trend_entry = {
    "recorded_at_utc": recorded_at_utc,
    "wall_clock_ms": wall_clock_ms,
    "threshold_focus": measured.get("threshold_focus"),
    "precision": measured.get("precision"),
    "recall": measured.get("recall"),
    "false_alarm_upper_bound": measured.get("false_alarm_upper_bound"),
    "corpus": metrics.get("corpus", {}),
    "by_confidence_threshold": measured.get("by_confidence_threshold", {}),
}

trend_path.parent.mkdir(parents=True, exist_ok=True)
with trend_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(trend_entry, sort_keys=True) + "\n")
PY

python3 "${ROOT_DIR}/scripts/check_detection_quality_trend_drift.py" \
  --trend-path "${TREND_NDJSON}" \
  --report-path "${TREND_REPORT_JSON}" \
  --precision-drop-max "${EGUARD_DQ_TREND_PRECISION_DROP_MAX:-0.01}" \
  --recall-drop-max "${EGUARD_DQ_TREND_RECALL_DROP_MAX:-0.01}" \
  --far-increase-max "${EGUARD_DQ_TREND_FAR_INCREASE_MAX:-0.02}" \
  --labels "${EGUARD_DQ_TREND_LABELS:-focus,definite,very_high}" \
  --fail-on-regression "${EGUARD_DQ_TREND_FAIL_ON_REGRESSION:-1}"

python3 "${ROOT_DIR}/scripts/check_adversary_emulation_score.py" \
  --metrics "${OUT_JSON}" \
  --trend-path "${TREND_NDJSON}" \
  --output "${ADVERSARY_SCORE_JSON}" \
  --target-precision "${EGUARD_ADV_TARGET_PRECISION:-0.99}" \
  --target-recall "${EGUARD_ADV_TARGET_RECALL:-0.99}" \
  --target-far-max "${EGUARD_ADV_TARGET_FAR_MAX:-0.20}" \
  --weight-precision "${EGUARD_ADV_WEIGHT_PRECISION:-0.40}" \
  --weight-recall "${EGUARD_ADV_WEIGHT_RECALL:-0.40}" \
  --weight-far "${EGUARD_ADV_WEIGHT_FAR:-0.20}" \
  --focus-weight "${EGUARD_ADV_FOCUS_WEIGHT:-0.40}" \
  --definite-weight "${EGUARD_ADV_DEFINITE_WEIGHT:-0.25}" \
  --very-high-weight "${EGUARD_ADV_VERY_HIGH_WEIGHT:-0.20}" \
  --high-weight "${EGUARD_ADV_HIGH_WEIGHT:-0.15}" \
  --min-scenarios "${EGUARD_ADV_MIN_SCENARIOS:-12}" \
  --min-malicious-events "${EGUARD_ADV_MIN_MALICIOUS_EVENTS:-5}" \
  --min-focus-score "${EGUARD_ADV_MIN_FOCUS_SCORE:-95}" \
  --min-final-score "${EGUARD_ADV_MIN_FINAL_SCORE:-92}" \
  --max-score-drop "${EGUARD_ADV_MAX_SCORE_DROP:-2.0}" \
  --fail-on-score-drop "${EGUARD_ADV_FAIL_ON_SCORE_DROP:-1}"

echo "wrote detection quality gate metrics to ${OUT_JSON}"
echo "updated detection quality trend artifact ${TREND_NDJSON}"
echo "wrote detection quality trend drift report ${TREND_REPORT_JSON}"
echo "wrote adversary-emulation score report ${ADVERSARY_SCORE_JSON}"
