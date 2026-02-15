#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/bundle-signature-contract"
METRICS_JSON="${OUT_DIR}/metrics.json"
ML_READINESS_JSON="${OUT_DIR}/signature-ml-readiness.json"
ML_READINESS_TREND_NDJSON="${OUT_DIR}/signature-ml-readiness-trend.ndjson"
ML_READINESS_TREND_REPORT_JSON="${OUT_DIR}/signature-ml-readiness-trend-report.json"
ML_CORPUS_SUMMARY_JSON="${OUT_DIR}/signature-ml-training-corpus-summary.json"
ML_SIGNALS_NDJSON="${OUT_DIR}/signature-ml-signals.ndjson"
ML_LABEL_REPORT_JSON="${OUT_DIR}/signature-ml-label-quality-report.json"
ML_LABELS_NDJSON="${OUT_DIR}/signature-ml-labels.ndjson"
ML_FEATURE_REPORT_JSON="${OUT_DIR}/signature-ml-feature-snapshot-report.json"
ML_FEATURES_NDJSON="${OUT_DIR}/signature-ml-features.ndjson"
ML_FEATURE_SCHEMA_JSON="${OUT_DIR}/signature-ml-feature-schema.json"
ML_MODEL_JSON="${OUT_DIR}/signature-ml-model.json"
ML_MODEL_METADATA_JSON="${OUT_DIR}/signature-ml-model-metadata.json"
ML_MODEL_SIG="${OUT_DIR}/signature-ml-model.json.sig"
ML_OFFLINE_EVAL_REPORT_JSON="${OUT_DIR}/signature-ml-offline-eval-report.json"
ML_OFFLINE_EVAL_TREND_NDJSON="${OUT_DIR}/signature-ml-offline-eval-trend.ndjson"
ML_OFFLINE_EVAL_TREND_REPORT_JSON="${OUT_DIR}/signature-ml-offline-eval-trend-report.json"
ML_REGISTRY_JSON="${OUT_DIR}/signature-ml-model-registry.json"

mkdir -p "${OUT_DIR}"

if [[ -n "${MOCK_LOG:-}" ]]; then
  {
    echo "python threat-intel/processing/build_bundle.py --sigma <mock> --yara <mock> --ioc <mock> --cve <mock> --output <mock> --version ci.mock"
    echo "python threat-intel/processing/bundle_coverage_gate.py --manifest <mock> --output <mock>"
    echo "python threat-intel/processing/signature_ml_readiness_gate.py --manifest <mock> --coverage <mock> --output <mock>"
    echo "python threat-intel/processing/signature_ml_readiness_trend_gate.py --current <mock> --previous-trend <mock> --output-trend <mock> --output-report <mock>"
    echo "python threat-intel/processing/signature_ml_build_training_corpus.py --manifest <mock> --coverage <mock> --readiness <mock> --output-signals <mock> --output-summary <mock>"
    echo "python threat-intel/processing/signature_ml_label_quality_gate.py --signals <mock> --output-report <mock> --output-labels <mock>"
    echo "python threat-intel/processing/signature_ml_feature_snapshot_gate.py --labels <mock> --output-features <mock> --output-schema <mock> --output-report <mock>"
    echo "python threat-intel/processing/signature_ml_train_model.py --dataset <mock> --feature-schema <mock> --labels-report <mock> --model-version <mock> --model-out <mock> --metadata-out <mock>"
    echo "python threat-intel/processing/signature_ml_offline_eval_gate.py --dataset <mock> --model <mock> --previous-report <mock> --auto-threshold <mock> --output-report <mock> --output-trend <mock>"
    echo "python threat-intel/processing/signature_ml_offline_eval_trend_gate.py --trend <mock> --output <mock>"
    echo "python threat-intel/processing/signature_ml_model_registry_gate.py --model-artifact <mock> --metadata <mock> --offline-eval <mock> --offline-eval-trend-report <mock> --feature-schema <mock> --labels-report <mock> --signature-file <mock> --public-key-file <mock> --output <mock>"
    echo "python threat-intel/processing/ed25519_sign.py --input <mock> --output-sig <mock>"
    echo "python threat-intel/processing/ed25519_verify.py --input <mock> --signature <mock>"
  } >>"${MOCK_LOG}"

  printf 'mock-bundle' >"${OUT_DIR}/fixture.bundle.tar.zst"
  printf 'mock-signature' >"${OUT_DIR}/fixture.bundle.tar.zst.sig"
  printf '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' >"${OUT_DIR}/fixture.bundle.tar.zst.pub.hex"

  cat >"${ML_READINESS_JSON}" <<'EOF'
{
  "suite": "signature_ml_readiness_gate",
  "status": "pass",
  "mode": "shadow",
  "readiness_tier": "strong",
  "scores": {
    "final_score": 90.0,
    "previous_final_score": null,
    "score_delta": null,
    "score_drop": null
  }
}
EOF

  cat >"${ML_READINESS_TREND_NDJSON}" <<'EOF'
{"component_scores":{"exploit_intel":88.0,"signature_scale":90.0,"source_diversity":92.0},"failure_count":0,"final_score":90.0,"mode":"shadow","projected_alert_streak":0,"readiness_tier":"strong","recorded_at_utc":"2026-02-15T00:00:00Z","score_delta":null,"score_drop":null,"source_final_score":90.0,"source_status":"pass","status":"pass_no_baseline","suite":"signature_ml_readiness_trend","warning_count":0}
EOF

  cat >"${ML_READINESS_TREND_REPORT_JSON}" <<'EOF'
{
  "suite": "signature_ml_readiness_trend_gate",
  "status": "pass_no_baseline",
  "history_status": "no_baseline",
  "scores": {
    "current_final_score": 90.0,
    "previous_final_score": null,
    "score_delta": null,
    "score_drop": null
  },
  "regressions": []
}
EOF

  cat >"${ML_SIGNALS_NDJSON}" <<'EOF'
{"adjudicated_at_utc":"2026-02-15T02:00:00Z","attack_surface_score":88.0,"critical_resilience_score":86.0,"database_total":26000,"host_id":"host-001","label":1,"label_source":"synthetic_ci","model_score":0.94,"observed_at_utc":"2026-02-15T00:00:00Z","rule_id":"sig-rule-0001","rule_severity":5,"sample_id":"sample-000001","signature_total":7200,"source_diversity_score":84.0}
{"adjudicated_at_utc":"2026-02-15T04:00:00Z","attack_surface_score":78.0,"critical_resilience_score":80.0,"database_total":26000,"host_id":"host-002","label":0,"label_source":"synthetic_ci","model_score":0.18,"observed_at_utc":"2026-02-15T01:00:00Z","rule_id":"sig-rule-0002","rule_severity":2,"sample_id":"sample-000002","signature_total":7200,"source_diversity_score":84.0}
EOF

  cat >"${ML_CORPUS_SUMMARY_JSON}" <<'EOF'
{
  "suite": "signature_ml_build_training_corpus",
  "status": "pass",
  "dataset_mode": "synthetic_ci",
  "measured": {
    "sample_count": 720,
    "adjudicated_count": 662,
    "unresolved_count": 58,
    "positive_count": 176,
    "negative_count": 486
  }
}
EOF

  cat >"${ML_LABEL_REPORT_JSON}" <<'EOF'
{
  "suite": "signature_ml_label_quality_gate",
  "status": "pass",
  "measured": {
    "adjudicated_count": 662,
    "positive_count": 176,
    "negative_count": 486,
    "unresolved_ratio": 0.0806,
    "unique_hosts": 160,
    "unique_rules": 220,
    "p95_label_latency_days": 2.4
  }
}
EOF

  cp "${ML_SIGNALS_NDJSON}" "${ML_LABELS_NDJSON}"

  cat >"${ML_FEATURE_REPORT_JSON}" <<'EOF'
{
  "suite": "signature_ml_feature_snapshot_gate",
  "status": "pass",
  "measured": {
    "row_count": 662,
    "unique_hosts": 160,
    "unique_rules": 220,
    "missing_feature_ratio": 0.0,
    "temporal_span_days": 44.9
  }
}
EOF

  cp "${ML_SIGNALS_NDJSON}" "${ML_FEATURES_NDJSON}"

  cat >"${ML_FEATURE_SCHEMA_JSON}" <<'EOF'
{
  "suite": "signature_ml_feature_schema",
  "version": 1,
  "features": [
    "rule_severity",
    "signature_total",
    "database_total",
    "source_diversity_score",
    "attack_surface_score",
    "critical_resilience_score"
  ],
  "label_field": "label",
  "score_field": "model_score"
}
EOF

  cat >"${ML_MODEL_JSON}" <<'EOF'
{
  "suite": "signature_ml_linear_logit_model",
  "model_type": "linear_logit_v1",
  "model_version": "ci.signature.ml.v1"
}
EOF

  cat >"${ML_MODEL_METADATA_JSON}" <<'EOF'
{
  "suite": "signature_ml_model_metadata",
  "model_version": "ci.signature.ml.v1"
}
EOF

  printf 'mock-model-signature' >"${ML_MODEL_SIG}"

  cat >"${ML_OFFLINE_EVAL_REPORT_JSON}" <<'EOF'
{
  "suite": "signature_ml_offline_eval_gate",
  "status": "pass",
  "metrics": {
    "precision": 0.84,
    "recall": 0.79,
    "pr_auc": 0.90,
    "roc_auc": 0.91,
    "brier_score": 0.11,
    "ece": 0.04
  }
}
EOF

  cat >"${ML_OFFLINE_EVAL_TREND_NDJSON}" <<'EOF'
{"brier_score":0.11,"dataset_total":662,"ece":0.04,"eval_count":220,"model_mode":"trained_model","precision":0.84,"pr_auc":0.90,"recall":0.79,"recorded_at_utc":"2026-02-15T00:00:00Z","roc_auc":0.91,"status":"pass","suite":"signature_ml_offline_eval_trend"}
EOF

  cat >"${ML_OFFLINE_EVAL_TREND_REPORT_JSON}" <<'EOF'
{
  "suite": "signature_ml_offline_eval_trend_gate",
  "status": "pass_no_baseline",
  "history_status": "no_baseline",
  "alerts": {
    "entry_count": 1,
    "consecutive_alerts": 0,
    "window_pass_rate": 1.0,
    "regression_count": 0
  },
  "regressions": []
}
EOF

  cat >"${ML_REGISTRY_JSON}" <<'EOF'
{
  "suite": "signature_ml_model_registry_gate",
  "status": "pass",
  "model_version": "ci.signature.ml.v1",
  "offline_metrics": {
    "pr_auc": 0.90,
    "roc_auc": 0.91
  }
}
EOF

  cat >"${METRICS_JSON}" <<'EOF'
{
  "suite": "bundle_signature_contract",
  "status": "pass",
  "signature_verified": true,
  "tamper_rejected": true,
  "coverage": {
    "signature_total": 2,
    "database_total": 6
  },
  "ml_readiness": {
    "status": "pass",
    "mode": "shadow",
    "readiness_tier": "strong",
    "final_score": 90.0
  },
  "ml_readiness_trend": {
    "status": "pass_no_baseline",
    "history_status": "no_baseline",
    "score_drop": null,
    "regression_count": 0
  },
  "ml_battle_ready": {
    "corpus": {
      "status": "pass",
      "dataset_mode": "synthetic_ci"
    },
    "label_quality": {
      "status": "pass",
      "adjudicated_count": 662
    },
    "feature_snapshot": {
      "status": "pass",
      "row_count": 662
    },
    "offline_eval": {
      "status": "pass",
      "pr_auc": 0.9,
      "roc_auc": 0.91
    },
    "offline_eval_trend": {
      "status": "pass_no_baseline",
      "history_status": "no_baseline",
      "regression_count": 0
    },
    "model_registry": {
      "status": "pass",
      "model_version": "ci.signature.ml.v1"
    }
  }
}
EOF
  exit 0
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

sigma_dir="${tmp_dir}/sigma/rules"
yara_dir="${tmp_dir}/yara/yara-forge"
ioc_dir="${tmp_dir}/ioc"
bundle_dir="${tmp_dir}/bundle"
archive_path="${tmp_dir}/eguard-rules.bundle.tar.zst"
sig_path="${archive_path}.sig"
pub_hex_path="${archive_path}.pub.hex"
tampered_path="${tmp_dir}/eguard-rules-tampered.bundle.tar.zst"
coverage_json="${tmp_dir}/coverage-metrics.json"
readiness_json="${tmp_dir}/signature-ml-readiness.json"
previous_readiness_trend_ndjson="${tmp_dir}/previous-signature-ml-readiness-trend.ndjson"
readiness_trend_ndjson="${tmp_dir}/signature-ml-readiness-trend.ndjson"
readiness_trend_report_json="${tmp_dir}/signature-ml-readiness-trend-report.json"
ml_signals_ndjson="${tmp_dir}/signature-ml-signals.ndjson"
ml_corpus_summary_json="${tmp_dir}/signature-ml-training-corpus-summary.json"
ml_label_report_json="${tmp_dir}/signature-ml-label-quality-report.json"
ml_labels_ndjson="${tmp_dir}/signature-ml-labels.ndjson"
ml_feature_report_json="${tmp_dir}/signature-ml-feature-snapshot-report.json"
ml_features_ndjson="${tmp_dir}/signature-ml-features.ndjson"
ml_feature_schema_json="${tmp_dir}/signature-ml-feature-schema.json"
ml_model_json="${tmp_dir}/signature-ml-model.json"
ml_model_metadata_json="${tmp_dir}/signature-ml-model-metadata.json"
ml_model_sig_path="${tmp_dir}/signature-ml-model.json.sig"
ml_offline_eval_report_json="${tmp_dir}/signature-ml-offline-eval-report.json"
ml_offline_eval_trend_ndjson="${tmp_dir}/signature-ml-offline-eval-trend.ndjson"
ml_offline_eval_trend_report_json="${tmp_dir}/signature-ml-offline-eval-trend-report.json"
ml_previous_offline_eval_report_json="${tmp_dir}/previous-signature-ml-offline-eval-report.json"
ml_previous_offline_eval_trend_ndjson="${tmp_dir}/previous-signature-ml-offline-eval-trend.ndjson"
ml_registry_json="${tmp_dir}/signature-ml-model-registry.json"

mkdir -p "${sigma_dir}" "${yara_dir}" "${ioc_dir}"

cat >"${sigma_dir}/rule.yml" <<'EOF'
title: signature_contract_sigma
detection:
  sequence:
    - event_class: process_exec
      process_any_of: [bash]
      within_secs: 30
EOF

cat >"${yara_dir}/rule.yar" <<'EOF'
rule signature_contract_yara {
  strings:
    $a = "signature-contract"
  condition:
    $a
}
EOF

cat >"${ioc_dir}/hashes.txt" <<'EOF'
deadbeef
EOF

cat >"${ioc_dir}/domains.txt" <<'EOF'
bad.example
EOF

cat >"${ioc_dir}/ips.txt" <<'EOF'
203.0.113.99
EOF

cat >"${tmp_dir}/cve.jsonl" <<'EOF'
{"cve":"CVE-2026-0001","actively_exploited":true}
EOF

python3 "${ROOT_DIR}/threat-intel/processing/build_bundle.py" \
  --sigma "${tmp_dir}/sigma" \
  --yara "${tmp_dir}/yara" \
  --ioc "${ioc_dir}" \
  --cve "${tmp_dir}/cve.jsonl" \
  --output "${bundle_dir}" \
  --version "ci.signature.contract"

python3 "${ROOT_DIR}/threat-intel/processing/bundle_coverage_gate.py" \
  --manifest "${bundle_dir}/manifest.json" \
  --output "${coverage_json}" \
  --min-sigma 1 \
  --min-yara 1 \
  --min-ioc-hash 1 \
  --min-ioc-domain 1 \
  --min-ioc-ip 1 \
  --min-cve 1 \
  --min-cve-kev 1 \
  --min-signature-total 2 \
  --min-database-total 6 \
  --min-yara-sources 1 \
  --min-sigma-sources 1 \
  --min-suricata 0 \
  --min-elastic 0

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_readiness_gate.py" \
  --manifest "${bundle_dir}/manifest.json" \
  --coverage "${coverage_json}" \
  --output "${readiness_json}" \
  --min-final-score 50 \
  --fail-on-threshold 1

cat >"${previous_readiness_trend_ndjson}" <<'EOF'
{"component_scores":{"exploit_intel":44.0,"signature_scale":65.0,"source_diversity":49.0},"failure_count":0,"final_score":56.8,"mode":"shadow","projected_alert_streak":0,"readiness_tier":"at_risk","recorded_at_utc":"2026-02-14T00:00:00Z","score_delta":null,"score_drop":null,"source_final_score":56.8,"source_status":"pass","status":"pass_no_baseline","suite":"signature_ml_readiness_trend","warning_count":1}
EOF

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_readiness_trend_gate.py" \
  --current "${readiness_json}" \
  --previous-trend "${previous_readiness_trend_ndjson}" \
  --output-trend "${readiness_trend_ndjson}" \
  --output-report "${readiness_trend_report_json}" \
  --max-score-drop 10 \
  --max-component-drop 25 \
  --max-consecutive-alerts 3 \
  --fail-on-regression 1

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_build_training_corpus.py" \
  --manifest "${bundle_dir}/manifest.json" \
  --coverage "${coverage_json}" \
  --readiness "${readiness_json}" \
  --output-signals "${ml_signals_ndjson}" \
  --output-summary "${ml_corpus_summary_json}" \
  --sample-count 720 \
  --window-days 45

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_label_quality_gate.py" \
  --signals "${ml_signals_ndjson}" \
  --output-report "${ml_label_report_json}" \
  --output-labels "${ml_labels_ndjson}" \
  --min-adjudicated 400 \
  --min-positive 120 \
  --min-negative 220 \
  --min-unique-hosts 80 \
  --min-unique-rules 120 \
  --max-unresolved-ratio 0.20 \
  --max-p95-label-latency-days 6 \
  --fail-on-threshold 1

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_feature_snapshot_gate.py" \
  --labels "${ml_labels_ndjson}" \
  --output-features "${ml_features_ndjson}" \
  --output-schema "${ml_feature_schema_json}" \
  --output-report "${ml_feature_report_json}" \
  --min-rows 360 \
  --min-unique-hosts 80 \
  --min-unique-rules 120 \
  --max-missing-feature-ratio 0.05 \
  --min-temporal-span-days 30 \
  --fail-on-threshold 1

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_train_model.py" \
  --dataset "${ml_features_ndjson}" \
  --feature-schema "${ml_feature_schema_json}" \
  --labels-report "${ml_label_report_json}" \
  --model-version "ci.signature.ml.v1" \
  --model-out "${ml_model_json}" \
  --metadata-out "${ml_model_metadata_json}"

cat >"${ml_previous_offline_eval_report_json}" <<'EOF'
{
  "suite": "signature_ml_offline_eval_gate",
  "metrics": {
    "pr_auc": 0.62,
    "roc_auc": 0.80
  }
}
EOF

cat >"${ml_previous_offline_eval_trend_ndjson}" <<'EOF'
{"brier_score":0.20,"dataset_total":640,"ece":0.14,"eval_count":210,"model_mode":"trained_model","precision":0.29,"pr_auc":0.62,"recall":0.88,"recorded_at_utc":"2026-02-14T00:00:00Z","roc_auc":0.80,"status":"pass","suite":"signature_ml_offline_eval_trend"}
EOF

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_offline_eval_gate.py" \
  --dataset "${ml_features_ndjson}" \
  --model "${ml_model_json}" \
  --previous-report "${ml_previous_offline_eval_report_json}" \
  --previous-trend "${ml_previous_offline_eval_trend_ndjson}" \
  --output-report "${ml_offline_eval_report_json}" \
  --output-trend "${ml_offline_eval_trend_ndjson}" \
  --threshold 0.20 \
  --auto-threshold 1 \
  --eval-ratio 0.35 \
  --min-eval-samples 140 \
  --min-precision 0.22 \
  --min-recall 0.80 \
  --min-pr-auc 0.60 \
  --min-roc-auc 0.76 \
  --max-brier-score 0.25 \
  --max-ece 0.22 \
  --max-pr-auc-drop 0.15 \
  --max-roc-auc-drop 0.15 \
  --fail-on-threshold 1 \
  --fail-on-regression 1

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_offline_eval_trend_gate.py" \
  --trend "${ml_offline_eval_trend_ndjson}" \
  --output "${ml_offline_eval_trend_report_json}" \
  --max-pr-auc-drop 0.15 \
  --max-roc-auc-drop 0.15 \
  --max-brier-increase 0.08 \
  --max-ece-increase 0.10 \
  --max-threshold-drift 0.25 \
  --max-consecutive-alerts 3 \
  --window-size 8 \
  --min-window-pass-rate 0.60 \
  --fail-on-regression 1

openssl genpkey -algorithm ed25519 -out "${tmp_dir}/bundle-signing-key.pem" >/dev/null 2>&1
openssl pkey \
  -in "${tmp_dir}/bundle-signing-key.pem" \
  -pubout \
  -out "${tmp_dir}/bundle-signing-pub.pem" >/dev/null 2>&1

THREAT_INTEL_ED25519_PRIVATE_KEY_PEM="$(cat "${tmp_dir}/bundle-signing-key.pem")" \
  python3 "${ROOT_DIR}/threat-intel/processing/ed25519_sign.py" \
    --input "${ml_model_json}" \
    --output-sig "${ml_model_sig_path}" >/dev/null

python3 "${ROOT_DIR}/threat-intel/processing/signature_ml_model_registry_gate.py" \
  --model-artifact "${ml_model_json}" \
  --metadata "${ml_model_metadata_json}" \
  --offline-eval "${ml_offline_eval_report_json}" \
  --offline-eval-trend-report "${ml_offline_eval_trend_report_json}" \
  --feature-schema "${ml_feature_schema_json}" \
  --labels-report "${ml_label_report_json}" \
  --signature-file "${ml_model_sig_path}" \
  --public-key-file "${tmp_dir}/bundle-signing-pub.pem" \
  --output "${ml_registry_json}" \
  --min-pr-auc 0.60 \
  --min-roc-auc 0.76 \
  --require-signed-model 1 \
  --verify-signature 1 \
  --require-offline-eval-trend-pass 1 \
  --fail-on-threshold 1

tar cf - -C "${bundle_dir}" . | zstd -3 -q -o "${archive_path}"

THREAT_INTEL_ED25519_PRIVATE_KEY_PEM="$(cat "${tmp_dir}/bundle-signing-key.pem")" \
  python3 "${ROOT_DIR}/threat-intel/processing/ed25519_sign.py" \
    --input "${archive_path}" \
    --output-sig "${sig_path}" \
    --public-key-hex-out "${pub_hex_path}" >/dev/null

THREAT_INTEL_ED25519_PUBLIC_KEY_PEM="$(cat "${tmp_dir}/bundle-signing-pub.pem")" \
  python3 "${ROOT_DIR}/threat-intel/processing/ed25519_verify.py" \
    --input "${archive_path}" \
    --signature "${sig_path}" >/dev/null

cp "${archive_path}" "${tampered_path}"
printf 'tamper' >>"${tampered_path}"

tamper_rejected="true"
if THREAT_INTEL_ED25519_PUBLIC_KEY_PEM="$(cat "${tmp_dir}/bundle-signing-pub.pem")" \
  python3 "${ROOT_DIR}/threat-intel/processing/ed25519_verify.py" \
    --input "${tampered_path}" \
    --signature "${sig_path}" >/dev/null 2>&1; then
  tamper_rejected="false"
fi

python3 - <<'PY' \
  "${coverage_json}" \
  "${readiness_json}" \
  "${readiness_trend_report_json}" \
  "${ml_corpus_summary_json}" \
  "${ml_label_report_json}" \
  "${ml_feature_report_json}" \
  "${ml_offline_eval_report_json}" \
  "${ml_offline_eval_trend_report_json}" \
  "${ml_registry_json}" \
  "${METRICS_JSON}" \
  "${tamper_rejected}"
import json
import sys

coverage = json.loads(open(sys.argv[1], "r", encoding="utf-8").read())
readiness = json.loads(open(sys.argv[2], "r", encoding="utf-8").read())
trend = json.loads(open(sys.argv[3], "r", encoding="utf-8").read())
corpus = json.loads(open(sys.argv[4], "r", encoding="utf-8").read())
label_report = json.loads(open(sys.argv[5], "r", encoding="utf-8").read())
feature_report = json.loads(open(sys.argv[6], "r", encoding="utf-8").read())
offline_eval = json.loads(open(sys.argv[7], "r", encoding="utf-8").read())
offline_eval_trend = json.loads(open(sys.argv[8], "r", encoding="utf-8").read())
registry = json.loads(open(sys.argv[9], "r", encoding="utf-8").read())
measured = coverage.get("measured", {})
scores = readiness.get("scores", {}) if isinstance(readiness.get("scores", {}), dict) else {}
trend_alerts = trend.get("alerts", {}) if isinstance(trend.get("alerts", {}), dict) else {}
trend_scores = trend.get("scores", {}) if isinstance(trend.get("scores", {}), dict) else {}
corpus_measured = corpus.get("measured", {}) if isinstance(corpus.get("measured", {}), dict) else {}
label_measured = label_report.get("measured", {}) if isinstance(label_report.get("measured", {}), dict) else {}
feature_measured = feature_report.get("measured", {}) if isinstance(feature_report.get("measured", {}), dict) else {}
offline_metrics = offline_eval.get("metrics", {}) if isinstance(offline_eval.get("metrics", {}), dict) else {}
offline_trend_alerts = offline_eval_trend.get("alerts", {}) if isinstance(offline_eval_trend.get("alerts", {}), dict) else {}
tamper_rejected = sys.argv[11].strip().lower() == "true"

metrics = {
    "suite": "bundle_signature_contract",
    "status": "pass" if tamper_rejected else "fail",
    "signature_verified": True,
    "tamper_rejected": tamper_rejected,
    "coverage": {
        "signature_total": measured.get("signature_total"),
        "database_total": measured.get("database_total"),
    },
    "ml_readiness": {
        "status": readiness.get("status"),
        "mode": readiness.get("mode"),
        "readiness_tier": readiness.get("readiness_tier"),
        "final_score": scores.get("final_score"),
    },
    "ml_readiness_trend": {
        "status": trend.get("status"),
        "history_status": trend.get("history_status"),
        "score_drop": trend_scores.get("score_drop"),
        "regression_count": trend_alerts.get("regression_count"),
    },
    "ml_battle_ready": {
        "corpus": {
            "status": corpus.get("status"),
            "dataset_mode": corpus.get("dataset_mode"),
            "sample_count": corpus_measured.get("sample_count"),
            "adjudicated_count": corpus_measured.get("adjudicated_count"),
        },
        "label_quality": {
            "status": label_report.get("status"),
            "adjudicated_count": label_measured.get("adjudicated_count"),
            "unresolved_ratio": label_measured.get("unresolved_ratio"),
        },
        "feature_snapshot": {
            "status": feature_report.get("status"),
            "row_count": feature_measured.get("row_count"),
            "missing_feature_ratio": feature_measured.get("missing_feature_ratio"),
        },
        "offline_eval": {
            "status": offline_eval.get("status"),
            "precision": offline_metrics.get("precision"),
            "recall": offline_metrics.get("recall"),
            "pr_auc": offline_metrics.get("pr_auc"),
            "roc_auc": offline_metrics.get("roc_auc"),
        },
        "offline_eval_trend": {
            "status": offline_eval_trend.get("status"),
            "history_status": offline_eval_trend.get("history_status"),
            "consecutive_alerts": offline_trend_alerts.get("consecutive_alerts"),
            "regression_count": offline_trend_alerts.get("regression_count"),
        },
        "model_registry": {
            "status": registry.get("status"),
            "model_version": registry.get("model_version"),
        },
    },
}

with open(sys.argv[10], "w", encoding="utf-8") as handle:
    handle.write(json.dumps(metrics, indent=2) + "\n")
PY

cp "${archive_path}" "${OUT_DIR}/fixture.bundle.tar.zst"
cp "${sig_path}" "${OUT_DIR}/fixture.bundle.tar.zst.sig"
cp "${pub_hex_path}" "${OUT_DIR}/fixture.bundle.tar.zst.pub.hex"
cp "${readiness_json}" "${ML_READINESS_JSON}"
cp "${readiness_trend_ndjson}" "${ML_READINESS_TREND_NDJSON}"
cp "${readiness_trend_report_json}" "${ML_READINESS_TREND_REPORT_JSON}"
cp "${ml_signals_ndjson}" "${ML_SIGNALS_NDJSON}"
cp "${ml_corpus_summary_json}" "${ML_CORPUS_SUMMARY_JSON}"
cp "${ml_label_report_json}" "${ML_LABEL_REPORT_JSON}"
cp "${ml_labels_ndjson}" "${ML_LABELS_NDJSON}"
cp "${ml_feature_report_json}" "${ML_FEATURE_REPORT_JSON}"
cp "${ml_features_ndjson}" "${ML_FEATURES_NDJSON}"
cp "${ml_feature_schema_json}" "${ML_FEATURE_SCHEMA_JSON}"
cp "${ml_model_json}" "${ML_MODEL_JSON}"
cp "${ml_model_metadata_json}" "${ML_MODEL_METADATA_JSON}"
cp "${ml_model_sig_path}" "${ML_MODEL_SIG}"
cp "${ml_offline_eval_report_json}" "${ML_OFFLINE_EVAL_REPORT_JSON}"
cp "${ml_offline_eval_trend_ndjson}" "${ML_OFFLINE_EVAL_TREND_NDJSON}"
cp "${ml_offline_eval_trend_report_json}" "${ML_OFFLINE_EVAL_TREND_REPORT_JSON}"
cp "${ml_registry_json}" "${ML_REGISTRY_JSON}"

if [[ "${tamper_rejected}" != "true" ]]; then
  echo "bundle signature contract failed: tampered bundle unexpectedly verified" >&2
  exit 1
fi

echo "wrote bundle signature contract metrics to ${METRICS_JSON}"
