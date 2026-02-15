#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/bundle-signature-contract"
METRICS_JSON="${OUT_DIR}/metrics.json"
ML_READINESS_JSON="${OUT_DIR}/signature-ml-readiness.json"
ML_READINESS_TREND_NDJSON="${OUT_DIR}/signature-ml-readiness-trend.ndjson"
ML_READINESS_TREND_REPORT_JSON="${OUT_DIR}/signature-ml-readiness-trend-report.json"

mkdir -p "${OUT_DIR}"

if [[ -n "${MOCK_LOG:-}" ]]; then
  {
    echo "python threat-intel/processing/build_bundle.py --sigma <mock> --yara <mock> --ioc <mock> --cve <mock> --output <mock> --version ci.mock"
    echo "python threat-intel/processing/bundle_coverage_gate.py --manifest <mock> --output <mock>"
    echo "python threat-intel/processing/signature_ml_readiness_gate.py --manifest <mock> --coverage <mock> --output <mock>"
    echo "python threat-intel/processing/signature_ml_readiness_trend_gate.py --current <mock> --previous-trend <mock> --output-trend <mock> --output-report <mock>"
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

tar cf - -C "${bundle_dir}" . | zstd -3 -q -o "${archive_path}"

openssl genpkey -algorithm ed25519 -out "${tmp_dir}/bundle-signing-key.pem" >/dev/null 2>&1
openssl pkey \
  -in "${tmp_dir}/bundle-signing-key.pem" \
  -pubout \
  -out "${tmp_dir}/bundle-signing-pub.pem" >/dev/null 2>&1

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

python3 - <<'PY' "${coverage_json}" "${readiness_json}" "${readiness_trend_report_json}" "${METRICS_JSON}" "${tamper_rejected}"
import json
import sys

coverage = json.loads(open(sys.argv[1], "r", encoding="utf-8").read())
readiness = json.loads(open(sys.argv[2], "r", encoding="utf-8").read())
trend = json.loads(open(sys.argv[3], "r", encoding="utf-8").read())
measured = coverage.get("measured", {})
scores = readiness.get("scores", {}) if isinstance(readiness.get("scores", {}), dict) else {}
trend_alerts = trend.get("alerts", {}) if isinstance(trend.get("alerts", {}), dict) else {}
trend_scores = trend.get("scores", {}) if isinstance(trend.get("scores", {}), dict) else {}
tamper_rejected = sys.argv[5].strip().lower() == "true"

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
}

with open(sys.argv[4], "w", encoding="utf-8") as handle:
    handle.write(json.dumps(metrics, indent=2) + "\n")
PY

cp "${archive_path}" "${OUT_DIR}/fixture.bundle.tar.zst"
cp "${sig_path}" "${OUT_DIR}/fixture.bundle.tar.zst.sig"
cp "${pub_hex_path}" "${OUT_DIR}/fixture.bundle.tar.zst.pub.hex"
cp "${readiness_json}" "${ML_READINESS_JSON}"
cp "${readiness_trend_ndjson}" "${ML_READINESS_TREND_NDJSON}"
cp "${readiness_trend_report_json}" "${ML_READINESS_TREND_REPORT_JSON}"

if [[ "${tamper_rejected}" != "true" ]]; then
  echo "bundle signature contract failed: tampered bundle unexpectedly verified" >&2
  exit 1
fi

echo "wrote bundle signature contract metrics to ${METRICS_JSON}"
