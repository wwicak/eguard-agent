#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/workflow-lint"
OUT_JSON="${OUT_DIR}/metrics.json"

mkdir -p "${OUT_DIR}"

WORKFLOWS=(
  ".github/workflows/build-bundle.yml"
  ".github/workflows/verification-suite.yml"
  ".github/workflows/package-agent.yml"
  ".github/workflows/release-agent.yml"
)

if ! command -v yq >/dev/null 2>&1; then
  echo "yq is required for workflow lint checks" >&2
  exit 1
fi

failure=0
entries=()

for workflow in "${WORKFLOWS[@]}"; do
  path="${ROOT_DIR}/${workflow}"
  if [[ ! -f "${path}" ]]; then
    echo "missing workflow file: ${workflow}" >&2
    entries+=("{\"workflow\":\"${workflow}\",\"status\":\"missing\"}")
    failure=1
    continue
  fi

  if ! yq '.' "${path}" >/dev/null; then
    echo "invalid YAML syntax: ${workflow}" >&2
    entries+=("{\"workflow\":\"${workflow}\",\"status\":\"invalid_yaml\"}")
    failure=1
    continue
  fi

  has_name="$(yq 'has("name")' "${path}")"
  has_on="$(yq 'has("on")' "${path}")"
  has_jobs="$(yq 'has("jobs")' "${path}")"
  jobs_count="$(yq '.jobs | keys | length' "${path}")"

  status="ok"
  attack_contract_ok=true
  if [[ "${has_name}" != "true" || "${has_on}" != "true" || "${has_jobs}" != "true" ]]; then
    status="missing_required_keys"
    failure=1
  elif [[ "${jobs_count}" == "0" ]]; then
    status="no_jobs"
    failure=1
  fi

  if [[ "${status}" == "ok" && "${workflow}" == ".github/workflows/build-bundle.yml" ]]; then
    required_steps=(
      "Enforce critical ATT&CK technique floor gate"
      "Enforce critical ATT&CK regression gate"
      "Update critical ATT&CK regression history"
      "Enforce critical ATT&CK owner streak gate"
      "Generate ATT&CK burn-down scoreboard"
      "Generate signature ML readiness report (shadow)"
      "Generate signature ML readiness trend report (shadow)"
      "Verify agent can ingest generated bundle output"
      "Create GitHub Release"
    )

    for step_name in "${required_steps[@]}"; do
      if ! yq -e ".jobs.\"build-bundle\".steps[] | select(.name == \"${step_name}\")" "${path}" >/dev/null 2>&1; then
        echo "build-bundle contract missing step: ${step_name}" >&2
        attack_contract_ok=false
      fi
    done

    release_run="$(yq -r '.jobs."build-bundle".steps[] | select(.name == "Create GitHub Release") | .run' "${path}" 2>/dev/null || true)"
    critical_regression_run="$(yq -r '.jobs."build-bundle".steps[] | select(.name == "Enforce critical ATT&CK regression gate") | .run' "${path}" 2>/dev/null || true)"
    owner_streak_run="$(yq -r '.jobs."build-bundle".steps[] | select(.name == "Enforce critical ATT&CK owner streak gate") | .run' "${path}" 2>/dev/null || true)"
    ml_readiness_run="$(yq -r '.jobs."build-bundle".steps[] | select(.name == "Generate signature ML readiness report (shadow)") | .run' "${path}" 2>/dev/null || true)"
    ml_readiness_trend_run="$(yq -r '.jobs."build-bundle".steps[] | select(.name == "Generate signature ML readiness trend report (shadow)") | .run' "${path}" 2>/dev/null || true)"
    agent_ingest_run="$(yq -r '.jobs."build-bundle".steps[] | select(.name == "Verify agent can ingest generated bundle output") | .run' "${path}" 2>/dev/null || true)"
    required_release_tokens=(
      "bundle/attack-critical-technique-gate.json"
      "bundle/attack-critical-regression.json"
      "bundle/attack-critical-regression-history.ndjson"
      "bundle/attack-critical-regression-history-summary.json"
      "bundle/attack-critical-owner-streak-gate.json"
      "bundle/attack-burndown-scoreboard.json"
      "bundle/attack-burndown-scoreboard.md"
      "bundle/signature-ml-readiness.json"
      "bundle/signature-ml-readiness-trend.ndjson"
      "bundle/signature-ml-readiness-trend-report.json"
      "## Critical ATT&CK Technique Floor"
      "## Critical ATT&CK Regression Guard"
      "## Critical ATT&CK Regression History"
      "## Critical ATT&CK Owner Streak Guard"
      "## ATT&CK Critical Burn-down Scoreboard"
      "## Signature ML Readiness (Shadow)"
      "## Signature ML Readiness Trend (Shadow)"
      "Delta uncovered vs previous"
      "Owner P0 regressions"
    )

    for token in "${required_release_tokens[@]}"; do
      if [[ "${release_run}" != *"${token}"* ]]; then
        echo "build-bundle contract missing release token: ${token}" >&2
        attack_contract_ok=false
      fi
    done

    if [[ "${critical_regression_run}" != *"--max-owner-p0-uncovered-increase"* ]]; then
      echo "build-bundle critical regression gate missing owner-level P0 threshold flag" >&2
      attack_contract_ok=false
    fi

    if [[ "${owner_streak_run}" != *"--max-consecutive-owner-regression"* ]]; then
      echo "build-bundle owner streak gate missing max-consecutive threshold flag" >&2
      attack_contract_ok=false
    fi

    if [[ "${ml_readiness_run}" != *"signature_ml_readiness_gate.py"* ]]; then
      echo "build-bundle ML readiness step missing signature ML readiness script invocation" >&2
      attack_contract_ok=false
    fi
    if [[ "${ml_readiness_run}" != *"--previous /tmp/previous-signature-ml-readiness.json"* ]]; then
      echo "build-bundle ML readiness step missing previous readiness baseline wiring" >&2
      attack_contract_ok=false
    fi
    if [[ "${ml_readiness_run}" != *"--output bundle/signature-ml-readiness.json"* ]]; then
      echo "build-bundle ML readiness step missing readiness output artifact wiring" >&2
      attack_contract_ok=false
    fi

    if [[ "${ml_readiness_trend_run}" != *"signature_ml_readiness_trend_gate.py"* ]]; then
      echo "build-bundle ML readiness trend step missing trend gate script invocation" >&2
      attack_contract_ok=false
    fi
    if [[ "${ml_readiness_trend_run}" != *"--previous-trend /tmp/previous-signature-ml-readiness-trend.ndjson"* ]]; then
      echo "build-bundle ML readiness trend step missing previous trend baseline wiring" >&2
      attack_contract_ok=false
    fi
    if [[ "${ml_readiness_trend_run}" != *"--output-trend bundle/signature-ml-readiness-trend.ndjson"* ]]; then
      echo "build-bundle ML readiness trend step missing trend output wiring" >&2
      attack_contract_ok=false
    fi
    if [[ "${ml_readiness_trend_run}" != *"--output-report bundle/signature-ml-readiness-trend-report.json"* ]]; then
      echo "build-bundle ML readiness trend step missing trend report output wiring" >&2
      attack_contract_ok=false
    fi

    if [[ "${agent_ingest_run}" != *"load_bundle_rules_reads_ci_generated_signed_bundle"* ]]; then
      echo "build-bundle agent ingest step missing CI generated bundle runtime test selector" >&2
      attack_contract_ok=false
    fi
    if [[ "${agent_ingest_run}" != *"load_bundle_rules_rejects_tampered_ci_generated_signed_bundle"* ]]; then
      echo "build-bundle agent ingest step missing tampered bundle rejection test selector" >&2
      attack_contract_ok=false
    fi
    if [[ "${agent_ingest_run}" != *"run_agent_bundle_ingestion_contract_ci.sh"* ]]; then
      echo "build-bundle agent ingest step missing shared bundle ingestion contract harness" >&2
      attack_contract_ok=false
    fi
    if [[ "${agent_ingest_run}" != *"EGUARD_CI_BUNDLE_PATH"* || "${agent_ingest_run}" != *"EGUARD_CI_BUNDLE_PUBHEX"* ]]; then
      echo "build-bundle agent ingest step missing bundle path/pubkey environment wiring" >&2
      attack_contract_ok=false
    fi

    if [[ "${attack_contract_ok}" != "true" ]]; then
      status="missing_attack_contracts"
      failure=1
    fi
  fi

  entries+=(
    "{\"workflow\":\"${workflow}\",\"status\":\"${status}\",\"jobs_count\":${jobs_count},\"has_name\":${has_name},\"has_on\":${has_on},\"has_jobs\":${has_jobs},\"attack_contract_ok\":${attack_contract_ok}}"
  )
done

NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
{
  echo "{"
  echo "  \"suite\": \"workflow_yaml_lint\"," 
  echo "  \"recorded_at_utc\": \"${NOW_UTC}\"," 
  echo "  \"entries\": ["
  for i in "${!entries[@]}"; do
    suffix=","
    if [[ "${i}" -eq $((${#entries[@]} - 1)) ]]; then
      suffix=""
    fi
    echo "    ${entries[$i]}${suffix}"
  done
  echo "  ]"
  echo "}"
} >"${OUT_JSON}"

echo "wrote workflow lint metrics to ${OUT_JSON}"

if [[ "${failure}" -ne 0 ]]; then
  exit 1
fi
