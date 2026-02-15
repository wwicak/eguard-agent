#!/usr/bin/env bash
set -euo pipefail

bundle_path="${EGUARD_CI_BUNDLE_PATH:-}"
bundle_pubhex="${EGUARD_CI_BUNDLE_PUBHEX:-}"
bundle_pubhex_file="${EGUARD_CI_BUNDLE_PUBHEX_FILE:-}"
test_selector="lifecycle::tests::load_bundle_rules_reads_ci_generated_signed_bundle"

to_abs_path() {
  local raw_path="$1"
  if [[ "${raw_path}" = /* ]]; then
    printf '%s' "${raw_path}"
  else
    printf '%s/%s' "$(pwd -P)" "${raw_path}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle)
      bundle_path="$2"
      shift 2
      ;;
    --pubhex)
      bundle_pubhex="$2"
      shift 2
      ;;
    --pubhex-file)
      bundle_pubhex_file="$2"
      shift 2
      ;;
    --test-selector)
      test_selector="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${bundle_path}" ]]; then
  echo "missing bundle path (set EGUARD_CI_BUNDLE_PATH or pass --bundle)" >&2
  exit 1
fi
if [[ ! -s "${bundle_path}" ]]; then
  echo "bundle not found or empty: ${bundle_path}" >&2
  exit 1
fi

bundle_path="$(to_abs_path "${bundle_path}")"

signature_path="${bundle_path}.sig"
if [[ ! -s "${signature_path}" ]]; then
  echo "bundle signature sidecar not found or empty: ${signature_path}" >&2
  exit 1
fi

if [[ -z "${bundle_pubhex}" ]]; then
  if [[ -n "${bundle_pubhex_file}" ]]; then
    bundle_pubhex_file="$(to_abs_path "${bundle_pubhex_file}")"
    if [[ ! -s "${bundle_pubhex_file}" ]]; then
      echo "bundle pubkey file not found or empty: ${bundle_pubhex_file}" >&2
      exit 1
    fi
    bundle_pubhex="$(tr -d '\r\n[:space:]' < "${bundle_pubhex_file}")"
  elif [[ -s "${bundle_path}.pub.hex" ]]; then
    bundle_pubhex="$(tr -d '\r\n[:space:]' < "${bundle_path}.pub.hex")"
  fi
fi

bundle_pubhex="$(printf '%s' "${bundle_pubhex}" | tr -d '\r\n[:space:]')"
if [[ -z "${bundle_pubhex}" ]]; then
  echo "missing bundle pubkey hex (set EGUARD_CI_BUNDLE_PUBHEX or pass --pubhex/--pubhex-file)" >&2
  exit 1
fi

if [[ -z "${test_selector}" ]]; then
  echo "missing test selector" >&2
  exit 1
fi

echo "[bundle-agent-contract] bundle=${bundle_path}"
echo "[bundle-agent-contract] signature=${signature_path}"
echo "[bundle-agent-contract] test_selector=${test_selector}"

EGUARD_CI_BUNDLE_PATH="${bundle_path}" \
EGUARD_CI_BUNDLE_PUBHEX="${bundle_pubhex}" \
  cargo test -p agent-core "${test_selector}" -- --exact
