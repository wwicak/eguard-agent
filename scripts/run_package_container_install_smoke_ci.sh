#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${EGUARD_PACKAGE_ARTIFACT_DIR:-${ROOT_DIR}/artifacts/package-agent}"
OUT_DIR="${EGUARD_CONTAINER_INSTALL_SMOKE_OUT_DIR:-${ARTIFACT_DIR}/container-install-smoke}"
OUT_JSON="${OUT_DIR}/metrics.json"
IMAGE="${EGUARD_CONTAINER_INSTALL_SMOKE_IMAGE:-debian:12}"
RUNTIME_TIMEOUT_SECS="${EGUARD_CONTAINER_INSTALL_SMOKE_TIMEOUT_SECS:-5}"
REQUIRE_EBPF_LIBBPF="${EGUARD_CONTAINER_REQUIRE_EBPF_LIBBPF:-0}"

mkdir -p "${OUT_DIR}"

NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

write_metrics_and_exit() {
  local status="$1"
  local reason="$2"
  local docker_exit_code="${3:-}"

  python3 - <<'PY' "${OUT_JSON}" "${NOW_UTC}" "${status}" "${reason}" "${IMAGE}" "${RUNTIME_TIMEOUT_SECS}" "${REQUIRE_EBPF_LIBBPF}" "${docker_exit_code}" "${OUT_DIR}"
import json
import pathlib
import sys

out_json = pathlib.Path(sys.argv[1])
now_utc = sys.argv[2]
status = sys.argv[3]
reason = sys.argv[4]
image = sys.argv[5]
runtime_timeout_secs = int(sys.argv[6])
require_ebpf = sys.argv[7].strip().lower() in {"1", "true", "yes", "on"}
docker_exit_code_raw = sys.argv[8].strip()
out_dir = pathlib.Path(sys.argv[9])

agent_log = out_dir / "agent-start.log"
query_log = out_dir / "dpkg-query.log"
exit_code_path = out_dir / "agent-exit-code.txt"

runtime_exit_code = None
if exit_code_path.exists():
    try:
        runtime_exit_code = int(exit_code_path.read_text(encoding="utf-8").strip())
    except Exception:
        runtime_exit_code = None

runtime_started = False
shard_pool_initialized = False
ebpf_libbpf_disabled_warning = False
if agent_log.exists():
    text = agent_log.read_text(encoding="utf-8", errors="replace")
    runtime_started = "eguard-agent core started" in text
    shard_pool_initialized = "initialized detection shard pool" in text
    ebpf_libbpf_disabled_warning = "feature 'ebpf-libbpf' is disabled in this build" in text

packages_registered = False
if query_log.exists():
    text = query_log.read_text(encoding="utf-8", errors="replace")
    packages_registered = "eguard-agent" in text and "eguard-agent-rules" in text

payload = {
    "suite": "package_container_install_smoke",
    "recorded_at_utc": now_utc,
    "status": status,
    "reason": reason,
    "image": image,
    "runtime_timeout_secs": runtime_timeout_secs,
    "require_ebpf_libbpf": require_ebpf,
    "docker_exit_code": int(docker_exit_code_raw) if docker_exit_code_raw else None,
    "checks": {
        "packages_registered": packages_registered,
        "runtime_started": runtime_started,
        "shard_pool_initialized": shard_pool_initialized,
        "runtime_exit_code": runtime_exit_code,
        "ebpf_libbpf_disabled_warning": ebpf_libbpf_disabled_warning,
    },
    "artifacts": {
        "dpkg_install_log": str((out_dir / "dpkg-install.log")),
        "dpkg_query_log": str(query_log),
        "agent_start_log": str(agent_log),
        "agent_exit_code": str(exit_code_path),
    },
}

out_json.parent.mkdir(parents=True, exist_ok=True)
out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"wrote package container install smoke metrics to {out_json}")
PY

  if [[ "${status}" != "pass" && "${status}" != "skipped_no_docker" ]]; then
    exit 1
  fi

  exit 0
}

if ! command -v docker >/dev/null 2>&1; then
  write_metrics_and_exit "skipped_no_docker" "docker unavailable"
fi

core_pkg="$(ls -1 "${ARTIFACT_DIR}/debian"/eguard-agent_*.deb 2>/dev/null | sort | tail -n1 || true)"
rules_pkg="$(ls -1 "${ARTIFACT_DIR}/debian"/eguard-agent-rules_*.deb 2>/dev/null | sort | tail -n1 || true)"

if [[ -z "${core_pkg}" || -z "${rules_pkg}" ]]; then
  write_metrics_and_exit "fail" "missing debian package artifacts"
fi

core_pkg_basename="$(basename "${core_pkg}")"
rules_pkg_basename="$(basename "${rules_pkg}")"

after_clean=(
  "${OUT_DIR}/dpkg-install.log"
  "${OUT_DIR}/dpkg-query.log"
  "${OUT_DIR}/agent-start.log"
  "${OUT_DIR}/agent-exit-code.txt"
)
for target in "${after_clean[@]}"; do
  rm -f "${target}"
done

docker_exit_code=0
set +e
docker run --rm \
  -v "${ARTIFACT_DIR}:/artifacts" \
  "${IMAGE}" \
  bash -lc "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y --no-install-recommends ca-certificates systemd >/dev/null

dpkg -i \
  /artifacts/debian/${core_pkg_basename} \
  /artifacts/debian/${rules_pkg_basename} \
  >/artifacts/container-install-smoke/dpkg-install.log 2>&1

dpkg-query -W eguard-agent eguard-agent-rules >/artifacts/container-install-smoke/dpkg-query.log

test -x /usr/bin/eguard-agent
test -f /usr/lib/systemd/system/eguard-agent.service
test -f /var/lib/eguard-agent/rules/sigma/default_webshell.yml
test -f /var/lib/eguard-agent/rules/yara/default.yar
test -f /var/lib/eguard-agent/rules/ioc/default_ioc.txt

set +e
RUST_LOG=info timeout ${RUNTIME_TIMEOUT_SECS} /usr/bin/eguard-agent >/artifacts/container-install-smoke/agent-start.log 2>&1
agent_rc=\$?
set -e
printf '%s\n' "\${agent_rc}" >/artifacts/container-install-smoke/agent-exit-code.txt

if [ "\${agent_rc}" -ne 124 ]; then
  echo "unexpected agent runtime exit code: \${agent_rc}" >&2
  exit 1
fi
"
docker_exit_code=$?
set -e

if [[ "${docker_exit_code}" -ne 0 ]]; then
  write_metrics_and_exit "fail" "docker install/runtime smoke command failed" "${docker_exit_code}"
fi

if [[ "${REQUIRE_EBPF_LIBBPF}" == "1" ]]; then
  if grep -q "feature 'ebpf-libbpf' is disabled in this build" "${OUT_DIR}/agent-start.log"; then
    write_metrics_and_exit "fail" "ebpf-libbpf feature is required but disabled in packaged binary" "${docker_exit_code}"
  fi
fi

write_metrics_and_exit "pass" "container install smoke checks passed" "${docker_exit_code}"
