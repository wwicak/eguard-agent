#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/package-agent"
OUT_JSON="${OUT_DIR}/metrics.json"
STAGE_DIR="${OUT_DIR}/stage"
TOOLS_DIR="${OUT_DIR}/tools"
NFPM_CORE_CFG="${OUT_DIR}/nfpm-core.yaml"
NFPM_RULES_CFG="${OUT_DIR}/nfpm-rules.yaml"

VERSION="${EGUARD_AGENT_VERSION:-0.1.0}"
RPM_RELEASE="${EGUARD_AGENT_RPM_RELEASE:-1}"
DEB_ARCH="${EGUARD_AGENT_DEB_ARCH:-amd64}"
RPM_ARCH="${EGUARD_AGENT_RPM_ARCH:-x86_64}"

REAL_BUILD="${EGUARD_PACKAGE_REAL_BUILD:-0}"
GENERATE_EPHEMERAL_GPG="${EGUARD_PACKAGE_GENERATE_EPHEMERAL_GPG:-0}"
ALLOW_UNSIGNED="${EGUARD_PACKAGE_ALLOW_UNSIGNED:-1}"
NFPM_VERSION="${EGUARD_NFPM_VERSION:-2.45.0}"

AGENT_BINARY_TARGET_MB="${EGUARD_PACKAGE_AGENT_BINARY_TARGET_MB:-}"
RULES_PACKAGE_TARGET_MB="5"
FULL_INSTALL_TARGET_MB="15"
RUNTIME_RSS_TARGET_MB="25"
DISTRIBUTION_BUDGET_MB="200"
AGENT_BINARY_COMPRESSED_MB="7"

AGENT_BINARY_TARGET_JSON="null"
if [[ -n "${AGENT_BINARY_TARGET_MB}" ]]; then
  AGENT_BINARY_TARGET_JSON="${AGENT_BINARY_TARGET_MB}"
fi
EBPF_PROGRAMS_COMPRESSED_KB="100"
ASM_LIB_COMPRESSED_KB="50"
SEED_BASELINE_COMPRESSED_KB="10"
DEFAULT_CONFIG_COMPRESSED_KB="5"
SYSTEMD_UNIT_KB="1"

NFPM_BIN="nfpm"

mkdir -p "${OUT_DIR}/debian" "${OUT_DIR}/rpm" "${STAGE_DIR}" "${TOOLS_DIR}"

ensure_file() {
  local src="$1"
  local dst="$2"
  local placeholder="${3:-}"

  mkdir -p "$(dirname "${dst}")"
  if [[ -f "${src}" ]]; then
    cp -f "${src}" "${dst}"
  elif [[ -n "${placeholder}" ]]; then
    printf '%s\n' "${placeholder}" >"${dst}"
  else
    : >"${dst}"
  fi
}

create_zig_musl_wrapper() {
  local path="$1"
  local subcommand="$2"

  cat >"${path}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
args=()
for arg in "\$@"; do
  case "\${arg}" in
    --target=x86_64-unknown-linux-musl)
      args+=("--target=x86_64-linux-musl")
      ;;
    x86_64-unknown-linux-musl)
      args+=("x86_64-linux-musl")
      ;;
    *)
      args+=("\${arg}")
      ;;
  esac
done
exec zig ${subcommand} "\${args[@]}"
EOF

  chmod +x "${path}"
}

configure_musl_toolchain() {
  if command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
    return
  fi

  if ! command -v zig >/dev/null 2>&1; then
    echo "x86_64-linux-musl-gcc not found and zig is unavailable" >&2
    exit 1
  fi

  local cc_wrapper="${TOOLS_DIR}/zig-musl-cc"
  local cxx_wrapper="${TOOLS_DIR}/zig-musl-cxx"
  local ar_wrapper="${TOOLS_DIR}/zig-musl-ar"

  if [[ ! -x "${cc_wrapper}" ]]; then
    create_zig_musl_wrapper "${cc_wrapper}" "cc"
  fi
  if [[ ! -x "${cxx_wrapper}" ]]; then
    create_zig_musl_wrapper "${cxx_wrapper}" "c++"
  fi
  if [[ ! -x "${ar_wrapper}" ]]; then
    cat >"${ar_wrapper}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec zig ar "$@"
EOF
    chmod +x "${ar_wrapper}"
  fi

  export CC_x86_64_unknown_linux_musl="${cc_wrapper}"
  export CXX_x86_64_unknown_linux_musl="${cxx_wrapper}"
  export AR_x86_64_unknown_linux_musl="${ar_wrapper}"

  local rust_lld="${RUST_LLD_PATH:-$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld}"
  if [[ -x "${rust_lld}" ]]; then
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${rust_lld}"
  else
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${cc_wrapper}"
  fi

  echo "warning: x86_64-linux-musl-gcc missing; using zig-based musl wrappers in ${TOOLS_DIR}" >&2
}

ensure_nfpm() {
  if command -v nfpm >/dev/null 2>&1; then
    NFPM_BIN="$(command -v nfpm)"
    return
  fi

  local archive="${TOOLS_DIR}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
  local extracted="${TOOLS_DIR}/nfpm"

  if [[ ! -x "${extracted}" ]]; then
    echo "nfpm not found on PATH; downloading nfpm v${NFPM_VERSION} to ${TOOLS_DIR}" >&2
    curl -sfL "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz" -o "${archive}"
    tar -xzf "${archive}" -C "${TOOLS_DIR}" nfpm
    chmod +x "${extracted}"
  fi

  NFPM_BIN="${extracted}"
}

prepare_stage_payload() {
  local core_root="${STAGE_DIR}/core"
  local rules_root="${STAGE_DIR}/rules"
  local bin_src="${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/agent-core"

  rm -rf "${core_root}" "${rules_root}"

  ensure_file "${bin_src}" "${core_root}/usr/bin/eguard-agent"
  ensure_file "${ROOT_DIR}/packaging/systemd/eguard-agent.service" "${core_root}/usr/lib/systemd/system/eguard-agent.service" "[Unit]"
  ensure_file "${ROOT_DIR}/conf/agent.conf.example" "${core_root}/etc/eguard-agent/agent.conf" "[agent]"
  ensure_file "${ROOT_DIR}/rules/baseline/seed_profiles.txt" "${core_root}/var/lib/eguard-agent/baselines/seed.bin" "seed_profiles"

  mkdir -p "${core_root}/usr/lib/eguard-agent/ebpf" "${core_root}/usr/lib/eguard-agent/lib"

  ensure_file "${ROOT_DIR}/zig-out/ebpf/process_exec_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/process_exec_bpf.o"
  ensure_file "${ROOT_DIR}/zig-out/ebpf/file_open_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/file_open_bpf.o"
  ensure_file "${ROOT_DIR}/zig-out/ebpf/file_write_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/file_write_bpf.o"
  ensure_file "${ROOT_DIR}/zig-out/ebpf/file_rename_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/file_rename_bpf.o"
  ensure_file "${ROOT_DIR}/zig-out/ebpf/file_unlink_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/file_unlink_bpf.o"
  ensure_file "${ROOT_DIR}/zig-out/ebpf/tcp_connect_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/tcp_connect_bpf.o"
  ensure_file "${ROOT_DIR}/zig-out/ebpf/dns_query_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/dns_query_bpf.o"
  ensure_file "${ROOT_DIR}/zig-out/ebpf/module_load_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/module_load_bpf.o"
  ensure_file "${ROOT_DIR}/zig-out/ebpf/lsm_block_bpf.o" "${core_root}/usr/lib/eguard-agent/ebpf/lsm_block_bpf.o"

  local asm_bundle="${core_root}/usr/lib/eguard-agent/lib/libeguard_asm.a"
  local asm_temp_dir="${STAGE_DIR}/asm-temp"
  rm -rf "${asm_temp_dir}"
  mkdir -p "${asm_temp_dir}"

  local have_asm_libs=0
  for lib in "${ROOT_DIR}"/zig-out/lib/libeguard_*.a; do
    if [[ -f "${lib}" ]]; then
      have_asm_libs=1
      while IFS= read -r member; do
        [[ -n "${member}" ]] || continue
        mkdir -p "${asm_temp_dir}/$(dirname "${member}")"
      done < <(ar t "${lib}" 2>/dev/null || true)
      (cd "${asm_temp_dir}" && ar x "${lib}") || true
    fi
  done

  mapfile -t asm_objects < <(find "${asm_temp_dir}" -type f -name '*.o' | sort)
  if [[ "${have_asm_libs}" -eq 1 ]] && [[ "${#asm_objects[@]}" -gt 0 ]]; then
    ar rcs "${asm_bundle}" "${asm_objects[@]}"
  else
    : >"${asm_bundle}"
  fi

  rm -rf "${asm_temp_dir}"

  ensure_file "${ROOT_DIR}/rules/sigma/default_webshell.yml" "${rules_root}/var/lib/eguard-agent/rules/sigma/default_webshell.yml"
  ensure_file "${ROOT_DIR}/rules/yara/default.yar" "${rules_root}/var/lib/eguard-agent/rules/yara/default.yar"
  ensure_file "${ROOT_DIR}/rules/ioc/default_ioc.txt" "${rules_root}/var/lib/eguard-agent/rules/ioc/default_ioc.txt"
}

generate_nfpm_configs() {
  local core_root="${STAGE_DIR}/core"
  local rules_root="${STAGE_DIR}/rules"

  cat >"${NFPM_CORE_CFG}" <<EOF
name: eguard-agent
arch: ${DEB_ARCH}
platform: linux
version: "${VERSION}"
release: "${RPM_RELEASE}"
maintainer: eGuard Team <info@eguard.id>
description: eGuard endpoint agent package
license: GPL-2.0-or-later
depends:
  - systemd
scripts:
  postinstall: packaging/postinstall.sh
  preremove: packaging/preremove.sh
contents:
  - src: ${core_root}/usr/bin/eguard-agent
    dst: /usr/bin/eguard-agent
    file_info:
      mode: 0755
  - src: ${core_root}/usr/lib/systemd/system/eguard-agent.service
    dst: /usr/lib/systemd/system/eguard-agent.service
    file_info:
      mode: 0644
  - src: ${core_root}/etc/eguard-agent/agent.conf
    dst: /etc/eguard-agent/agent.conf
    type: config|noreplace
    file_info:
      mode: 0644
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/process_exec_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/process_exec_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/file_open_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/file_open_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/file_write_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/file_write_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/file_rename_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/file_rename_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/file_unlink_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/file_unlink_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/tcp_connect_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/tcp_connect_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/dns_query_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/dns_query_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/module_load_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/module_load_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/ebpf/lsm_block_bpf.o
    dst: /usr/lib/eguard-agent/ebpf/lsm_block_bpf.o
  - src: ${core_root}/usr/lib/eguard-agent/lib/libeguard_asm.a
    dst: /usr/lib/eguard-agent/lib/libeguard_asm.a
  - src: ${core_root}/var/lib/eguard-agent/baselines/seed.bin
    dst: /var/lib/eguard-agent/baselines/seed.bin
  - dst: /var/lib/eguard-agent/rules
    type: dir
  - dst: /var/lib/eguard-agent/rules-staging
    type: dir
  - dst: /var/lib/eguard-agent/quarantine
    type: dir
overrides:
  rpm:
    depends:
      - systemd
EOF

  cat >"${NFPM_RULES_CFG}" <<EOF
name: eguard-agent-rules
arch: ${DEB_ARCH}
platform: linux
version: "${VERSION}"
release: "${RPM_RELEASE}"
maintainer: eGuard Team <info@eguard.id>
description: Optional bootstrap rule bundle for eGuard endpoint agent
license: GPL-2.0-or-later
depends:
  - eguard-agent
contents:
  - src: ${rules_root}/var/lib/eguard-agent/rules/sigma/default_webshell.yml
    dst: /var/lib/eguard-agent/rules/sigma/default_webshell.yml
  - src: ${rules_root}/var/lib/eguard-agent/rules/yara/default.yar
    dst: /var/lib/eguard-agent/rules/yara/default.yar
  - src: ${rules_root}/var/lib/eguard-agent/rules/ioc/default_ioc.txt
    dst: /var/lib/eguard-agent/rules/ioc/default_ioc.txt
overrides:
  rpm:
    depends:
      - eguard-agent = ${VERSION}-${RPM_RELEASE}
EOF
}

sign_packages_if_possible() {
  local packages=(
    "${OUT_DIR}/debian/eguard-agent_${VERSION}_${DEB_ARCH}.deb"
    "${OUT_DIR}/debian/eguard-agent-rules_${VERSION}_${DEB_ARCH}.deb"
    "${OUT_DIR}/rpm/eguard-agent-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"
    "${OUT_DIR}/rpm/eguard-agent-rules-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"
  )

  export GNUPGHOME="${OUT_DIR}/.gnupg"
  mkdir -p "${GNUPGHOME}"
  chmod 700 "${GNUPGHOME}"

  if ! gpg --batch --list-secret-keys --with-colons 2>/dev/null | awk -F: '$1 == "sec" { found = 1 } END { exit found ? 0 : 1 }'; then
    if [[ "${GENERATE_EPHEMERAL_GPG}" == "1" ]]; then
      gpg --batch --pinentry-mode loopback --passphrase "" --quick-generate-key \
        "eGuard CI Package Signer <ci@eguard.local>" rsa2048 sign 1d
    elif [[ "${ALLOW_UNSIGNED}" != "1" ]]; then
      echo "no GPG secret key available and unsigned packages are not allowed" >&2
      exit 1
    else
      echo "warning: no GPG secret key available; skipping package signatures" >&2
      return
    fi
  fi

  for pkg in "${packages[@]}"; do
    gpg --batch --yes --armor --detach-sign "${pkg}"
  done
}

build_real_packages() {
  ensure_nfpm

  generate_nfpm_configs

  "${NFPM_BIN}" package --packager deb --config "${NFPM_CORE_CFG}" \
    --target "${OUT_DIR}/debian/eguard-agent_${VERSION}_${DEB_ARCH}.deb"
  "${NFPM_BIN}" package --packager deb --config "${NFPM_RULES_CFG}" \
    --target "${OUT_DIR}/debian/eguard-agent-rules_${VERSION}_${DEB_ARCH}.deb"

  "${NFPM_BIN}" package --packager rpm --config "${NFPM_CORE_CFG}" \
    --target "${OUT_DIR}/rpm/eguard-agent-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"
  "${NFPM_BIN}" package --packager rpm --config "${NFPM_RULES_CFG}" \
    --target "${OUT_DIR}/rpm/eguard-agent-rules-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"

  sign_packages_if_possible
}

build_placeholder_packages() {
  touch "${OUT_DIR}/debian/eguard-agent_${VERSION}_${DEB_ARCH}.deb"
  touch "${OUT_DIR}/debian/eguard-agent-rules_${VERSION}_${DEB_ARCH}.deb"
  touch "${OUT_DIR}/rpm/eguard-agent-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"
  touch "${OUT_DIR}/rpm/eguard-agent-rules-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"
}

# Build static binary and eBPF/asm assets.
if [[ "${EGUARD_ENABLE_LTO:-1}" == "1" ]]; then
  export CARGO_PROFILE_RELEASE_LTO="fat"
  export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1"
fi

configure_musl_toolchain

cargo build --release --target x86_64-unknown-linux-musl -p agent-core --features platform-linux/ebpf-libbpf
zig build

BIN="${ROOT_DIR}/target/x86_64-unknown-linux-musl/release/agent-core"
if [[ -f "${BIN}" ]]; then
  strip "${BIN}" || true
  cp -f "${BIN}" "${OUT_DIR}/eguard-agent"
fi

prepare_stage_payload

if [[ "${REAL_BUILD}" == "1" ]]; then
  build_real_packages
else
  build_placeholder_packages
fi

NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "${OUT_JSON}" <<EOF
{
  "suite": "package-agent",
  "recorded_at_utc": "${NOW_UTC}",
  "real_build": ${REAL_BUILD},
  "version": "${VERSION}",
  "targets_mb": {
    "agent_binary": ${AGENT_BINARY_TARGET_JSON},
    "rules_package": ${RULES_PACKAGE_TARGET_MB},
    "full_install": ${FULL_INSTALL_TARGET_MB},
    "runtime_rss": ${RUNTIME_RSS_TARGET_MB},
    "distribution_budget": ${DISTRIBUTION_BUDGET_MB}
  },
  "component_budget": {
    "agent_binary_compressed_mb": ${AGENT_BINARY_COMPRESSED_MB},
    "ebpf_programs_compressed_kb": ${EBPF_PROGRAMS_COMPRESSED_KB},
    "asm_lib_compressed_kb": ${ASM_LIB_COMPRESSED_KB},
    "seed_baseline_compressed_kb": ${SEED_BASELINE_COMPRESSED_KB},
    "default_config_compressed_kb": ${DEFAULT_CONFIG_COMPRESSED_KB},
    "systemd_unit_kb": ${SYSTEMD_UNIT_KB}
  },
  "build_commands": [
    "cargo build --release --target x86_64-unknown-linux-musl -p agent-core --features platform-linux/ebpf-libbpf",
    "zig build",
    "strip target/x86_64-unknown-linux-musl/release/agent-core"
  ],
  "package_outputs": [
    "debian/eguard-agent_${VERSION}_${DEB_ARCH}.deb",
    "debian/eguard-agent-rules_${VERSION}_${DEB_ARCH}.deb",
    "rpm/eguard-agent-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm",
    "rpm/eguard-agent-rules-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"
  ]
}
EOF

echo "wrote package metrics to ${OUT_JSON}"
