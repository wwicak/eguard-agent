#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${WRAP_DIR}" || true
}
trap cleanup EXIT

for bin in cargo zig; do
  if ! command -v "${bin}" >/dev/null 2>&1; then
    echo "missing required tool: ${bin}" >&2
    exit 1
  fi
done

if ! cargo xwin --help >/dev/null 2>&1; then
  echo "cargo-xwin is required (cargo install cargo-xwin)" >&2
  exit 1
fi

cat > "${WRAP_DIR}/clang" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=()
for a in "$@"; do
  case "$a" in
    --target=x86_64-pc-windows-msvc|--target=x86_64-unknown-windows-msvc)
      args+=("--target=x86_64-windows-msvc")
      ;;
    *)
      args+=("$a")
      ;;
  esac
done
exec zig cc "${args[@]}"
EOF

cat > "${WRAP_DIR}/clang++" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=()
for a in "$@"; do
  case "$a" in
    --target=x86_64-pc-windows-msvc|--target=x86_64-unknown-windows-msvc)
      args+=("--target=x86_64-windows-msvc")
      ;;
    *)
      args+=("$a")
      ;;
  esac
done
exec zig c++ "${args[@]}"
EOF

cat > "${WRAP_DIR}/llvm-lib" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec zig lib "$@"
EOF

cat > "${WRAP_DIR}/lld-link" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec zig lld-link "$@"
EOF

chmod +x "${WRAP_DIR}/clang" "${WRAP_DIR}/clang++" "${WRAP_DIR}/llvm-lib" "${WRAP_DIR}/lld-link"

export PATH="${WRAP_DIR}:${PATH}"

cd "${ROOT_DIR}"

if [[ -z "${RUSTFLAGS:-}" ]]; then
  export RUSTFLAGS="-D warnings"
fi

# Linux filesystems are case-sensitive; sqlite3's bundled source includes <Windows.h>.
# Ensure both casings resolve when compiling against xwin headers.
XWIN_INCLUDE_DIR="${HOME}/.cache/cargo-xwin/windows-msvc-sysroot/windows-msvc-sysroot/include"
if [[ -f "${XWIN_INCLUDE_DIR}/windows.h" && ! -e "${XWIN_INCLUDE_DIR}/Windows.h" ]]; then
  ln -s windows.h "${XWIN_INCLUDE_DIR}/Windows.h"
fi

cargo xwin check --cross-compiler clang --target x86_64-pc-windows-msvc -p agent-core "$@"
