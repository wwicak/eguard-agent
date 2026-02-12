#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAX_COMPRESSED_KB=50
BLOCKED_SYMBOLS=(malloc free new delete)

cargo build -p crypto-accel --release

mapfile -t ARCHIVES < <(find "${ROOT_DIR}/target" -type f -name "libeguard_*.a" | sort)

if [[ "${#ARCHIVES[@]}" -eq 0 ]]; then
  echo "no asm static archives found under target/"
  exit 1
fi

for archive in "${ARCHIVES[@]}"; do
  echo "auditing ${archive}"
  nm -u "${archive}" >"${archive}.undefined.txt" || true
  for sym in "${BLOCKED_SYMBOLS[@]}"; do
    if grep -E "(^|[[:space:]])${sym}($|[[:space:]])" "${archive}.undefined.txt" >/dev/null 2>&1; then
      echo "blocked symbol import detected in ${archive}: ${sym}"
      exit 1
    fi
  done

  size_kb="$(( ( $(wc -c <"${archive}") + 1023 ) / 1024 ))"
  if [[ "${size_kb}" -gt "${MAX_COMPRESSED_KB}" ]]; then
    echo "archive too large (${size_kb} KB > ${MAX_COMPRESSED_KB} KB): ${archive}"
    exit 1
  fi
done

echo "asm symbol and size audit passed"
