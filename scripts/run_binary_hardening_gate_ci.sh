#!/usr/bin/env bash
set -euo pipefail

binary_path="${1:-target/release/agent-core}"

if [[ ! -f "$binary_path" ]]; then
  echo "[hardening] binary not found: $binary_path" >&2
  exit 1
fi

if command -v checksec >/dev/null 2>&1; then
  echo "[hardening] checker=checksec binary=$binary_path"
  checksec --file "$binary_path"
  exit 0
fi

if ! command -v readelf >/dev/null 2>&1; then
  echo "[hardening] checksec unavailable and readelf missing; cannot validate hardening" >&2
  exit 1
fi

echo "[hardening] checker=readelf-fallback binary=$binary_path"

relro_segment=0
gnu_stack_seen=0
exec_stack=0
while IFS= read -r line; do
  if [[ "$line" == *"GNU_RELRO"* ]]; then
    relro_segment=1
  fi
  if [[ "$line" == *"GNU_STACK"* ]]; then
    gnu_stack_seen=1
    if [[ "$line" =~ [[:space:]]RWE([[:space:]]|$) ]] || [[ "$line" =~ [[:space:]]RWX([[:space:]]|$) ]] || [[ "$line" =~ [[:space:]]E([[:space:]]|$) ]]; then
      exec_stack=1
    fi
  fi
done < <(readelf -W -l "$binary_path")

bind_now=0
while IFS= read -r line; do
  if [[ "$line" == *"(BIND_NOW)"* ]]; then
    bind_now=1
  fi
  if [[ "$line" == *"(FLAGS)"* && "$line" == *"BIND_NOW"* ]]; then
    bind_now=1
  fi
  if [[ "$line" == *"(FLAGS_1)"* && "$line" == *"NOW"* ]]; then
    bind_now=1
  fi
done < <(readelf -W -d "$binary_path")

pie=0
while IFS= read -r line; do
  if [[ "$line" == *"Type:"* ]]; then
    if [[ "$line" == *"DYN"* ]]; then
      pie=1
    fi
    break
  fi
done < <(readelf -W -h "$binary_path")

stack_canary=0
while IFS= read -r line; do
  if [[ "$line" == *"__stack_chk_fail"* ]]; then
    stack_canary=1
    break
  fi
done < <(readelf -W -s "$binary_path")

full_relro=0
if [[ "$relro_segment" -eq 1 && "$bind_now" -eq 1 ]]; then
  full_relro=1
fi

nx_enabled=0
if [[ "$gnu_stack_seen" -eq 1 && "$exec_stack" -eq 0 ]]; then
  nx_enabled=1
fi

echo "[hardening] full_relro=$full_relro pie=$pie nx=$nx_enabled canary=$stack_canary"

failed=0
if [[ "$full_relro" -ne 1 ]]; then
  echo "[hardening] FAIL: Full RELRO requirement not met" >&2
  failed=1
fi
if [[ "$pie" -ne 1 ]]; then
  echo "[hardening] FAIL: PIE requirement not met" >&2
  failed=1
fi
if [[ "$nx_enabled" -ne 1 ]]; then
  echo "[hardening] FAIL: NX requirement not met" >&2
  failed=1
fi

require_canary="${EGUARD_HARDENING_REQUIRE_CANARY:-0}"
if [[ "$stack_canary" -ne 1 ]]; then
  if [[ "$require_canary" == "1" || "$require_canary" == "true" || "$require_canary" == "TRUE" ]]; then
    echo "[hardening] FAIL: stack canary requirement not met" >&2
    failed=1
  else
    echo "[hardening] WARN: stack canary symbol not found (set EGUARD_HARDENING_REQUIRE_CANARY=1 to enforce)"
  fi
fi

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "[hardening] all checks passed"
