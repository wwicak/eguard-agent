- [x] Review existing control-plane pipeline responsibilities and boundaries.
- [x] Split control-plane pipeline into focused submodules (scheduler, executor, policy, baseline, IOC/campaign, outbound sends, rollout helpers).
- [x] Keep behavior and public runtime method signatures unchanged while refactoring.
- [x] Run agent-core tests that cover control-plane and related flows.
- [x] Document outcome and verification notes.

## Windows release flake fix + v0.2.11
- [x] Make ETW session startup resilient to Windows `ERROR_ALREADY_EXISTS` races.
- [x] Remove shared session-name collision in ETW engine unit tests.
- [x] Run platform-windows and agent-core test suites locally.
- [ ] Commit fix, tag `v0.2.11`, and push.
- [ ] Trigger/verify release workflow and confirm published release assets.

---

## Live deploy + benchmark re-test (Linux + Windows VMs, 2026-03-02)

### Plan
- [x] Build updated Linux + Windows agent binaries from current source.
- [x] Deploy binaries to Linux and Windows endpoint VMs with service restart.
- [x] Re-run ransomware-churn ON/OFF benchmark on both VMs.
- [x] Summarize results and evaluate provisional gate.

### Review
- Build outputs:
  - `target/release/agent-core`
  - `target/x86_64-pc-windows-gnu/release/agent-core.exe`
- Deployed endpoints:
  - Linux (`agent@103.183.74.3`): `/usr/bin/eguard-agent`
  - Windows (`administrator@103.31.39.30`): `C:\Program Files\eGuard\eguard-agent.exe`
- Hash parity (local == deployed):
  - Linux: `dd1b2cfb1ddb86e11b1aa216365d7f190e25866c7400b5035d531ee3a13e22d7`
  - Windows: `ca110804d433b33698b008f79953da84ee50f184135ed524efd9ab4f51c7489d`
- Benchmark run tag: `retest-20260302T043407Z`
  - `artifacts/perf/retest-20260302T043407Z/linux/ransomware/raw.json`
  - `artifacts/perf/retest-20260302T043407Z/windows/ransomware/raw.json`
  - `artifacts/perf/retest-20260302T043407Z/summary.json`
  - `artifacts/perf/retest-20260302T043407Z/report.md`

### Result summary (ransomware scenario)
- Linux (6 ON + 6 OFF, 1 warmup):
  - median overhead: `-23.70%`
  - p95 overhead: `-51.36%`
  - agent CPU avg: `0.172s`
- Windows (6 ON + 6 OFF, 1 warmup):
  - median overhead: `+32.98%`
  - p95 overhead: `+19.40%`
  - agent CPU avg: `0.318s`
- Provisional gate verdict: **FAIL** (Windows thresholds exceeded).

### Verification
- `cargo build -p agent-core --release --features platform-linux/ebpf-libbpf` ✅
- `cargo build -p agent-core --release --target x86_64-pc-windows-gnu` ✅
- `python3 scripts/perf/summarize.py --input-root artifacts/perf/retest-20260302T043407Z` ✅
- `python3 scripts/perf/gate.py --summary artifacts/perf/retest-20260302T043407Z/summary.json --profile provisional` ❌ (expected fail)

---

## Live re-run: deploy improved agent + re-test benchmark (2026-03-02, second pass)

### Plan
- [x] Rebuild latest Linux + Windows agent binaries from current source.
- [x] Redeploy binaries to Linux and Windows endpoint VMs and verify hash parity.
- [x] Re-run ransomware benchmark matrix on both VMs.
- [x] Summarize gate outcome and restore agent services to running state.

### Review
- Rebuilt binaries from current source and redeployed:
  - Linux `/usr/bin/eguard-agent`
  - Windows `C:\Program Files\eGuard\eguard-agent.exe`
- Hash parity (local == remote):
  - Linux: `196dc49ab4c1117a23b291d7c869670d330704a79050370fb5a3e51f01e81e51`
  - Windows: `a3caccfe42454bfcf4627935529d8b6d6e8a5a7ff37eddfb214adf8e94202be1`
- Re-test run tag: `rerun2-20260302T061620Z`
  - `artifacts/perf/rerun2-20260302T061620Z/linux/ransomware/raw.json`
  - `artifacts/perf/rerun2-20260302T061620Z/windows/ransomware/raw.json`
  - `artifacts/perf/rerun2-20260302T061620Z/summary.json`
  - `artifacts/perf/rerun2-20260302T061620Z/report.md`

### Result summary
- Linux headline (`ransomware`):
  - median overhead: `-8.33%`
  - p95 overhead: `-6.59%`
  - agent CPU avg: `0.175s`
- Windows headline (`ransomware`):
  - median overhead: `-23.26%`
  - p95 overhead: `+0.56%`
  - agent CPU avg: `0.234s`
- Provisional gate verdict: **PASS**.

### Verification
- `cargo build -p agent-core --release --features platform-linux/ebpf-libbpf` ✅
- `cargo build -p agent-core --release --target x86_64-pc-windows-gnu` ✅
- `python3 scripts/perf/summarize.py --input-root artifacts/perf/rerun2-20260302T061620Z` ✅
- `python3 scripts/perf/gate.py --summary artifacts/perf/rerun2-20260302T061620Z/summary.json --profile provisional` ✅ (PASS)
- Final service state:
  - Linux `eguard-agent`: `active`
  - Windows `eGuardAgent`: `Running`

---

## Live re-run: deploy improved agent + re-test benchmark (2026-03-02, third pass)

### Plan
- [x] Rebuild latest Linux + Windows agent binaries from current source.
- [x] Redeploy binaries to Linux and Windows endpoint VMs and verify hash parity.
- [x] Re-run ransomware benchmark matrix on both VMs.
- [x] Summarize gate outcome and restore agent services to running state.

### Review
- Rebuild:
  - `cargo build -p agent-core --release --features platform-linux/ebpf-libbpf`
  - `cargo build -p agent-core --release --target x86_64-pc-windows-gnu`
- Redeploy:
  - Linux deployed binary hash: `196dc49ab4c1117a23b291d7c869670d330704a79050370fb5a3e51f01e81e51`
  - Windows deployed binary hash: `a3caccfe42454bfcf4627935529d8b6d6e8a5a7ff37eddfb214adf8e94202be1`
- Benchmark run tag: `rerun3-20260302T062911Z`
  - `artifacts/perf/rerun3-20260302T062911Z/linux/ransomware/raw.json`
  - `artifacts/perf/rerun3-20260302T062911Z/windows/ransomware/raw.json`
  - `artifacts/perf/rerun3-20260302T062911Z/summary.json`
  - `artifacts/perf/rerun3-20260302T062911Z/report.md`

### Result summary
- Linux (`ransomware`):
  - median overhead: `+1.61%`
  - p95 overhead: `-31.24%`
  - agent CPU avg: `0.172s`
- Windows (`ransomware`):
  - median overhead: `-6.33%`
  - p95 overhead: `-21.53%`
  - agent CPU avg: `0.185s`
- Provisional gate: **PASS**.

### Verification
- `python3 scripts/perf/summarize.py --input-root artifacts/perf/rerun3-20260302T062911Z` ✅
- `python3 scripts/perf/gate.py --summary artifacts/perf/rerun3-20260302T062911Z/summary.json --profile provisional` ✅
- Final service state:
  - Linux `eguard-agent`: `active`
  - Windows `eGuardAgent`: `Running`

### Additional polish (benchmark runner hygiene)
- Updated perf scripts to preserve endpoint service state automatically:
  - `scripts/perf/linux_phase3.sh`
    - captures initial `eguard-agent` service state
    - restores it on exit via `trap`
  - `scripts/perf/windows_phase3.ps1`
    - captures initial `eGuardAgent` status
    - restores it in `finally` block
- Quick validation:
  - Linux short run (`idle`, 1s) kept service state `active` before/after.
  - Windows short run (`idle`, 1s) kept service state `Running` before/after.

---

## Additional polish: telemetry backpressure observability + coalesce quality

### Plan
- [x] Add cumulative observability counters for coalesced and backlog-dropped telemetry events.
- [x] Track strict budget-mode transitions for debugging churn behavior.
- [x] Improve sampling dequeue behavior to keep earliest event each stride.
- [x] Normalize file coalesce keys (case-insensitive) to reduce duplicate path variants.
- [x] Add/extend tests for coalescing behavior and strict-budget transitions.

### Review
- Updated runtime metrics and snapshot contracts:
  - `telemetry_coalesced_events_total`
  - `telemetry_raw_backlog_dropped_total`
  - `strict_budget_mode_transition_total`
- Updated telemetry pipeline behavior:
  - coalesce counter increments on dropped burst events,
  - backlog-drop counter increments when cap enforcement drops oldest events,
  - strict-budget transition counter increments when mode toggles,
  - sampling now dequeues first event then skips additional stride slots,
  - coalesce key path normalization now lowercases values.
- Updated tests (`crates/agent-core/src/lifecycle/tests_ebpf_policy.rs`):
  - coalesced counter assertion for repeated writes,
  - path-case normalization coalesce regression test,
  - strict-budget transition counter assertion after backlog clears.

### Verification
- `cargo fmt --all` ✅
- `cargo test -p agent-core tests_ebpf_policy -- --nocapture` ✅ (12 passed)
- `bash -n scripts/perf/linux_phase3.sh` ✅
- quick remote runner hygiene checks still pass (Linux/Windows service states preserved) ✅

---

## Additional polish: benchmark control stability + noisy-service shutdown handling

### Plan
- [x] Add wait-for-state loops to perf runners when toggling agent service ON/OFF.
- [x] Suppress noisy Windows service stop warnings and ensure deterministic mode transitions.
- [x] Keep service-state restoration intact after benchmark completion.
- [x] Re-verify scripts + targeted tests + quick live smoke.

### Review
- `scripts/perf/linux_phase3.sh`
  - added `wait_for_service_state()` with configurable timeout (`EGUARD_AGENT_STATE_WAIT_SECS`, default 45s),
  - `set_agent_mode` now waits for `active/inactive` convergence,
  - restore path also waits and logs explicit warning on timeout.
- `scripts/perf/windows_phase3.ps1`
  - added `Wait-AgentServiceStatus()` with configurable timeout (`EGUARD_AGENT_STATE_WAIT_SECS`, default 90s),
  - `Set-AgentMode` and `Restore-AgentState` now wait for `Running/Stopped` convergence,
  - added `-WarningAction SilentlyContinue` to service start/stop calls to suppress non-actionable noise.
- telemetry/runtime polish retained from prior pass:
  - coalesced/backlog-drop/strict-budget transition counters now available in observability snapshot.

### Verification
- `bash -n scripts/perf/linux_phase3.sh` ✅
- `cargo test -p agent-core tests_ebpf_policy -- --nocapture` ✅ (12 passed)
- Windows quick runner smoke (`idle`, 1s) now completes without warning spam ✅

---

## Additional polish: benchmark quality signaling + stricter gate sample checks

### Plan
- [x] Enforce minimum measured ON/OFF sample counts in gate evaluation.
- [x] Surface scenario quality flags directly in summary/report output.
- [x] Validate pass/fail behavior with real artifacts and stricter thresholds.

### Review
- `scripts/perf/gate.py`
  - added `--min-runs-per-mode` (default `6`),
  - gate now fails if either `runs_on` or `runs_off` is below minimum,
  - gate output now prints min-threshold checks alongside max-threshold metrics,
  - JSON output includes `min_runs_per_mode` for auditability.
- `scripts/perf/summarize.py`
  - added per-scenario `quality_flags` (e.g. low sample count, missing overheads, highly negative p95 overhead noise hint),
  - report table now includes `Quality flags` column,
  - headline section now prints quality flags explicitly.

### Verification
- `python3 -m py_compile scripts/perf/summarize.py scripts/perf/gate.py` ✅
- `python3 scripts/perf/summarize.py --input-root artifacts/perf/rerun3-20260302T062911Z --output-summary /tmp/rerun3-summary-polish.json --output-report /tmp/rerun3-report-polish.md` ✅
- `python3 scripts/perf/gate.py --summary /tmp/rerun3-summary-polish.json --profile provisional` ✅ (PASS)
- `python3 scripts/perf/gate.py --summary artifacts/perf/rerun3-20260302T062911Z/summary.json --profile provisional --min-runs-per-mode 7` ✅ (expected FAIL)

---

## Additional polish: workflow-level quality gating controls + fail-list semantics

### Plan
- [x] Add quality-flag fail-list support to gate evaluator.
- [x] Pass min-run and quality-flag controls from GitHub workflow inputs.
- [x] Persist machine-readable gate result artifact for audit/debug.
- [x] Verify default pass and targeted fail behavior with real summary artifacts.

### Review
- `scripts/perf/gate.py`
  - added `--fail-on-quality-flags` (CSV, default fails on missing/low-sample conditions),
  - gate now evaluates `quality_flags` from summary and fails when configured flags are present,
  - gate result JSON now includes quality fail-list config,
  - human output now prints quality-flag check details explicitly.
- `.github/workflows/performance-gate.yml`
  - added dispatch inputs:
    - `min_runs_per_mode`
    - `fail_on_quality_flags`
  - enforce step now passes both controls to `gate.py`,
  - emits `artifacts/perf/<run>/gate.json` and uploads it with summary/report.

### Verification
- `python3 -m py_compile scripts/perf/gate.py scripts/perf/summarize.py` ✅
- `python3 scripts/perf/gate.py --summary /tmp/rerun3-summary-polish.json --profile provisional` ✅ (PASS)
- `python3 scripts/perf/gate.py --summary /tmp/rerun3-summary-polish.json --profile provisional --fail-on-quality-flags 'high_negative_p95_overhead_check_for_noise'` ✅ (expected FAIL)
