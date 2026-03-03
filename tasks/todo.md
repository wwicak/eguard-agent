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

---

## Additional polish: cross-run trend comparator for regression visibility

### Plan
- [x] Add a dedicated trend comparator for multiple run summaries.
- [x] Support explicit baseline selection (not only implicit ordering).
- [x] Emit both JSON and Markdown outputs for humans + automation.
- [x] Validate using existing `retest/rerun2/rerun3` artifacts.

### Review
- Added `scripts/perf/compare_trend.py`:
  - accepts repeated `--input` (run dir or summary file) or `--artifact-root` discovery,
  - compares `overhead_median_pct`, `overhead_p95_pct`, `agent_cpu_avg_s` across runs,
  - detects regressions via configurable max delta thresholds,
  - supports `--baseline-run` override (default oldest discovered timestamp),
  - writes optional `--json-output` and `--report-output`,
  - supports optional non-zero exit via `--fail-on-regression`.
- Sorting and baseline logic now use timestamp extraction (`YYYYMMDDTHHMMSSZ`) to avoid lexical run-name bias.

### Verification
- `python3 -m py_compile scripts/perf/compare_trend.py` ✅
- `python3 scripts/perf/compare_trend.py --input artifacts/perf/retest-20260302T043407Z --input artifacts/perf/rerun2-20260302T061620Z --input artifacts/perf/rerun3-20260302T062911Z --report-output /tmp/perf-trend.md --json-output /tmp/perf-trend.json` ✅
- `python3 scripts/perf/compare_trend.py --input artifacts/perf/retest-20260302T043407Z --input artifacts/perf/rerun2-20260302T061620Z --input artifacts/perf/rerun3-20260302T062911Z --baseline-run rerun2-20260302T061620Z --report-output /tmp/perf-trend.md --json-output /tmp/perf-trend.json` ✅

---

## Additional polish: trend comparator correctness + CLI regression tests

### Plan
- [x] Fix baseline-delta reporting bug when explicit baseline is not the first row.
- [x] Add optional trend regression rule for newly introduced quality flags.
- [x] Add lightweight CLI tests for gate + trend tools to prevent regressions.
- [x] Validate against synthetic fixtures and real rerun artifacts.

### Review
- `scripts/perf/compare_trend.py`
  - report deltas now resolve baseline row by `baseline_run` (not row index),
  - added `--fail-on-new-quality-flags` to treat newly introduced flags as regressions,
  - report now includes `Quality flags` and `New flags vs baseline` columns,
  - JSON output now records `fail_on_new_quality_flags` policy.
- Added tests: `scripts/perf/tests/test_perf_cli_tools.py`
  - verifies baseline override math in generated trend report,
  - verifies `--fail-on-new-quality-flags` + `--fail-on-regression` exit behavior,
  - verifies gate min-run enforcement and configurable quality-flag fail-list behavior.

### Verification
- `python3 -m py_compile scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (3 passed)
- `python3 scripts/perf/compare_trend.py --input artifacts/perf/retest-20260302T043407Z --input artifacts/perf/rerun2-20260302T061620Z --input artifacts/perf/rerun3-20260302T062911Z --baseline-run rerun2-20260302T061620Z --report-output /tmp/perf-trend-polish4.md --json-output /tmp/perf-trend-polish4.json` ✅
- `python3 scripts/perf/compare_trend.py --input artifacts/perf/retest-20260302T043407Z --input artifacts/perf/rerun2-20260302T061620Z --input artifacts/perf/rerun3-20260302T062911Z --baseline-run rerun2-20260302T061620Z --fail-on-regression` ✅ (expected exit `1`)

---

## Additional polish: optional workflow trend-gate integration

### Plan
- [x] Add workflow inputs to control baseline trend comparison and regression policies.
- [x] Add optional CI step that runs trend comparison when a baseline path is provided.
- [x] Publish trend JSON/Markdown artifacts together with summary+gate outputs.
- [x] Verify workflow YAML validity and CLI regression tests after integration.

### Review
- `.github/workflows/performance-gate.yml`
  - new dispatch inputs:
    - `trend_baseline_summary`
    - `trend_fail_on_regression`
    - `trend_fail_on_new_quality_flags`
    - `trend_max_regression_overhead_median_pct`
    - `trend_max_regression_overhead_p95_pct`
    - `trend_max_regression_agent_cpu_avg_s`
  - new `Compare trend vs optional baseline` step:
    - skips cleanly when no baseline path is provided,
    - fails fast if baseline path is configured but missing,
    - runs `scripts/perf/compare_trend.py` against current run + baseline,
    - supports optional hard fail on regression / new quality flags.
  - artifact upload now also includes:
    - `artifacts/perf/<run>/trend.json`
    - `artifacts/perf/<run>/trend.md`
    - with `if-no-files-found: warn` for optional trend outputs.

### Verification
- `yq '.' .github/workflows/performance-gate.yml` ✅ (valid YAML parse)
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (3 passed)

---

## Additional polish: trend baseline safety + required-platform enforcement

### Plan
- [x] Prevent workflow trend checks from accidentally using current run as baseline.
- [x] Make trend comparator enforce required platform presence across runs.
- [x] Add regression tests for required-platform missing cases.
- [x] Re-validate YAML + test suites + real artifact trend output.

### Review
- `.github/workflows/performance-gate.yml`
  - added `trend_baseline_run` input,
  - trend step now derives baseline run from provided baseline path when not explicitly set,
  - passes `--baseline-run` to `scripts/perf/compare_trend.py` to avoid implicit ordering mistakes.
- `scripts/perf/compare_trend.py`
  - added `--required-platforms` (default `linux,windows`),
  - regression evaluation now fails on missing required platform data,
  - regression evaluation now fails on missing required metrics (baseline/current) with explicit diagnostics,
  - output JSON now records `required_platforms`.
- `scripts/perf/tests/test_perf_cli_tools.py`
  - added `test_compare_trend_fails_when_required_platform_data_missing`,
  - helper now supports per-fixture platform sets for targeted negative tests.

### Verification
- `python3 -m py_compile scripts/perf/compare_trend.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (4 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/compare_trend.py --input artifacts/perf/retest-20260302T043407Z --input artifacts/perf/rerun2-20260302T061620Z --input artifacts/perf/rerun3-20260302T062911Z --baseline-run rerun2-20260302T061620Z --report-output /tmp/perf-trend-polish5.md --json-output /tmp/perf-trend-polish5.json` ✅

---

## Additional polish: trend validation noise reduction + workflow required-platform control

### Plan
- [x] Reduce duplicate trend failures when baseline metrics are missing.
- [x] Add workflow control for required platform set in trend checks.
- [x] Add tests for required-platform override behavior.
- [x] Re-run lint/parse/tests and real artifact trend command.

### Review
- `scripts/perf/compare_trend.py`
  - baseline-missing metric failures are now emitted once per platform/metric (not repeated for every run),
  - per-row regression details still record baseline metric absence for transparency,
  - `--required-platforms` remains enforced for run/platform completeness, now included in end-to-end workflow path.
- `.github/workflows/performance-gate.yml`
  - added `trend_required_platforms` dispatch input (default `linux,windows`),
  - trend compare step now passes `--required-platforms` explicitly,
  - baseline run selection remains explicit via `trend_baseline_run` or derived from baseline path.
- `scripts/perf/tests/test_perf_cli_tools.py`
  - added `test_compare_trend_required_platforms_override_allows_linux_only_runs`,
  - suite now validates both strict default and explicit relaxed platform requirements.

### Verification
- `python3 -m py_compile scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (5 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/compare_trend.py --input artifacts/perf/retest-20260302T043407Z --input artifacts/perf/rerun2-20260302T061620Z --input artifacts/perf/rerun3-20260302T062911Z --baseline-run rerun2-20260302T061620Z --required-platforms linux,windows --report-output /tmp/perf-trend-polish6.md --json-output /tmp/perf-trend-polish6.json` ✅

---

## Additional polish: baseline pointer resolver + safer workflow baseline selection

### Plan
- [x] Add a dedicated resolver to unify baseline input handling (direct path vs pointer file).
- [x] Integrate resolver into workflow and expose pointer-based baseline input.
- [x] Expand CLI test coverage for resolver behaviors.
- [x] Re-run parses/tests and validate real baseline resolution command.

### Review
- Added `scripts/perf/resolve_baseline.py`:
  - resolves baseline from either `--baseline-summary` or `--baseline-pointer` (JSON/plain text),
  - supports relative path resolution against `--workspace-root`,
  - derives baseline run automatically when not provided,
  - can emit JSON output and GitHub step outputs (`resolved`, `baseline_input`, `baseline_run`).
- `.github/workflows/performance-gate.yml`
  - added dispatch input `trend_baseline_pointer`,
  - added `Resolve optional trend baseline` step (`id: resolve-trend-baseline`),
  - trend compare step now consumes resolver outputs and skips cleanly when unresolved,
  - uploads `trend-baseline-resolution.json` artifact for audit/debug.
- `scripts/perf/tests/test_perf_cli_tools.py`
  - added `test_resolve_baseline_direct_summary_derives_run`,
  - added `test_resolve_baseline_pointer_json_relative_path`.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (7 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/resolve_baseline.py --baseline-summary artifacts/perf/rerun2-20260302T061620Z --workspace-root /home/dimas/eguard-agent` ✅

---

## Additional polish: baseline pointer lifecycle automation + stricter pointer policy controls

### Plan
- [x] Add a script to update baseline pointer files from chosen run artifacts.
- [x] Default workflow pointer lookup to `.ci/perf-baseline.json` (auto-resolve when present).
- [x] Add strict-pointer mode control in workflow inputs.
- [x] Extend tests to cover pointer update/resolution roundtrip and strict-missing behavior.

### Review
- Added `scripts/perf/update_baseline_pointer.py`:
  - writes normalized baseline pointer JSON (`summary_path`, `baseline_run`, `updated_at_utc`),
  - supports relative path output against workspace root,
  - supports custom pointer destinations (default `.ci/perf-baseline.json`).
- Added `.ci/perf-baseline.example.json` as repo convention/sample pointer payload.
- Updated `.github/workflows/performance-gate.yml`:
  - `trend_baseline_pointer` now defaults to `.ci/perf-baseline.json`,
  - added `trend_baseline_pointer_strict` input,
  - resolver step now conditionally appends `--strict-pointer`.
- Expanded `scripts/perf/tests/test_perf_cli_tools.py`:
  - `test_update_baseline_pointer_roundtrip_with_resolver`,
  - `test_resolve_baseline_strict_pointer_missing_fails`.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (9 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/update_baseline_pointer.py --baseline-summary artifacts/perf/rerun2-20260302T061620Z/summary.json --workspace-root /home/dimas/eguard-agent --pointer-path /tmp/perf-baseline-pointer.json` ✅
- `python3 scripts/perf/resolve_baseline.py --baseline-pointer /tmp/perf-baseline-pointer.json --workspace-root /home/dimas/eguard-agent` ✅

---

## Additional polish: perf baseline runbook + candidate pointer emission workflow

### Plan
- [x] Add operator-facing perf tooling README covering summarize/gate/trend/pointer lifecycle.
- [x] Emit optional candidate baseline pointer artifact from successful workflow runs.
- [x] Tighten resolver semantics so direct baseline input fully overrides pointer metadata.
- [x] Expand CLI tests for pointer precedence and absolute-path update mode.

### Review
- Added `scripts/perf/README.md`:
  - concise usage for `summarize.py`, `gate.py`, `compare_trend.py`,
  - baseline pointer lifecycle commands,
  - links to `.ci/perf-baseline.example.json` convention.
- Updated `.github/workflows/performance-gate.yml`:
  - added `trend_emit_candidate_pointer` input,
  - added `Emit baseline pointer candidate artifact` step,
  - uploads `perf-baseline.candidate.json` + metadata artifact.
- Updated `scripts/perf/resolve_baseline.py`:
  - direct summary now overrides pointer-provided `baseline_run` (prevents mismatched run labels).
- Expanded `scripts/perf/tests/test_perf_cli_tools.py`:
  - `test_resolve_baseline_prefers_direct_input_over_pointer`,
  - `test_update_baseline_pointer_absolute_paths_mode`.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (11 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅

---

## Additional polish: baseline promotion helper + stricter summary-path normalization

### Plan
- [x] Add one-command baseline promotion helper for run-tag/candidate workflows.
- [x] Enforce canonical `summary.json` paths in resolver/updater to avoid ambiguous inputs.
- [x] Expand tests for directory normalization and promotion guardrails.
- [x] Re-run lint/tests and smoke-check promotion/resolution flow.

### Review
- Added `scripts/perf/promote_baseline.py`:
  - promotes baseline from `--run-tag` or `--candidate-pointer`,
  - requires gate status `pass` by default (`--skip-gate-check` override available),
  - writes normalized pointer payload to `.ci/perf-baseline.json` (or custom path).
- Tightened input validation:
  - `scripts/perf/resolve_baseline.py` now canonicalizes baseline input to `summary.json` and accepts run-dir shorthand only if `summary.json` exists,
  - `scripts/perf/update_baseline_pointer.py` now writes canonical `summary.json` paths when given run directories and rejects non-summary files.
- Added/updated docs:
  - `scripts/perf/README.md` now includes promotion flow commands.
- Expanded tests in `scripts/perf/tests/test_perf_cli_tools.py`:
  - `test_resolve_baseline_directory_input_normalizes_to_summary_json`,
  - `test_update_baseline_pointer_directory_input_writes_summary_json`,
  - `test_promote_baseline_requires_gate_pass`,
  - `test_promote_baseline_from_candidate_pointer`.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/promote_baseline.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (15 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/promote_baseline.py --run-tag rerun3-20260302T062911Z --artifact-root artifacts/perf --workspace-root /home/dimas/eguard-agent --pointer-path /tmp/perf-baseline-promoted.json --skip-gate-check` ✅
- `python3 scripts/perf/resolve_baseline.py --baseline-pointer /tmp/perf-baseline-promoted.json --workspace-root /home/dimas/eguard-agent` ✅

---

## Additional polish: baseline gate-pass enforcement + stronger baseline input guardrails

### Plan
- [x] Wire `--require-gate-pass` behavior end-to-end in baseline resolver.
- [x] Add workflow input to enforce baseline gate-pass policy during trend baseline resolution.
- [x] Expand tests for resolver gate-pass handling and stricter updater input validation.
- [x] Re-run compiles/tests/workflow parse and smoke-check failure path.

### Review
- Updated `scripts/perf/resolve_baseline.py`:
  - `--require-gate-pass` is now enforced,
  - resolver checks `<baseline_run>/gate.json` and requires `status == pass` when enabled,
  - resolver payload and GitHub outputs now include `baseline_gate_status`.
- Updated `.github/workflows/performance-gate.yml`:
  - added dispatch input `trend_require_baseline_gate_pass` (default `true`),
  - resolver step now conditionally passes `--require-gate-pass`.
- Strengthened baseline-path guardrails:
  - `scripts/perf/update_baseline_pointer.py` now canonicalizes to `summary.json` and rejects non-summary files,
  - `scripts/perf/resolve_baseline.py` similarly canonicalizes and validates baseline target.
- Expanded tests in `scripts/perf/tests/test_perf_cli_tools.py`:
  - `test_resolve_baseline_require_gate_pass_accepts_passing_gate`,
  - `test_resolve_baseline_require_gate_pass_rejects_non_pass_gate`,
  - `test_update_baseline_pointer_rejects_non_summary_file`.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/promote_baseline.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py scripts/perf/tests/test_perf_cli_tools.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (18 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/resolve_baseline.py --baseline-summary artifacts/perf/rerun3-20260302T062911Z/summary.json --workspace-root /home/dimas/eguard-agent --require-gate-pass` ✅ (expected fail: missing gate.json)

---

## Additional polish: promotion/trend safety hardening + richer baseline diagnostics

### Plan
- [x] Enforce `--require-gate-pass` behavior in resolver with explicit diagnostics.
- [x] Add workflow toggle for baseline gate-pass enforcement and surface baseline gate status in logs.
- [x] Extend promotion helper with trend-pass policy and dry-run mode.
- [x] Expand tests for new promotion/resolver edge-cases.

### Review
- `scripts/perf/resolve_baseline.py`
  - `--require-gate-pass` now validates `<baseline-run>/gate.json` status,
  - resolver payload now includes `baseline_gate_status`,
  - GitHub outputs now also include `baseline_gate_status` for workflow visibility.
- `.github/workflows/performance-gate.yml`
  - added `trend_require_baseline_gate_pass` input (default `true`),
  - resolver step conditionally appends `--require-gate-pass`,
  - compare step now logs baseline input/run/gate status for auditability.
- `scripts/perf/promote_baseline.py`
  - added `--require-trend-pass` (checks `trend.json` status),
  - added `--dry-run` to validate and print promotion payload without writing pointer,
  - result now includes gate/trend statuses + dry-run metadata.
- `scripts/perf/tests/test_perf_cli_tools.py`
  - added resolver tests for gate-pass accept/reject,
  - added updater test for non-summary-file rejection,
  - added promotion tests for trend-pass enforcement and dry-run no-write behavior.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/promote_baseline.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py scripts/perf/tests/test_perf_cli_tools.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (20 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/promote_baseline.py --run-tag rerun3-20260302T062911Z --artifact-root artifacts/perf --workspace-root /home/dimas/eguard-agent --pointer-path /tmp/perf-baseline-promote-dry.json --skip-gate-check --dry-run` ✅

---

## Additional polish: baseline trend-pass policy + promotion control hardening

### Plan
- [x] Add optional baseline trend-pass enforcement in resolver and workflow.
- [x] Expose baseline trend status in resolver outputs + workflow logs.
- [x] Extend promotion helper with trend-pass and dry-run safety controls.
- [x] Expand tests for resolver trend-pass and promotion edge-cases.

### Review
- `scripts/perf/resolve_baseline.py`
  - added `--require-trend-pass` to require `trend.json` status `pass`,
  - payload/GitHub outputs now include `baseline_trend_status`.
- `.github/workflows/performance-gate.yml`
  - added `trend_require_baseline_trend_pass` input (default `false`),
  - resolver step conditionally appends `--require-trend-pass`,
  - trend compare step now logs `baseline_trend_status`.
- `scripts/perf/promote_baseline.py`
  - added `--require-trend-pass` enforcement on run promotion,
  - added `--dry-run` for safe preview (no pointer file write),
  - promotion payload now stores `gate_status`, `trend_status`, and `promoted_at_utc`.
- `scripts/perf/README.md`
  - documented combined gate+trend resolver checks and promotion dry-run/require-trend-pass usage.
- `scripts/perf/tests/test_perf_cli_tools.py`
  - added resolver tests for trend-pass accept/reject,
  - added promotion tests for trend-pass reject + dry-run no-write.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/promote_baseline.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py scripts/perf/tests/test_perf_cli_tools.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (22 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/resolve_baseline.py --baseline-summary artifacts/perf/rerun3-20260302T062911Z/summary.json --workspace-root /home/dimas/eguard-agent --require-trend-pass` ✅ (expected fail: missing trend.json)

---

## Additional polish: overwrite-safety guardrails for pointer updates/promotions

### Plan
- [x] Prevent accidental baseline pointer replacement without explicit override.
- [x] Add optional automatic backup of existing pointer files before overwrite.
- [x] Extend tests for overwrite refusal and force+backup behaviors.
- [x] Re-run full perf CLI test suite and workflow YAML validation.

### Review
- `scripts/perf/update_baseline_pointer.py`
  - added `--force` and `--backup-existing`,
  - now refuses replacing existing pointer when baseline target differs unless `--force` is set,
  - optional timestamped backup (`*.bak-<utc>`) before overwrite,
  - result payload now includes `has_existing_pointer`, `pointer_changed`, and `backup_path`.
- `scripts/perf/promote_baseline.py`
  - added `--force` and `--backup-existing` with same safety semantics,
  - existing-pointer comparison is based on `summary_path` + `baseline_run`,
  - result payload now includes overwrite/backup metadata.
- `scripts/perf/tests/test_perf_cli_tools.py`
  - added:
    - `test_update_baseline_pointer_requires_force_for_overwrite`,
    - `test_update_baseline_pointer_force_with_backup`,
    - `test_promote_baseline_requires_force_for_pointer_replacement`,
    - `test_promote_baseline_force_with_backup`.
- `scripts/perf/README.md`
  - added safe overwrite command examples (`--force --backup-existing`).

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/promote_baseline.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py scripts/perf/tests/test_perf_cli_tools.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (26 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅

---

## Additional polish: summary-digest integrity checks + pointer mutation safeguards

### Plan
- [x] Add summary SHA-256 integrity metadata to baseline pointer flows.
- [x] Validate pointer digest during baseline resolution to detect stale/tampered references.
- [x] Harden pointer overwrite behavior in updater/promoter with force+backup policy.
- [x] Extend tests for digest mismatch and overwrite guardrails.

### Review
- `scripts/perf/update_baseline_pointer.py`
  - now computes/stores `summary_sha256`,
  - overwrite comparison includes digest consistency when existing digest is present,
  - supports guarded overwrite with `--force` and optional `--backup-existing`.
- `scripts/perf/promote_baseline.py`
  - now computes/stores `summary_sha256` in promoted pointer payload,
  - overwrite comparison includes digest consistency,
  - guarded replacement controls (`--force`, `--backup-existing`) retained.
- `scripts/perf/resolve_baseline.py`
  - parses pointer `summary_sha256` and verifies against resolved summary file when present,
  - emits `baseline_summary_sha256` to JSON + GitHub outputs,
  - failure path is explicit on digest mismatch.
- `.github/workflows/performance-gate.yml`
  - now logs `baseline_summary_sha256` after resolver step for auditability.
- `.ci/perf-baseline.example.json`
  - updated to include `summary_sha256` field.
- `scripts/perf/tests/test_perf_cli_tools.py`
  - added digest mismatch test for resolver,
  - expanded overwrite/backup tests for updater/promoter,
  - total test count increased to 27.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/promote_baseline.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py scripts/perf/tests/test_perf_cli_tools.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (27 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅

---

## Additional polish: pointer digest integrity + no-op rewrite suppression

### Plan
- [x] Add summary digest integrity fields throughout pointer lifecycle.
- [x] Verify pointer digest during baseline resolution and fail on mismatch.
- [x] Prevent unnecessary pointer rewrites when baseline is unchanged.
- [x] Expand tests for digest mismatch and rewrite/no-op behavior.

### Review
- `scripts/perf/resolve_baseline.py`
  - added summary SHA-256 computation and pointer digest verification,
  - added output field `baseline_summary_sha256` (JSON + GitHub outputs),
  - pointer resolution now rejects mismatched digest values explicitly.
- `scripts/perf/update_baseline_pointer.py`
  - now writes `summary_sha256` into pointer payload,
  - unchanged pointers are no-op by default (`pointer_written=false`),
  - added `--rewrite-if-unchanged` override for intentional rewrites.
- `scripts/perf/promote_baseline.py`
  - now writes `summary_sha256` into promoted pointer payload,
  - unchanged promotions are no-op by default,
  - added `--rewrite-if-unchanged` override.
- `scripts/perf/tests/test_perf_cli_tools.py`
  - added digest mismatch test for resolver,
  - added no-op/rewrite tests for updater/promoter,
  - total suite now covers digest + overwrite + rewrite controls.
- `scripts/perf/README.md` and `.ci/perf-baseline.example.json`
  - documented digest field and no-op rewrite semantics.

### Verification
- `python3 -m py_compile scripts/perf/resolve_baseline.py scripts/perf/update_baseline_pointer.py scripts/perf/promote_baseline.py scripts/perf/compare_trend.py scripts/perf/gate.py scripts/perf/summarize.py scripts/perf/tests/test_perf_cli_tools.py` ✅
- `python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'` ✅ (31 passed)
- `yq '.' .github/workflows/performance-gate.yml` ✅
- `python3 scripts/perf/update_baseline_pointer.py --baseline-summary /tmp/summary.json --workspace-root /home/dimas/eguard-agent --pointer-path /tmp/pointer.json` followed by a second identical invocation confirms `pointer_written=false` on unchanged baseline ✅

---

## Live check: 24h ML pipeline health (server + Linux VM + Windows VM)

### Plan
- [x] Read ML ops manual + production acceptance criteria and derive required runtime checks.
- [x] Verify server-side ML/baseline services, scheduler outputs, and DB/API evidence for the last 24h.
- [x] Verify Linux/Windows agent runtime evidence (heartbeat, baseline upload/seed apply, service health).
- [x] Summarize pass/fail per acceptance-relevant criterion and list remediation actions if gaps are found.

### Review
- Scope validated against:
  - `docs/ml-ops-operations-manual.md` (sections 5, 8, 11, 12)
  - `docs/baseline-ml-production-acceptance.md` (AC-BML-010/011/020/022/030/033/060 and runtime status notes)
- Server (`eguard@103.49.238.102`):
  - `eguard-agent-server` and `eguard-api-frontend` are `active`.
  - Signature-ML runtime artifacts exist and latest report is `status=success`, `run_id=20260302T020001Z` under `/usr/local/eg/var/mlops/signature-ml-feedback/latest-report.json`.
  - Baseline API evidence from `eg-agent-server` (`:50053`):
    - Linux latest baseline `learned_at=2026-03-03T00:49:10Z`
    - Windows latest baseline `learned_at=2026-03-03T00:54:18Z`
    - Inventory rows continue hourly for both agents in last 24h.
  - Fleet endpoint before manual aggregate: fallback built-in seed (`seeded=true`, `source=built_in_seed`) because cohort gate default is higher than active distinct contributors.
  - Manual aggregate (`POST /api/v1/endpoint/baseline/aggregate` with `min_agents=2`) succeeded with `aggregated=7`; subsequent fleet fetch returned `seeded=false`, `source=fleet_aggregated`.
- Linux agent (`agent@103.183.74.3`):
  - Service `eguard-agent` is `active`.
  - Last-24h logs show repeated baseline uploads every ~15m (`00:34`, `00:49`, `01:04`) with `uploaded baseline profile batch`.
  - No fleet-seed apply in last 24h (consistent with non-learning/non-stale fetch rules).
- Windows agent (`administrator@103.31.39.30`):
  - Service `eGuardAgent` is `Running`.
  - Baseline uploads continue every ~15m (`00:24`, `00:39`, `00:54`) with `uploaded baseline profile batch`.
  - Fleet seed apply evidence exists in the last 24h: `2026-03-02T03:25:48Z ... applied fleet baseline seed profiles ... seeded_profiles=1`.

### Verification
- Manual checks executed across all three hosts via SSH.
- API checks (server-local against `http://127.0.0.1:50053`):
  - `GET /api/v1/endpoint/baseline?agent_id=...`
  - `GET /api/v1/endpoint/inventory?limit=500`
  - `GET /api/v1/endpoint/baseline/fleet?limit=...`
  - `POST /api/v1/endpoint/baseline/aggregate` (validation run with `min_agents=2`)
- Agent log checks:
  - Linux: `sudo journalctl -u eguard-agent --since "24 hours ago" ...`
  - Windows: `Select-String` on `C:\ProgramData\eGuard\logs\agent.log`

---

## Plan — Cross-platform "magic inside agent" (Linux + Windows + macOS)

### Objective
Generalize performance optimizations into a shared internal architecture so endpoint overhead is minimized by default while preserving detection quality across Linux, Windows, and macOS.

### Implementation plan
- [ ] Define canonical internal event contract (`EventTxn`) in agent-core for process/file/network transactions, independent of OS collectors.
- [ ] Add platform adapter layer in each platform crate to map raw OS events into canonical transaction inputs:
  - Linux: eBPF/inotify adapter
  - Windows: ETW/file adapter
  - macOS: EndpointSecurity/FSEvents adapter
- [ ] Implement transactionizer in `agent-core` to collapse burst raw events into stable transaction units (write/rename/unlink/open aggregation).
- [ ] Implement progressive detection cascade in detection engine:
  - Stage A (cheap): IOC prefilter + metadata/reputation
  - Stage B (medium): temporal/anomaly lightweight checks
  - Stage C (expensive): YARA/deep ML/hash-heavy path only for gated suspicious transactions
- [ ] Implement shared scan memoization cache keyed by `(content fingerprint, policy hash, rule bundle version)` with deterministic invalidation.
- [ ] Implement adaptive QoS governor in runtime loop to maintain target tick latency and queue health by auto-tuning sampling/coalescing/deep-scan concurrency.
- [ ] Expose cross-platform observability counters (coalesced txns, deep-scan skips, memo hits, QoS transitions, backlog drops, stage distribution).
- [ ] Add policy/config controls for all new mechanisms (with safe defaults + env overrides) and ensure runtime policy sync updates these values.
- [ ] Add deterministic tests for parity + safety:
  - transactionization correctness
  - cascade gating correctness
  - memoization invalidation correctness
  - no regression for high-confidence/blocking detections
- [ ] Add platform acceptance harness and run on Linux+Windows+macOS fixtures/VMs.
- [ ] Run benchmark matrix (idle/office/build/ransomware-like) before vs after, compare p50/p95/p99 overhead and CPU/IO metrics, then document rollout plan.

### Acceptance criteria
- [ ] AC1 — Functional parity: no drop in must-detect regression suite vs baseline across Linux/Windows/macOS for high-confidence attack scenarios.
- [ ] AC2 — Event reduction: transactionizer reduces raw event volume by >=40% under churn workloads without losing required detection context.
- [ ] AC3 — Cost shaping: >=70% of benign events remain in Stage A/B and do not trigger expensive Stage C scans.
- [ ] AC4 — Memo effectiveness: repeated benign file/process workloads produce >=50% memo hit rate for expensive scan decisions after warm-up.
- [ ] AC5 — Latency guardrail: runtime governor keeps tick p95 within configured target band and prevents sustained backlog growth under burst load.
- [ ] AC6 — Benchmark target (provisional):
  - Linux: median overhead <=12%, p95 <=30%
  - Windows: median overhead <=6%, p95 <=12%
  - macOS: median overhead <=8%, p95 <=20% (initial provisional target)
- [ ] AC7 — Benchmark target (hard):
  - Linux: median <=8%, p95 <=20%
  - Windows: median <=5%, p95 <=8%
  - macOS: median <=6%, p95 <=12%
- [ ] AC8 — Observability: new counters/metrics are visible in runtime snapshot and exported in benchmark artifacts.
- [ ] AC9 — Safe fallback: disabling new features via config returns behavior to prior pipeline semantics without restart failures.
- [ ] AC10 — Rollout safety: staged canary (10% -> 50% -> 100%) completes with no increase in incident miss-rate and no service instability across platforms.

### Implementation status — Phase A (cross-platform enrichment parity) ✅
- [x] Removed no-op stubs for enrichment budget controls on Windows/macOS:
  - `set_budget_mode(...)`
  - `set_hash_finalize_delay_ms(...)`
  - `set_expensive_check_exclusions(...)`
- [x] Implemented churn-aware hash finalization cache on Windows/macOS (pending fingerprint + finalize delay).
- [x] Implemented strict-budget skip behavior for expensive file hashing on Windows/macOS.
- [x] Implemented expensive path/process exclusion filtering for hashing on Windows/macOS.
- [x] Wired process/file hashing paths to honor exclusions and budget mode consistently with Linux behavior.
- [x] Wired runtime policy sync to apply `file_hash_finalize_delay_ms` / `detection_file_hash_finalize_delay_ms` to the live enrichment cache.
- [x] Added deterministic unit tests for new Windows/macOS behaviors and policy-sync runtime wiring.

### Verification — Phase A
- `cargo test -p platform-windows --lib -- --nocapture` ✅ (71 passed)
- `cargo test -p platform-macos --lib -- --nocapture` ✅ (38 passed)
- `cargo test -p agent-core tests_ebpf_policy -- --nocapture` ✅ (12 passed)

### Acceptance criteria status after Phase A
- [x] AC9 (safe fallback / config toggles do not break runtime semantics) — implemented and tested for Windows/macOS enrichment path controls.
- [x] AC8 (observability compatibility for strict-budget behavior) — existing runtime counters remain valid; cross-platform enrichment now responds to strict-budget toggles.
- [ ] AC1–AC7, AC10 remain open for full architecture rollout (transactionizer, cascade, benchmark hard-gate convergence, canary).

### Implementation status — Phase B (EventTxn canonical wiring) ✅
- [x] Added canonical internal transaction model `EventTxn` in `crates/agent-core/src/lifecycle/event_txn.rs`.
- [x] Wired event transaction creation into hot path (`tick.rs`) and kernel-integrity synthetic detection path (`kernel_integrity_scan.rs`).
- [x] Embedded `event_txn` object into telemetry payload JSON for server-side/forensics correlation.
- [x] Unified file burst coalescing key generation to use canonical transaction parsing (`coalesce_file_event_key`) instead of duplicate ad-hoc parser logic.
- [x] Added observability metric `telemetry_event_txn_total` to runtime snapshot.
- [x] Added deterministic unit tests for transaction key normalization and transaction payload fields.

### Verification — Phase B
- `cargo test -p agent-core tests_ebpf_policy -- --nocapture` ✅ (12 passed)
- `cargo test -p agent-core tests_observability -- --nocapture` ✅ (13 passed)
- `cargo test -p agent-core policy_ -- --nocapture` ✅ (11 passed)
- `cargo test -p agent-core coalesce_file_event_key_normalizes_windows_separators -- --nocapture` ✅ (1 passed)

### Implementation status — Phase C (response dedupe + transaction-linked action path) ✅
- [x] Added transaction-linked response action identity (`txn_key`) to `PendingResponseAction`.
- [x] Implemented response action dedupe window in runtime path:
  - Env: `EGUARD_RESPONSE_ACTION_DEDUPE_WINDOW_SECS` (default 30s)
  - Policy: `response_action_dedupe_window_secs` / `detection_response_action_dedupe_window_secs`
- [x] Wired dedupe for both primary confidence-based responses and playbook-generated responses.
- [x] Added dedupe state pruning and guardrail to avoid unbounded key growth.
- [x] Added observability metric `response_action_deduped_total` and exposed in runtime snapshot.

### Verification — Phase C
- `cargo test -p agent-core response_action_dedupe -- --nocapture` ✅ (3 passed)
- `cargo test -p agent-core tests_observability -- --nocapture` ✅ (13 passed)
- `cargo test -p agent-core tests_ebpf_policy -- --nocapture` ✅ (12 passed)
- `cargo test -p agent-core policy_ -- --nocapture` ✅ (11 passed)
- `cargo test -p platform-windows --lib -- --nocapture` ✅ (72 passed)
- `cargo test -p platform-macos --lib -- --nocapture` ✅ (38 passed)

### Implementation status — Phase D (event-transaction coalescing + policy wiring) ✅
- [x] Implemented EventTxn-based burst coalescing stage in telemetry pipeline for noisy classes (file/network/dns).
- [x] Added runtime knobs for EventTxn coalescing:
  - Env: `EGUARD_EVENT_TXN_COALESCE_WINDOW_MS` (default `0`, safe disabled-by-default rollout)
  - Policy: `event_txn_coalesce_window_ms` / `detection_event_txn_coalesce_window_ms`
- [x] Added bounded in-memory coalesce state + retention pruning for transaction keys.
- [x] Added observability metric `telemetry_event_txn_coalesced_total` and surfaced in runtime snapshot.
- [x] Hardened raw TCP transaction parsing to use `dst_ip` + `dst_port` fields when `dst` is absent.

### Verification — Phase D
- `cargo test -p agent-core tests_ebpf_policy -- --nocapture` ✅ (13 passed)
- `cargo test -p agent-core tests_observability -- --nocapture` ✅ (13 passed)
- `cargo test -p agent-core response_action_dedupe -- --nocapture` ✅ (3 passed)
- `cargo test -p agent-core policy_ -- --nocapture` ✅ (13 passed)
- `cargo test -p agent-core event_txn -- --nocapture` ✅ (6 passed)
- `cargo test -p platform-windows --lib -- --nocapture` ✅ (72 passed)
- `cargo test -p platform-macos --lib -- --nocapture` ✅ (38 passed)
