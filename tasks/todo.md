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
