# eGuard Agent Refactor / Optimization TODO

Last updated: 2026-02-15
Mode: Plan-first (next-job tranche implemented; operational closure pending)

## Objective

Maximize endpoint detection + response performance under strict AC contracts:

`J = w1*p99_detection + w2*p99_tick + w3*RSS + w4*CPU + w5*drop_rate + w6*false_alarm`

Hard constraints:
- Preserve AC correctness (DET/RSP/EBP/ATP/ASM)
- Preserve deterministic replay behavior
- Keep detection memory in single-digit MB envelope; binary size is tracked as telemetry only (no hard cap)
- No detection decision logic in assembly (acceleration only)

## Current Batch Plan (all remaining TODO items)

- [x] Extract remaining lifecycle orchestration into focused modules (ingest + control-plane heartbeat/compliance + response)
- [x] Introduce bounded queue-driven connected-tick control/response execution and expose depth/lag metrics per loop
- [x] Implement L2 compact numeric temporal entity keying and verify replay determinism semantics
- [x] Implement bounded parser buffer reuse/pooling in eBPF ingest backend
- [x] Surface eBPF probe attach/degrade capability status in runtime observability snapshots
- [x] Add sustained drop-rate validation harness invocation to verification set
- [x] Add perf/flamegraph profiling gate + optional release profile script (PGO/LTO/BOLT-friendly)
- [x] Prepare commit slicing + release prep checklist for clean rollout in dirty working tree
- [x] Run full verification matrix and refresh metrics/docs

## Binary Budget Release (Outcome Quality Priority)

- [x] Remove hard binary-size enforcement from `scripts/run_ebpf_resource_budget_ci.sh` while preserving binary-size metric reporting
- [x] Remove 10 MB binary threshold failure in `.github/workflows/verification-suite.yml`
- [x] Update harness/contract tests that assumed fixed `limits.binary_size_mb == 10`
- [x] Re-run targeted verification for modified crates/workflows/scripts

## Active Plan — Outcome Quality Policy Alignment (2026-02-14)

- [x] Rewrite all remaining hard `<10 MB` binary-size wording in `ACCEPTANCE_CRITERIA.md` to telemetry-first language
- [x] Align package metrics contracts to remove fixed `agent_binary=10 MB` assumptions
- [x] Regenerate acceptance artifacts after AC wording updates
- [x] Run full verification (`cargo test --workspace`) and refresh evidence in task docs

## Active Plan — Detection Quality Gate Hardening (2026-02-14)

- [x] Add replay quality metrics emission test (precision/recall/false-alarm upper bound) in detection crate
- [x] Add CI harness script to run replay quality gate and emit artifact (`artifacts/detection-quality-gate/metrics.json`)
- [x] Wire replay quality gate into verification workflow with explicit threshold enforcement
- [x] Run full verification (`cargo test --workspace`) and document results

## Active Plan — Dedicated Async Worker Split (2026-02-14)

- [x] Decouple control-plane heartbeat/compliance network sends from tick execution via bounded async worker task queues
- [x] Decouple response report network sends from response action execution via bounded async worker task queues
- [x] Keep command execution, threat-intel reload semantics, and determinism contracts intact
- [x] Run full verification (`cargo test --workspace`) and guardrail harnesses

## Active Plan — Adversarial Replay Quality Expansion (2026-02-14)

- [x] Expand detection replay quality metrics from a single reference trace to a multi-scenario adversarial corpus
- [x] Emit per-confidence-class precision/recall/false-alarm upper-bound metrics in `artifacts/detection-quality-gate/metrics.json`
- [x] Add trend artifact output for per-confidence metrics over time in CI artifact directory
- [x] Enforce adversarial-corpus + per-confidence thresholds in CI workflow guardrail checks
- [x] Run targeted + workspace verification and refresh task evidence

## Active Plan — Layer4 False-Positive Suppression (2026-02-14)

- [x] Reproduce and isolate high-confidence replay false positives to kill-chain evaluation scope leakage
- [x] Scope Layer4 template evaluation to current-event lineage roots (event PID + ancestors) instead of global graph sweeps
- [x] Add regression test to prevent stale kill-chain matches from leaking into unrelated event contexts
- [x] Re-enable strict high-confidence quality gate thresholds after FP suppression
- [x] Run targeted + workspace verification and refresh quality artifacts

## Active Plan — PID Reuse + Stale-State Adversarial Hardening (2026-02-14)

- [x] Add adversarial replay scenario that exercises PID reuse after a prior malicious chain
- [x] Reset Layer4 per-process derived risk flags on `process_exec` to prevent stale state carry-over across process image changes / PID reuse
- [x] Add Layer4 regression test proving PID reuse does not leak prior risk flags into new process lifetimes
- [x] Raise adversarial corpus minimum scenario threshold in quality-gate contracts
- [x] Run targeted + workspace verification and refresh quality artifacts

## Active Plan — Temporal Timestamp-Skew + Reorder Hardening (2026-02-14)

- [x] Add TemporalEngine regression test for stale stage restart attempts using timestamp skew beyond reorder tolerance
- [x] Add per-PID last-seen timestamp guardrail in Layer2 to reject severely out-of-order event injections before state transitions
- [x] Expand adversarial replay corpus with timestamp-skew sequence attempting stale stage reuse and validate strict no-FP behavior
- [x] Raise adversarial corpus minimum scenario threshold again after corpus expansion
- [x] Run targeted + workspace verification and refresh quality artifacts

## Active Plan — Temporal Identity-Continuity Hardening (2026-02-14)

- [x] Add Layer2 state identity continuity guard for non-`process_exec` follow-up stages to block PID-reuse stale-chain continuation when exec telemetry is missing
- [x] Add regression test proving non-exec identity drift on reused PID cannot complete stale pending webshell stages
- [x] Expand adversarial replay corpus with identity-drift PID-reuse scenario and raise corpus floor contracts
- [x] Update detection quality CI/workflow/script contracts for new minimum scenario coverage
- [x] Run targeted + workspace verification and refresh metrics/trend artifacts

## Active Plan — Temporal Lifecycle Eviction Hardening (2026-02-14)

- [x] Add Layer2 stale-state lifecycle pruning across per-rule temporal states and per-PID metadata maps under long-horizon telemetry churn
- [x] Add regression test proving stale pending state and PID metadata are evicted before reused-PID follow-ups are evaluated
- [x] Expand adversarial replay corpus with long-horizon stale-state churn scenario and raise corpus floor contracts
- [x] Update detection quality CI/workflow/script contracts for the new minimum scenario threshold
- [x] Run targeted + workspace verification and refresh metrics/trend artifacts

## Active Plan — Temporal Cardinality Cap + Deterministic Eviction Hardening (2026-02-14)

- [x] Add deterministic Layer2 capacity caps for temporal state and per-PID metadata maps to bound churn-driven memory growth
- [x] Add regression test proving oldest pending temporal chains are evicted first under state-cap pressure and retained chains still detect
- [x] Add regression test proving per-PID metadata cap evicts oldest entries first with stable low-PID tie-break behavior
- [x] Run targeted + workspace verification and refresh metrics/trend artifacts

## Next Job Backlog — All Remaining Items (2026-02-14)

Reference acceptance criteria: `tasks/next-job-acceptance-criteria.md`

### CI / Release Readiness

- [x] Verify workflow YAML syntax via GitHub Actions linter/dry-run checks
- [x] Confirm guardrail thresholds are realistic on CI runners under both cold and warm cache conditions
- [x] Verify perf-profile gate stays non-blocking when `perf` is unavailable on hosted runners
- [x] Confirm release/package workflows still produce valid `.deb` and `.rpm` artifacts
- [x] Upload and inspect optimization guardrail artifacts from workflow runs

### Operational Closure

- [x] Run `bash scripts/run_verification_suite_ci.sh` end-to-end in an environment with `cargo-audit` available
- [x] Complete commit slicing / PR hygiene by landing isolated slices with per-slice validation evidence

### Detection Hardening — Next Technical Tranche

- [x] Add ProcessExit-aware Layer2 teardown hooks to immediately retire per-PID temporal state/metadata on process end
- [x] Add Layer2 eviction observability counters with reason tags (retention, state-cap, metadata-cap)
- [x] Add adversarial replay scenarios for cap-pressure timestamp ties and combined cap/reorder abuse
- [x] Add cross-layer PID churn adversarial scenario validating no stale-state contamination across Layer2 + Layer4
- [x] Add detection-quality trend drift alarms from `per-confidence-trend.ndjson` for precision/recall/FAR regression bounds

## Active Plan — Next Job Full Implementation (2026-02-14)

- [x] Implement ProcessExit-aware Layer2 teardown semantics (immediate PID state/metadata retirement + idempotent stale-exit handling)
- [x] Add Layer2 reason-tagged eviction counters and regression coverage (`retention_prune`, `state_cap_evict`, `metadata_cap_evict`)
- [x] Expand adversarial replay corpus with cap-pressure timestamp-tie, cap+reorder abuse, and cross-layer PID churn scenarios
- [x] Raise corpus-floor contracts and synchronize detection-quality script/workflow thresholds with new scenario count
- [x] Add detection-quality trend drift regression gate from `per-confidence-trend.ndjson` + artifactized drift report
- [x] Add CI workflow lint/dry-run guard script for verification/package/release workflows
- [x] Add cold/warm guardrail threshold realism harness and wire scheduled/workflow-dispatch CI execution
- [x] Add package artifact validation gate (`.deb`/`.rpm` structural checks) to package/release workflows
- [x] Add optimization artifact inspection summary output + archived verification-suite logs in CI artifacts
- [x] Run targeted verification (`cargo test -p detection`, `bash scripts/run_detection_quality_gate_ci.sh`) and update docs/checklists

## Baseline Discovery (Completed)

- [x] Read design + implementation trackers from `/home/dimas/fe_eguard/docs`
- [x] Audited current agent code hotspots in `/home/dimas/eguard-agent/crates`
- [x] Ran benchmark harness: `scripts/run_detection_benchmark_ci.sh`
- [x] Ran budget harness: `scripts/run_ebpf_resource_budget_ci.sh`
- [x] Ran SLO harness: `scripts/run_rule_push_slo_ci.sh`
- [x] Captured baseline artifacts under `/home/dimas/eguard-agent/artifacts`
- [x] Added runtime optimization acceptance criteria (`AC-OPT-001..005`) to `ACCEPTANCE_CRITERIA.md`

## Priority Refactor Plan

### P1 — Runtime Orchestration Decomposition (highest ROI)
- [x] Split `crates/agent-core/src/lifecycle.rs` into focused modules:
  - ingest loop
  - detection/response loop
  - control-plane loop (heartbeat/compliance/commands)
  - intel reload loop
- [x] Replace single sequential connected tick with bounded async work queues
- [x] Add explicit queue depth and lag metrics per loop
- [x] Add jittered retry (not only deterministic exponential backoff)
- [x] Verify p99 tick latency improves and degraded-mode churn decreases
- [x] P1 slice: introduce bounded command backlog queue + per-tick command execution budget
- [x] P1 slice: split connected/degraded tick orchestration into telemetry/control stage helpers
- [x] P1 slice: expose command backlog/fetch/execute observability metrics and add coverage
- [x] P1 slice: extract threat-intel refresh/download/corroboration/reload orchestration into `lifecycle/threat_intel_pipeline.rs`
- [x] P1 slice: extract command backlog fetch/execute orchestration into dedicated lifecycle module and add backlog-age lag observability
- [x] P1 slice: run focused + workspace verification and compare benchmark artifacts

### P2 — Hot-Path Data Structure Optimization
- [x] Layer 2: replace string entity keys with compact numeric keys where safe
- [x] Layer 3: replace fixed-domain `HashMap<EventClass, _>` counters with array-backed counters
- [x] Platform enrichment cache: replace O(n) LRU touch (`VecDeque` search) with O(1) LRU map/list
- [x] Validate no semantic drift via deterministic replay tests

### P3 — Telemetry Path Hardening + Throughput
- [x] Remove synthetic event fallback on empty eBPF poll path (no fake events)
- [x] Introduce bounded parser buffer reuse/pooling in eBPF ingest path
- [x] Surface per-probe attach/degrade status directly into runtime observability snapshots
- [x] Validate drop-rate behavior under sustained event pressure

### P4 — Low-Level Optimization (only after measured hotspot proof)
- [x] Add `perf`/flamegraph profiling gate to prove dominant kernels before asm changes
- [x] For proven kernels only: add SIMD/asm primitives with Rust fallback + differential tests (no new detection asm admitted until profiling proof; existing `crypto-accel` asm path remains guarded by fallback+differential coverage)
- [x] Add optional PGO/LTO/BOLT profile for release builds
- [x] Keep ABI/fuzz/symbol-audit/soak checks green

## Verification Matrix (must pass before claiming completion)

- [x] `cargo test --workspace` on touched crates
- [x] Deterministic replay + confidence policy contract tests
- [x] `bash scripts/run_detection_benchmark_ci.sh`
- [x] `bash scripts/run_runtime_tick_slo_ci.sh`
- [x] `bash scripts/run_replay_determinism_ci.sh`
- [x] `bash scripts/run_detection_quality_gate_ci.sh`
- [x] `bash scripts/run_ebpf_drop_rate_pressure_ci.sh`
- [x] `bash scripts/run_ebpf_resource_budget_ci.sh`
- [x] `bash scripts/run_rule_push_slo_ci.sh`
- [x] `bash scripts/run_self_protection_verification_ci.sh`
- [x] `bash scripts/run_asm_symbol_audit_ci.sh`
- [x] `bash scripts/run_perf_profile_gate_ci.sh`
- [x] `bash scripts/run_release_profile_opt_ci.sh`

## Initial Findings to Drive Refactor

- `agent-core/src/lifecycle.rs` remains large, but orchestration is now split across dedicated modules: `telemetry_pipeline`, `control_plane_pipeline`, `command_control_pipeline`, `response_pipeline`, and `threat_intel_pipeline`
- Connected tick now executes bounded queue-driven control-plane and response work instead of a strictly sequential stage chain
- Runtime observability now includes queue depth/lag for control-plane, command backlog, and response pipeline
- Layer 2 temporal engine now uses compact numeric entity keying (PID) instead of string keys in state map
- eBPF ingest now reclaims raw record buffers through backend pooling and surfaces probe attach-degradation status in runtime observability
- Low-level optimization gates now include perf/flamegraph profiling and optional release profile optimization workflow (PGO/LTO/BOLT-friendly)

## Review

- 2026-02-13 baseline run completed:
  - detection benchmark wall-clock: `238 ms`
  - release build wall-clock: `54,946 ms`
  - release binary size: `9.792 MB`
  - rule push transfer/rollout estimates: `5.000 s` / `30.000 s`

- 2026-02-13 implementation slices completed:
  - Added `AC-OPT-001..005` to `ACCEPTANCE_CRITERIA.md`
  - Implemented jittered retry backoff in `crates/grpc-client/src/retry.rs`
  - Wired jittered backoff into `Client::with_retry` in `crates/grpc-client/src/client.rs`
  - Replaced O(n) enrichment cache recency updates with O(1) LRU cache operations in `crates/platform-linux/src/lib.rs`
  - Reworked L3 anomaly window counters to fixed array-backed state in `crates/detection/src/layer3.rs`
  - Removed synthetic idle telemetry fallback in `crates/agent-core/src/lifecycle.rs` (no fake events when eBPF poll is empty)
  - Regenerated acceptance generated artifacts for new AC IDs (`crates/acceptance/tests/*generated*.rs`) and refreshed `crates/acceptance/AC_STATUS.md`
  - Fixed asm symbol audit size check to measure compressed archive size per AC-ASM/PKG wording (`scripts/run_asm_symbol_audit_ci.sh`)
  - Added bounded command backlog + per-tick command execution budget in lifecycle orchestration (`COMMAND_BACKLOG_CAPACITY`, `COMMAND_EXECUTION_BUDGET_PER_TICK`)
  - Added command fetch interval gating and local command-first fetch path to reduce command-stage network stalls (`COMMAND_FETCH_INTERVAL_SECS`, `Client::fetch_commands`)
  - Split connected/degraded tick orchestration into stage helpers (telemetry/control/response, degraded telemetry/control)
  - Added bounded command ack/report timeouts in command pipeline (`command_pipeline.rs`)
  - Added observability metrics for command backlog/fetch/execute and coverage test in `tests_observability.rs`
  - Hardened signed threat-intel bundle pipeline with manifest validation, per-file SHA-256 verification, and manifest-vs-loaded count corroboration before accepting bundle load (`rule_bundle_loader.rs`)
  - Added server-metadata corroboration gate before detection-state swap so threat-intel version/count mismatches are rejected pre-apply (`reload_detection_state(..., expected_intel)`)
  - Extracted threat-intel orchestration methods from `lifecycle.rs` into `crates/agent-core/src/lifecycle/threat_intel_pipeline.rs` (refresh cadence, remote bundle prep/download, corroboration, hot-reload)
  - Extracted command backlog fetch/execute orchestration from `lifecycle.rs` into `crates/agent-core/src/lifecycle/command_control_pipeline.rs` and added command backlog oldest-age lag observability metrics
  - Extracted connected control-plane orchestration into `crates/agent-core/src/lifecycle/control_plane_pipeline.rs` with bounded task queue scheduling
  - Extracted telemetry ingest/send orchestration into `crates/agent-core/src/lifecycle/telemetry_pipeline.rs`
  - Extracted response action/report orchestration into `crates/agent-core/src/lifecycle/response_pipeline.rs` with bounded response queue scheduling
  - Added dedicated async worker-task queues to decouple control-plane heartbeat/compliance sends and response report sends from the tick hot path
  - Added queue depth/lag observability metrics for control-plane and response queues (`RuntimeObservabilitySnapshot`)
  - Reworked L2 temporal engine state keys to compact numeric PID keys in `crates/detection/src/layer2.rs`
  - Added eBPF raw-record reclaim hook and record buffer pooling path in `crates/platform-linux/src/ebpf.rs` (+ pooling contract test)
  - Surfaced eBPF probe attach-degradation status in runtime observability snapshot (`ebpf_failed_probe_count`, `ebpf_attach_degraded`, capability flags)
  - Added verification harnesses/scripts for runtime tick SLO, replay determinism, sustained eBPF drop-rate pressure, perf profile gate, and release profile optimization
  - Promoted optimization guardrail checks into CI workflows with explicit threshold enforcement and metrics artifact upload (`verification-suite.yml`, `package-agent.yml`, `release-agent.yml`)
  - Released hard binary-size gating: eBPF resource harness now reports binary size without enforcing a default cap; verification workflow tracks metric validity instead of failing at 10 MB
  - Added commit slicing + release prep checklist in `tasks/commit-slicing-release-prep.md`

- Verification:
  - `cargo test -p grpc-client` => `78 passed`
  - `cargo test -p platform-linux` => `53 passed`
  - `cargo test -p detection` => `71 passed`
  - `cargo test -p agent-core --bin agent-core` => `100 passed`
  - `cargo test --workspace` => pass
  - `bash scripts/run_detection_benchmark_ci.sh` => pass
    - detection benchmark wall-clock: `253 ms`
  - `bash scripts/run_runtime_tick_slo_ci.sh` => pass
    - runtime tick SLO harness wall-clock: `413 ms`
  - `bash scripts/run_replay_determinism_ci.sh` => pass
    - replay determinism harness wall-clock: `211 ms`
  - `bash scripts/run_detection_quality_gate_ci.sh` => pass
    - focus (very_high) precision/recall/FAR upper-bound: `1.0 / 1.0 / 0.025713`
    - high-threshold precision/recall/FAR upper-bound: `1.0 / 1.0 / 0.027866`
    - corpus coverage: `9 scenarios`, `122 events`, `16 malicious labels`
  - `bash scripts/run_ebpf_drop_rate_pressure_ci.sh` => pass
    - sustained drop-rate harness wall-clock: `226 ms`
  - `bash scripts/run_rule_push_slo_ci.sh` => pass
    - transfer/rollout estimates: `5.000 s` / `30.000 s`
  - `bash scripts/run_ebpf_resource_budget_ci.sh` => pass
    - release build wall-clock: `43,031 ms` (post-change full release rebuild)
    - release binary size: `9.881 MB` (metric-only, no default hard cap)
  - `bash scripts/run_self_protection_verification_ci.sh` => pass
  - `bash scripts/run_asm_symbol_audit_ci.sh` => pass
  - `bash scripts/run_perf_profile_gate_ci.sh` => pass (skipped: `perf` unavailable)
  - `bash scripts/run_release_profile_opt_ci.sh` => pass
    - baseline release build wall-clock: `396 ms`
  - `bash scripts/run_verification_suite_ci.sh` => pass (end-to-end) with archived log: `artifacts/verification-suite/run-20260214-205256.log`

- 2026-02-14 outcome-quality update:
  - Removed default hard binary-size enforcement in `scripts/run_ebpf_resource_budget_ci.sh` (size now measured + reported)
  - Updated optimization guardrail threshold check in `verification-suite.yml` to validate metric presence instead of failing over 10 MB
  - Rewrote all remaining `<10 MB` binary-cap wording in `ACCEPTANCE_CRITERIA.md` to telemetry-first policy language (AC-EBP/AC-RES/AC-PKG/AC-VER)
  - Aligned package harness metrics/contracts to remove fixed `agent_binary=10 MB` assumptions (`scripts/build-agent-packages-ci.sh`, `tests_pkg_contract.rs`, `tests_tst_ver_contract.rs`)
  - Added replay quality metrics emission + CI gate (`replay_quality_gate_emits_metrics_artifact`, `scripts/run_detection_quality_gate_ci.sh`) and wired threshold enforcement in `verification-suite.yml`
  - Added replay quality gate invocation to `scripts/run_verification_suite_ci.sh`
  - Added dedicated async worker-task queues for control-plane heartbeat/compliance sends and response report sends, decoupling network I/O from tick hot-path execution
  - Regenerated acceptance artifacts (`scripts/generate_acceptance_tests.py`, `scripts/generate_acceptance_status_report.py`)
  - Expanded replay quality gate to adversarial corpus + per-confidence metrics (`artifacts/detection-quality-gate/metrics.json`):
    - focus threshold (`very_high`) precision `1.0`, recall `1.0`, false_alarm_upper_bound `0.025713`
    - per-confidence metrics published for `definite`, `very_high`, `high`, `medium`, `low`
  - Added trend artifact for per-confidence quality metrics: `artifacts/detection-quality-gate/per-confidence-trend.ndjson`
  - Fixed Layer4 scope leakage by evaluating kill-chain templates only on current-event lineage roots (event PID + ancestors), eliminating stale unrelated high-confidence carry-over
  - Added PID-reuse adversarial scenarios and hardened Layer4 state handling by resetting derived risk flags on `process_exec` and cleaning stale parent-child links
  - Hardened Layer2 temporal state against PID-reuse stale-stage leakage via process-exec epoch tracking on non-process follow-up stages
  - Added Layer2 identity-continuity guard for non-`process_exec` transitions to block stale-chain continuation when PID reuse is observed only via identity drift
  - Added Layer2 lifecycle eviction pruning across stale temporal states and per-PID metadata maps under long-horizon churn
  - Added deterministic Layer2 cardinality caps for temporal state map and per-PID metadata map with oldest-first/lowest-PID tie-break eviction policy
  - Added regression guards:
    - `layer4_pid_reuse_does_not_inherit_stale_non_web_network_signal`
    - `temporal_engine_pid_reuse_process_exec_clears_stale_pending_webshell_state`
    - `temporal_engine_rejects_stage_restart_from_timestamp_skew_beyond_tolerance`
    - `temporal_engine_pid_reuse_without_exec_observation_does_not_continue_stale_chain`
    - `temporal_engine_prunes_stale_state_and_pid_metadata_after_retention_horizon`
    - `temporal_engine_state_capacity_evicts_oldest_pending_chain_deterministically`
    - `temporal_engine_pid_metadata_capacity_evicts_oldest_then_tie_breaks_by_pid`
  - Added Layer2 per-PID last-seen timestamp guard to reject stale out-of-order stage-restart injections beyond reorder tolerance
  - Raised detection quality corpus floor to `minimum_scenarios=9` and expanded corpus coverage to `122` events / `16` malicious labels
  - High-threshold replay quality improved from `precision=0.5` to `precision=1.0` on the adversarial corpus; strict `high` CI threshold enforcement re-enabled
  - Verification rerun: `cargo test --workspace` => pass
  - Guardrail threshold aggregation rerun => `optimization guardrail thresholds passed`
    - includes adversarial corpus coverage checks + per-confidence (`definite`, `very_high`, `high`) precision/recall/FAR bounds + trend artifact presence validation

- 2026-02-14 next-job full implementation update:
  - Added `EventClass::ProcessExit` end-to-end mapping (`platform-linux` event mapping in `agent-core`) and Layer2 immediate PID teardown semantics.
  - Layer2 now exposes reason-tagged eviction counters (`retention_prune`, `state_cap_evict`, `metadata_cap_evict`) with deterministic accounting under retention/cap pressure.
  - Added Layer2 regressions:
    - `temporal_engine_process_exit_tears_down_state_and_metadata_immediately`
    - `temporal_engine_process_exit_teardown_is_idempotent_and_ignores_stale_out_of_order_exit`
    - `temporal_engine_eviction_counters_track_retention_and_capacity_reasons`
  - Expanded adversarial replay corpus to `12` scenarios (`adversarial_reference_v2`) including:
    - timestamp-tie cap-pressure abuse
    - combined cap-pressure + reorder-skew abuse
    - cross-layer Layer2+Layer4 churn with process-exit + PID reuse boundaries
  - Detection quality gate now enforces `minimum_scenarios=12` across tests/script/workflow contracts.
  - Added drift-regression gate over `per-confidence-trend.ndjson` via `scripts/check_detection_quality_trend_drift.py` and artifact `artifacts/detection-quality-gate/trend-drift-report.json`.
  - Added CI release-readiness tooling:
    - `scripts/run_workflow_yaml_lint_ci.sh`
    - `scripts/check_optimization_guardrail_thresholds.py`
    - `scripts/run_guardrail_threshold_realism_ci.sh`
    - `scripts/verify_package_artifacts_ci.py`
    - `scripts/run_binary_hardening_gate_ci.sh`
    - `scripts/stream_verification_log_ci.sh`
  - Updated workflows:
    - `verification-suite.yml` now captures verification logs, runs workflow lint, enforces thresholds via script summary, uploads drift + summary artifacts, and supports scheduled/workflow-dispatch cold/warm realism sweeps.
    - `package-agent.yml` and `release-agent.yml` now validate `.deb`/`.rpm` artifact structure before publish.
  - Latest quality metrics (`artifacts/detection-quality-gate/metrics.json`):
    - corpus: `scenario_count=12`, `total_events=1034`, `malicious_events=24`
    - focus (`very_high`): precision `1.0`, recall `1.0`, FAR upper `0.002924`
    - `high`: precision `1.0`, recall `1.0`, FAR upper `0.002962`
  - Verification reruns:
    - `cargo test -p detection` => pass (`74` tests)
    - `cargo test -p acceptance` => pass
    - `cargo test --workspace` => pass
    - guardrail harness matrix rerun => pass
    - `python3 scripts/check_optimization_guardrail_thresholds.py --root .` => pass
    - `EGUARD_GUARDRAIL_REALISM_COLD_CLEAN=0 bash scripts/run_guardrail_threshold_realism_ci.sh` => pass
    - `bash scripts/run_verification_suite_ci.sh` => pass (`artifacts/verification-suite/run-20260214-205256.log`)

- 2026-02-14 campaign + bundle-signature hardening update:
  - Added cross-endpoint campaign correlation scoring API (`correlate_campaign_iocs`) with deterministic severity tiers (`advisory`, `elevated`, `outbreak`) and strongest-per-host confidence deduplication.
  - Added campaign regression coverage:
    - `campaign_correlation_deduplicates_host_signals_and_ignores_empty_fields`
    - `campaign_correlation_assigns_elevated_and_outbreak_severity_tiers`
  - Added end-to-end bundle signature contract harness:
    - `scripts/run_bundle_signature_contract_ci.sh`
    - includes processed bundle fixture build, coverage gate snapshot, Ed25519 sign/verify, and tamper rejection check
  - Wired bundle signature contract into verification suite (`scripts/run_verification_suite_ci.sh`) and artifact upload (`.github/workflows/verification-suite.yml`).
  - Added acceptance criteria coverage for campaign correlation + bundle signature verification (`AC-DET-186..189`, `AC-VER-052..054`) and regenerated acceptance artifacts/status.
  - Verification reruns:
    - `bash scripts/run_bundle_signature_contract_ci.sh` => pass
    - `cargo test -p detection tests_stub_completion::campaign_correlation_deduplicates_host_signals_and_ignores_empty_fields -- --exact` => pass
    - `cargo test -p detection tests_stub_completion::campaign_correlation_assigns_elevated_and_outbreak_severity_tiers -- --exact` => pass
    - `cargo test -p agent-core lifecycle::tests::verify_bundle_signature_with_material_rejects_tampered_payload -- --exact` => pass
    - `cargo test -p acceptance tests_tst_ver_contract::verification_coverage_and_security_pipeline_contracts_are_present -- --exact` => pass
    - `bash scripts/run_verification_suite_ci.sh` => pass (`artifacts/verification-suite/run-20260214-205256.log`)

- 2026-02-14 response + bundle-ingest contract completion update:
  - Finalized optional auto-isolation observability/runtime coverage by running in explicit active-baseline mode for deterministic enforcement assertions.
  - Hardened bundle-ingest contract pathing by passing absolute bundle fixture paths into runtime ingestion tests (`EGUARD_CI_BUNDLE_PATH`) in both verification suite and build-bundle workflow.
  - Added workflow path wiring so generated signed bundles are validated by agent runtime in CI without crate-working-directory path drift.
  - Verification reruns:
    - `cargo test -p agent-core --bin agent-core` => pass (`120 passed`)
    - `cargo test -p detection` => pass (`76 passed`)
    - `pytest -q threat-intel/tests/test_bundle.py` => pass (`43 passed, 7 skipped`)
    - `bash scripts/run_workflow_yaml_lint_ci.sh` => pass
    - `bash scripts/run_verification_suite_ci.sh` => pass (includes bundle-signature gate + signed bundle ingestion contract)
    - `cargo test --workspace` => pass

- 2026-02-14 dependency risk burn-down update:
  - Replaced unmaintained baseline serialization dependency with maintained `wincode` while preserving bincode-compatible wire behavior (`crates/baseline`).
  - Upgraded `lru` to a RustSec-patched release (`>=0.16.3`) to remove unsound `IterMut` advisory exposure in enrichment cache.
  - Upgraded gRPC/protobuf toolchain from `tonic 0.12`/`prost 0.13` to `tonic 0.14`/`prost 0.14`, migrated build generation to `tonic-prost-build`, and added `tonic-prost` runtime codec dependency.
  - Aligned fuzz harness protobuf dependency to `prost 0.14` to eliminate mixed-prost trait mismatch under CI fuzz stages.
  - Kept baseline persistence semantics and budget envelopes intact (`baselines.bin` path + save/load + snapshot-size tests remain green).
  - Verification reruns:
    - `cargo test -p baseline` => pass (`15 passed`)
    - `cargo test -p platform-linux` => pass (`53 passed`)
    - `cargo test -p grpc-client` => pass (`79 passed`)
    - `cargo test -p agent-core --bin agent-core` => pass (`120 passed`)
    - `cargo test --workspace` => pass
    - `bash scripts/run_verification_suite_ci.sh` => pass
    - `cargo audit` => pass with `0` warnings (`3` warnings eliminated: `bincode`, `lru`, `rustls-pemfile`)

## Active Plan — Clippy + Acceptance Closure Sweep (2026-02-15)

- [x] Scan broad repo/file/markdown state (`git status`, `git diff --stat`, task docs + acceptance docs)
- [x] Clear strict clippy blockers in touched test files (`grpc-client`, `agent-core`)
- [x] Re-run strict clippy gate (`cargo clippy --workspace --all-targets --all-features -- -D warnings`)
- [x] Re-run touched crate tests (`grpc-client`, `agent-core`)
- [x] Resolve acceptance generated-id drift after AC updates by regenerating acceptance artifacts
- [x] Re-run acceptance suite and confirm green after regeneration
- [x] Re-run full end-to-end `bash scripts/run_verification_suite_ci.sh` and archive fresh log evidence for this sweep

## Review — 2026-02-15

- Fixed clippy duplicate-attribute regression introduced during test-module cleanup:
  - Removed redundant file-level `#![allow(clippy::field_reassign_with_default)]` from:
    - `crates/agent-core/src/lifecycle/tests.rs`
    - `crates/agent-core/src/lifecycle/tests_ebpf_policy.rs`
    - `crates/agent-core/src/lifecycle/tests_det_stub_completion.rs`
    - `crates/agent-core/src/lifecycle/tests_observability.rs`
- Clippy verification:
  - `cargo clippy -p grpc-client --tests -- -D warnings` => pass
  - `cargo clippy -p agent-core --tests -- -D warnings` => pass
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings` => pass
- Runtime/contract verification:
  - `cargo test -p grpc-client` => pass (`79 passed`)
  - `cargo test -p agent-core --bin agent-core` => pass (`121 passed`)
- Acceptance drift found and fixed:
  - `cargo test -p acceptance` initially failed at `generated_id_list_matches_acceptance_document` because generated IDs missed `AC-RSP-124..126`.
  - Regenerated acceptance artifacts:
    - `python3 scripts/generate_acceptance_tests.py`
    - `python3 scripts/generate_acceptance_status_report.py`
  - Post-regeneration:
    - `cargo test -p acceptance --test acceptance_criteria_generated` => pass (`734 passed`)
    - `cargo test -p acceptance` => pass
  - `crates/acceptance/AC_STATUS.md` now reports `730` total executable AC IDs.
- End-to-end verification suite rerun:
  - `bash scripts/run_verification_suite_ci.sh` => pass
  - Archived log: `artifacts/verification-suite/run-20260215-101200.log`
  - Includes bundle-signature contract, signed-bundle ingestion contract, fuzz, miri, hardening probe, and guardrail stages.
- Post-packaging-hardening verification suite rerun:
  - `bash scripts/run_verification_suite_ci.sh` => pass
  - Archived log: `artifacts/verification-suite/run-20260215-110333.log`

## Active Plan — Real Package Artifact Closure (2026-02-15)

- [x] Add packaging-script fallback for environments without `x86_64-linux-musl-gcc` (use Zig musl cc wrapper for ring/cc-rs compatibility)
- [x] Add `nfpm` auto-bootstrap fallback (local tool path) when real package build is requested and `nfpm` is not on PATH
- [x] Build real `.deb`/`.rpm` artifacts locally (`EGUARD_PACKAGE_REAL_BUILD=1`) and validate with `scripts/verify_package_artifacts_ci.py`
- [x] Capture/update evidence paths in task docs after successful local real-build validation

## Review — 2026-02-15 (real package artifact closure)

- Packaging script hardening (`scripts/build-agent-packages-ci.sh`):
  - Added Zig-based musl toolchain fallback when `x86_64-linux-musl-gcc` is unavailable:
    - wrapper binaries under `artifacts/package-agent/tools/` (`zig-musl-cc`, `zig-musl-cxx`, `zig-musl-ar`)
    - target triple normalization from `x86_64-unknown-linux-musl` to Zig-accepted `x86_64-linux-musl` for cc-rs/ring compile paths
    - Rust musl linker fallback to rust-lld (`.../rustlib/x86_64-unknown-linux-gnu/bin/rust-lld`) to avoid duplicate musl CRT symbol collisions
  - Added automatic `nfpm` bootstrap when absent on PATH:
    - downloads `nfpm v2.45.0` to `artifacts/package-agent/tools/nfpm`
  - Updated nfpm config rendering to emit `release` at top-level schema (instead of unsupported `overrides.rpm.release`) for real RPM packaging compatibility.
  - Fixed asm static-archive bundling for Zig archives with nested member paths (creates member directory tree before `ar x`, then repacks recursively found `.o` files), producing a non-empty `libeguard_asm.a` in package stage.
- Local real-build validation:
  - `EGUARD_PACKAGE_REAL_BUILD=1 EGUARD_PACKAGE_GENERATE_EPHEMERAL_GPG=1 bash scripts/build-agent-packages-ci.sh` => pass
  - `python3 scripts/verify_package_artifacts_ci.py --artifact-dir artifacts/package-agent` => pass
  - Validation artifact: `artifacts/package-agent/verification.json` (`status: "ok"`, `debian_count: 2`, `rpm_count: 2`)
  - Package metrics artifact: `artifacts/package-agent/metrics.json` (`real_build: 1`)
  - Staged asm archive is non-empty after fix: `artifacts/package-agent/stage/core/usr/lib/eguard-agent/lib/libeguard_asm.a` (`319386 bytes`)
- Targeted contract regression check:
  - `cargo test -p agent-core lifecycle::tests_pkg_contract::package_build_harness_executes_and_emits_metrics_with_mocked_toolchain -- --exact` => pass
- Repository hygiene closure for CI-critical new files:
  - Staged previously untracked verification/build assets to avoid release-time omissions:
    - `fuzz/Cargo.toml`, `fuzz/Cargo.lock`, `fuzz/fuzz_targets/*.rs`
    - `scripts/run_bundle_signature_contract_ci.sh`, `scripts/run_agent_bundle_ingestion_contract_ci.sh`
    - `threat-intel/processing/attack_critical_owner_streak_gate.py`, `threat-intel/processing/update_attack_critical_regression_history.py`

## Active Plan — Layer4 Graph Capacity Hardening (2026-02-15)

- [x] Add deterministic Layer4 process-graph capacity controls (node + edge caps) with bounded eviction policy
- [x] Add Layer4 eviction telemetry counters with reason tags (retention prune / node-cap evict / edge-cap evict)
- [x] Add Layer4 regression coverage for process-exit stale-order behavior and capacity-eviction determinism
- [x] Run targeted verification (`cargo test -p detection`, `cargo clippy -p detection --tests -- -D warnings`) and record evidence

## Review — 2026-02-15 (Layer4 graph capacity hardening)

- Implemented deterministic Layer4 graph-capacity controls in `crates/detection/src/layer4.rs`:
  - Added bounded graph capacities with defaults (`DEFAULT_LAYER4_MAX_NODES`, `DEFAULT_LAYER4_MAX_EDGES`) and constructor override `Layer4Engine::with_capacity(...)`.
  - Added deterministic oldest-first eviction (`last_seen`, then `pid` tiebreak) for both node and edge pressure.
  - Added explicit edge accounting (`edge_count`) and consistent link teardown helpers (`insert_child_link`, `remove_child_link`, `remove_outgoing_links`, `remove_incoming_links`, `remove_node`).
- Added Layer4 eviction observability via `Layer4EvictionCounters`:
  - reason-tagged counters for `retention_prune`, `node_cap_evict`, `edge_cap_evict`.
  - public accessor `Layer4Engine::eviction_counters()` and test helper `debug_eviction_counters()`.
  - exported counter type from `crates/detection/src/lib.rs`.
- Added/updated Layer4 regressions in `crates/detection/src/tests.rs`:
  - `layer4_process_exit_tears_down_node_and_ignores_stale_out_of_order_exit`
  - `layer4_node_capacity_evicts_oldest_then_lowest_pid_deterministically`
  - `layer4_edge_capacity_evicts_oldest_nodes_until_edge_budget_is_met`
  - strengthened `layer4_graph_state_is_pruned_by_sliding_window_to_stay_bounded` with retention-counter assertion.
- Verification evidence:
  - `cargo test -p detection` => pass (`79 passed`)
  - `cargo clippy -p detection --tests -- -D warnings` => pass

## Active Plan — Signature ML Readiness Integration Closure (2026-02-15)

- [x] Verify `threat-intel/processing/signature_ml_readiness_gate.py` behavior via targeted threat-intel tests
- [x] Validate bundle-signature contract harness executes ML readiness gate and emits readiness artifact + metrics
- [x] Validate verification contract acceptance test still passes with bundle-signature + readiness wiring

## Review — 2026-02-15 (signature ML readiness integration closure)

- Verified script behavior and contract coverage:
  - `pytest -q threat-intel/tests/test_bundle.py -k "signature_ml_readiness"` => pass (`3 passed`)
  - Confirms strong-bundle pass behavior, shadow-alert behavior on score/drop breaches, and enforced fail mode when threshold gating is enabled.
- Verified bundle-signature harness integration:
  - `bash scripts/run_bundle_signature_contract_ci.sh` => pass
  - Confirms harness executes `signature_ml_readiness_gate.py` and emits:
    - `artifacts/bundle-signature-contract/signature-ml-readiness.json`
    - `artifacts/bundle-signature-contract/metrics.json` with `ml_readiness` summary fields.
- Verified acceptance contract fidelity after readiness wiring:
  - `cargo test -p acceptance tests_tst_ver_contract::verification_coverage_and_security_pipeline_contracts_are_present -- --exact` => pass
  - Contract checks still assert ML readiness invocation tokens and emitted release artifacts.

## Active Plan — Endpoint Signature-DB Runtime Hardening (2026-02-15)

- [ ] Enforce endpoint-side signature database floor on hot-reload so runtime cannot downgrade to empty/near-empty bundle content
- [ ] Harden multi-shard reload to prebuild + validate every shard engine before swap, rejecting cross-shard bundle-load divergence
- [ ] Add regression tests for signature-floor rejection and shard consistency reload behavior
- [ ] Run targeted verification (`cargo test -p agent-core --bin agent-core`, `cargo clippy -p agent-core --tests -- -D warnings`) and record evidence
