# eGuard Agent Refactor + Optimization Plan

Last updated: 2026-02-14
Owner: Agent Platform Team

## Scope

This plan is based on the local repository state in `/home/dimas/eguard-agent` and
the design source in `/home/dimas/fe_eguard/docs/eguard-agent-design.md`.
Planning therefore uses:

- `/home/dimas/fe_eguard/docs/eguard-agent-design.md` as architecture source of truth
- `ACCEPTANCE_CRITERIA.md` as the normative contract
- Runtime code in `crates/agent-core`, `crates/detection`, `crates/platform-linux`, `crates/self-protect`, `crates/crypto-accel`
- Existing CI harnesses under `scripts/`

## Optimization Objective Function

We optimize against a constrained objective, not a single metric:

`J = w1*p99_detection_latency + w2*p99_tick_latency + w3*RSS_MB + w4*CPU_idle + w5*event_drop_rate + w6*false_alert_rate`

Subject to hard constraints:

- AC-DET math and correctness constraints remain true
- AC resource budgets remain true (`AC-DET-100..106`, `AC-RES`, `AC-PKG-001`), with binary footprint tracked as telemetry rather than a hard release gate
- Safety constraints for low-level code remain true (`AC-DET-110..124`)

No optimization is accepted if constraints are violated.

## Current Bottleneck Map (from code audit)

1. `agent-core` main tick path is mostly sequential and couples network/control operations to detection delivery.
2. Event sending now has bounded jittered backoff; remaining risk is orchestration coupling (send path still shares tick budget with control-plane work).
3. Detection state hot paths still have avoidable allocation patterns (string keys, full graph sweeps); L3 fixed-cardinality hash-map counters were replaced with array-backed counters.
4. eBPF ring-buffer ingestion alloc/copy path is heavier than necessary in high-rate scenarios.
5. Feature fallbacks (eBPF disabled, crypto asm disabled) are graceful but weakly surfaced in runtime telemetry.

## Baseline Snapshot (2026-02-13)

Collected from local harnesses:

- `scripts/run_detection_benchmark_ci.sh`
  - wall-clock: `238 ms` for reference p99 latency contract test
  - artifact: `artifacts/detection-benchmark/metrics.json`
- `scripts/run_ebpf_resource_budget_ci.sh`
  - release build wall-clock: `54,946 ms`
  - binary size: `10,267,824 bytes` (`9.792 MB`)
  - artifact: `artifacts/ebpf-resource-budget/metrics.json`
- `scripts/run_rule_push_slo_ci.sh`
  - transfer estimate: `5.000 s` (at 1 Mbps)
  - fleet rollout estimate: `30.000 s` (at 1000 cmd/s, 30k agents)
  - artifact: `artifacts/rule-push-slo/metrics.json`

Observed optimization debt from this run:

- `agent-core` still emits multiple dead-code warnings in release build; this is a refactor smell and signal of lifecycle responsibility drift.
- Current resource-budget harness measures command wall-clock proxies, but not full runtime p99 tick stage distribution under live traffic.

## Program Phases

## P0 - Measurement First (must-have baseline)

Status: Planned
Target window: 2-4 days

Deliverables:

- Add per-stage tick timing in `agent-core`:
  - detect/evaluate
  - send batch
  - heartbeat/compliance
  - threat-intel reload
  - command sync
- Add queue depth/backpressure metrics:
  - buffered event depth
  - detection worker queue depth
  - command pipeline backlog
- Add explicit degraded-mode cause counters.
- Emit eBPF drop/fallback counters through Rust stats path.

Acceptance:

- We can produce a single benchmark report with p50/p95/p99 for each stage.
- Regressions become CI-failable via explicit thresholds.

## P1 - Runtime Orchestration Refactor (highest ROI)

Status: In progress
Target window: 1-2 weeks

Goal:
Decouple detection and event ingestion from slow control-plane/network tasks.

Changes:

1. Split the monolithic tick into bounded asynchronous work loops:
   - ✅ Introduced explicit telemetry/control/response stage helpers in connected and degraded paths.
   - ✅ telemetry path (high priority) — extracted to `lifecycle/telemetry_pipeline.rs`.
   - ✅ command/control path (medium priority) — bounded command backlog + per-tick execution budget extracted to `lifecycle/command_control_pipeline.rs` with backlog-age lag metrics.
   - ✅ control-plane scheduling path (heartbeat/compliance/threat-intel/commands) — extracted to `lifecycle/control_plane_pipeline.rs` with bounded control task queue.
   - ✅ threat-intel/policy reload path (low priority, cancellable) — extracted to `lifecycle/threat_intel_pipeline.rs`.
2. ✅ Add exponential backoff + jitter to event send retries and recovery probes.
3. ✅ Move command handling and acknowledgements to a dedicated worker queue.
   - bounded command backlog + fetch interval + bounded ack/report timeouts landed; orchestration is now module-isolated.
4. ✅ Isolate threat-intel download/compile/reload into staged background work with atomic swap at commit.
   - signed bundle manifest hash/count corroboration + metadata corroboration gate added before swap; orchestration is module-isolated.
5. ✅ Replace strictly sequential connected control/response execution with bounded queue-driven scheduling.
6. ✅ Add queue depth/lag observability for control-plane + command + response loops.
7. ✅ Decouple control-plane heartbeat/compliance sends and response report sends from tick via dedicated async worker task queues.

Acceptance:

- p99 tick time reduced by >= 40% under induced network latency.
- Degraded transitions reduced by >= 80% in transient fault tests.
- Detection processing continuity preserved during rule reload.

## P2 - Detection Pipeline Optimization (algorithmic and data-structure)

Status: In progress
Target window: 2-3 weeks

Goal:
Hit single-digit MB detection budget with lower p99 decision latency while preserving AC math semantics.

Changes:

1. L1 IOC path:
   - Implement true prefilter/exact split to match AC intent.
   - Remove duplicate string storage where possible.
   - Shift normalization work toward load-time preprocessing.
2. L2 temporal engine:
   - ✅ Replace string-heavy entity keys with compact numeric keys (PID-keyed monitor state).
   - Bound and prune monitor state using explicit stale eviction.
3. L3 anomaly engine:
   - ✅ Replace fixed-domain `HashMap` paths with array-backed counters.
   - Remove avoidable allocations in KL and robust-z loops.
4. L4 graph matching:
   - Introduce candidate indexing for stage-0 predicate matches.
   - Replace full-node sweeps with bounded active-node traversal.

Acceptance:

- p99 detection decision latency improves >= 30%.
- Detection RSS in stress replay remains within AC envelope.
- Deterministic replay remains byte-identical for same inputs.

## P3 - Kernel/User Boundary + Platform Hardening

Status: In progress
Target window: 1-2 weeks (parallelizable with P2)

Changes:

1. eBPF ingestion:
   - ✅ Replace high-churn allocation path with reusable raw-record buffer pool/reclaim hook in backend poll path.
   - ✅ Surface per-probe attach errors and drop counters in telemetry/observability snapshots.
2. Enrichment cache:
   - ✅ Replace O(n) LRU touch behavior with O(1) structure.
3. Self-protection:
   - Add stronger CI coverage for capability/seccomp failure paths.
4. Crypto acceleration:
   - Cache CPU feature detection once at startup.
   - Add explicit runtime flag indicating asm-accelerated vs fallback mode.

Acceptance:

- Event drop rate stays below target under synthetic high-rate replay.
- Idle CPU and peak CPU remain under `scripts/run_ebpf_resource_budget_ci.sh` thresholds.
- Platform fallback modes are visible in metrics and alertable.

## P4 - Low-Level and Binary Optimization (only after P1-P3)

Status: In progress
Target window: optional, after measured need

Principle:
Only optimize with asm/binary-level techniques when profiling proves hotspot dominance.

Current implementation status:
- ✅ Added `scripts/run_perf_profile_gate_ci.sh` (perf/flamegraph-aware profile gate).
- ✅ Added `scripts/run_release_profile_opt_ci.sh` (optional PGO/LTO/BOLT-friendly release optimization flow).
- ✅ Kept existing `crypto-accel` asm primitives behind Rust wrappers with differential-policy coverage; no new detection-decision asm admitted without hotspot proof.

Allowed techniques:

1. SIMD/assembly microkernels for pure compute loops (e.g., KL vector math, byte-scan primitives) with Rust fallback.
2. PGO/LTO tuning by workload class.
3. Binary post-link optimization (for example BOLT) if reproducible and CI-safe.
4. Targeted allocator tuning only if heap profiles show allocator contention.

Guardrails:

- No detection decision logic in assembly.
- Differential tests must prove output equivalence.
- Fuzzing at FFI boundaries is mandatory for new asm entry points.
- Any change that increases false-alert risk is rejected.

## Verification Matrix

Every phase must update and run:

1. Correctness tests (`cargo test` on touched crates).
2. Replay determinism tests (`AC-DET-090`).
3. Resource budget CI scripts:
   - `scripts/run_detection_benchmark_ci.sh`
   - `scripts/run_runtime_tick_slo_ci.sh`
   - `scripts/run_replay_determinism_ci.sh`
   - `scripts/run_detection_quality_gate_ci.sh`
   - `scripts/run_ebpf_drop_rate_pressure_ci.sh`
   - `scripts/run_ebpf_resource_budget_ci.sh`
   - `scripts/run_rule_push_slo_ci.sh`
   - `scripts/run_self_protection_verification_ci.sh`
   - `scripts/run_perf_profile_gate_ci.sh`
   - `scripts/run_release_profile_opt_ci.sh`
4. Release footprint check (`AC-PKG-001`).

Done criteria for this program:

- Measured p99 improvements on detection and runtime loop.
- No AC regressions.
- No budget regressions.
- No increase in missed detections or false-alert envelope.

## 2026-02-14 Detection Quality Gate Expansion

- Replay quality gate now evaluates an expanded adversarial corpus (`adversarial_reference_v2`) instead of a single reference trace.
- Metrics artifact now includes corpus coverage fields (`scenario_count`, `total_events`, `malicious_events`) and per-confidence thresholds (`definite`, `very_high`, `high`, `medium`, `low`).
- CI threshold checks now enforce strong bounds for autonomous classes (`definite`, `very_high`) and high-confidence triage class (`high`), and require trend artifact publication.
- Per-confidence trend lines are appended to `artifacts/detection-quality-gate/per-confidence-trend.ndjson` for historical quality monitoring.
- Layer4 kill-chain evaluation was narrowed to current-event lineage roots (event PID + ancestors) to prevent stale historical graph matches from leaking into unrelated events; replay high-class precision recovered to 1.0 on adversarial corpus.
- PID-reuse hardening landed in Layer4 by resetting derived risk flags on `process_exec` and removing stale parent-child links; adversarial corpus now includes explicit PID-reuse replay scenarios.
- Layer2 temporal hardening now tracks per-PID process-exec epochs so stale pending non-process stages are invalidated after process-exec reuse on the same PID.
- Layer2 now also rejects per-PID timestamp-skewed out-of-order restart attempts beyond reorder tolerance using a last-seen timestamp guard.
- Layer2 adds non-process identity-continuity checks (process+parent+uid fingerprint) so PID reuse without an observed exec cannot continue stale pending temporal stages.
- Layer2 now proactively prunes stale temporal states and per-PID metadata maps under long-horizon telemetry churn to prevent stale-state accumulation and cross-lifetime contamination.
- Layer2 now enforces deterministic cardinality caps on temporal state and per-PID metadata maps, evicting oldest entries first with stable PID tie-break ordering under churn pressure.
- Corpus gate floor increased to `minimum_scenarios=12` with current adversarial coverage at 1034 events / 24 malicious labels.

## First Sprint Execution Order

1. Implement P0 instrumentation and publish baseline report artifact.
2. Land P1 retry/backoff and command-path decoupling first.
3. Start P2 with L3 array refactor and L2 key compaction (highest CPU-allocation payoff).
4. Run full verification matrix and freeze before deeper low-level optimization.

## Next Job Backlog (All Remaining)

Reference acceptance criteria backlog: `tasks/next-job-acceptance-criteria.md`.

### CI + Release Closure

Completed in this tranche:
- Workflow YAML lint/dry-run contract added (`scripts/run_workflow_yaml_lint_ci.sh`) and wired into `verification-suite.yml`.
- Guardrail threshold realism harness added (`scripts/run_guardrail_threshold_realism_ci.sh`) with scheduled/workflow-dispatch execution path.
- Perf profile non-blocking semantics preserved and now asserted through `check_optimization_guardrail_thresholds.py`.
- Package/release workflows now validate produced `.deb`/`.rpm` artifacts via `scripts/verify_package_artifacts_ci.py`.
- Optimization artifact inspection summary is now emitted (`artifacts/optimization-guardrail-summary/metrics.json`) and uploaded with guardrail artifacts.

### Operational Closure

Completed:
- Ran `bash scripts/run_verification_suite_ci.sh` end-to-end with `cargo-audit` available; archived evidence at `artifacts/verification-suite/run-20260214-205256.log`.
- Finalized commit slicing into reviewable, rollback-safe slices with per-slice validation evidence (`12198f2`, `70c34da`, `a24d2d0`, `330e46d`, `1e311ef`).

### Detection Hardening Follow-Up

Completed in this tranche:
- ProcessExit-aware Layer2 teardown for immediate per-PID state retirement.
- Layer2 eviction observability counters with reason tags.
- Adversarial replay scenarios for timestamp-tie cap-pressure and combined cap/reorder abuse.
- Cross-layer PID churn adversarial replay (Layer2 + Layer4 contamination guard).
- Trend-drift alarms over `per-confidence-trend.ndjson` for precision/recall/FAR regressions.
