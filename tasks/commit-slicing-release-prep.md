# Commit Slicing + Release Prep Plan

Last updated: 2026-02-15

Reference backlog acceptance criteria: `tasks/next-job-acceptance-criteria.md`

## Goal
Keep review and rollback risk low despite broad repository churn by slicing this stabilization work into isolated commits.

## Suggested Commit Slices

### Slice 1 — Runtime orchestration modularization
Files:
- `crates/agent-core/src/lifecycle.rs`
- `crates/agent-core/src/lifecycle/telemetry_pipeline.rs`
- `crates/agent-core/src/lifecycle/control_plane_pipeline.rs`
- `crates/agent-core/src/lifecycle/command_control_pipeline.rs`
- `crates/agent-core/src/lifecycle/response_pipeline.rs`
- `crates/agent-core/src/lifecycle/threat_intel_pipeline.rs`
- `crates/agent-core/src/lifecycle/tests_observability.rs`

Validation:
- `cargo test -p agent-core --bin agent-core`

### Slice 2 — Detection hot-path compact keying
Files:
- `crates/detection/src/layer2.rs`

Validation:
- `cargo test -p detection`
- `bash scripts/run_replay_determinism_ci.sh`

### Slice 3 — eBPF ingest pooling + contracts
Files:
- `crates/platform-linux/src/ebpf.rs`
- `crates/platform-linux/src/ebpf/tests_ring_contract.rs`

Validation:
- `cargo test -p platform-linux`
- `bash scripts/run_ebpf_drop_rate_pressure_ci.sh`

### Slice 4 — CI guardrail harnesses + workflow gates
Files:
- `scripts/run_runtime_tick_slo_ci.sh`
- `scripts/run_replay_determinism_ci.sh`
- `scripts/run_ebpf_drop_rate_pressure_ci.sh`
- `scripts/run_perf_profile_gate_ci.sh`
- `scripts/run_release_profile_opt_ci.sh`
- `scripts/run_verification_suite_ci.sh`
- `.github/workflows/verification-suite.yml`
- `.github/workflows/package-agent.yml`
- `.github/workflows/release-agent.yml`

Validation:
- `bash scripts/run_detection_benchmark_ci.sh`
- `bash scripts/run_runtime_tick_slo_ci.sh`
- `bash scripts/run_replay_determinism_ci.sh`
- `bash scripts/run_ebpf_drop_rate_pressure_ci.sh`
- `bash scripts/run_rule_push_slo_ci.sh`
- `bash scripts/run_ebpf_resource_budget_ci.sh`
- `bash scripts/run_perf_profile_gate_ci.sh`
- `bash scripts/run_release_profile_opt_ci.sh`

### Slice 5 — Planning/documentation updates
Files:
- `tasks/todo.md`
- `tasks/agent-refactor-optimization-plan.md`
- `tasks/lessons.md`
- `tasks/commit-slicing-release-prep.md`

Validation:
- Manual doc review for consistency with metrics + implemented changes

## Per-slice Validation Evidence (2026-02-14)

- Slice 1 runtime orchestration validation: `cargo test -p agent-core --bin agent-core` (evidence in `artifacts/verification-suite/run-20260214-205256.log` at stage `agent-core shard IOC reload test`)
- Slice 2 detection hot-path validation: `cargo test -p detection` + replay determinism and quality gates (evidence in `artifacts/verification-suite/run-20260214-205256.log` and `artifacts/detection-quality-gate/metrics.json`)
- Slice 3 eBPF ingest validation: `cargo test -p platform-linux` + drop-rate pressure harness (evidence in `artifacts/verification-suite/run-20260214-205256.log` and `artifacts/ebpf-drop-rate-pressure/metrics.json`)
- Slice 4 CI/workflow validation: full suite pass + workflow lint/guardrail scripts (evidence in `artifacts/verification-suite/run-20260214-205256.log`)
- Slice 5 docs validation: consistency refresh in `tasks/*.md` with synchronized evidence paths

## Release Prep Checklist

Implemented automation in this tranche:
- `scripts/run_workflow_yaml_lint_ci.sh`
- `scripts/check_optimization_guardrail_thresholds.py`
- `scripts/run_guardrail_threshold_realism_ci.sh`
- `scripts/verify_package_artifacts_ci.py`
- CI wiring in `.github/workflows/verification-suite.yml`, `.github/workflows/package-agent.yml`, and `.github/workflows/release-agent.yml`

- [x] Verify all workflow YAML syntax via GitHub Actions linter / dry run
- [x] Confirm threshold values are realistic on CI runners (cold + warm)
- [x] Ensure perf gate remains non-blocking when perf is unavailable on hosted runners
- [x] Confirm release/package workflows still produce `.deb` and `.rpm`
  - Local real-build evidence: `artifacts/package-agent/metrics.json` (`real_build: 1`) + `artifacts/package-agent/verification.json` (`status: ok`, validated via `dpkg-deb --info` / `rpm -qpi`)
- [x] Upload and inspect optimization artifacts from workflow runs
- [x] Run `bash scripts/run_verification_suite_ci.sh` in an environment with `cargo-audit` available and archive log evidence (`artifacts/verification-suite/run-20260214-205256.log`, latest rerun: `artifacts/verification-suite/run-20260215-110333.log`)
- [x] Land commit slices as isolated PR-ready commits with per-slice validation attached (`12198f2`, `70c34da`, `a24d2d0`, `330e46d`, `1e311ef`)
