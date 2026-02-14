# Next Job Acceptance Criteria (Backlog)

Last updated: 2026-02-14

This document tracks **planned acceptance criteria** for the next release-prep + hardening tranche.
These are intentionally kept outside `ACCEPTANCE_CRITERIA.md` until implementation is complete and executable coverage is wired.

## Implementation Status (2026-02-14)

- ✅ Implemented: `NXT-CR-001..005`, `NXT-CR-008..012`
- ✅ Completed operational closure: `NXT-CR-006` (verification-suite run in cargo-audit-enabled env; evidence: `artifacts/verification-suite/run-20260214-203041.log`)
- ✅ Completed operational closure: `NXT-CR-007` (commit slicing/PR hygiene finalized in isolated slices: `12198f2`, `70c34da`, `a24d2d0`, `330e46d`, `1e311ef`)

## A) CI / Release Readiness

- **NXT-CR-001**: Workflow YAML files (`verification-suite`, `package-agent`, `release-agent`) pass syntax lint/dry-run checks.
- **NXT-CR-002**: Optimization guardrail thresholds are validated with evidence from both cold-cache and warm-cache CI runner executions.
- **NXT-CR-003**: Perf gate remains non-blocking on runners without `perf`; skipped-state metrics include explicit reason `perf_not_available`.
- **NXT-CR-004**: Release/package workflows produce valid `.deb` and `.rpm` artifacts for the release candidate.
- **NXT-CR-005**: Optimization guardrail artifacts are uploaded and inspected (`detection-benchmark`, `runtime-tick-slo`, `replay-determinism`, `detection-quality-gate`, `ebpf-drop-rate-pressure`, `rule-push-slo`, `ebpf-resource-budget`, `perf-profile-gate`, `release-profile-opt`).

## B) Operational Closure

- **NXT-CR-006**: `bash scripts/run_verification_suite_ci.sh` is executed end-to-end in an environment with `cargo-audit` installed, and logs are archived.
- **NXT-CR-007**: Commit slicing is finalized into isolated, reviewable commits with per-slice validation evidence (runtime split, detection hardening, eBPF pooling/contracts, CI/workflows, docs).

## C) Detection Hardening Follow-Up

- **NXT-CR-008**: Layer2 adds ProcessExit-aware teardown hooks that immediately remove per-PID temporal state/metadata at process end.
- **NXT-CR-009**: Layer2 emits eviction observability counters with reason tags (`retention`, `state_cap`, `metadata_cap`).
- **NXT-CR-010**: Adversarial replay corpus includes cap-pressure timestamp-tie and combined cap/reorder abuse scenarios with zero high-confidence stale-state false positives.
- **NXT-CR-011**: Cross-layer PID churn adversarial replay validates no stale-state contamination across Layer2 and Layer4 boundaries.
- **NXT-CR-012**: Detection quality trend monitoring applies drift bounds to `per-confidence-trend.ndjson` and raises alert/fail on precision/recall/FAR regressions.

## Validation Plan for This Backlog

- CI workflow dry-run + artifact inspection.
- Full guardrail harness rerun after each slice.
- Targeted detection regressions + workspace tests.
- Release/package workflow artifact verification.
- Final release-prep signoff checklist in `tasks/commit-slicing-release-prep.md`.
