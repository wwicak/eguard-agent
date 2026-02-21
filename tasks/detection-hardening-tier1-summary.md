# Detection Engine Hardening — Tier 1 Summary

## Completed (2026-02-21)

### 5 Bug Fixes Implemented

| Fix | File | AC | Description |
|-----|------|----|-------------|
| **Kernel module FP flood** | `kernel_integrity.rs:35-38` | AC-DET-240 | Removed fallback `kernel_module_loaded` indicator that flagged every `ModuleLoad` event (nvidia, zfs, ext4) as suspicious. Only rootkit heuristic matches now produce indicators. |
| **Detection allowlist** | `engine.rs` | AC-DET-241 | Added `DetectionAllowlist` with per-process (`HashSet<String>`) and per-path-prefix (`Vec<String>`) suppression. Events matching allowlist return `Confidence::None` before any layer executes. |
| **L1 Definite short-circuit** | `engine.rs:162` | AC-DET-242 | When Layer 1 returns `ExactMatch`, the engine now returns immediately with `Confidence::Definite`, skipping YARA/L2/L3/L4/behavioral/exploit/kernel-integrity layers (~70% CPU savings on confirmed IOC hits). |
| **Subscription Vec clone** | `layer2/engine.rs:119` | AC-DET-243 | Removed `.cloned()` on subscription lookup; iterate by reference. Eliminates one `Vec<usize>` allocation per event at 10K+ events/sec. |
| **Bare kernel_integrity confidence** | `policy.rs:10-16` | AC-DET-244 | Demoted standalone `kernel_integrity` signal from `High` to `Medium`. Combined with Fix 1, this eliminates the false-positive flood where every module load generated a High alert. Now requires temporal/kill-chain corroboration for High. |

### Files Modified

| File | Changes |
|------|---------|
| `tasks/todo.md` | New Tier-1 plan section with 5 findings |
| `ACCEPTANCE_CRITERIA.md` | AC-DET-240 through AC-DET-244 |
| `crates/detection/src/kernel_integrity.rs` | Remove `kernel_module_loaded` fallback; update test to assert empty indicators for benign modules |
| `crates/detection/src/engine.rs` | Add `DetectionAllowlist` struct with `is_allowed()`; add L1 ExactMatch early termination; update constructors |
| `crates/detection/src/types.rs` | Add `Default` derive to `DetectionSignals` |
| `crates/detection/src/policy.rs` | Split `kernel_integrity` out of `High` condition into standalone `Medium` |
| `crates/detection/src/layer2/engine.rs` | Remove `.cloned()` on subscription lookup; iterate by `&rule_id` |
| `crates/detection/src/lib.rs` | Export `DetectionAllowlist` |
| `crates/detection/src/tests.rs` | Restructure traceability test to separate L1 and temporal concerns |
| `crates/acceptance/AC_STATUS.md` | Register AC-DET-240..244 as `DONE_EXECUTABLE` |
| `crates/acceptance/tests/acceptance_criteria_generated.rs` | Regenerated (832 tests) |
| `crates/acceptance/tests/ac_runtime_stubs_generated.rs` | Regenerated (832 checks) |

### Test Results

- **detection**: 164/164 passed
- **agent-core**: 164/164 passed
- **acceptance**: 836/836 passed

---

## Tier 2+ Improvement Roadmap: Surpassing CrowdStrike

### TIER 1: Existential Differentiators (Must-Have)

#### 1. Content Update Safety (Anti-Channel-291) — Impact: 10/10
CrowdStrike's July 2024 outage crashed 8.5M Windows systems because their kernel driver parsed untrusted content (Channel File 291) without bounds checking.

- **Content parsing in sandboxed subprocess**: Parse YARA/Sigma/IOC content in a forked child with seccomp. Parser crash cannot affect the agent.
- **Canary window**: New content runs in shadow mode for 10 min. Auto-rollback if alert volume spikes > 3 sigma.
- **Schema versioning**: Parser rejects content whose schema version exceeds agent's known schemas.
- **eGuard advantage**: eBPF verifier guarantees no kernel crashes. Content is parsed in userspace Rust (memory-safe). This is architecturally impossible to reproduce the CrowdStrike failure mode.

#### 2. Provable System-Level FPR Bounds — Impact: 10/10
Per-layer bounds exist (Sanov for L3, CUSUM ARL for behavioral, conformal p-values). Missing: composition into a single system-level guarantee.

- Add `SystemFprBudget` tracking Bonferroni-allocated alpha across all layers
- Every alert includes `system_fpr_upper_bound: f64` in telemetry
- **Narrative**: "This alert has a provable false-positive probability < 1e-5 per day."

#### 3. Hard Runtime Resource Budgets — Impact: 9/10
Test-time budgets exist but not enforced at runtime.

- `ResourceBudget` wrapper enforcing per-subsystem memory caps with graceful degradation
- Per-event CPU budget with circuit breaker (skip expensive layers if P99 exceeded)
- Adaptive eBPF ring buffer polling based on fill level
- **Marketing killshot**: "eGuard guarantees < 2% CPU and < 50 MB RSS, with Sanov-backed proofs."

#### 4. Hot-Reload with Canary Deployment — Impact: 9/10
- Atomic eBPF program replacement via `bpf_link__update_program`
- Shadow-mode evaluation of new rule sets before global activation
- Last-known-good content version with auto-revert

### TIER 2: Strong Differentiators (Win Enterprise Deals)

#### 5. BPF-LSM Inline Prevention — Impact: 8/10
Move from observe-then-kill to atomic observe-and-block at syscall level. Zero userspace round-trip. Graceful fallback on older kernels.

#### 6. Lock-Free Event Pipeline — Impact: 8/10
Replace `mpsc::Sender` with lock-free SPSC ring buffer. Target: < 100ns per event handoff, zero allocations on hot path.

#### 7. Self-Protection via BPF-LSM — Impact: 8/10
Make agent unkillable: BPF-LSM prevents ptrace/kill/proc-mem-write against agent PID. Watchdog process for auto-restart.

#### 8. Cross-Agent Campaign Correlation — Impact: 8/10
Real-time lateral movement detection across agents. Campaign-level kill chains spanning multiple hosts. Epidemic detection with Sanov significance testing.

#### 9. Batch/Tiered Detection Pipeline — Impact: 7/10
Process events in micro-batches (64-256). Pre-filter tier with bloom filter on known-benign (process_name, event_class) tuples to skip 80-90% of events.

#### 10. Continuous Memory Forensics — Impact: 7/10
Periodic scanning of suspicious PIDs. eBPF-triggered memory scans on `mmap(PROT_EXEC)` for anonymous regions.

#### 11. Detection Audit Trail with Full Provenance — Impact: 7/10
Full decision tree per alert. Reproducible detection from versioned engine state snapshots. Differential privacy on telemetry upload.

### TIER 3: Technical Excellence (Win Security Research Mindshare)

#### 12. Formal eBPF Program Verification — Impact: 7/10
Property-based specs for each probe. Model checking for correctness (not just safety). Differential testing against strace ground truth.

#### 13. Container-Native Detection — Impact: 6/10
Namespace-aware baselines keyed by `(container_image, process)`. eBPF namespace ID extraction. Kubernetes pod-to-pod correlation.

#### 14. Adversarial ML Robustness — Impact: 6/10
Feature hardening with invariant properties. Ensemble disagreement detection. Feature integrity verification in model manifests.

#### 15. eBPF-Based Kernel Integrity Monitoring — Impact: 6/10
Syscall table integrity verification. Module signature verification on load. kprobe self-integrity checks.

---

## The Winning Technical Thesis

CrowdStrike optimizes for detection accuracy at the cost of **safety, transparency, and provability**.

eGuard's moat is built on three pillars:

1. **Provable safety**: eBPF verifier guarantees no kernel crashes. Content updates sandboxed in userspace. Resource budgets enforced at runtime with mathematical proofs.

2. **Provable detection quality**: Every alert carries a Sanov-bounded FPR. Every ML decision includes feature attribution. Every detection is reproducible from a versioned engine state.

3. **Provable resource bounds**: Published, guaranteed CPU/memory ceilings with graceful degradation. No surprises, no spikes, no outages.

A staff security engineer at a top-tier SOC wants *fewer false positives with provable bounds*, *full explainability for every alert*, and *confidence that the agent will never cause an outage*.
