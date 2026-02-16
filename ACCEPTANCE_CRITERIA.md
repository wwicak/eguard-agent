# eGuard Agent — Acceptance Criteria

Derived from `docs/eguard-agent-design.md`. These acceptance criteria define the testable requirements for every agent subsystem. Use these as the basis for unit tests, integration tests, and verification.

**Total ACs: ~700+** across 14 domains.

---

## Table of Contents

1. [Detection Engine (AC-DET)](#1-detection-engine)
2. [Active Response Engine (AC-RSP)](#2-active-response-engine)
3. [Baseline Learning System (AC-BSL)](#3-baseline-learning-system)
4. [Compliance/MDM Engine (AC-CMP)](#4-compliancemdm-engine)
5. [eBPF Telemetry (AC-EBP)](#5-ebpf-telemetry)
6. [Anti-Tamper & Self-Protection (AC-ATP)](#6-anti-tamper--self-protection)
7. [Crypto Acceleration / Assembly (AC-ASM)](#7-crypto-acceleration--assembly)
8. [gRPC Protocol & Protobuf (AC-GRP)](#8-grpc-protocol--protobuf)
9. [Agent Configuration (AC-CFG)](#9-agent-configuration)
10. [Lightweight Runtime (AC-RES)](#10-lightweight-runtime)
11. [NAC Integration (AC-NAC)](#11-nac-integration)
12. [Enrollment & Certificates (AC-ENR)](#12-enrollment--certificates)
13. [Packaging & Distribution (AC-PKG)](#13-packaging--distribution)
14. [Testing & Verification (AC-TST, AC-VER)](#14-testing--verification)

---

## 1. Detection Engine

*Design doc sections: 2 (Philosophy), 6 (Mathematical Framework), 15 (Rule Hot-Reload)*

### L1: Cuckoo Filter + Exact IOC Matching

- **AC-DET-001**: Cuckoo filter `contains(x)` is used as a prefilter only; every positive from the Cuckoo filter MUST be verified against the exact IOC set (SQLite/hash set) before a match is declared.
- **AC-DET-002**: Final Layer-1 decision MUST have zero algorithmic false positives — any item not in the exact IOC set MUST return `Clean` even if the Cuckoo filter returns positive.
- **AC-DET-003**: Layer-1 MUST have zero algorithmic false negatives for loaded entries, provided insertion succeeded and filter/set state is intact.
- **AC-DET-004**: Cuckoo filter false-positive rate MUST approximate `epsilon_cf ~= (2b) / 2^f` for bucket size `b` and fingerprint size `f` bits. For `b=4`: `f=12` yields ~1.95e-3, `f=16` yields ~1.22e-4, `f=18` yields ~3.05e-5, `f=20` yields ~7.63e-6.
- **AC-DET-005**: Cuckoo filter load factor MUST be kept <= 0.95; the filter MUST be rebuilt on insertion failure.
- **AC-DET-006**: Unsigned or partially loaded IOC bundles MUST be rejected; only signed, fully loaded bundles are accepted.
- **AC-DET-007**: On startup, a self-check MUST verify that a sample of `N` known entries pass both `contains()` on the Cuckoo filter and exact lookup on the authoritative store.
- **AC-DET-008**: The `IocFilter` struct MUST support three distinct filter categories: `malware_hashes` (SHA256Hash), `c2_domains` (DomainHash), and `c2_ips` (IpAddr), each backed by a Cuckoo filter plus exact store.
- **AC-DET-009**: `check_hash` (and equivalent check functions for domains/IPs) MUST return `Clean` when the Cuckoo filter returns negative, without consulting the exact store.

### L1: Aho-Corasick Multi-Pattern Matching

- **AC-DET-010**: Aho-Corasick matching MUST operate in O(n + m) time where `n` is input bytes and `m` is number of matches.
- **AC-DET-011**: Aho-Corasick space usage MUST be O(sum of pattern lengths).
- **AC-DET-012**: Aho-Corasick correctness claim ("exact for normalized byte stream") requires that normalization policies are fixed and documented: UTF-8 validation policy, case-folding policy, and path canonicalization policy MUST be defined before correctness claims are valid.
- **AC-DET-013**: Without consistent normalization, "exact" correctness claims MUST NOT be asserted across platforms.

### L2: Bounded Temporal Logic (LTLf)

- **AC-DET-020**: Behavioral rules MUST use bounded temporal operators only: `F_[0,T] p` (eventually within T), `G_[0,T] p` (always within T), `p U_[0,T] q` (until within T). No unbounded liveness over infinite traces.
- **AC-DET-021**: The webshell detection rule MUST match: `F_[0,30s](exec(parent in {nginx, apache2, httpd, caddy}, comm in SHELLS) AND F_[0,10s](net_connect(same_pid=true, dst_port notin {80,443})))`.
- **AC-DET-022**: The privilege escalation rule MUST match: `F_[0,60s](exec(uid != 0) AND F_[0,20s](exec(uid = 0, descendant_of_same_chain=true)))`.
- **AC-DET-023**: SIGMA/YAML rules MUST be compiled through the pipeline: predicate normalization -> bounded temporal AST -> deterministic monitor automaton with timers.
- **AC-DET-024**: Runtime semantics MUST be per-entity (pid, session, or process-chain key): `state' = delta(state, event_class, guards, timers)` and alert fires iff `state'` is in `accepting_states`.
- **AC-DET-025**: Per-event complexity MUST be O(r_e) where `r_e` is the number of monitors subscribed to the event class.
- **AC-DET-026**: **Soundness**: a monitor alert MUST imply the trace satisfies the compiled bounded formula.
- **AC-DET-027**: **Completeness (windowed)**: any trace satisfying the formula within monitor window `W` MUST trigger an alert, assuming telemetry integrity (A1) and temporal ordering (A2).
- **AC-DET-028**: Events MUST be processed in timestamp order with bounded reordering tolerance `delta_reorder`.

### L3: KL-Divergence Anomaly Detection

- **AC-DET-030**: KL-divergence MUST be computed over event-class distributions for `k` event classes and window size `n`.
- **AC-DET-031**: Event-class probabilities MUST be computed as `P_i = c_i / n` for observed counts.
- **AC-DET-032**: Baseline probabilities MUST use Laplace smoothing: `Q_i = (b_i + alpha) / (B + alpha * k)` with `alpha > 0`.
- **AC-DET-033**: KL-divergence MUST be computed as `D_KL(P || Q) = sum_i P_i * log2(P_i / Q_i)` (log base 2, bits).
- **AC-DET-034**: Decision rule MUST produce `alert_high` if `D_KL > tau_high` and `alert_med` if `D_KL > tau_med`.
- **AC-DET-035**: False-alarm calibration MUST use the Sanov/type-class upper bound: `Pr[D_KL(P_hat_n || Q) >= tau] <= (n + 1)^k * 2^(-n * tau)`.
- **AC-DET-036**: Threshold MUST be computed as `tau_delta(n, k, delta) = (k * log2(n + 1) + log2(1 / delta)) / n`.
- **AC-DET-037**: `tau_high = max(tau_floor_high, tau_delta(n, k, delta_high))` and `tau_med = max(tau_floor_med, tau_delta(n, k, delta_med))` MUST be enforced.
- **AC-DET-038**: For reference parameters `n=512`, `k=12`, `delta_high=1e-6`, the computed `tau_delta` MUST be approximately 0.25 bits.
- **AC-DET-039**: Anomaly baselines MUST expire and re-learn when stale. Baselines go stale after 30 days without refresh.
- **AC-DET-040**: KL/entropy monitor memory MUST fit within 0.2-1 MB. Update complexity MUST be O(1) per event and O(k) per window close.

### L3: Character Entropy for Obfuscation

- **AC-DET-041**: Character entropy MUST be computed as `H(s) = -sum_c p(c) * log2 p(c)` over the command string `s`.
- **AC-DET-042**: A minimum length guard MUST be enforced: `|s| >= N_min` where recommended `N_min >= 40`. Strings shorter than `N_min` MUST NOT trigger entropy alerts.
- **AC-DET-043**: An optional alphabet-ratio gate (base64-like character set ratio) MAY be applied as an additional filter.
- **AC-DET-044**: Per-interpreter robust z-score MUST use median/MAD baseline (not mean/stddev).
- **AC-DET-045**: Flagging policy MUST require all of: `|s| >= N_min AND H(s) > H_threshold AND z_entropy > z_threshold`.

### L4: Graph-Theoretic Kill Chain Detection

- **AC-DET-050**: Process lineage MUST be modeled as a time-labeled tree over a sliding window `W_graph`: `G_t = (V_t, E_t, L_t)`.
- **AC-DET-051**: Kill chain templates MUST be bounded-depth stage sequences with optional OR branches and max inter-stage delay `Delta`.
- **AC-DET-052**: Template matching MUST NOT use general subgraph isomorphism (NP-complete); it MUST be restricted template matching on bounded-depth lineage trees.
- **AC-DET-053**: Complexity per evaluation MUST be `O(|V| * |templates| * depth_max * b_eff)` where `b_eff` is effective branching factor after predicate pruning.
- **AC-DET-054**: Process graph + templates memory MUST fit within 1-2 MB. Evaluation is periodic batch check.

### Multi-Layer Decision Policy

- **AC-DET-060**: Confidence class **Definite** MUST be assigned if and only if L1 exact IOC match (`z1`).
- **AC-DET-061**: Confidence class **Very High** MUST be assigned if `z2 AND (z4 OR L1 prefilter hit)`, and not `z1`.
- **AC-DET-062**: Confidence class **High** MUST be assigned if `z2 OR z4`, and not Definite/Very High.
- **AC-DET-063**: Confidence class **Medium** MUST be assigned if `z3h` (L3 anomaly above high threshold) and not any of `z1`, `z2`, or `z4`.
- **AC-DET-064**: Confidence class **Low** MUST be assigned if `z3m` (L3 anomaly above medium threshold) and not any of `z1`, `z2`, or `z4`.
- **AC-DET-065**: The policy MUST be evaluated in order (Definite -> Very High -> High -> Medium -> Low) and is deterministic — first matching class wins.
- **AC-DET-066**: Only **Definite** and **Very High** MAY trigger autonomous kill/quarantine. High/Medium/Low MUST NOT trigger kill or quarantine.
- **AC-DET-067**: **Definite** MUST trigger: kill + quarantine + isolate.
- **AC-DET-068**: **Very High** MUST trigger: kill + quarantine.
- **AC-DET-069**: **High** MUST trigger: capture script + alert only.
- **AC-DET-070**: **Medium** MUST trigger: log + flag for review only.
- **AC-DET-071**: **Low** MUST trigger: log only.

### Detection Engine Assumptions and Invariants

- **AC-DET-075**: Assumption A1 (telemetry integrity): ring-buffer drop rate MUST be bounded and measured; dropped events MUST be counted and surfaced.
- **AC-DET-076**: Assumption A2 (temporal ordering): events MUST be processed in timestamp order with bounded reordering tolerance `delta_reorder`.
- **AC-DET-077**: Assumption A3 (rule/filter integrity): signed rule bundle MUST be verified before load.
- **AC-DET-078**: Assumption A4 (baseline freshness): anomaly baselines MUST expire and re-learn when stale.
- **AC-DET-079**: Assumption A5 (deterministic evaluation): all predicates MUST be pure functions over normalized event fields.
- **AC-DET-080**: Every detection decision MUST be traceable to a specific mathematical property (exact rule name + matched fields).

### Validation Protocol

- **AC-DET-085**: L1 correctness MUST be validated via property tests over random IOC sets; assert exact-verification path has 0 algorithmic FP/FN on loaded entries.
- **AC-DET-086**: L2 semantics MUST be validated by generating satisfying and violating traces; assert monitor soundness and completeness within bounded window.
- **AC-DET-087**: L3 calibration MUST be validated by computing `tau_*` from `(n, k, delta)` and validating empirical false-alarm rate on clean corpora.
- **AC-DET-088**: L4 template tests MUST replay labeled process trees and verify template match/non-match outcomes.
- **AC-DET-089**: Ring-buffer drop rate MUST be below configured SLO (< 1e-5 at 10k events/s).
- **AC-DET-090**: Deterministic replay MUST produce byte-identical alerts from identical input streams.
- **AC-DET-091**: p99 detection decision latency MUST be within target budget on reference hardware.
- **AC-DET-092**: Confidence-class action gating MUST be enforced exactly as the policy table (AC-DET-060 through AC-DET-071).
- **AC-DET-093**: For each confidence class, empirical precision/recall on labeled replay sets MUST be reported.
- **AC-DET-094**: Clopper-Pearson upper bound for false-alarm rate MUST be reported per confidence class.
- **AC-DET-095**: Drift indicators MUST be reported: baseline age, KL quantiles by process family.

### Resource Budget Envelope

- **AC-DET-100**: IOC prefilters + exact cache memory MUST fit within 0.2-0.8 MB; O(1) per lookup.
- **AC-DET-101**: Aho-Corasick matcher memory MUST fit within 1-3 MB; O(n + m) per scan.
- **AC-DET-102**: Temporal monitors memory MUST fit within 0.5-2 MB; O(r_e) per event.
- **AC-DET-103**: KL/entropy monitor memory MUST fit within 0.2-1 MB; O(1) update, O(k) per window close.
- **AC-DET-104**: Process graph + templates memory MUST fit within 1-2 MB; periodic batch check.
- **AC-DET-105**: Total detection subsystem memory MUST fit within 4-9 MB.
- **AC-DET-106**: Benchmark harness in CI MUST publish measured numbers. No unmeasured performance claims.

### Hand-Written Assembly Policy

- **AC-DET-110**: All detection decisions MUST remain in Rust. Assembly MUST NOT contain detection logic.
- **AC-DET-111**: Assembly MUST be restricted to pure compute kernels only: SHA/AES/SIMD byte scan, checksum, fixed parsing loops.
- **AC-DET-112**: Assembly MUST be in dedicated files under `zig/asm/` with one exported function per primitive.
- **AC-DET-113**: Every assembly primitive MUST have runtime CPU feature dispatch and a tested pure-Rust fallback.
- **AC-DET-114**: Assembly is optional acceleration; MUST NOT be the only correctness path.
- **AC-DET-115**: Assembly functions MUST NOT allocate heap memory, free memory, or retain global mutable state.
- **AC-DET-116**: Assembly functions MUST NOT perform file/network syscalls; only caller-provided buffers.
- **AC-DET-117**: Rust MUST own all allocations and lifetime; assembly MUST only read/write within bounds.
- **AC-DET-118**: Every exported assembly symbol MUST have a documented ABI contract.
- **AC-DET-119**: Hot-path runtime state MUST remain bounded with TTL/LRU eviction.
- **AC-DET-120**: Differential tests: assembly output MUST match Rust reference output across randomized corpora.
- **AC-DET-121**: A fuzz harness at the FFI boundary MUST be run with random lengths, alignment offsets, and malformed inputs.
- **AC-DET-122**: A soak test (minimum 24 hours replay) MUST demonstrate RSS/heap slope near zero after warmup.
- **AC-DET-123**: Sanitizer/leak builds (ASAN/LSAN) MUST be run in CI; monotonic growth of live allocations MUST cause CI failure.
- **AC-DET-124**: Symbol audit on produced asm library MUST reject unexpected allocator imports (`malloc`, `free`, `new`, `delete`).

### Server-Side Intelligence Constraints

- **AC-DET-130**: Server-side intelligence MUST be advisory ONLY — MUST NEVER trigger automatic enforcement actions.
- **AC-DET-131**: Cross-agent correlation MUST use threshold: same IOC on 3+ hosts constitutes an incident.
- **AC-DET-132**: Mathematical detection on the agent MUST remain the sole enforcement authority.
- **AC-DET-186**: Cross-endpoint campaign correlation MUST compute a weighted campaign score per IOC using the strongest per-host confidence weight (`Definite=5`, `VeryHigh=4`, `High=3`, `Medium=2`, `Low=1`, `None=0`).
- **AC-DET-187**: Campaign correlation MUST deduplicate duplicate host/IOC signals by retaining the strongest confidence per host and MUST ignore empty host or IOC identifiers.
- **AC-DET-188**: Campaign severity MUST be tiered deterministically: `Advisory` for 3+ hosts, `Elevated` for 5+ hosts or weighted score >= 18, and `Outbreak` for 8+ hosts or weighted score >= 30.
- **AC-DET-189**: Campaign incidents MUST remain advisory-only and emit deterministic ordering (severity desc, weighted score desc, IOC asc) with lexicographically sorted host lists.

### Rule Hot-Reload (Section 15)

- **AC-DET-140**: Rule updates MUST be distributed via the heartbeat cycle. Server compares agent's `config_version` and `active_sigma` count against latest `threat_intel_version`.
- **AC-DET-141**: When a newer version is available, heartbeat response MUST include `rule_update` with `current_version`, `available_version`, and `emergency` flag.
- **AC-DET-142**: Agent MUST download the rule bundle via `DownloadRuleBundle(version)`; server streams bundle chunks of 1 MB each.
- **AC-DET-143**: Agent MUST verify bundle signature using Ed25519 before extraction.
- **AC-DET-144**: Bundle MUST be extracted to `rules-staging/` directory (not directly into active rules).
- **AC-DET-145**: Hot-reload MUST compile in order: (1) SIGMA -> LTL monitors, (2) rebuild Aho-Corasick, (3) rebuild Cuckoo filters, (4) load YARA rules, (5) atomic swap staging to active.
- **AC-DET-146**: Rule updates MUST be applied without restarting the agent process.
- **AC-DET-147**: All detection state MUST be behind `Arc<RwLock>` for lock-free reads during normal operation.
- **AC-DET-148**: In-flight event processing MUST continue using old rules during compilation. Swap MUST be atomic.
- **AC-DET-149**: Write lock during atomic swap MUST block readers for ~1 microsecond only.
- **AC-DET-150**: New detection state build time MUST be ~2 seconds (before acquiring write lock).
- **AC-DET-151**: `ReloadReport` MUST contain: `old_version`, `new_version`, `sigma_rules` count, `yara_rules` count, `ioc_entries` count.
- **AC-DET-152**: Next heartbeat after reload MUST report updated `config_version`.

### Emergency Rule Push

- **AC-DET-160**: Emergency rules MUST be pushed immediately via CommandChannel without waiting for next heartbeat.
- **AC-DET-161**: Emergency rules triggered when `emergency = 1` in `endpoint_detection_rule` table.
- **AC-DET-162**: Server pushes via `ServerCommand` with `command_type: EMERGENCY_RULE_PUSH` and `EmergencyRuleParams`.
- **AC-DET-163**: Agent MUST receive emergency rule on CommandChannel with < 1 second latency.
- **AC-DET-164**: Agent MUST compile single emergency rule in < 100 milliseconds.
- **AC-DET-165**: Emergency rules MUST be appended to active detection state without full rebuild.
- **AC-DET-166**: Agent MUST confirm via `CommandResult`.
- **AC-DET-167**: Emergency rules MUST be reconciled into regular bundle at next scheduled build.

### Rule Bundle Format

- **AC-DET-170**: Bundle MUST be packaged as `eguard-rules-<date>.bundle.tar.zst` (zstd compressed tar).
- **AC-DET-171**: Bundle MUST contain: `manifest.json`, `signature.ed25519`, `sigma/linux/`, `yara/{malware,webshell,packer}/`, `ioc/{hashes,domains,ips}.json`, `cve/cve-checks.json`.
- **AC-DET-172**: Compressed bundle size (zstd level 3) MUST be ~2-5 MB typical.
- **AC-DET-173**: Uncompressed bundle size MUST be ~10-20 MB.
- **AC-DET-174**: Transfer time at 1 Mbps MUST be < 5 seconds.

### Design Philosophy Constraints

- **AC-DET-180**: Rule push to all agents MUST complete within 30 seconds.
- **AC-DET-181**: Total detection subsystem memory MUST be single-digit MB.
- **AC-DET-182**: Detection MUST have zero external dependencies — pure Rust + Zig, no ML frameworks.
- **AC-DET-183**: Detection MUST operate at full capability in offline mode.
- **AC-DET-184**: System MUST be event-driven and sleep when idle.
- **AC-DET-185**: All detection algorithms MUST be lightweight online: O(1) or O(k) per event/window.
- **AC-DET-190**: Ransomware burst detection MUST flag a process that performs >= 25 write-intent file opens to user-data paths within 20 seconds (defaults; configurable).
- **AC-DET-191**: Ransomware burst detection MUST ignore write-intent opens confined to system or temporary paths (e.g., /tmp, /proc, /Windows, /Program Files, /Library) unless explicitly overridden by policy.
- **AC-DET-192**: Ransomware burst detection MUST support an adaptive threshold based on per-process baseline write rates, using concentration bounds (Hoeffding/Bernstein) with configurable delta, minimum samples, and minimum floor.
- **AC-DET-193**: Ransomware burst detection MUST learn non-default user-data roots by observing repeated write-intent paths, promoting roots after a configurable minimum hit count up to a bounded maximum.

---

## 2. Active Response Engine

*Design doc section: 7*

### Process Termination

- **AC-RSP-001**: Definite confidence + `autonomous_response=true` + `[response.definite].kill=true` MUST autonomously kill the process.
- **AC-RSP-002**: VeryHigh confidence + `autonomous_response=true` + `[response.very_high].kill=true` MUST autonomously kill.
- **AC-RSP-003**: High confidence MUST NOT autonomously kill (default `kill=false`).
- **AC-RSP-004**: Medium confidence MUST NOT autonomously kill (default `kill=false`).
- **AC-RSP-005**: Process kill MUST complete in < 50 ms from detection event.
- **AC-RSP-006**: Kill sequence MUST first send SIGSTOP to freeze target.
- **AC-RSP-007**: Kill sequence MUST walk `/proc` to find all descendant processes.
- **AC-RSP-008**: SIGKILL MUST be sent bottom-up (children first, then parent).
- **AC-RSP-009**: Each child MUST be checked against protected process list; protected children MUST be skipped.
- **AC-RSP-010**: After all descendants killed, SIGKILL MUST be sent to original target.
- **AC-RSP-011**: `kill_process_tree` MUST return `KillReport` with `pid` and `killed_pids`.
- **AC-RSP-012**: If target pid is protected, MUST return `ResponseError::ProtectedProcess(pid)` without sending signals.
- **AC-RSP-013**: Descendant collection MUST recurse through `/proc/<pid>/task/<pid>/children`.

### File Quarantine

- **AC-RSP-020**: File quarantine MUST complete in < 100 ms from detection event.
- **AC-RSP-021**: Quarantine MUST be triggered on Definite confidence when `quarantine=true`.
- **AC-RSP-022**: Quarantine MUST be triggered on VeryHigh confidence when `quarantine=true`.
- **AC-RSP-023**: Quarantine MUST NOT be triggered on High or Medium confidence (default `quarantine=false`).
- **AC-RSP-024**: Protected path MUST return `ResponseError::ProtectedPath` without modifying file.
- **AC-RSP-025**: MUST copy file to `/var/lib/eguard-agent/quarantine/<sha256>` before modification.
- **AC-RSP-026**: File metadata MUST be preserved for potential restore.
- **AC-RSP-027**: Original file permissions MUST be stripped to `0o000`.
- **AC-RSP-028**: First 4 KB (or full file if smaller) MUST be overwritten with zeros.
- **AC-RSP-029**: Original file MUST be deleted after overwrite.
- **AC-RSP-030**: MUST return `QuarantineReport` with `original_path`, `quarantine_path`, `sha256`, `file_size`.
- **AC-RSP-031**: Quarantine directory MUST be `/var/lib/eguard-agent/quarantine`.
- **AC-RSP-032**: Admin MUST be able to restore via server `RestoreQuarantine` command.
- **AC-RSP-033**: Default protected paths: `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/lib`, `/boot`, `/usr/local/eg`.

### Script Capture

- **AC-RSP-040**: Script capture MUST complete in < 50 ms.
- **AC-RSP-041**: Before killing a malicious interpreter, agent MUST capture the script.
- **AC-RSP-042**: MUST read `/proc/<pid>/cmdline` and extract script path from `argv[1]`.
- **AC-RSP-043**: If `argv[1]` is a file, read content up to 1 MB (1,048,576 bytes).
- **AC-RSP-044**: Scripts exceeding 1 MB MUST NOT be captured.
- **AC-RSP-045**: For piped scripts (e.g., `curl | bash`), check `/proc/<pid>/fd/0`; if symlink contains "pipe:", read pipe fd.
- **AC-RSP-046**: MUST capture process environment from `/proc/<pid>/environ`.
- **AC-RSP-047**: Captured scripts MUST be uploaded as part of `ResponseReport`.
- **AC-RSP-048**: Capture enabled for Definite/VeryHigh (default `capture_script=true`).
- **AC-RSP-049**: Capture enabled for High (default `capture_script=true`) but without kill.
- **AC-RSP-050**: Capture MUST NOT be enabled for Medium (default `capture_script=false`).
- **AC-RSP-051**: `ScriptCapture` MUST contain: `script_content`, `script_path`, `stdin_content`, `environment`.

### eBPF LSM Blocking

- **AC-RSP-060**: On kernel >= 5.7 with BPF LSM, MUST use `lsm/bprm_check_security` hook.
- **AC-RSP-061**: Hook MUST check exe hash against Cuckoo block-filter.
- **AC-RSP-062**: On hash match, MUST return `-EPERM` (process NEVER starts).
- **AC-RSP-063**: On match, MUST emit block event to ring buffer for logging.
- **AC-RSP-064**: On no match, MUST return `0` (allow execution).
- **AC-RSP-065**: Block-filter hash map MUST support up to 65,536 entries.
- **AC-RSP-066**: Execution prevention via LSM MUST have 0 ms added latency.
- **AC-RSP-067**: `lsm/socket_connect` MUST block C2 connections, returning `-ECONNREFUSED`.
- **AC-RSP-068**: `lsm/file_open` MUST prevent reads of credential files during active incident.
- **AC-RSP-069**: On kernel < 5.7, MUST fall back to post-execution kill in < 50 ms.
- **AC-RSP-070**: Network connection reset via eBPF MUST complete in < 10 ms.

### Rate Limiting & Protected Processes

- **AC-RSP-080**: Maximum 10 kills per minute (`max_kills_per_minute=10`).
- **AC-RSP-081**: Maximum 5 quarantines per minute (`max_quarantines_per_minute=5`).
- **AC-RSP-082**: After hitting rate limit, 60-second cooldown (`cooldown_secs=60`).
- **AC-RSP-083**: Rate limiter MUST prevent runaway false positive cascades.
- **AC-RSP-084**: PID 1 (init/systemd) MUST always be protected.
- **AC-RSP-085**: `sshd` MUST be in default protected process list.
- **AC-RSP-086**: `^systemd` MUST be in default protected process list.
- **AC-RSP-087**: `journald` MUST be in default protected process list.
- **AC-RSP-088**: `dbus-daemon` MUST be in default protected process list.
- **AC-RSP-089**: `eguard-agent` MUST be in default protected process list.
- **AC-RSP-090**: `containerd` MUST be in default protected process list.
- **AC-RSP-091**: `dockerd` MUST be in default protected process list.
- **AC-RSP-092**: Protected process matching MUST use regex patterns.
- **AC-RSP-093**: Protected process list MUST be configurable via `agent.conf`.
- **AC-RSP-094**: Protected path list MUST be configurable via `agent.conf`.

### Master Switches & Modes

- **AC-RSP-100**: `autonomous_response` MUST default to `false`.
- **AC-RSP-101**: When `autonomous_response=false`, detection runs but MUST NOT execute response actions.
- **AC-RSP-102**: When `dry_run=true`, MUST log what WOULD be done but MUST NOT execute.
- **AC-RSP-103**: `dry_run` MUST default to `false`.
- **AC-RSP-104**: Learning period is 7 days with `autonomous_response=false`.
- **AC-RSP-105**: After learning period, `autonomous_response` MUST be set to `true`.
- **AC-RSP-106**: Each confidence level MUST have independent toggles for `kill`, `quarantine`, `capture_script`.

### Response Reporting

- **AC-RSP-110**: Every response action MUST generate a `ResponseReport` protobuf.
- **AC-RSP-111**: `ResponseReport` MUST contain: `agent_id`, `alert_id`, `action`, `detection_to_action_us`, `success`, `error_message`, `captured_script`.
- **AC-RSP-112**: `ResponseAction` enum MUST include: `KILL_PROCESS`, `KILL_TREE`, `QUARANTINE_FILE`, `BLOCK_EXECUTION`, `BLOCK_CONNECTION`, `CAPTURE_SCRIPT`.
- **AC-RSP-113**: `ResponseReport` MUST be sent to server after each action.
- **AC-RSP-114**: Every action MUST be logged locally (full audit trail).
- **AC-RSP-115**: Server MUST log to `endpoint_response_action` table.
- **AC-RSP-116**: Server MUST log quarantine to `endpoint_quarantine` table.
- **AC-RSP-117**: Host network isolation MUST complete in < 1 second (server-initiated only).
- **AC-RSP-118**: Forensic snapshot MUST complete in < 5 seconds (server-initiated only).
- **AC-RSP-119**: Quarantine restore MUST be manual/server-initiated only.

### Script Execution Response Pipeline (End-to-End)

- **AC-RSP-120**: On kernel >= 5.7 with LSM + hash match, process MUST be prevented via `bprm_check_security` returning `-EPERM`.
- **AC-RSP-121**: On kernel < 5.7 with HIGH+ confidence, pipeline MUST execute: (1) capture_script, (2) kill(pid, SIGKILL), (3) kill_process_tree(ppid), (4) quarantine_file(exe_path).
- **AC-RSP-122**: After response actions, Alert + ResponseReport MUST be sent to server.
- **AC-RSP-123**: Detection rule evaluation on post-exec path MUST complete in < 50 ms.
- **AC-RSP-124**: Optional confidence-banded auto-isolation MUST only consider `Definite` and `VeryHigh` events and MUST remain disabled by default.
- **AC-RSP-125**: Auto-isolation MUST trigger only after `min_incidents_in_window` qualifying events within `window_secs` and MUST enforce `max_isolations_per_hour` blast-radius limits.
- **AC-RSP-126**: Auto-isolation decisions MUST emit explicit response reports with `action_type="auto_isolate"` and must update host isolation state deterministically.

---

## 3. Baseline Learning System

*Design doc section: 8*

### Two Baseline Sources

- **AC-BSL-001**: Agent MUST maintain two baseline sources: agent-local (from endpoint behavior) and fleet (median across agents from server).
- **AC-BSL-002**: Agent-local baseline MUST have highest priority after 7-day learning.
- **AC-BSL-003**: Fleet baseline MUST be used as fallback for fresh deployments.

### Learning Period

- **AC-BSL-004**: Learning period MUST last exactly 7 days from installation.
- **AC-BSL-005**: During LEARNING mode, `autonomous_response` MUST be `false`.
- **AC-BSL-006**: During LEARNING, detection runs but MUST NOT auto-respond.
- **AC-BSL-007**: During LEARNING, all events MUST still be reported to server.
- **AC-BSL-008**: During LEARNING, agent MUST collect: per-(process, parent) event distributions, syscall frequency, network patterns, file access patterns.
- **AC-BSL-009**: During LEARNING, fleet baseline MUST be loaded from server as initial seed.

### Learning-to-Active Transition

- **AC-BSL-010**: After 7 days, agent MUST transition from LEARNING to ACTIVE.
- **AC-BSL-011**: On ACTIVE, `autonomous_response` MUST be `true`.
- **AC-BSL-012**: On ACTIVE, baselines frozen and used by EntropyMonitor (L3).
- **AC-BSL-013**: On ACTIVE, per-process entropy thresholds calculated via `optimal_threshold()`.
- **AC-BSL-014**: On ACTIVE, BaselineStore MUST be saved to disk.
- **AC-BSL-015**: `learning_completed` MUST be set to current SystemTime.
- **AC-BSL-016**: In ACTIVE, L3 anomaly detection MUST generate alerts.
- **AC-BSL-017**: In ACTIVE, baselines MUST be refreshed weekly (rolling window).
- **AC-BSL-018**: In ACTIVE, `BaselineReport` MUST be sent with every heartbeat.

### Stale Baseline

- **AC-BSL-019**: If no refresh for 30 days, agent MUST transition to STALE.
- **AC-BSL-020**: In STALE, L3 thresholds MUST be widened to reduce false positives.
- **AC-BSL-021**: In STALE, "baseline stale" alert MUST be sent to server.
- **AC-BSL-022**: Admin MUST be able to trigger re-learning via server command.

### Per-Process Event Distributions

- **AC-BSL-023**: Baselines keyed by `ProcessKey` = `(comm, parent_comm)`.
- **AC-BSL-024**: Each `ProcessBaseline` MUST contain: `event_distribution`, `sample_count` (u64), `entropy_threshold` (f64).
- **AC-BSL-025**: `entropy_threshold` = `median_kl + 3 * stddev`.
- **AC-BSL-026**: `learn()` MUST accumulate events per process by observing event type distributions.

### Baseline Storage

- **AC-BSL-027**: Baselines stored at `/var/lib/eguard-agent/baselines.bin` (bincode serialized).
- **AC-BSL-028**: `BaselineStore` persists: `status` (Learning/Active/Stale), `learning_started`, `learning_completed`, `last_refresh`, `HashMap<ProcessKey, ProcessBaseline>`.
- **AC-BSL-029**: On startup, `init_entropy_monitor()` loads baselines and initializes EntropyMonitor.
- **AC-BSL-030**: If per-process threshold unavailable, global default threshold MUST be used.

### Fleet Aggregation

- **AC-BSL-031**: On install, agent requests fleet baseline from server via `GetPolicy` RPC.
- **AC-BSL-032**: Server returns `fleet_baseline` rows as seed.
- **AC-BSL-033**: Agent uses fleet baseline for L3 until local learning completes.
- **AC-BSL-034**: After local learning, agent switches to local baselines.
- **AC-BSL-035**: Agent reports `BaselineReport` every heartbeat with `agent_id`, `process_key`, `event_distribution`, `sample_count`.
- **AC-BSL-036**: Server stores in `endpoint_baseline` table.
- **AC-BSL-037**: Weekly `egcron` task (`baseline_aggregation`) computes element-wise median distribution per process_key across fleet.
- **AC-BSL-038**: New agents receive updated fleet baselines as seed.

### Seed Baselines

- **AC-BSL-039**: First deployment ships with built-in seed baseline (~50 common process profiles) compiled into binary.
- **AC-BSL-040**: Seed profiles include `"bash:sshd"`, `"nginx:systemd"`, `"python3:bash"`, etc.
- **AC-BSL-041**: Seed baselines MUST use intentionally broad thresholds.
- **AC-BSL-042**: Seed baselines replaced by fleet baselines (first heartbeat) or local baselines (7 days).

### Baseline Protobuf

- **AC-BSL-043**: `BaselineReport` message: `agent_id`, `status` (BaselineLearningStatus), `baselines` (repeated ProcessBaseline).
- **AC-BSL-044**: `BaselineLearningStatus` enum: LEARNING=0, ACTIVE=1, STALE=2.
- **AC-BSL-045**: `ProcessBaseline` message: `process_key` (string "comm:parent_comm"), `event_distribution` (map<string,double>), `sample_count` (uint64), `entropy_threshold` (double).
- **AC-BSL-046**: Heartbeat request includes `baseline_report` (field 6).
- **AC-BSL-047**: Heartbeat response includes `fleet_baseline` (field 5) for learning agents.
- **AC-BSL-048**: Config: `learning_period_days=7`, `refresh_interval_days=7`, `stale_after_days=30`.

---

## 4. Compliance/MDM Engine

*Design doc section: 9*

### Linux Checks (13 total)

- **AC-CMP-001**: `os_version` check: parse `/etc/os-release`.
- **AC-CMP-002**: `kernel_version` check: `uname()` syscall.
- **AC-CMP-003**: `disk_encryption` check: query LUKS headers via `/sys/block/*/dm/uuid` (CRYPT- prefix) + `dmsetup status`.
- **AC-CMP-004**: `firewall_enabled` check: count iptables/nftables rules via netlink, check ufw status.
- **AC-CMP-005**: `package_installed` check: parse `/var/lib/dpkg/status` (Debian) or RPM DB.
- **AC-CMP-006**: `package_not_installed` check: same source, negative list.
- **AC-CMP-007**: `running_services` check: query systemd via D-Bus.
- **AC-CMP-008**: `password_policy` check: parse `/etc/login.defs` + `/etc/pam.d/common-password`.
- **AC-CMP-009**: `screen_lock_enabled` check: query GNOME via D-Bus/dconf.
- **AC-CMP-010**: `ssh_config` check: parse `/etc/ssh/sshd_config` for `PermitRootLogin`, `PasswordAuthentication`, `Protocol`.
- **AC-CMP-011**: `auto_updates` check: verify `unattended-upgrades` installed and enabled.
- **AC-CMP-012**: `agent_version` check: self-report from embedded version string.
- **AC-CMP-013**: `antivirus_running` check: process list for known AV (e.g., clamav).

### Compliance Policy Format

- **AC-CMP-014**: Policy received from server via `GetPolicy` RPC.
- **AC-CMP-015**: Policy includes: `policy_id`, `version`, `checks` array.
- **AC-CMP-016**: Each check: `type`, `op` (gte/eq/contains/not_contains), `value`, `severity`, `remediation`, optionally `remediation_command` and `key`.
- **AC-CMP-017**: `check_interval_secs` (e.g., 300s / 5 minutes).
- **AC-CMP-018**: `grace_period_secs` (e.g., 3600s / 1 hour) before enforcement.
- **AC-CMP-019**: `auto_remediate` boolean flag.

### Auto-Remediation

- **AC-CMP-020**: Firewall disabled: `ufw --force enable`.
- **AC-CMP-021**: Prohibited package: `apt-get remove -y <package>`.
- **AC-CMP-022**: SSH misconfiguration: update sshd_config + `systemctl reload sshd`.
- **AC-CMP-023**: Required service stopped: `systemctl start <service>`.
- **AC-CMP-024**: Non-remediable failures (disk encryption, OS version, kernel) MUST NOT be auto-remediated; reported to server instead.

### Check Operators

- **AC-CMP-025**: `os_version`: operator `gte`, value e.g. "22.04", severity `critical`.
- **AC-CMP-026**: `disk_encryption`: operator `eq`, value `true`, severity `critical`.
- **AC-CMP-027**: `firewall_enabled`: operator `eq`, value `true`, severity `high`, remediation=auto.
- **AC-CMP-028**: `package_installed`: operator `contains`, severity `critical`.
- **AC-CMP-029**: `package_not_installed`: operator `not_contains`, severity `medium`, remediation=auto.
- **AC-CMP-030**: `kernel_version`: operator `gte`, severity `high`.
- **AC-CMP-031**: `ssh_config`: operator `eq`, with `key` parameter, severity `high`, remediation=auto.

### Compliance Reporting

- **AC-CMP-032**: Report via `ReportCompliance` RPC with `ComplianceReport` protobuf.
- **AC-CMP-033**: Config: `check_interval_secs=300`, `auto_remediate=false`.

---

## 5. eBPF Telemetry

*Design doc section: 5*

### eBPF Programs

- **AC-EBP-001**: Agent MUST load exactly 8 eBPF programs: `process_exec.c`, `file_open.c`, `file_write.c`, `file_rename.c`, `file_unlink.c`, `tcp_connect.c`, `dns_query.c`, `module_load.c`. Compiled by Zig to BPF ELF, loaded via `libbpf-rs`.
- **AC-EBP-002**: `process_exec.c`: attach to `tracepoint/sched/sched_process_exec`, collect pid/ppid/uid/comm/filename/argv(256B)/cgroup_id. Event ~512 bytes.
- **AC-EBP-003**: `file_open.c`: attach to `tracepoint/syscalls/sys_enter_openat`, collect pid/path(256B)/flags/mode. Event ~384 bytes.
- **AC-EBP-004**: `tcp_connect.c`: attach to `tracepoint/sock/inet_sock_set_state`, collect pid/saddr/daddr/sport/dport/protocol. Event ~64 bytes.
- **AC-EBP-005**: `tcp_connect.c` MUST only emit events for NEW connections (not keepalives/retransmits).
- **AC-EBP-006**: `dns_query.c`: attach to `kprobe/udp_sendmsg` with port 53 filter, collect pid/qname(128B)/qtype. Event ~256 bytes.
- **AC-EBP-007**: `module_load.c`: attach to `kprobe/__do_sys_finit_module`, collect pid/module_name(64B). Event ~128 bytes.
- **AC-EBP-008**: `file_open.c` MUST only emit for executable files or monitored directories (kernel-side filtering).
- **AC-EBP-009**: All 5 programs MUST pass kernel BPF verifier on kernel 5.10+.
- **AC-EBP-190**: `file_write.c`: attach to `tracepoint/syscalls/sys_enter_write`, collect pid/fd/size/path(256B). Event includes `size` for telemetry `event_size`.
- **AC-EBP-191**: `file_rename.c`: attach to `tracepoint/syscalls/sys_enter_renameat2`, collect pid/src_path(256B)/dst_path(256B).
- **AC-EBP-192**: `file_unlink.c`: attach to `tracepoint/syscalls/sys_enter_unlinkat`, collect pid/path(256B).

### Ring Buffer

- **AC-EBP-010**: All programs MUST write to single shared BPF ring buffer, default 8 MB.
- **AC-EBP-011**: Ring buffer size MUST be configurable.
- **AC-EBP-012**: Ring buffer MUST use memory-mapped shared pages (no `read()` syscall, no data copying).
- **AC-EBP-013**: Rust consumer (`EbpfEngine`) MUST poll ring buffer and send events via `mpsc::Sender<RawEvent>`.
- **AC-EBP-014**: Consumer MUST wake via `epoll_wait()` on ring buffer fd (no polling loop).
- **AC-EBP-015**: Drop rate MUST be bounded and measured; dropped events counted and surfaced.
- **AC-EBP-016**: Drop rate MUST be below SLO (< 1e-5 at 10K events/sec).

### Event Header

- **AC-EBP-020**: Every event MUST begin with common `EventHeader`: `event_type: u8`, `pid: u32`, `tid: u32`, `uid: u32`, `timestamp_ns: u64`.
- **AC-EBP-021**: eBPF event_type values: PROCESS_EXEC=1, FILE_OPEN=2, TCP_CONNECT=3, DNS_QUERY=4, MODULE_LOAD=5.
- **AC-EBP-022**: Protobuf EventType enum: PROCESS_EXEC=0, FILE_OPEN=1, TCP_CONNECT=2, DNS_QUERY=3, MODULE_LOAD=4, USER_LOGIN=5, ALERT=6.

### Event Enrichment Pipeline

- **AC-EBP-030**: Raw events deserialized from packed structs (Raw Event Parser).
- **AC-EBP-031**: Process events enriched from `/proc/{pid}/exe`, `/proc/{pid}/cmdline`, `/proc/{pid}/status`.
- **AC-EBP-032**: File events enriched with SHA-256 (via crypto-accel with hardware acceleration).
- **AC-EBP-033**: Network events enriched with reverse DNS (async, cached) and optional GeoIP.
- **AC-EBP-034**: Process events build parent chain of up to 5 ancestors via ppid walking.
- **AC-EBP-035**: Pipeline order: Raw Parser -> Enrichment -> Detection (4 layers) -> Response -> Event Router.

### Event Router & Streaming

- **AC-EBP-040**: All events sent via gRPC `StreamEvents` (bidirectional streaming), batched with 100ms flush.
- **AC-EBP-041**: `TelemetryBatch`: `agent_id`, `events`, `compressed`, `events_compressed` (zstd).
- **AC-EBP-042**: Alerts MUST be sent immediately (not waiting for batch flush).
- **AC-EBP-043**: Response reports sent via `ResponseReport`.
- **AC-EBP-044**: When offline, events buffered to SQLite `/var/lib/eguard-agent/buffer.db`, 100 MB cap, FIFO eviction, ~500K events.
- **AC-EBP-045**: Telemetry types individually toggleable in `[telemetry]` config section.
- **AC-EBP-046**: `flush_interval_ms=100`, `max_batch_size=100`.

### Adaptive Polling & Backpressure

- **AC-EBP-050**: At 0 events/sec: block on `epoll_wait` indefinitely, zero CPU.
- **AC-EBP-051**: At < 100/sec: poll at 100ms, < 0.01% CPU.
- **AC-EBP-052**: At 100-1K/sec: poll at 10ms, < 0.1% CPU.
- **AC-EBP-053**: At 1K-10K/sec: poll at 1ms, < 0.5% CPU.
- **AC-EBP-054**: At > 10K/sec: continuous polling with statistical sampling, < 1% CPU.
- **AC-EBP-055**: When rate exceeds capacity, MUST enable statistical sampling.

### Caching

- **AC-EBP-060**: `FileHashCache`: LRU cache keyed on (PathBuf, u64/mtime) -> SHA256Hash, 10K entries, ~500 KB.
- **AC-EBP-061**: `ProcessCache`: HashMap<u32, ProcessInfo>, evicted on process_exit eBPF event.
- **AC-EBP-062**: File hashing once per (path, mtime); process info once per process lifetime.

### Compression & Bandwidth

- **AC-EBP-070**: 100 process events: ~50 KB uncompressed, ~5 KB compressed (zstd level 3).
- **AC-EBP-071**: Heartbeat: ~200 bytes uncompressed, ~150 bytes compressed.
- **AC-EBP-072**: Average bandwidth: ~500 bytes/sec compressed.

### Performance Budget

- **AC-EBP-080**: Idle CPU < 0.05%. Verified via `pidstat` averaged over 60s.
- **AC-EBP-081**: Active CPU < 0.5% at 1K-10K events/sec.
- **AC-EBP-082**: Peak CPU < 3% during on-demand YARA scan.
- **AC-EBP-083**: Memory RSS < 25 MB.
- **AC-EBP-084**: Disk I/O < 100 KB/s average.
- **AC-EBP-085**: Network < 500 bytes/s average.
- **AC-EBP-086**: Binary size MUST be measured and reported for stripped/LTO release builds; no fixed hard cap is enforced by default.
- **AC-EBP-087**: Startup time < 2 seconds.
- **AC-EBP-088**: Detection latency < 500 ns/event.
- **AC-EBP-089**: Response latency (kill) < 50 ms.
- **AC-EBP-090**: Response latency (LSM block) < 1 ms.
- **AC-EBP-091**: Heartbeat overhead < 200 bytes/30s.
- **AC-EBP-092**: Rule reload time < 5 seconds.

### Memory Layout

- **AC-EBP-100**: Rust runtime + tokio: ~3 MB.
- **AC-EBP-101**: eBPF ring buffer: ~8 MB (kernel-mapped).
- **AC-EBP-102**: Detection engine: ~3.8 MB (Cuckoo ~0.1, Aho-Corasick ~2, LTL ~0.5, entropy ~0.2, graph ~1).
- **AC-EBP-103**: gRPC + TLS: ~2 MB.
- **AC-EBP-104**: Process cache: ~0.5 MB.
- **AC-EBP-105**: File hash cache: ~0.5 MB.
- **AC-EBP-106**: YARA compiled rules: ~3 MB.
- **AC-EBP-107**: Offline buffer (SQLite mmap): ~2 MB when offline.
- **AC-EBP-108**: Baseline store: ~0.5 MB.
- **AC-EBP-109**: Stack + misc: ~1 MB.
- **AC-EBP-110**: Total RSS target: ~25 MB.

### LSM eBPF Program

- **AC-EBP-120**: `lsm_block.zig` attaches to `lsm/bprm_check_security` on kernel 5.7+.
- **AC-EBP-121**: Checks exe hash against Cuckoo block-filter in BPF map (65,536 entries), returns `-EPERM` on match.
- **AC-EBP-122**: On match, emits block event to ring buffer before returning `-EPERM`.
- **AC-EBP-123**: On kernel < 5.7, falls back to post-execution kill within < 50 ms.

### Temporal Ordering

- **AC-EBP-130**: Events MUST be processed in timestamp order with bounded reordering tolerance.
- **AC-EBP-131**: Agent MUST count and surface dropped ring buffer events.

---

## 6. Anti-Tamper & Self-Protection

*Design doc section: 10*

### Binary Integrity Verification

- **AC-ATP-001**: On startup, compute SHA-256 over `.text` and `.rodata` ELF sections, compare against embedded expected hash.
- **AC-ATP-002**: Integrity check repeats every 60 seconds (configurable: `integrity_check_interval_secs=60`).
- **AC-ATP-003**: Hash mismatch MUST emit `AlertEvent` with `severity=CRITICAL`, `rule_name="agent_tamper"`.
- **AC-ATP-004**: On tamper, attempt to report alert to server before entering degraded mode.
- **AC-ATP-005**: On tamper, enter DEGRADED mode.
- **AC-ATP-006**: `rdtsc` timing checks to detect debugger. Two `rdtsc` calls; if delta exceeds THRESHOLD, debugger detected.
- **AC-ATP-007**: `check_debugger()` returns `true` when rdtsc delta exceeds threshold.
- **AC-ATP-008**: Integrity code in `zig/asm/integrity.zig`, compiled to C ABI static library, linked via FFI.

### Capability Dropping

- **AC-ATP-020**: Agent retains exactly: `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`.
- **AC-ATP-021**: ALL other capabilities MUST be dropped.
- **AC-ATP-022**: Verification: `/proc/<pid>/status` CapEff contains only those 4 capabilities.

### File Protection

- **AC-ATP-025**: `/etc/eguard-agent/` files MUST have permissions `0600`.
- **AC-ATP-026**: Files MUST be owned by `eguard-agent` user.
- **AC-ATP-027**: Files at specified paths: `bootstrap.conf`, `agent.conf`, `certs/agent.crt`, `certs/agent.key`, `certs/ca.crt`.

### prctl Protections

- **AC-ATP-030**: `prctl(PR_SET_DUMPABLE, 0)` to prevent core dumps.
- **AC-ATP-031**: After PR_SET_DUMPABLE, `/proc/<pid>/dumpable` MUST be `0`.
- **AC-ATP-032**: `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` to prevent ptrace.
- **AC-ATP-033**: `ptrace(PTRACE_ATTACH, <agent_pid>)` from unprivileged process MUST fail with `EPERM`.

### Seccomp Filter

- **AC-ATP-040**: Seccomp BPF filter in whitelist mode (default deny).
- **AC-ATP-041**: Whitelist: `bpf`, `read`, `write`, `openat`, `socket`, `connect`, etc.
- **AC-ATP-042**: Non-whitelisted syscalls MUST be rejected.
- **AC-ATP-043**: Verification via `strace` every release.

### Watchdog

- **AC-ATP-050**: Systemd unit: `WatchdogSec=30s`.
- **AC-ATP-051**: If watchdog pings stop for 30s, systemd MUST restart agent.
- **AC-ATP-052**: Agent integrates via `sd-notify` for readiness and keepalive.

### Namespace Isolation

- **AC-ATP-055**: Optional mount namespace support to restrict filesystem view.

### Uninstall Protection

- **AC-ATP-060**: When `prevent_uninstall=true`, agent MUST resist unauthorized removal.
- **AC-ATP-061**: `UNINSTALL` command requires valid `auth_token` in `UninstallParams`.
- **AC-ATP-062**: `wipe_data` flag controls whether data is wiped on uninstall.

### Binary Hardening

- **AC-ATP-070**: Binary MUST pass `checksec`: Full RELRO, PIE, NX, stack canary.
- **AC-ATP-071**: Verified on every release.

### Communication Security

- **AC-ATP-080**: All communication MUST use mTLS via `rustls` with eGuard PKI CA.
- **AC-ATP-081**: Both client and server certificates MUST be verified.
- **AC-ATP-082**: CA certificate hash MUST be pinned at enrollment.
- **AC-ATP-083**: If CA changes, agent MUST reject connection.
- **AC-ATP-084**: Certificate expiry checked on every heartbeat.
- **AC-ATP-085**: Auto-renewal 30 days before expiry via SCEP.
- **AC-ATP-086**: Renewal: generate CSR, include renewal flag, server auto-approves.
- **AC-ATP-087**: Hot-swap TLS session to new cert without connection drop.

### Offline Buffering

- **AC-ATP-090**: Events buffered to SQLite at `/var/lib/eguard-agent/buffer.db`.
- **AC-ATP-091**: Buffer capped at 100 MB.
- **AC-ATP-092**: FIFO eviction when full.
- **AC-ATP-093**: ~500K events within 100 MB.

### Local Encryption

- **AC-ATP-095**: Agent config encrypted at rest with AES-256-GCM.
- **AC-ATP-096**: Key derived from machine-id (`/etc/machine-id`).
- **AC-ATP-097**: Optional TPM2 as additional key source.

---

## 7. Crypto Acceleration / Assembly

*Design doc sections: 4.2, 6.8*

### SHA-NI Accelerated Hashing

- **AC-ASM-001**: `zig/asm/sha256_ni.zig` implements SHA-256 using SHA-NI x86_64 instructions.
- **AC-ASM-002**: `sha256_ni_available()` returns `true` if CPU supports SHA-NI (CPUID detection).
- **AC-ASM-003**: `sha256_ni_hash(data, len, out) -> i32` computes SHA-256, writes 32-byte result.
- **AC-ASM-004**: If SHA-NI unavailable, MUST fall back to pure-Rust SHA-256 with identical output.
- **AC-ASM-005**: SHA-NI output MUST match Rust reference bit-for-bit (differential testing).

### AES-NI Acceleration

- **AC-ASM-010**: `zig/asm/aes_ni.zig` implements AES using AES-NI instructions.
- **AC-ASM-011**: Runtime CPUID detection; if unavailable, pure-Rust fallback.
- **AC-ASM-012**: AES-NI output MUST match Rust reference bit-for-bit.

### Zig-to-Rust FFI Contract

- **AC-ASM-020**: All assembly compiled by Zig to C ABI static library (`-target x86_64-linux-gnu -O ReleaseFast`).
- **AC-ASM-021**: Rust `crypto-accel` crate links via `rustc-link-lib=static=eguard_asm`.
- **AC-ASM-022**: Assembly restricted to pure compute kernels. No detection decisions.
- **AC-ASM-023**: Assembly in `zig/asm/` with one exported function per primitive.
- **AC-ASM-024**: Assembly MUST NOT allocate/free heap memory or retain global mutable state.
- **AC-ASM-025**: Assembly MUST NOT perform file/network syscalls.
- **AC-ASM-026**: Rust owns all allocations; assembly reads/writes within bounds only.
- **AC-ASM-027**: Every exported symbol MUST have documented ABI contract.
- **AC-ASM-028**: Runtime CPU feature dispatch required for every primitive.
- **AC-ASM-029**: Assembly is optional acceleration, never the only correctness path.

### Assembly Verification

- **AC-ASM-030**: Differential tests: assembly matches Rust reference across randomized corpora.
- **AC-ASM-031**: Fuzz harness at FFI boundary with random lengths, alignment, malformed inputs.
- **AC-ASM-032**: Soak test (24+ hours replay) demonstrating RSS/heap slope near zero.
- **AC-ASM-033**: ASAN/LSAN in CI; monotonic allocation growth causes failure.
- **AC-ASM-034**: Symbol audit rejects unexpected allocator imports (`malloc`, `free`, `new`, `delete`).
- **AC-ASM-040**: Compiled Zig asm library MUST be ~50 KB or less compressed.

---

## 8. gRPC Protocol & Protobuf

*Design doc sections: 3, 13-14*

### Enrollment

- **AC-GRP-001**: `AgentService` exposes `Enroll(EnrollRequest) returns (EnrollResponse)` (unary).
- **AC-GRP-002**: `EnrollRequest` fields: `enrollment_token`, `hostname`, `mac_address`, `os_type`, `os_version`, `kernel_version`, `agent_version`, `machine_id`, `csr` (PKCS#10), `capabilities`.
- **AC-GRP-003**: `AgentCapabilities`: `ebpf_supported`, `lsm_supported`, `yara_supported`, `ebpf_programs`.
- **AC-GRP-004**: `EnrollResponse`: `agent_id`, `signed_certificate` (X.509), `ca_certificate`, `initial_policy`, `initial_rules`.
- **AC-GRP-005**: Enrollment uses server-only TLS; after enrollment, reconnect with mTLS.
- **AC-GRP-006**: Read `bootstrap.conf` for `server.address`, `grpc_port` (50052), `enrollment_token`, optional `tenant_id`.
- **AC-GRP-007**: Server validates token against `endpoint_enrollment_token` table (exists, not expired, usage count).
- **AC-GRP-008**: Server forwards CSR to SCEP CA, returns signed certificate.
- **AC-GRP-009**: Server creates `endpoint_agent` record on enrollment.

### Heartbeat

- **AC-GRP-010**: `Heartbeat(HeartbeatRequest) returns (HeartbeatResponse)` (unary).
- **AC-GRP-011**: `HeartbeatRequest`: `agent_id`, `timestamp`, `agent_version`, `status`, `resource_usage`, `baseline_report`, `config_version`, `buffered_events`.
- **AC-GRP-012**: `AgentStatus`: `mode` (LEARNING/ACTIVE/DEGRADED), `autonomous_response_enabled`, `active_sigma_rules`, `active_yara_rules`, `active_ioc_entries`, `last_detection`, `last_response_action`.
- **AC-GRP-013**: `ResourceUsage`: `cpu_percent`, `memory_rss_bytes`, `disk_usage_bytes`, `events_per_second`.
- **AC-GRP-014**: `HeartbeatResponse`: `heartbeat_interval_secs`, `policy_update`, `rule_update`, `pending_commands`, `fleet_baseline`.
- **AC-GRP-015**: Default heartbeat interval: 30s. Server may dynamically override.
- **AC-GRP-016**: `PolicyUpdate`: `config_version`, `policy_json`.
- **AC-GRP-017**: `RuleUpdate`: `current_version`, `available_version`, `emergency`, `bundle_download_url`.
- **AC-GRP-018**: `BaselineReport`: `agent_id`, `status` (LEARNING/ACTIVE/STALE), `baselines`.
- **AC-GRP-019**: `ProcessBaseline`: `process_key`, `event_distribution`, `sample_count`, `entropy_threshold`.

### Telemetry Streaming

- **AC-GRP-020**: `StreamEvents(stream TelemetryBatch) returns (stream EventAck)` (bidirectional streaming).
- **AC-GRP-021**: `TelemetryBatch`: `agent_id`, `events`, `compressed`, `events_compressed` (zstd).
- **AC-GRP-022**: `TelemetryEvent`: `event_id`, `event_type`, `severity`, `timestamp`, `pid`, `ppid`, `uid`, `comm`, `parent_comm`, `oneof detail`.
- **AC-GRP-023**: `EventType` enum: PROCESS_EXEC=0, FILE_OPEN=1, TCP_CONNECT=2, DNS_QUERY=3, MODULE_LOAD=4, USER_LOGIN=5, ALERT=6.
- **AC-GRP-024**: `Severity` enum: INFO=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4.
- **AC-GRP-025**: `ProcessExecEvent`: `exe_path`, `cmdline`, `sha256`, `cgroup_id`, `ancestors`.
- **AC-GRP-026**: `EventAck`: `last_event_offset`, `events_accepted`.
- **AC-GRP-027**: Default flush interval 100ms, max batch size 100 events.
- **AC-GRP-028**: Alerts sent immediately (not waiting for batch flush).
- **AC-GRP-029**: zstd level 3 compression; 100 process events ~50 KB -> ~5 KB.

### Compliance

- **AC-GRP-030**: `ReportCompliance(ComplianceReport) returns (ComplianceAck)` (unary).
- **AC-GRP-031**: `ComplianceReport`: `agent_id`, `policy_id`, `policy_version`, `checked_at`, `checks`, `overall_status`.
- **AC-GRP-032**: `ComplianceStatus`: COMPLIANT=0, NON_COMPLIANT=1, ERROR=2.
- **AC-GRP-033**: `ComplianceCheckResult`: `check_type`, `status`, `actual_value`, `expected_value`, `detail`, `auto_remediated`, `remediation_detail`.
- **AC-GRP-034**: `CheckStatus`: PASS=0, FAIL=1, CHECK_ERROR=2.
- **AC-GRP-035**: `ComplianceAck`: `accepted`, `next_check_override_secs`.
- **AC-GRP-036**: Default check interval 300s; server may override.

### Command Channel

- **AC-GRP-040**: `CommandChannel(CommandPollRequest) returns (stream ServerCommand)` (server-streaming).
- **AC-GRP-041**: `CommandPollRequest`: `agent_id`, `completed_command_ids`.
- **AC-GRP-042**: `ServerCommand`: `command_id`, `command_type`, `issued_at`, `issued_by`, `oneof params`.
- **AC-GRP-043**: `CommandType`: ISOLATE_HOST=0, UNISOLATE_HOST=1, RUN_SCAN=2, UPDATE_RULES=3, FORENSICS_COLLECT=4, CONFIG_CHANGE=5, RESTORE_QUARANTINE=6, UNINSTALL=7, EMERGENCY_RULE_PUSH=8.
- **AC-GRP-044**: `IsolateParams`: `allow_server_connection`.
- **AC-GRP-045**: `ScanParams`: `paths`, `yara_scan`, `ioc_scan`.
- **AC-GRP-046**: `UpdateParams`: `target_version`, `download_url`, `checksum`.
- **AC-GRP-047**: `ForensicsParams`: `memory_dump`, `process_list`, `network_connections`, `open_files`, `loaded_modules`, `target_pids`.
- **AC-GRP-048**: `ConfigChangeParams`: `config_json`, `config_version`.
- **AC-GRP-049**: `RestoreQuarantineParams`: `sha256`, `original_path`.

### Response Action Reporting

- **AC-GRP-050**: `ReportResponse(ResponseReport) returns (ResponseAck)` (unary).
- **AC-GRP-051**: `ResponseReport`: `agent_id`, `alert_id`, `action`, `confidence`, `detection_layers`, `detection_to_action_us`, `success`, `error_message`, `timestamp`, `oneof detail`.
- **AC-GRP-052**: `ResponseAction`: KILL_PROCESS=0, KILL_TREE=1, QUARANTINE_FILE=2, BLOCK_EXECUTION=3, BLOCK_CONNECTION=4, CAPTURE_SCRIPT=5, NETWORK_ISOLATE=6.
- **AC-GRP-053**: `ResponseConfidence`: DEFINITE=0, VERY_HIGH=1, HIGH=2, MEDIUM=3.
- **AC-GRP-054**: `KillReport`: `target_pid`, `target_exe`, `killed_pids`.
- **AC-GRP-055**: `QuarantineReport`: `original_path`, `quarantine_path`, `sha256`, `file_size`, `detection_rule`.
- **AC-GRP-056**: `BlockReport`: `blocked_target`, `block_method`.
- **AC-GRP-057**: `CaptureReport`: `interpreter`, `script_path`, `script_content` (max 1 MB), `environment`.
- **AC-GRP-058**: `ResponseAck`: `accepted`, `incident_id`.

### Policy & Rule Bundle RPCs

- **AC-GRP-060**: `GetPolicy(PolicyRequest) returns (PolicyResponse)` (unary).
- **AC-GRP-061**: `DownloadRuleBundle(RuleBundleRequest) returns (stream RuleBundleChunk)` (server-streaming). Chunks of 1 MB.
- **AC-GRP-062**: Bundles zstd-compressed, 2-5 MB, Ed25519 signed, verified before applying.
- **AC-GRP-063**: Emergency rule updates MUST be downloaded immediately.
- **AC-GRP-064**: After download, extract to staging, hot-reload detection engine, report new config_version.
- **AC-GRP-065**: Rule reload < 5 seconds end-to-end.

### Schema Requirements

- **AC-GRP-070**: All protos use `syntax = "proto3"`, `package eguard.v1`.
- **AC-GRP-071**: `agent.proto` imports telemetry, compliance, command, response protos.
- **AC-GRP-076**: `AgentService` defines exactly 8 RPCs.

### Connection Resilience

- **AC-GRP-080**: Auto-reconnect with exponential backoff, max 300s.
- **AC-GRP-081**: DEGRADED mode: local detection with cached rules, agent-autonomous response, last-known baselines, buffer to SQLite.
- **AC-GRP-082**: Offline buffer: `/var/lib/eguard-agent/buffer.db`, 100 MB cap, FIFO eviction, ~500K events.
- **AC-GRP-083**: On reconnect, drain buffered events chronologically with original timestamps.
- **AC-GRP-084**: `buffered_events` count reported in heartbeat.
- **AC-GRP-085**: `AgentStatus.mode` = DEGRADED during server-unreachable periods.

### TLS & Authentication

- **AC-GRP-090**: All communication via protobuf v3 over gRPC with mTLS.
- **AC-GRP-091**: Agent uses `rustls` with eGuard PKI CA.
- **AC-GRP-092**: CA certificate hash pinned at enrollment.
- **AC-GRP-093**: Auto certificate rotation 30 days before expiry, no connection drop.
- **AC-GRP-094**: Server requires client cert for all RPCs except `Enroll`.
- **AC-GRP-095**: Server `grpc.MaxRecvMsgSize(16 << 20)` (16 MB).
- **AC-GRP-096**: gRPC server on port 50052 for direct agent connections (Caddy passthrough optional).
- **AC-GRP-097**: Agent config stores cert paths.
- **AC-GRP-098**: Go server registered via `pb.RegisterAgentServiceServer`.
- **AC-GRP-099**: Go protobuf package: `gitlab.com/devaistech77/fe_eguard/go/api/agent/v1`.

---

## 9. Agent Configuration

*Design doc section: 12*

### Bootstrap Config

- **AC-CFG-001**: Bootstrap config at `/etc/eguard-agent/bootstrap.conf`, used only for enrollment.
- **AC-CFG-002**: Contains `[server]`: `address`, `grpc_port` (50052), `enrollment_token`, `tenant_id` (optional).
- **AC-CFG-003**: MUST be deleted after successful enrollment.

### Agent Config

- **AC-CFG-004**: Persistent config at `/etc/eguard-agent/agent.conf` in TOML format, updatable by server.
- **AC-CFG-005**: `[agent]`: `agent_id` (UUID), `machine_id`.
- **AC-CFG-006**: `[server]`: `address`, `grpc_port`, `cert_file`, `key_file`, `ca_file`.
- **AC-CFG-007**: `[heartbeat]`: `interval_secs=30`, `reconnect_backoff_max_secs=300`.
- **AC-CFG-008**: `[telemetry]`: `process_exec`, `file_events`, `network_connections`, `dns_queries`, `module_loads`, `user_logins` (all bool true), `flush_interval_ms=100`, `max_batch_size=100`.
- **AC-CFG-009**: `[detection]`: `sigma_rules_dir`, `yara_rules_dir`, `ioc_dir`, `scan_on_create`, `max_file_scan_size_mb=100`.
- **AC-CFG-010**: `[response]`: `autonomous_response=false`, `dry_run=false`.
- **AC-CFG-011**: `[response.definite]`: kill=true, quarantine=true, capture_script=true.
- **AC-CFG-012**: `[response.very_high]`: kill=true, quarantine=true, capture_script=true.
- **AC-CFG-013**: `[response.high]`: kill=false, quarantine=false, capture_script=true.
- **AC-CFG-014**: `[response.medium]`: kill=false, quarantine=false, capture_script=false.
- **AC-CFG-015**: `[response.protected_processes]`: patterns `^systemd`, `^sshd`, `^init$`, `^journald`, `^dbus-daemon`, `^eguard-agent`, `^containerd`, `^dockerd`.
- **AC-CFG-016**: `[response.protected_paths]`: `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/lib`, `/boot`, `/usr/local/eg`.
- **AC-CFG-017**: `[response.rate_limit]`: `max_kills_per_minute=10`, `max_quarantines_per_minute=5`, `cooldown_secs=60`.
- **AC-CFG-018**: `[compliance]`: `check_interval_secs=300`, `auto_remediate=false`.
- **AC-CFG-019**: `[baseline]`: `learning_period_days=7`, `refresh_interval_days=7`, `stale_after_days=30`.
- **AC-CFG-020**: `[offline]`: `buffer_path=/var/lib/eguard-agent/buffer.db`, `buffer_max_size_mb=100`.
- **AC-CFG-021**: `[self_protection]`: `integrity_check_interval_secs=60`, `prevent_uninstall=true`.

### Local Data Paths

- **AC-CFG-022**: Config: `/etc/eguard-agent/` with `bootstrap.conf`, `agent.conf`, `certs/{agent.crt,agent.key,ca.crt}`.
- **AC-CFG-023**: Data: `/var/lib/eguard-agent/` with `buffer.db`, `baselines.bin`, `rules/{sigma,yara,ioc}/`, `quarantine/`, `rules-staging/`.

---

## 10. Lightweight Runtime

*Design doc section: 11*

### Performance Targets

- **AC-RES-001**: Binary size MUST be measured and reported for stripped/LTO static-musl builds; release blocking thresholds are deployment-policy configurable.
- **AC-RES-002**: Memory RSS MUST be < 25 MB (detection ~4 MB + gRPC + runtime + buffers).
- **AC-RES-003**: Idle CPU < 0.05%.
- **AC-RES-004**: Active CPU < 0.5% at 1K-10K events/sec.
- **AC-RES-005**: Peak CPU < 3% during YARA scan.
- **AC-RES-006**: Detection latency MUST be < 500 ns/event.
- **AC-RES-007**: Agent startup MUST be < 2 seconds.
- **AC-RES-008**: Zero external dependencies (pure Rust + Zig, no ML frameworks).
- **AC-RES-009**: No busy-wait or sleep-loop (pure event-driven architecture).

### Memory Layout

- **AC-RES-010**: Rust runtime + tokio: ~3 MB.
- **AC-RES-011**: eBPF ring buffer: 8 MB (default, configurable).
- **AC-RES-012**: Detection engine: ~4 MB.
- **AC-RES-013**: gRPC + TLS: ~2 MB.
- **AC-RES-014**: Process cache (500 entries): ~0.5 MB.
- **AC-RES-015**: File hash cache (10K entries): ~0.5 MB.
- **AC-RES-016**: YARA compiled rules: ~3 MB.
- **AC-RES-017**: Offline buffer (SQLite mmap): ~2 MB when offline.
- **AC-RES-018**: Baseline store: ~0.5 MB.

### Runtime Techniques

- **AC-RES-019**: eBPF programs filter in kernel before reaching userspace.
- **AC-RES-020**: Ring buffer uses zero-copy mmap (no `read()` syscall).
- **AC-RES-021**: Adaptive polling with backpressure.
- **AC-RES-022**: File hash LRU cache: 10K entries, ~500 KB.
- **AC-RES-023**: Process cache evicted on process exit.
- **AC-RES-024**: gRPC telemetry: zstd-level-3 compression + batching.
- **AC-RES-025**: Every component event-driven: `epoll_wait`, tokio async, `tokio::time::interval`, `inotify`.

---

## 11. NAC Integration

*Design doc section: 24*

### Enrollment Flow

- **AC-NAC-001**: New device with no agent: RADIUS assigns "registration" VLAN (captive portal).
- **AC-NAC-002**: Captive portal presents agent install page with OS auto-detection and enrollment token.
- **AC-NAC-003**: After enrollment + first heartbeat (LEARNING): assign "agent-learning" VLAN.
- **AC-NAC-004**: After 7-day learning + compliance=compliant: assign "production" VLAN.

### Posture-to-Enforcement Mapping

- **AC-NAC-005**: No agent -> Registration VLAN (captive portal only).
- **AC-NAC-006**: Agent LEARNING -> Agent-learning VLAN (limited access).
- **AC-NAC-007**: ACTIVE + compliant -> Production VLAN (full access).
- **AC-NAC-008**: ACTIVE + non_compliant -> Restricted VLAN (limited until remediated).
- **AC-NAC-009**: ACTIVE + critical alert -> Quarantine VLAN (eGuard server only).
- **AC-NAC-010**: Dead agent (no heartbeat) -> Quarantine VLAN.

### Threat-to-Security-Event Bridge

- **AC-NAC-011**: Go gRPC server implements NAC bridge at `go/agent/server/nac_bridge.go`.
- **AC-NAC-012**: Event 1300010: "Malware detected (YARA)" on `alert.RuleType=="yara"` with Severity>=High. Action: reevaluate_access, email_admin, role(quarantine).
- **AC-NAC-013**: Event 1300011: "Suspicious process (SIGMA)" on `alert.RuleType=="sigma"` with Severity>=High. Action: email_admin, log.
- **AC-NAC-014**: Event 1300012: "Unauthorized kernel module" on `alert.RuleName=="unauthorized_kernel_module"`. Action: reevaluate_access, email_admin.
- **AC-NAC-015**: Event 1300013: "DNS to C2 domain" on `alert.RuleType=="ioc"` with T1071. Action: reevaluate_access, email_admin.
- **AC-NAC-016**: Event 1300014: "Compliance failed". Severity: Medium. Action: reevaluate_access, role(noncompliant).
- **AC-NAC-017**: Event 1300015: "Agent tamper detected" on `alert.RuleName=="agent_tamper"`. Action: reevaluate_access, email_admin.
- **AC-NAC-018**: Event 1300016: "Lateral movement" on MITRE T1021/T1534. Action: email_admin, log.
- **AC-NAC-019**: Event 1300017: "Privilege escalation" on MITRE T1548/T1068. Action: reevaluate_access, email_admin.
- **AC-NAC-020**: `BridgeAlertToSecurityEvent` calls `security_event.Trigger(mac, eventID, alert.Description)`.

---

## 12. Enrollment & Certificates

*Design doc section: 14*

- **AC-ENR-001**: Agent performs SCEP enrollment: read bootstrap.conf, generate RSA-2048 keypair, create PKCS#10 CSR, call Enroll() RPC.
- **AC-ENR-002**: Server validates token, forwards CSR to SCEP CA, creates `endpoint_agent` record.
- **AC-ENR-003**: Agent stores cert + key in `/etc/eguard-agent/certs/`, writes `agent.conf`, deletes `bootstrap.conf`.
- **AC-ENR-004**: Agent reconnects with mTLS, starts heartbeat, starts telemetry, enters LEARNING.
- **AC-ENR-005**: Auto-renewal 30 days before expiry: new CSR, renewal flag in heartbeat, server auto-approves, hot-swap TLS (no drop).
- **AC-ENR-006**: Enrollment tokens: random 128-char, `max_uses` (0=unlimited), `target_category`, `target_role`, `expires_at`.

---

## 13. Packaging & Distribution

*Design doc section: 25*

### Binary Packaging

- **AC-PKG-001**: Two packages: `eguard-agent` (.deb/.rpm) and `eguard-agent-rules` (.deb/.rpm, optional).
- **AC-PKG-002**: `eguard-agent`: binary + eBPF programs + seed baselines + systemd unit + default config. Package footprint MUST be measured and published (no fixed hard cap by default).
- **AC-PKG-003**: `eguard-agent-rules`: initial SIGMA + YARA + IOC bundle. ~5 MB.

### Size Budget

- **AC-PKG-004**: Agent binary (Rust, stripped, LTO) compressed size MUST be tracked per release artifact; historical baseline is ~7 MB.
- **AC-PKG-005**: eBPF programs (6 BPF ELF): ~100 KB compressed.
- **AC-PKG-006**: Zig asm library: ~50 KB compressed.
- **AC-PKG-007**: Seed baselines (bincode): ~10 KB compressed.
- **AC-PKG-008**: Default config: ~5 KB compressed.
- **AC-PKG-009**: Systemd unit: ~1 KB.
- **AC-PKG-010**: Package total (agent-only and with rules) MUST be measured and published in CI/release artifacts; optional thresholds may be enforced by deployment policy.
- **AC-PKG-011**: Runtime memory < 25 MB RSS.
- **AC-PKG-012**: Total distribution budget < 200 MB.

### Distribution Channels

- **AC-PKG-013**: Primary: agent downloads from eGuard server (captive portal or API).
- **AC-PKG-014**: Secondary: apt/yum repository.
- **AC-PKG-015**: Manual: .deb/.rpm download from admin UI.
- **AC-PKG-016**: Open-source: GitHub Releases.

### Install Script

- **AC-PKG-017**: One-line install script accepts `--server`, `--token`, `--url`.
- **AC-PKG-018**: Auto-detect OS: Debian-based (`dpkg -i`) or RedHat-based (`rpm -i`).
- **AC-PKG-019**: Downloads from `https://${SERVER}/api/v1/agent-install/linux-${FORMAT}` if no --url.
- **AC-PKG-020**: Writes bootstrap config to `/etc/eguard-agent/bootstrap.conf`.
- **AC-PKG-021**: Runs `systemctl enable eguard-agent && systemctl start eguard-agent`.

### Auto-Update

- **AC-PKG-022**: Server signals updates via `HeartbeatResponse`.
- **AC-PKG-023**: Agent downloads new binary from server API.
- **AC-PKG-024**: Verifies SHA-256 checksum before installing.
- **AC-PKG-025**: Saves to `/var/lib/eguard-agent/update/eguard-agent-X.Y.Z.deb`.
- **AC-PKG-026**: `dpkg -i` to install; dpkg restarts systemd service.
- **AC-PKG-027**: New version reported in subsequent heartbeats.

### Build Pipeline

- **AC-PKG-028**: `cargo build --release --target x86_64-unknown-linux-musl` (static binary).
- **AC-PKG-029**: `zig build` for eBPF + asm library.
- **AC-PKG-030**: `strip` + LTO MUST be applied to optimize binary footprint and emit reproducible size metrics.
- **AC-PKG-031**: Produce both .deb and .rpm packages.
- **AC-PKG-032**: Packages GPG-signed.
- **AC-PKG-033**: Artifacts uploaded to GitHub Releases + package repository.

---

## 14. Testing & Verification

*Design doc sections: 28-29*

### Test Environment (Docker Compose)

- **AC-TST-001**: Docker Compose at `tests/docker-compose.test.yml` with 3 services: `eguard-server`, `agent-test`, `malware-simulator`.
- **AC-TST-002**: `eguard-server`: builds from `Dockerfile.runtime`, exposes 50052 (gRPC) + 9999 (REST), `EGUARD_TEST_MODE=1`.
- **AC-TST-003**: `agent-test`: builds from test Dockerfile, `privileged: true`, capabilities `SYS_ADMIN`, `BPF`, `NET_ADMIN`.
- **AC-TST-004**: `agent-test` env: `EGUARD_SERVER=eguard-server:50052`, `ENROLLMENT_TOKEN=test-token-12345`.
- **AC-TST-005**: `agent-test` mounts `/sys/kernel/debug` and `/sys/fs/bpf`.
- **AC-TST-006**: `malware-simulator`: shares `agent-test` network via `network_mode: "service:agent-test"`.

### Agent Test Dockerfile

- **AC-TST-007**: Builder: `rust:1.78-bookworm` with clang, llvm, libbpf-dev, linux-headers, Zig 0.13.0.
- **AC-TST-008**: Builder runs `cargo build --release` and `cargo test --no-run`.
- **AC-TST-009**: Runtime: `debian:bookworm-slim` with procps, iproute2, curl, python3, ncat, strace.
- **AC-TST-010**: Copies agent binary, test binaries, and fixtures to runtime.
- **AC-TST-011**: Default CMD: `/usr/local/bin/tests/run-all.sh`.

### Integration Test Scenarios

- **AC-TST-012**: **Enrollment**: enroll, receive cert, start heartbeat, server creates `endpoint_agent` record.
- **AC-TST-013**: **Known malware hash**: EICAR test file -> L1 Cuckoo match -> quarantine. Server logs alert + response.
- **AC-TST-014**: **SIGMA webshell**: python3 http.server -> curl|bash -> L2 LTL match -> capture + kill.
- **AC-TST-015**: **C2 domain**: nslookup known-c2 -> L1 domain IOC match.
- **AC-TST-016**: **Kernel module load**: insmod -> module_load event -> L1/L2 check.
- **AC-TST-017**: **Reverse shell**: bash -i >& /dev/tcp/... -> L2 + L4 -> kill.
- **AC-TST-018**: **Entropy anomaly**: high-entropy command -> L3 entropy alert.
- **AC-TST-019**: **Compliance failure**: ufw disable -> compliance fail report.
- **AC-TST-020**: **Agent tamper**: kill -9 agent -> systemd restart -> tamper alert -> event 1300015.
- **AC-TST-021**: **Offline mode**: block gRPC -> buffer to SQLite (100 MB cap).
- **AC-TST-022**: **Reconnect drain**: unblock -> send buffered events in order with original timestamps.
- **AC-TST-023**: **Rule hot-reload**: push new bundle -> reload without restart -> new count in heartbeat.
- **AC-TST-024**: **Emergency rule**: push IOC hash -> add to Cuckoo within seconds -> CommandResult confirms.
- **AC-TST-025**: **Protected process**: detection on sshd -> NOT killed -> alert logged, no response.
- **AC-TST-026**: **Rate limit**: 15 detections in 30s -> first 10 killed -> rate limit -> cooldown alert.
- **AC-TST-027**: **Quarantine + restore**: detect -> quarantine -> admin restore -> file restored.
- **AC-TST-028**: **LSM block** (kernel 5.7+): execute blocked hash -> EPERM -> block event logged.
- **AC-TST-029**: **Fleet correlation**: same hash on 3 containers -> incident with 3 agents.
- **AC-TST-030**: **Fleet Z-score anomaly**: 100x normal DNS -> fleet_anomaly alert at medium.

### Malware Simulator

- **AC-TST-031**: Script at `tests/malware-sim/simulate.sh`.
- **AC-TST-032**: 6 scenarios: (1) EICAR drop, (2) webshell sim, (3) reverse shell, (4) high-entropy cmd, (5) suspicious DNS, (6) firewall toggle.

### Response Action Tests (Rust Integration)

- **AC-TST-033**: `test_kill_malicious_process`: spawn sleep, inject Definite detection, verify killed < 200ms, ResponseReport success < 100ms.
- **AC-TST-034**: `test_protected_process_not_killed`: inject detection for sshd, verify NOT killed, ResponseReport error="protected".
- **AC-TST-035**: `test_rate_limiter`: max_kills=3, trigger 5 detections, verify 3 killed + 2 survive.
- **AC-TST-036**: `test_quarantine_and_restore`: create file, quarantine, verify deleted + quarantine copy, restore, verify match.
- **AC-TST-037**: Threat-intel processing tests MUST validate critical ATT&CK technique floor gate pass/fail behavior and burn-down scoreboard artifact generation (JSON + Markdown) with and without previous baseline input.
- **AC-TST-038**: Signature-ML training MUST use deterministic second-order optimization (IRLS/Newton) with class weighting + regularization sweep.
- **AC-TST-039**: Signature-ML training MUST remain framework-free (no numpy/sklearn/torch/tensorflow) and emit calibration via temperature scaling.
- **AC-TST-040**: Signature-ML training artifacts MUST include advanced metrics: PR/ROC AUC, log-loss, Brier score, and ECE.
- **AC-TST-041**: QEMU eBPF smoke test MUST load real eBPF objects and observe process_exec, file_open, and tcp_connect events.
- **AC-TST-042**: QEMU agent kill/quarantine smoke test MUST detect IOC hash via eBPF and quarantine the executable.
- **AC-TST-043**: QEMU multi-PID chain test MUST correlate temporal webshell stages across sibling PIDs in the same process tree and raise a High-or-higher confidence detection.
- **AC-TST-044**: QEMU malware harness MUST download or generate real malware samples inside the VM only, execute the detection pipeline on each sample, and emit TPR/FPR metrics (JSON or log).
- **AC-TST-045**: Malware harness MUST evaluate at least 20 malware samples and 50 benign samples, achieving ≥80% TPR and 0% FPR in isolated QEMU runs.
- **AC-TST-046**: IOC collection workflow MUST wire `MALWARE_BAZAAR_KEY` and use MalwareBazaar API with `Auth-Key` header to enrich hash feeds when the secret is present.
- **AC-TST-047**: QEMU DNS tunneling harness MUST replay high-entropy DNS queries and produce a Medium-or-higher confidence detection.
- **AC-TST-048**: QEMU memory scanner harness MUST detect a YARA shellcode marker in an RWX anonymous mapping and emit a Definite confidence alert.
- **AC-TST-049**: QEMU container escape harness MUST flag container escape + privileged container kill chain detections.
- **AC-TST-050**: QEMU credential theft harness MUST flag sensitive credential access kill chain detections.
- **AC-TST-051**: Sigma compiler MUST accept file path predicates and ship a credential access rule that uses them.
- **AC-VER-057**: QEMU harness MUST use user-mode networking with no host forwards and explicit RFC1918/link-local blackhole routes inside the guest (outbound HTTPS allowed).

### Performance Targets (Section 29.1)

- **AC-VER-001**: Stripped release binary size MUST be recorded and validated as a non-empty metric.
- **AC-VER-002**: RSS (idle) < 25 MB after 1 hour.
- **AC-VER-003**: RSS (active, 5K events/sec) < 25 MB.
- **AC-VER-004**: CPU (idle) < 0.05%.
- **AC-VER-005**: CPU (1K events/sec) < 0.5%.
- **AC-VER-006**: CPU (10K events/sec) < 3%.
- **AC-VER-007**: Detection latency < 500 ns/event.
- **AC-VER-008**: Response (kill) < 50 ms.
- **AC-VER-009**: Response (LSM block) < 1 ms.
- **AC-VER-010**: Heartbeat overhead < 200 bytes/30s.
- **AC-VER-011**: Startup < 2 seconds.
- **AC-VER-012**: Rule reload < 5 seconds.
- **AC-VER-013**: Offline buffer: 100 MB / ~500K events with FIFO eviction.

### Correctness Verification (Section 29.2)

- **AC-VER-014**: ~200 unit tests via `cargo test`.
- **AC-VER-015**: ~20 eBPF tests via custom harness.
- **AC-VER-016**: ~100 detection layer tests via `cargo test`.
- **AC-VER-017**: ~30 response engine tests via `cargo test` + integration.
- **AC-VER-018**: ~50 integration tests via Docker Compose.
- **AC-VER-019**: ~40 Perl API tests via `Test::More`.
- **AC-VER-020**: ~20 Vue component tests via Jest.
- **AC-VER-021**: ~15 performance benchmarks via `criterion`.
- **AC-VER-022**: ~5 stress tests (10K events/sec, 1000 agents, offline/reconnect).

### Security Verification (Section 29.3)

- **AC-VER-023**: `cargo audit` on every build.
- **AC-VER-024**: `cargo clippy` (all warnings) on every build.
- **AC-VER-025**: `cargo-fuzz` on protobuf parsing + detection inputs weekly.
- **AC-VER-026**: `cargo +nightly miri test` (subset) weekly.
- **AC-VER-027**: `checksec` (RELRO, PIE, NX, stack canary) every release.
- **AC-VER-028**: `strace` seccomp verification every release.
- **AC-VER-029**: Certificate validation with expired/revoked/wrong-CA certs every release.
- **AC-VER-030**: All eBPF programs pass kernel verifier on 5.10+ every build.

### Consistent Metrics (Section 29.4)

- **AC-VER-031**: Binary size telemetry is consistently reported across Sections 1.3, 11.1, 25.2, and 29.1; fixed hard caps are deployment-policy configurable.
- **AC-VER-032**: Memory RSS < 25 MB (Sections 11.1, 11.3, 25.2, 29.1).
- **AC-VER-033**: Distribution total < 200 MB (Section 25.2).
- **AC-VER-034**: Detection latency ~400 ns/event (Sections 2.2, 6.6, 29.1).
- **AC-VER-035**: Detection engine memory ~4 MB (Sections 2.2, 6.6, 11.3).
- **AC-VER-036**: Heartbeat interval 30 seconds (Sections 1.4, 12.2, 14.1).
- **AC-VER-037**: Learning period 7 days (Sections 1.4, 8.2, 24.1).
- **AC-VER-038**: Baseline stale threshold 30 days (Sections 3.7, 8.2, 8.3).
- **AC-VER-039**: IOC stale threshold 30-90 days (Section 16.4).
- **AC-VER-040**: Rate limit (kills) 10/minute (Sections 7.1, 7.8).
- **AC-VER-041**: Offline buffer 100 MB (Sections 1.4, 10.3, 12.2).
- **AC-VER-042**: Threat intel poll interval 4 hours (Sections 3.6, 18.4, 22.1).
- **AC-VER-043**: eBPF ring buffer 8 MB (Sections 5.1, 11.2).
- **AC-VER-044**: Multi-host incident threshold 3+ agents (Section 20.2).
- **AC-VER-045**: Z-score anomaly threshold 3.0 (Section 20.3).
- **AC-VER-046**: MinHash bands x rows 16 x 8 = 128 hashes (Section 20.4).
- **AC-VER-047**: Triage score weights sum to 1.0 (Section 20.5).
- **AC-VER-048**: Bundle pipeline MUST enforce a critical ATT&CK technique floor gate from curated `attack_critical_techniques.json` and fail release creation when required critical techniques are uncovered.
- **AC-VER-049**: Bundle pipeline MUST generate and publish ATT&CK critical burn-down scoreboard artifacts (`attack-burndown-scoreboard.json` and `attack-burndown-scoreboard.md`) for every bundle build.
- **AC-VER-050**: Bundle release notes MUST include critical ATT&CK floor status and burn-down scoreboard deltas (`delta_uncovered`, newly covered, newly uncovered).
- **AC-VER-051**: Bundle pipeline MUST consume previous release scoreboard baseline when available and report trend values; absence of baseline MUST be explicitly handled without crashing the pipeline.
- **AC-VER-052**: Verification suite MUST run a bundle-signature contract harness that builds a minimal processed bundle, signs it with Ed25519, verifies the signature, and emits `artifacts/bundle-signature-contract/metrics.json`.
- **AC-VER-053**: Bundle-signature contract harness MUST reject a tampered archive when verified against the original detached signature.
- **AC-VER-054**: Verification artifacts MUST include bundle signature contract metrics (`signature_verified`, `tamper_rejected`) and measured signature/database totals from `bundle_coverage_gate.py`.
- **AC-VER-055**: Verification MUST execute at least one acceptance/contract test inside an isolated QEMU VM (no host execution).
- **AC-VER-056**: QEMU harness MUST mount host root read-only via 9p and execute a provided command script via `rdinit=/init`.

---

## 15. Runtime Optimization & Refactor Contracts

### Retry Backoff Jitter

- **AC-OPT-001**: Transport retry backoff MUST apply bounded symmetric jitter to avoid synchronized retry spikes across agents.
- **AC-OPT-002**: Jittered backoff MUST stay within configured bounds and preserve exponential cap semantics (`<= max_backoff`, `>= base*(1-jitter)` and `<= base*(1+jitter)`).

### Enrichment Cache Hot Path

- **AC-OPT-003**: Process and file-hash enrichment caches MUST use O(1) recency updates and O(1) eviction operations on the hot path.
- **AC-OPT-004**: Enrichment cache capacities MUST remain bounded with deterministic eviction under churn.

### Idle Tick Behavior

- **AC-OPT-005**: Idle runtime ticks MUST NOT synthesize fake telemetry events when no eBPF events are available; offline buffer growth in degraded mode must reflect real events only.
