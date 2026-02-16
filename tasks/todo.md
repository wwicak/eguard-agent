# eGuard Agent — Battle Plan to Beat CrowdStrike

## 🧭 Plan: Refine ML pipeline, detection, telemetry, MDM wiring
- [ ] Review /home/dimas/fe_eguard/docs/eguard-agent-design.md and summarize ML pipeline, detection, telemetry, MDM requirements
- [ ] Audit GitHub Actions ML pipeline under .github/workflows for gaps vs design; propose concrete improvements
- [ ] Audit crates/detection ML detection layer for feature parity, thresholds, and wiring; align with design
- [ ] Audit telemetry pipeline to eguard server in /home/dimas/fe_eguard; verify schema, batching, auth, and error handling
- [ ] Audit MDM feature wiring end-to-end; verify agent ↔ server flows and config/telemetry hooks
- [ ] Improve signature ML math: runtime-aligned feature generation + deterministic logistic training (no ML frameworks), strict runtime-feature gates
- [ ] Implement agreed changes with minimal impact, add acceptance tests (no stubs)
- [ ] Verify behavior (lint/tests if applicable) and document results in this plan

## ✅ Completed (Foundation)
- [x] 5-layer detection engine (IOC, SIGMA, anomaly, kill chain, ML)
- [x] YARA file scanning + memory scanner module
- [x] Behavioral change-point engine (8 CUSUM dimensions)
- [x] Information-theoretic detection (Rényi entropy, NCD, spectral)
- [x] CI bundle pipeline (7 layers + ML model training + signing)
- [x] ML model flows CI → bundle → agent runtime → all shards
- [x] Autonomous kill + quarantine in real VM
- [x] 15/15 E2E acceptance tests
- [x] NAC integration (PacketFence) — CrowdStrike doesn't have this
- [x] 2,142 tests, 0 failures

---

## 🔴 Tier 1: Critical Gaps (Must fix to be production-credible)

### 1.1 Real eBPF Monitoring — End to End
**Why**: Our eBPF backend exists but has never been tested with real kernel events.
The replay backend proves the pipeline works, but CrowdStrike runs real eBPF in production.
Without this, we're a signature scanner, not an EDR.

- [ ] Build VM with BTF-enabled kernel + BPF LSM
- [ ] Compile agent with `ebpf-libbpf` feature
- [ ] Boot VM, start agent, run actual malicious commands
- [ ] Verify agent sees real `sched_process_exec`, `security_file_open`, `tcp_connect`
- [ ] Verify detection fires on real events (not replay)
- [ ] Verify kill/quarantine on real live processes
- **Acceptance**: Agent detects+kills a real `ncat` reverse shell via eBPF

### 1.2 Real Malware Sample Testing
**Why**: We test against simulated threats. CrowdStrike tests against millions of real samples.
A simulated `sleep` process with a malicious name is not a real reverse shell.

- [ ] Download EICAR + test malware from MalwareBazaar (safe research samples)
- [ ] Run actual reverse shell (`ncat -e /bin/sh`) in VM, verify detection+kill
- [ ] Run actual crypto miner binary (xmrig), verify detection+kill
- [ ] Run actual privilege escalation (dirty pipe PoC), verify detection
- [ ] Run fileless payload (`curl | bash` dropping in-memory payload)
- [ ] YARA memory scan on running process with injected shellcode
- **Acceptance**: ≥80% TPR on 20 real malware samples, 0% FPR on 50 benign

### 1.3 Multi-PID Attack Chain Correlation (L4 Fix)
**Why**: Our SIGMA temporal rules use `entity = event.pid` — multi-PID attack chains
(e.g., curl downloading → bash executing → payload running) don't correlate.
CrowdStrike's ThreatGraph tracks causal chains across processes.

- [ ] Add `session_id` correlation key (ppid-based process tree)
- [ ] SIGMA rules should match `entity = session_id` for multi-step
- [ ] Kill chain templates should correlate across PIDs in same tree
- [ ] Test: `curl | bash | nc` chain detected as single kill chain
- **Acceptance**: 3+ multi-PID attack chains correlated with ≥High confidence

---

## 🟡 Tier 2: High-Impact Differentiators

### 2.1 DNS Threat Detection (Tunneling + DGA)
**Why**: DNS is the most abused protocol. CrowdStrike detects DNS tunneling,
DGA domains, DNS-over-HTTPS abuse. We only match IOC domains.

- [ ] DNS entropy analyzer — high entropy subdomains = tunneling
- [ ] DGA classifier — ML model for domain generation algorithms
- [ ] DNS query rate anomaly — sudden burst = C2 beaconing
- [ ] DNS TXT record size anomaly — large TXT = data exfil
- [ ] Wire into L1/L3 detection layers
- **Acceptance**: Detect iodine/dnscat2 tunneling, detect 5 DGA families

### 2.2 Fileless Attack Detection (Memory Scanning)
**Why**: `memory_scanner.rs` exists (352 lines) but isn't wired into the
detection pipeline. CrowdStrike scans process memory for shellcode,
injected DLLs, and fileless payloads.

- [ ] Wire `memory_scanner.rs` into response pipeline (scan on Definite)
- [ ] Add trigger: scan suspicious process memory on `mmap(PROT_EXEC)`
- [ ] Add YARA rules for common shellcode patterns (meterpreter, cobalt strike)
- [ ] Periodic scan of high-risk processes (uid=0, network-connected)
- **Acceptance**: Detect meterpreter shellcode injected via `memfd_create`

### 2.3 Container/Namespace Awareness
**Why**: Modern infrastructure runs in containers. CrowdStrike Falcon has
dedicated container runtime security. We need at minimum to:

- [ ] Read `/proc/[pid]/cgroup` to identify container context
- [ ] Read `/proc/[pid]/ns/pid` for namespace isolation detection
- [ ] Add `container_id` field to TelemetryEvent
- [ ] Container escape detection (nsenter, mount namespace traversal)
- [ ] Privileged container detection (SYS_ADMIN, SYS_PTRACE caps)
- **Acceptance**: Detect container escape attempt + privileged container spawn

### 2.4 Credential Theft Detection
**Why**: Credential theft is the #1 attack technique. We have basic string
sigs for `/etc/shadow` but nothing for real credential attacks.

- [ ] Detect `/etc/shadow` reads by non-root, non-system processes
- [ ] Detect SSH key exfiltration (`~/.ssh/id_*` reads)
- [ ] Detect credential dumping tools (linpeas, pspy, mimipenguin)
- [ ] Detect brute-force SSH login patterns (repeated auth failures)
- [ ] Add SIGMA rules for Linux credential theft techniques
- **Acceptance**: Detect linpeas execution + /etc/shadow dump as Definite

---

## 🟢 Tier 3: Competitive Advantages (Where We Beat CrowdStrike)

### 3.1 NAC-Integrated Response (Already Built)
**Why**: CrowdStrike can kill processes but CANNOT isolate a host at the network
level. Our PacketFence integration can quarantine-VLAN an entire machine.

- [ ] Test NAC bridge with real PacketFence in Docker
- [ ] Auto-isolation on ≥3 Definite detections within 60s window
- [ ] Demonstrate: attack detected → process killed → host quarantined

### 3.2 On-Device ML (No Cloud Dependency)
**Why**: CrowdStrike requires cloud connectivity for full ML scoring.
Our 18-feature model runs entirely on-device with zero latency.
In air-gapped environments, CrowdStrike is blind; we're not.

- [ ] Benchmark ML inference latency (target: <1ms per event)
- [ ] Add offline mode documentation
- [ ] Test full detection capability with network disabled

### 3.3 Transparent Detection Logic
**Why**: CrowdStrike is a black box. Our SIGMA rules, YARA rules, and ML
model weights are all auditable. SOC teams can understand WHY something was detected.

- [ ] Export detection explanation per event (which layers fired, why)
- [ ] Add rule attribution to response reports
- [ ] Human-readable detection audit trail

---

## 🔵 Tier 4: Future Roadmap

### 4.1 Cross-Host Correlation (Fleet-Level)
- [ ] Server-side correlation of events from multiple agents
- [ ] Detect lateral movement: same credential used on 3+ hosts
- [ ] Attack graph visualization across fleet

### 4.2 Exploit Detection
- [ ] Stack pivot detection via eBPF
- [ ] ROP chain detection (return address anomaly)
- [ ] Heap spray detection (large uniform allocations)

### 4.3 Windows/macOS Support
- [ ] `platform-windows` crate (ETW consumer)
- [ ] `platform-macos` crate (EndpointSecurity.framework)

---

## Priority Order (Next Actions)

| # | Task | Impact | Effort | Priority |
|---|------|--------|--------|----------|
| 1 | Real eBPF E2E in VM | Critical | Medium | 🔴 NOW |
| 2 | Real malware testing | Critical | Medium | 🔴 NOW |
| 3 | Multi-PID correlation fix | Critical | Small | 🔴 NOW |
| 4 | DNS tunneling + DGA | High | Medium | 🟡 NEXT |
| 5 | Wire memory scanner | High | Small | 🟡 NEXT |
| 6 | Container awareness | High | Medium | 🟡 NEXT |
| 7 | Credential theft SIGMA | High | Small | 🟡 NEXT |
| 8 | NAC integration test | Differentiator | Small | 🟢 THEN |
| 9 | Detection explanations | Differentiator | Small | 🟢 THEN |
| 10 | ML inference benchmark | Differentiator | Small | 🟢 THEN |
