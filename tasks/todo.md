# eGuard Agent — Battle Plan to Beat CrowdStrike

## 🧭 Plan: Tidy todo duplication + Tier 2.3 container awareness (2026-02-16)
- [x] Review todo for duplicated Tier execution sections and inconsistent checkbox status
- [x] Consolidate Tier execution sections into a single source of truth (keep latest results)
- [x] Update Tier 2.1/2.2 checkboxes in the main Tier 2 list to reflect completed work
- [x] Implement Tier 2.3 container/namespace awareness (telemetry fields, detection signals, tests)
- [x] Add QEMU harness + acceptance criteria/contracts for container escape/privileged container detection
- [x] Validate Tier 2.3 in QEMU only and document results

## 🧭 Plan: Tier 2.4 credential theft detection (2026-02-16)
- [x] Identify credential theft signals to cover (shadow, passwd, ssh keys, credential files) and align with design doc
- [x] Add SIGMA/YARA or structural detections + tests for credential access patterns
- [x] Extend telemetry/detection payloads if needed (minimal changes)
- [x] Add acceptance criteria + contract tests (AC-TST-050+)
- [x] Build QEMU harness to replay credential access and validate detections
- [x] Validate Tier 2.4 in QEMU only and document results

## 🧭 Plan: Sigma file path predicates + cross-platform credential heuristics (2026-02-16)
- [x] Extend Sigma schema/compiler to support file path predicates for FileOpen events
- [x] Wire file path predicates into TemporalPredicate matching
- [x] Add Sigma rules for credential access using file path predicates
- [x] Expand sensitive credential path heuristics to include Windows/macOS paths (forward-compatible)
- [x] Add detection + sigma compiler tests + acceptance/contract coverage
- [x] Verify with QEMU (Linux) harness only and document results

## 🧭 Plan: Tier 4.2 exploit detection acceptance criteria (Linux-only) (2026-02-16)
- [x] Define exploit detection signals (stack pivot, RWX/mprotect abuse, memfd exec chain, heap/JIT spray) aligned with current telemetry limits
- [x] Draft acceptance criteria (AC-DET/AC-TST/AC-VER) for exploit detection coverage and QEMU-only validation
- [x] Add contract tests enforcing exploit detection AC entries (no stubs)
- [x] Document scope limitations (Linux-only, NAC + Windows/macOS deferred)

## 🧭 Plan: Tier 4.2 exploit detection implementation (Linux tests, cross-platform signals) (2026-02-16)
- [x] Add exploit indicators (memfd/\"(deleted)\"/procfd) to detection signals and confidence policy
- [x] Extend detection heuristics to include Windows/macOS fileless exec path patterns (forward-compatible)
- [x] Add tests for exploit indicator matching + confidence escalation
- [x] Add QEMU harness for exploit fileless exec replay (Linux only) + acceptance criteria/contracts
- [x] Validate in QEMU only and document results

## 🧭 Plan: Refine ML pipeline, detection, telemetry, MDM wiring
- [x] Review /home/dimas/fe_eguard/docs/eguard-agent-design.md and summarize ML pipeline, detection, telemetry, MDM requirements
- [x] Audit GitHub Actions ML pipeline under .github/workflows for gaps vs design; propose concrete improvements
- [x] Audit crates/detection ML detection layer for feature parity, thresholds, and wiring; align with design
- [x] Audit telemetry pipeline to eguard server in /home/dimas/fe_eguard; verify schema, batching, auth, and error handling
- [x] Audit MDM feature wiring end-to-end; verify agent ↔ server flows and config/telemetry hooks
- [x] Improve signature ML math: runtime-aligned feature generation + deterministic logistic training (no ML frameworks), strict runtime-feature gates
- [x] Implement agreed changes with minimal impact, add acceptance tests (no stubs)
- [ ] Verify behavior (lint/tests if applicable) and document results in this plan

## 🧭 Plan: Advanced signature ML training upgrade (2026-02-16)
- [x] Review current `signature_ml_train_model.py` outputs + gates to preserve schema/runtime compatibility
- [x] Design advanced deterministic training: robust scaling + class weighting + Newton/IRLS optimizer with regularization sweep
- [x] Add calibration + richer metrics (ROC/PR AUC, log-loss/Brier) while keeping output schema stable
- [x] Implement changes and update metadata/diagnostics (no new dependencies)
- [x] Add acceptance criteria + contract tests for advanced ML training pipeline
- [ ] Verify behavior (do not run tests on VM) and document results

## 🧭 Plan: Execute Tier 1–4 roadmap (2026-02-16)

## 🧭 Plan: Tier 1.3b multi-PID chain validation in QEMU (2026-02-16)
- [x] Inspect detection correlation + rules that should group by session_id across PIDs
- [x] Design QEMU scenario + replay/live event mapping to a real process tree
- [x] Implement QEMU harness + acceptance contract/AC entry (no stubs)
- [x] Verify in QEMU only and record results

## 🧭 Plan: Tier 1.2 malware sample testing harness in QEMU (2026-02-16)
- [x] Enable QEMU user-mode networking with `restrict=on` + no hostfwd, block RFC1918/link-local in guest, and add BusyBox applets (wget/udhcpc/tar/unzip/gzip) for in-VM downloads
- [x] Decide safe sample set + acquisition path (EICAR, EICAR ZIP, xmrig release, MalwareBazaar SHA list) and document any required API tokens
- [x] Design QEMU harness flow for staging samples, running them, and collecting detection metrics (TPR/FPR)
- [x] Implement harness scripts + acceptance criteria/tests (AC-TST-044+), no stubs
- [x] Verify in isolated QEMU only and record results + metrics in this plan

## 🧭 Plan: QEMU outbound network relaxation for malware downloads (2026-02-16)
- [x] Relax QEMU user-mode networking to allow outbound HTTPS while still blocking RFC1918/link-local routes in guest
- [x] Update AC-VER-057 + contract test to reflect new isolation policy (no hostfwd, RFC1918 blackhole)
- [x] Re-run malware harness in QEMU with MalwareBazaar key and record results

## 🧭 Plan: Remove unused detection bootstrap helper (2026-02-16)
- [x] Locate all references to `build_detection_engine` and confirm it is unused
- [x] Remove the dead code or scope it to tests only
- [x] Ensure no other warnings/errors introduced (no host tests)

## 🧭 Plan: GitHub Actions MalwareBazaar API wiring (2026-02-16)
- [x] Inspect workflows under .github/workflows for threat-intel or bundle collection steps
- [x] Decide where MalwareBazaar downloads belong (collect-ioc vs build-bundle)
- [x] Inject `MALWARE_BAZAAR_KEY` secret into relevant jobs and pass env into scripts
- [x] Update CI scripts (if needed) to respect `MALWARE_BAZAAR_KEY` and log sample counts
- [x] Add/update contract test to ensure the workflow wiring is enforced
- [x] Verify workflow YAML changes locally (no CI run)

## 🧭 Plan: Tier 2–4 testing execution (QEMU-only) (2026-02-16)
- [x] Tier 2.1 DNS tunneling/DGA/anomaly: locate DNS telemetry fields + add entropy/DGA checks + rules/tests + QEMU replay validation
- [x] Tier 2.2 Memory scanner + YARA shellcode: wire scanner into response pipeline, add YARA rules/tests, QEMU validation with injected marker
- [x] Tier 2.3 Container/namespace awareness: add cgroup/ns fields + escape heuristics + tests + QEMU validation
- [x] Tier 2.4 Credential theft: add sensitive credential access killchain + tests + QEMU validation
- [ ] Tier 3.1 NAC bridge: define server/agent test harness (Docker/QEMU), add acceptance tests + validation
- [ ] Tier 3.2 ML latency benchmark + offline mode tests: add benchmark harness + acceptance metrics (no host run)
- [ ] Tier 3.3 Detection explanation/audit trail: add rule attribution + tests + QEMU validation
- [ ] Tier 4.1 Cross-host correlation: add server-side fixtures/tests + agent batch replay
- [ ] Tier 4.2 Exploit detection: add stack pivot/ROP/heap-spray rules + tests + QEMU validation
- [ ] Tier 4.3 Platform support scaffolding: add placeholder tests + build gating for windows/macos crates
- [ ] Document results for every tier in this plan


## Review / Results (2026-02-16)
- Updated agent ML pipeline gates, runtime feature alignment, and model threshold handling.
- Upgraded signature ML training to IRLS/Newton optimization with class weighting, regularization sweep, and temperature scaling diagnostics.
- Wired telemetry payload enrichment, gRPC severity/rule mapping, and compliance envelope with checks + remediation metadata.
- Added policy refresh loop with TLS policy updates plus compliance caching/interval override; server protos/handlers aligned to TelemetryBatch + ComplianceReport.
- Added bufconn gRPC acceptance tests for telemetry batches and compliance checks (no stubs), plus contract test for advanced ML training pipeline and new AC entries.
- QEMU-only verification: ran acceptance tests for QEMU harness + advanced ML training pipeline inside isolated QEMU.
  - tests/qemu/run_qemu_command.sh ...acceptance... qemu_verification_harness_is_enforced --exact
  - tests/qemu/run_qemu_command.sh ...acceptance... signature_ml_training_pipeline_is_framework_free_and_advanced --exact
- QEMU eBPF smoke test: tests/qemu/run_ebpf_smoke.sh (exec/file_open/tcp_connect captured).
- QEMU agent kill/quarantine validation: run_agent_kill_smoke.sh succeeded after prioritizing response stage before enrollment and downgrading threat-intel refresh failures to warnings.
- QEMU multi-PID chain validation: tests/qemu/run_agent_multipid_chain.sh succeeded (High confidence network connect correlated across sibling bash PIDs).
- QEMU malware harness validation: tests/qemu/run_agent_malware_harness.sh succeeded with MalwareBazaar key + outbound HTTPS (TPR=100% FPR=0%) after switching to Auth-Key header and enabling curl; external samples downloaded inside VM.
- QEMU DNS tunneling validation: tests/qemu/run_agent_dns_tunnel.sh succeeded (Medium+ confidence on high-entropy DNS queries).
- QEMU memory scan validation: tests/qemu/run_agent_memory_scan.sh succeeded (shellcode marker detected via memory scan).
- QEMU container escape validation: tests/qemu/run_agent_container_escape.sh succeeded (container escape + privileged container killchain).
- QEMU credential theft validation: tests/qemu/run_agent_credential_theft.sh succeeded (credential killchain on /etc/shadow and SSH key).
- QEMU exploit detection validation: tests/qemu/run_agent_exploit_harness.sh succeeded (memfd/procfd/tmp fileless exec indicators at High+ confidence).
- Sigma file path predicates: extended compiler with file_path_any_of/contains, added credential_access rule, and expanded cross-platform sensitive path heuristics; re-validated QEMU credential harness.
- Exploit detection acceptance criteria: added Linux-only fileless-exec indicators (memfd/deleted/procfd/tmp), QEMU exploit harness AC, and contract checks; documented Windows/macOS + NAC deferral.

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
