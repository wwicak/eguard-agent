# ML Pipeline Upgrade — Outshine CrowdStrike (2026-03-01)

## Plan
- [x] 1) Upgrade `docs/ml-ops-operations-manual.md` to v2.0 (sections 3.4-3.7, 5.3, enhanced section 9)
- [x] 2) Upgrade `docs/baseline-ml-production-acceptance.md` to v2.0 (AC-BML-080 through AC-BML-087)
- [x] 3) Wire conformal calibrator into L5 engine (calibration_scores in model, p-value in MlScore)
- [x] 4) Wire CUSUM drift detection per process key in anomaly engine
- [x] 5) Wire mutual information beaconing detection (per-destination MI tracker)
- [x] 6) Add 6 new L5 features (27-32): tree_depth, tree_breadth, child_entropy, spawn_rate, rare_parent_child, c2_beacon_mi
- [x] 7) Add c2_beaconing_detected + process_tree_anomaly to DetectionSignals
- [x] 8) Add Bayesian Dirichlet prior to fleet seed merge in baseline crate
- [x] 9) Implement trimmed median aggregation in Go server
- [x] 10) Implement JS-divergence fleet health monitoring in Go server
- [x] 11) Implement ADWIN drift monitor in Go server (new baseline_drift.go)
- [x] 12) Add conformal calibration export to Python training pipeline
- [x] 13) Extend Python feature schema from 27 to 33 features
- [x] 14) Add real feedback integration to training corpus builder
- [x] 15) Create A/B testing framework (signature_ml_ab_test.py)

## Verification
- `cargo check -p detection` ✅
- `cargo check -p baseline` ✅
- `cargo test -p detection` ✅ (186 passed)
- `cargo test -p baseline` ✅ (24 passed, incl. 4 new Bayesian tests)
- `go build ./...` ✅ (Go server compiles)
- `go test ./agent/server/ -run "TestBaseline|TestAdwin|TestJS|TestTrimmed"` ✅ (16 passed)
- Python syntax validation ✅ (all 4 scripts parse correctly)

---

# Linux RAM type enrichment (DDR4/DDR5 visibility)

## Plan
- [x] 1) Add Linux RAM type detection from SMBIOS/DMI and emit `hw.ram.type` when available.
- [x] 2) Add unit tests for SMBIOS parsing and type mapping logic.
- [x] 3) Run `cargo test -p platform-linux` and ensure no regressions.
- [x] 4) Build/redeploy Linux agent VM and verify new inventory snapshot contains `hw.ram.type` when firmware exposes it.
- [x] 5) Update operations notes with Linux RAM-type extraction behavior and caveats.

## Review
- Implemented Linux RAM type extraction in `crates/platform-linux/src/inventory.rs` by parsing SMBIOS/DMI Type-17 memory device records (`/sys/firmware/dmi/tables/DMI`) and mapping to `hw.ram.type` (`DDR3/DDR4/DDR5`, LPDDR variants when provided).
- Added parser tests:
  - `parse_linux_ram_type_from_dmi_bytes_detects_ddr4`
  - `parse_linux_ram_type_from_dmi_bytes_prefers_dominant_type`
  - `parse_linux_ram_type_from_dmi_bytes_returns_none_on_unknown`
- Validation:
  - `cargo fmt --all` ✅
  - `cargo test -p platform-linux` ✅ (77 passed)
- Live redeploy/verify:
  - built `agent-core` release, deployed to Linux VM, restarted `eguard-agent.service`.
  - backup: `/var/lib/eguard-agent/bin-backup-20260228091725`.
  - latest Linux inventory row (id=60) still shows `hw.ram.type=None` in this VM because firmware exposes generic SMBIOS memory type code `7` (RAM), not DDR generation.
- Updated docs: `docs/operations-guide.md` now documents Linux `hw.ram.type` extraction + virtualization caveat.

---

# OS-level inventory enrichment (Linux/Windows/macOS)

## Plan
- [x] 1) Audit current platform inventory collectors for missing OS-extractable fields (disk interface/bus/security posture).
- [x] 2) Implement Linux inventory enrichment: disk interface/bus inference + security keys (secure boot, TPM presence/version).
- [x] 3) Implement Windows inventory enrichment: disk interface extraction + security keys (secure boot, TPM presence/readiness/version).
- [x] 4) Implement macOS inventory enrichment: disk interface inference + security signals available from OS tools.
- [x] 5) Add/adjust unit tests for new helper logic and parsing behavior.
- [x] 6) Run targeted test/build verification and summarize emitted `hw.*` keys for inventory/UI filtering.

## Review
- Implemented Linux enrichment in `crates/platform-linux/src/inventory.rs`:
  - new disk metadata keys: `hw.disk.interface`, `hw.disk.bus_type` (+ enriched `hw.disk.disks` entries),
  - new security keys: `hw.security.secure_boot`, `hw.security.tpm.present`, `hw.security.tpm.version`.
  - added inference helpers + tests for common interface classification.
- Implemented Windows enrichment in `crates/platform-windows/src/inventory/hardware_detail.rs`:
  - disk extraction now includes `InterfaceType` + `PNPDeviceID`,
  - new keys: `hw.disk.interface`, `hw.disk.bus_type`,
  - security keys from OS: `hw.security.secure_boot`, `hw.security.tpm.present`, `hw.security.tpm.ready`, `hw.security.tpm.version`.
- Implemented macOS enrichment in `crates/platform-macos/src/inventory.rs`:
  - disk metadata keys: `hw.disk.interface`, `hw.disk.bus_type`,
  - security keys: `hw.security.filevault_enabled`, `hw.security.secure_enclave.present`, `hw.security.secure_chip.model`, `hw.security.secure_boot.mode`, plus explicit `hw.security.tpm.present=false`.
- Validation:
  - `cargo fmt --all` ✅
  - `cargo test -p platform-linux` ✅ (74 passed)
  - `cargo test -p platform-windows` ✅ (68 passed)
  - `cargo test -p platform-macos` ✅ (35 passed)
  - `cargo check -p agent-core` ✅
- Live Linux VM verification after deploying rebuilt `agent-core`:
  - server inventory now includes `hw.disk.interface=VirtIO`, `hw.disk.bus_type=VirtIO`, `hw.security.tpm.present=false` for `agent-31bbb93f38b4`.
- Live Windows VM verification after deploying rebuilt `agent-core.exe`:
  - server inventory latest row includes `hw.disk.interface=VirtIO`, `hw.disk.bus_type=VirtIO`, `hw.domain.joined=false`, `hw.domain.name=WORKGROUP`, `hw.security.tpm.present=false`, `hw.security.tpm.ready=false` for `agent-4412`.
- Windows inventory OS-version correction follow-up:
  - fixed `collect_platform_snapshot()` to stop using `PROCESSOR_ARCHITECTURE` (`Windows (AMD64)`),
  - now uses registry `ProductName` (+ `DisplayVersion`/`ReleaseId`) with numeric fallback,
  - verified live row moved to `Windows Server 2019 Standard 1809` (`id=61`).
- Live UI deployment verification:
  - new `EndpointInventory` bundle on server includes dropdown filters for `Disk Interface` and `Disk Bus`, plus expanded security posture CSV columns.

---

# Windows NAC MAC fallback fix (agent-1356)

## Plan
- [x] 1) Confirm where Windows agent MAC is sourced and why `00:00:00:00:00:00` is emitted.
- [x] 2) Implement Windows primary-MAC detection + normalization in `platform-windows` inventory.
- [x] 3) Backfill config load so placeholder MAC values are replaced with detected MAC when possible.
- [x] 4) Add unit tests for MAC normalization/selection logic.
- [x] 5) Run targeted validation and document results.

## Review
- Root cause confirmed: `AgentConfig::default()` only detected MAC on Linux and hardcoded `00:00:00:00:00:00` for non-Linux targets, so Windows enrollment/inventory payloads inherited placeholder MAC.
- Added Windows MAC detection path in `crates/platform-windows/src/inventory/network.rs`:
  - `primary_mac_address()` helper,
  - MAC normalization (`AA-BB-...` → `aa:bb:...`),
  - reserved-MAC filtering (`00:..`, `ff:..`),
  - adapter prioritization (non-virtual + routable IP preferred).
- Re-exported helper via `crates/platform-windows/src/inventory/mod.rs`.
- Updated `crates/agent-core/src/config/defaults.rs` to use `detect_primary_mac()` on Windows and added placeholder backfill hook (`refresh_placeholder_mac`).
- Updated `crates/agent-core/src/config/load.rs` to repair placeholder MAC after file/bootstrap/env overlays (so existing `00:...` config values are auto-corrected when detectable).
- Validation:
  - `cargo fmt --all` ✅
  - `cargo test -p platform-windows` ✅
  - `cargo test -p agent-core config::tests` ✅
  - `cargo check -p platform-windows -p agent-core` ✅
  - `cargo check --target x86_64-pc-windows-msvc -p platform-windows -p agent-core` ⚠️ blocked in this environment (`lib.exe`/MSVC toolchain unavailable).

---

# Windows NAC+EDR+MDM parity + build/release workflow update

## Plan
- [x] 1) Make `agent-core` a real Windows service application (SCM-aware runtime), while preserving console mode fallback for local debugging.
- [x] 2) Remove Linux-hardcoded runtime behavior in cross-platform control paths (inventory collection, marker/data paths, MDM command execution plumbing).
- [x] 3) Implement Windows MDM/NAC command handlers in `agent-core` (lock/restart/isolation/network-profile/app mgmt/profile application) using Windows-appropriate commands/APIs.
- [x] 4) Extend NAC install target detection and endpoints to include Windows install channel (`/api/v1/agent-install/windows-exe`).
- [x] 5) Add/adjust unit tests for Windows-specific command/path/target behavior and existing cross-platform contracts.
- [x] 6) Update CI/release workflows to build/package Windows artifacts as first-class outputs (service-capable binary + MSI) and include them in release publishing.
- [x] 7) Validate with targeted checks/tests and document a concise review summary here.

## Acceptance Criteria
- [x] AC-WIN-001 Service runtime via SCM + console fallback (`docs/windows-nac-edr-mdm-acceptance.md`)
- [x] AC-WIN-002 Windows defaults/inventory path correctness
- [x] AC-WIN-003 Windows NAC network profile apply path
- [x] AC-WIN-004 Windows isolate/unisolate command execution
- [x] AC-WIN-005 Windows MDM command execution (lock/restart/forensics/restore)
- [x] AC-WIN-006 Cross-platform MDM path hygiene (no Linux hardcoded marker path)
- [x] AC-WIN-007 NAC install-target/channel contract for Windows endpoint
- [x] AC-WIN-008 Release workflow emits `.exe` + `.msi` Windows artifacts
- [x] AC-WIN-009 Regression tests/contracts green

## Review
- Implemented Windows SCM-aware runtime entry path in `crates/agent-core/src/main.rs` using `windows-service` and retained console fallback (`EGUARD_WINDOWS_CONSOLE=1`).
- Removed Linux-hardcoded runtime assumptions in inventory/control paths (`crates/agent-core/src/lifecycle/inventory.rs`, marker path handling in command pipeline, platform-aware network profile default path).
- Added Windows command execution for isolate/unisolate/forensics/restore/app-management/device lock+restart in `crates/agent-core/src/lifecycle/command_pipeline.rs`.
- Added Windows NAC install target detection and endpoint mapping in `crates/nac/src/policy.rs`, with updated tests and channel contract updates.
- Updated release workflow to produce and publish Windows `.exe` + `.msi` + bootstrap script artifacts (`.github/workflows/release-agent.yml`) and parameterized MSI version (`installer/windows/eguard-agent.wxs`).
- Added explicit acceptance criteria in `docs/windows-nac-edr-mdm-acceptance.md`.
- Validation run:
  - `cargo test -p nac` ✅
  - `cargo test -p platform-windows` ✅
  - `cargo test -p agent-core command_pipeline::tests -- --nocapture` ✅
  - `cargo test -p agent-core lifecycle::tests_pkg_contract::distribution_channels_cover_server_repo_manual_and_github_release -- --exact` ✅
  - `bash scripts/check_agent_core_windows_xwin.sh` ✅

---

# macOS NAC+EDR+MDM parity (replace stub behavior with real handlers)

## Plan
- [x] 1) Replace `platform-macos` ESF stub behavior with a real event backend stack (eslogger ingestion + replay + process polling fallback) and typed event normalization.
- [x] 2) Implement concrete macOS NAC profile application flow in `platform-macos` and wire `agent-core` `config_change` command path to macOS-specific executor.
- [x] 3) Implement macOS host isolate/unisolate + quarantine restore + forensics command execution in `agent-core` command pipeline using `platform-macos::response`.
- [x] 4) Implement macOS MDM app-management command execution path (`brew`-based install/remove/update with input validation) instead of Linux `apt-get` fallback.
- [x] 5) Extend NAC install-target detection/contracts to include macOS install channel and update packaging channel contract tests.
- [x] 6) Add/adjust tests for parser logic, NAC target mapping, and packaging contracts; run targeted validation and document review.

## Acceptance Criteria
- [x] AC-MAC-001 ESF backend no longer hardcoded-empty; emits normalized `RawEvent` values from at least one concrete backend path.
- [x] AC-MAC-002 `config_change` network profile command on macOS executes a macOS-specific profile apply flow (not Linux NetworkManager file drop).
- [x] AC-MAC-003 `isolate`/`unisolate`/`restore_quarantine`/`forensics` commands execute concrete macOS implementations in `agent-core`.
- [x] AC-MAC-004 App management on macOS uses a macOS command path with sanitized inputs (no Linux package-manager fallback).
- [x] AC-MAC-005 NAC install target detection includes macOS user agents and returns `/api/v1/agent-install/macos` channel.
- [x] AC-MAC-006 Packaging channel contract lists macOS install channel entry.
- [x] AC-MAC-007 Targeted tests green for updated macOS/NAC/package contracts.

## Review
- Replaced `platform-macos` ESF collector stub with a real backend stack in `crates/platform-macos/src/esf/mod.rs`: replay backend (`EGUARD_ESF_REPLAY_PATH`), `eslogger --json` ingestion path, and process-poll fallback when ES entitlements/tools are unavailable.
- Added JSON event normalization helpers that map ES-style event payloads into shared `RawEvent`/`EventType` contracts and emit key-value payloads compatible with existing enrichment pipeline.
- Added macOS NAC network profile executor in `crates/platform-macos/src/response/network_profile.rs` and wired `agent-core` `config_change` handling to this macOS-specific path.
- Implemented macOS command handlers in `crates/agent-core/src/lifecycle/command_pipeline.rs` for isolate/unisolate, restore quarantine, forensics snapshot capture, app management via `brew`, and mobileconfig profile install attempts via `profiles`.
- Extended NAC install target detection to macOS in `crates/nac/src/policy.rs` and updated contracts/tests/channels (`crates/nac/tests/captive_portal.rs`, `packaging/repositories/channels.txt`, `crates/agent-core/src/lifecycle/tests_pkg_contract.rs`).
- Updated launchd plist generator process type to `Background` in `crates/platform-macos/src/service/plist.rs`.
- Validation run:
  - `cargo test -p platform-macos` ✅
  - `cargo test -p nac` ✅
  - `cargo test -p agent-core command_pipeline::tests -- --nocapture` ✅
  - `cargo test -p agent-core lifecycle::tests_pkg_contract::distribution_channels_cover_server_repo_manual_and_github_release -- --exact` ✅
  - `cargo check -p agent-core` ✅
  - `cargo check -p platform-macos --target aarch64-apple-darwin` ⚠️ target stdlib not installed (`rustup target add aarch64-apple-darwin` required)

---

# command_pipeline SOLID refactor + LOC cap (agent-core)

## Plan
- [x] 1) Baseline current `command_pipeline.rs` responsibilities and split points (dispatch, payload parsing, sanitization, platform command execution, helpers, tests).
- [x] 2) Extract cohesive helper modules under `crates/agent-core/src/lifecycle/command_pipeline/` and keep `command_pipeline.rs` as orchestration-focused façade.
- [x] 3) Preserve behavior for all command handlers (emergency/config/isolate/quarantine/forensics/MDM/app/profile) while reducing `command_pipeline.rs` to <=500 LOC.
- [x] 4) Update/relocate command-pipeline unit tests so sanitizer/parser behavior remains covered after refactor.
- [x] 5) Run formatting + tests (at minimum command-pipeline tests and crate tests) and record verification results here.

## Review
- Refactored `crates/agent-core/src/lifecycle/command_pipeline.rs` into a thin orchestration façade (224 LOC) with command dispatch + ACK/reporting, while moving detailed responsibilities into focused submodules:
  - `crates/agent-core/src/lifecycle/command_pipeline/handlers.rs`
  - `crates/agent-core/src/lifecycle/command_pipeline/app_management.rs`
  - `crates/agent-core/src/lifecycle/command_pipeline/command_utils.rs`
  - `crates/agent-core/src/lifecycle/command_pipeline/paths.rs`
  - `crates/agent-core/src/lifecycle/command_pipeline/payloads.rs`
  - `crates/agent-core/src/lifecycle/command_pipeline/sanitize.rs`
  - `crates/agent-core/src/lifecycle/command_pipeline/windows_network_profile.rs` (Windows-specific)
  - `crates/agent-core/src/lifecycle/command_pipeline/tests.rs`
- Preserved behavior for emergency-rule push, config-change network profile handling, isolate/unisolate, restore quarantine, forensics, MDM actions, app actions, and profile application with existing platform-specific branches.
- Validation run:
  - `wc -l crates/agent-core/src/lifecycle/command_pipeline.rs` → `224` ✅ (<=500 LOC)
  - `cargo fmt --all` ✅
  - `cargo test -p agent-core command_pipeline::tests -- --nocapture` ✅
  - `cargo test -p agent-core` ✅
  - `cargo test --workspace` ✅

---

# Windows platform hardening + E2E-audit round (MDM/NAC/EDR)

## Plan
- [x] 1) Baseline `crates/platform-windows/` quality gates: run targeted tests/checks and collect current warnings/hotspots.
- [x] 2) Perform static audit across ETW/inventory/response/service/self-protect modules for reliability + security hardening opportunities.
- [x] 3) Implement focused code hardening/polish fixes with minimal blast radius, prioritizing input validation, error handling, and safe defaults.
- [x] 4) Add/expand unit tests for newly hardened paths and regression-prone behavior.
- [x] 5) Run verification (`fmt`, targeted tests/checks) and document concrete review findings + residual E2E gaps.

## Acceptance Criteria
- [x] AC-WIN-HARDEN-001 No new clippy/test regressions in touched crates.
- [x] AC-WIN-HARDEN-002 Hardened code paths have explicit tests or rationale for why not testable locally.
- [x] AC-WIN-HARDEN-003 Audit summary includes risk findings, applied remediations, and remaining E2E-on-Windows actions.

## Review
- Audit findings (high impact):
  - **PATH hijack risk**: privileged subprocesses used bare command names (`powershell`, `netsh`, `taskkill`, `sc.exe`, `reg`, etc.), enabling executable search-order abuse.
  - **Isolation allowlist fragility**: `isolate_host()` accepted raw strings (including invalid/empty entries) and could leave partial firewall state on mid-sequence errors.
  - **WFP rule input trust**: remote IP/CIDR and description fields were not normalized/sanitized before `netsh` usage.
  - **Service install idempotency edge**: `install()` treated all `sc query` failures as “service missing”, masking permission/runtime errors.
  - **Registry value parsing ambiguity**: prefix matching (`starts_with`) could read wrong keys (e.g., `ProductNameEx` vs `ProductName`).
- Applied hardening/polish:
  - Added canonical Windows system binary paths in `crates/platform-windows/src/windows_cmd.rs` and switched command execution to absolute paths across compliance, enrichment, inventory, response, service, self-protect, and WFP modules.
  - Hardened host isolation in `crates/platform-windows/src/response/isolation.rs`:
    - strict IP/CIDR validation + normalization,
    - dedupe + bounded allowlist size,
    - explicit rejection of empty allowlists,
    - rollback cleanup on rule application failures.
  - Hardened WFP filter handling in `crates/platform-windows/src/wfp/filters.rs`:
    - remote IP/CIDR normalization (supports `any`),
    - description sanitization + length bounds,
    - duplicate cfg cleanup.
  - Hardened service lifecycle in `crates/platform-windows/src/service/lifecycle.rs`:
    - validate service name and binary path inputs,
    - distinguish “service not found” from other `sc query` errors,
    - preserve access-denied/error propagation.
  - Hardened registry parser in `crates/platform-windows/src/compliance/registry.rs` to require exact value-name match.
  - Polished clippy findings:
    - derived `Default` where appropriate,
    - simplified lazy option fallback and boolean comparison.
- Added/expanded tests:
  - isolation allowlist normalization/validation tests,
  - WFP remote IP normalization + description sanitization tests,
  - service lifecycle input validation + not-found detection tests,
  - registry prefix-mismatch regression test.
- Validation run:
  - `cargo fmt --all` ✅
  - `cargo test -p platform-windows` ✅ (66 passed)
  - `cargo clippy -p platform-windows --all-targets --all-features -- -D warnings` ✅
  - `cargo check -p platform-windows --target x86_64-pc-windows-msvc` ✅
  - `cargo check -p agent-core` ✅
- Remaining E2E-on-Windows actions (cannot fully prove from Linux CI host):
  - validate service install/start/stop/recovery against real SCM + admin/UAC contexts,
  - execute real host isolation/unisolation and confirm management-server reachability during isolation,
  - run live ETW + response command cycle (forensics/quarantine/isolation) on Windows host,
  - run signed-binary integrity/authenticode checks on release-signed artifacts.

---

# Windows E2E validation checklist doc

## Plan
- [x] 1) Create a single executable checklist document for Windows MDM/NAC/EDR E2E validation.
- [x] 2) Include environment preconditions, command-level verification checkpoints, and evidence capture fields.
- [x] 3) Add pass/fail sign-off + failure template so QA can run and report consistently.

## Review
- Added `tasks/windows-e2e-validation-checklist.md` with a full, checkable runbook covering:
  - preflight and bootstrap correctness guardrails,
  - build/package gates,
  - install/service lifecycle,
  - enrollment/control-plane,
  - EDR telemetry+detection,
  - response/quarantine/forensics,
  - NAC + host isolation,
  - MDM actions,
  - self-protect hardening checks,
  - resilience + soak validation,
  - final sign-off + failure report template.

---

# Live 3-VM E2E validation + Endpoint Inventory UX enrichment

## Plan
- [ ] 1) Baseline all three VMs (server, Linux endpoint, Windows endpoint): connectivity, service health, and existing deployment state.
- [ ] 2) Execute safe E2E enrollment and telemetry validation flow (Linux + Windows) against eGuard server, including threat-intel ingestion from GitHub pipeline artifacts.
- [ ] 3) Run MDM and EDR response-command test matrix (safe simulation only), capture evidence/logs, and identify edge cases/bugs.
- [ ] 4) Implement endpoint inventory enhancements in PacketFence fork UI/API: advanced hardware filters (CPU/RAM/HDD), hostname/domain-join/status filters, intuitive UX, CSV export.
- [ ] 5) Build and deploy updated server/frontend artifacts to server VM, validate in-browser (admin UI), and verify telemetry + inventory workflows end-to-end.
- [ ] 6) Update `docs/operations-guide.md` with tested runbook steps, environment-specific findings, fixed issues, and residual gaps.

## Acceptance Criteria
- [ ] AC-E2E-001 Linux and Windows agents enroll from fresh/bootstrap flow and appear in endpoint inventory.
- [ ] AC-E2E-002 Telemetry events and command acknowledgements are visible in server UI and API.
- [ ] AC-E2E-003 MDM command matrix and EDR-safe simulations are executed with documented PASS/FAIL evidence.
- [ ] AC-E2E-004 Endpoint inventory supports filtering by CPU/RAM/HDD + hostname + join-domain status and supports CSV export.
- [ ] AC-E2E-005 Updated build artifacts are deployed on server VM and verified from live UI.
- [ ] AC-E2E-006 Operations guide reflects exact tested commands/procedures and troubleshooting notes.

---

# Operations guide update: Endpoint Audit inline details + whitelist UX

## Plan
- [x] 1) Document the Endpoint Audit UX rollout scope (inline details, response labeling, whitelist actions).
- [x] 2) Record deployment evidence (backup path, dist deployment target) from live VM rollout.
- [x] 3) Record browser smoke validation outcomes and rollback steps in operations guide.

## Review
- Added **Appendix F** to `docs/operations-guide.md`: `Endpoint Audit Inline Details + Whitelist UX (Feb 2026)`.
- Captured rollout evidence:
  - backup: `/usr/local/eg/var/backups/audit-ui-inline-20260228165204`
  - deployment target: `/usr/local/eg/html/egappserver/root/dist/`
- Captured browser validation outcomes on live server (`103.49.238.102:1443`) including:
  - inline audit row expansion behavior,
  - readable response badges,
  - audit-driven whitelist creation flow,
  - endpoint whitelist nav visibility + route reachability.
- Added rollback procedure for restoring previous dist backup.

---

# NAC operations manual update (debrand PF -> eGuard NAC enforcer)

## Plan
- [x] 1) Update `docs/nac-edr-operations-manual.md` to reflect new NAC enforcer architecture (`local` default, optional `http` compatibility mode).
- [x] 2) Replace PF-bridge-specific operational guidance with debranded NAC-enforcer instructions, env vars, and troubleshooting.
- [x] 3) Add latest live validation notes for GUI isolate/allow/status flow under local mode.

## Review
- Updated manual version to 1.2 and validation context to local-enforcer mode.
- Reworked architecture + config sections to use `NACEnforcer` model and `EGUARD_NAC_*` env vars.
- Kept explicit legacy compatibility note for `EGUARD_PF_*` fallback.
- Updated troubleshooting and known limitations to local/http mode behavior and removed PF-branded language.
- Added live validation summary (GUI isolate/allow/status + server log confirmation).

---

# fe_eguard NAC local-only cleanup (remove HTTP/PF bridge path)

## Plan
- [x] 1) Remove HTTP enforcer implementation (`nac_pf_bridge.go`) and legacy PF env-variable fallback from NAC enforcer selection.
- [x] 2) Restrict `newNACEnforcer()` to local (default) and disabled modes only, with explicit log when unsupported mode is requested.
- [x] 3) Run `go test ./...` for `go/agent/server` to verify no regressions.
- [x] 4) Update review notes and lessons learned for topology assumptions (same-host guaranteed).

## Review
- Removed file: `/home/dimas/fe_eguard/go/agent/server/nac_pf_bridge.go`.
- Updated `/home/dimas/fe_eguard/go/agent/server/nac_enforcer.go`:
  - removed HTTP mode and legacy `EGUARD_PF_BRIDGE_ENABLED` fallback,
  - mode handling is now local-only by default with optional explicit `disabled`.
  - unsupported mode values now log and force `local`.
- Verification:
  - `cd /home/dimas/fe_eguard/go/agent/server && go test ./...` ✅
  - `cd /home/dimas/fe_eguard/go/cmd/eg-agent-server && go test ./...` ✅ (compile check)
- Synced operator doc to local-only contract: updated `/home/dimas/eguard-agent/docs/nac-edr-operations-manual.md` to remove HTTP/split-host/legacy PF variable guidance.

---

# Human-like GUI re-validation after NAC local-only cleanup

## Plan
- [x] 1) Re-run backend sanity checks for server package (`go test ./...`) to confirm local-only enforcer compiles and passes.
- [x] 2) Execute browser-driven (human-like) NAC workflow in live GUI: login → select endpoint → isolate → status verify → allow → status verify.
- [x] 3) Spot-check adjacent endpoint UX impacted by recent rollout (Audit inline details + Inventory filters page loads) to ensure no regressions.
- [x] 4) Capture fresh validation evidence screenshot(s) and summarize outcomes/errors in review notes.

## Review
- Backend sanity:
  - `cd /home/dimas/fe_eguard/go/agent/server && go test ./...` ✅
- Human-like GUI NAC validation (live server `https://103.49.238.102:1443/admin`):
  - login as `admin`
  - route: `/admin#/endpoint-nac`
  - selected `eg-agent (agent-31bbb93f38b4)`
  - manual isolate with reason `human-like revalidation isolate` → banner: `Node isolated — security event applied`
  - status check → `NAC Status: 🔒 ISOLATED ... Open events: Malware Detected`
  - manual allow with reason `human-like revalidation allow` → banner: `Node allowed — all eGuard security events closed`
  - final status check → `NAC Status: ✅ ALLOWED ... No open security events`
- Adjacent UX regression spot-checks:
  - `/admin#/endpoint-audit` inline row details toggle works (`▶` → `▼`) and whitelist controls remain visible.
  - `/admin#/endpoint-inventory` loads advanced filters (OS Platform / OS Type / OS Version / Domain Join / CPU/RAM/Disk dropdowns) and inventory table correctly.
- Evidence screenshots:
  - `/tmp/nac-local-only-human-validate-20260228.png`
  - `/tmp/audit-inline-revalidate-20260228.png`
  - `/tmp/inventory-filters-revalidate-20260228.png`

---

# NAC operations manual refresh (post re-validation)

## Plan
- [x] 1) Update `docs/nac-edr-operations-manual.md` version/validation metadata after local-only cleanup and human-like GUI re-test.
- [x] 2) Refresh validation narrative with exact isolate/status/allow outcomes and evidence artifact paths.
- [x] 3) Align navigation/config/troubleshooting text with current local-only runtime behavior.

## Review
- Updated `/home/dimas/eguard-agent/docs/nac-edr-operations-manual.md`:
  - version bumped to `1.3` with latest validation context.
  - latest validation block now includes exact GUI outcomes + screenshot artifacts.
  - NAC page direct URL normalized to `/admin#/endpoint-nac`.
  - config section clarifies unsupported enforcer mode values are forced to `local`.
  - troubleshooting expected logs updated to include forced-local warning + local enable message.

---

# Baseline+ML production wiring acceptance criteria draft

## Plan
- [x] 1) Define production-ready acceptance criteria for baseline loop wiring (agent learn → upload → fleet aggregate → seed consume).
- [x] 2) Add explicit acceptance criteria for storage strategy (agent local snapshot/journal + server fleet retention/compaction).
- [x] 3) Publish criteria in a dedicated doc for engineering sign-off.

## Review
- Added `/home/dimas/eguard-agent/docs/baseline-ml-production-acceptance.md` with measurable AC IDs covering:
  - end-to-end baseline data flow,
  - local-only safe response behavior during learning,
  - fleet seeding and shard application,
  - storage efficiency and retention,
  - rollout safety (canary/kill-switch),
  - observability and regression gates.

---

# Baseline+ML production wiring implementation (including workflow bundle ingestion)

## Plan
- [x] 1) Wire agent baseline upload path (batched) and schedule it in control-plane pipeline.
- [x] 2) Wire agent fleet-baseline fetch/apply path in runtime learning loop and re-seed anomaly shards after apply.
- [x] 3) Extend server baseline API for efficient batch ingest and workflow bundle fleet-baseline import.
- [x] 4) Align auth scopes so agent token can post baselines and fetch fleet baselines.
- [x] 5) Persist baseline entropy/expiry fields in DB path and validate via tests.
- [x] 6) Run verification tests across Rust + Go.

## Review
- Agent/runtime wiring (`/home/dimas/eguard-agent`):
  - Added control-plane tasks: `BaselineUpload`, `FleetBaselineFetch`.
  - Added periodic upload/fetch intervals + batch size constants.
  - Baseline dirty-key tracking now marks per-process keys during `observe_baseline()` and uploads changed profiles in bounded batches.
  - Added client API: `send_baseline_profiles()` and HTTP path `/api/v1/endpoint/baseline/batch`.
  - Fleet baseline seeds are now applied in runtime (not test-only), persisted, and pushed to anomaly shards.
- Server wiring (`/home/dimas/fe_eguard`):
  - Added endpoint: `POST /api/v1/endpoint/baseline/batch` (agent batched baseline ingest).
  - Added endpoint: `POST /api/v1/endpoint/baseline/fleet/import` (workflow/database bundle ingestion).
  - Added normalization/validation for baseline distributions and robust upsert flow.
  - Updated auth scope classification:
    - agent POST allowed for `/api/v1/endpoint/baseline` and `/api/v1/endpoint/baseline/batch`.
    - agent/admin GET allowed for `/api/v1/endpoint/baseline/fleet`.
  - Updated DB persistence to store/load `entropy_threshold` and `expires_at` for endpoint baselines.
- Acceptance criteria/doc update:
  - Added workflow ingestion criterion `AC-BML-024` to `/home/dimas/eguard-agent/docs/baseline-ml-production-acceptance.md`.
- Verification:
  - `cd /home/dimas/fe_eguard/go/agent/server && go test ./...` ✅
  - `cd /home/dimas/fe_eguard/go/cmd/eg-agent-server && go test ./...` ✅
  - `cd /home/dimas/eguard-agent && cargo test -p grpc-client` ✅
  - `cd /home/dimas/eguard-agent && cargo test -p agent-core` ✅

---

# Baseline+ML acceptance completion pass (no-stub storage + workflow bundle path)

## Plan
- [x] 1) Implement real baseline journaled storage (snapshot + append journal + replay/compaction) with crash-safe tail handling.
- [x] 2) Make runtime baseline windows config-driven and enforce bounded baseline profile cardinality.
- [x] 3) Enforce payload-size bounded baseline upload and strengthen seed merge policy (weak-local only, protect mature-local).
- [x] 4) Add runtime kill-switch flags for baseline upload/fleet-seed via policy JSON fields.
- [x] 5) Remove CI placeholder aggregation script and emit real workflow fleet baseline bundle artifact.
- [x] 6) Persist fleet baseline provenance (`source`, `source_version`) with backward-compatible DB fallback paths.
- [x] 7) Re-run full verification suite.

## Review
- Agent storage/runtime (`/home/dimas/eguard-agent`):
  - `crates/baseline/src/lib.rs`
    - Added append journal (`*.journal`) + metadata sidecar (`*.journal.meta`).
    - Added checksum-validated replay and corrupted-tail truncation behavior (ignore invalid tail line, continue from last valid seq).
    - Added journal compaction trigger (age/size based).
    - Added profile cap + LRU eviction.
    - Added weak-local fleet seed strengthening while protecting mature local profiles from overwrite.
  - `crates/agent-core/src/lifecycle/runtime.rs`
    - Baseline windows now configured from agent config (`baseline_learning_period_days`, `baseline_stale_after_days`).
    - Added max-profile runtime limit from env (`EGUARD_BASELINE_MAX_PROFILES`).
    - Added runtime flags: `baseline_upload_enabled`, `fleet_seed_enabled`.
  - `crates/agent-core/src/lifecycle/control_plane_pipeline.rs`
    - Upload/fetch scheduling now respects runtime flags.
    - Added policy-driven live toggles from policy JSON:
      - `baseline_upload_enabled`
      - `fleet_seed_enabled`
    - Added payload cap for upload (`BASELINE_UPLOAD_MAX_BYTES`), with profile truncation/chunking behavior.
  - Added/updated tests:
    - `crates/baseline/src/tests.rs`
    - `crates/baseline/src/tests_seed.rs`
    - `crates/agent-core/src/lifecycle/tests_baseline_seed_policy.rs`
- Workflow path (`/home/dimas/eguard-agent`):
  - Replaced placeholder script with working median aggregation:
    - `scripts/run_baseline_aggregation_ci.sh`
  - Added fixture:
    - `scripts/fixtures/baseline-ci-input.json`
  - Artifact now includes:
    - `artifacts/baseline-aggregation/fleet-baseline-bundle.json`
    - `artifacts/baseline-aggregation/summary.txt`
- Server provenance + compatibility (`/home/dimas/fe_eguard`):
  - `go/agent/server/types.go`: added `source_version` on `FleetBaselineRecord`.
  - `go/agent/server/baseline.go`:
    - Fleet import now supports `source`, `bundle_version`, `bundle_sha256` provenance mapping.
    - Aggregation median output normalized to sum ~1.0.
  - `go/agent/server/persistence_endpoint_data.go`:
    - Save/load now includes `source` + `source_version`.
    - Added legacy-schema fallback for DBs missing new columns (Unknown column fallback).
  - `db/eg-schema-15.0.sql`:
    - Added `fleet_baseline.source`, `fleet_baseline.source_version`, and source index.
  - `lib/eg/dal/fleet_baseline.pm` + `lib/eg/egcron/task/baseline_aggregation.pm`:
    - Added source/source_version field awareness and write path.
    - Added stale endpoint baseline pruning in aggregation cycle.
- Acceptance doc update:
  - `docs/baseline-ml-production-acceptance.md` bumped to v1.1 with implementation status and verification evidence.
- Verification:
  - `cd /home/dimas/eguard-agent && cargo test -p baseline` ✅
  - `cd /home/dimas/eguard-agent && cargo test -p grpc-client` ✅
  - `cd /home/dimas/eguard-agent && cargo test -p agent-core` ✅
  - `cd /home/dimas/fe_eguard/go/agent/server && go test ./...` ✅
  - `cd /home/dimas/fe_eguard/go/cmd/eg-agent-server && go test ./...` ✅
  - `cd /home/dimas/eguard-agent && ./scripts/run_baseline_aggregation_ci.sh` ✅
- Follow-up completion pass (same acceptance scope):
  - Added runtime baseline observability counters (uploaded rows, seeded rows, payload rejects, stale transitions).
  - Added `EGUARD_BASELINE_UPLOAD_MAX_BYTES` override + deterministic oversized payload reject test.
  - Added gRPC heartbeat fleet-baseline response wiring (removed `FleetBaseline: nil` stub path when fleet data exists).
  - Added end-to-end server test for upload→aggregate→fleet-fetch and expanded GRPC integration assertion for non-empty fleet baseline payload.

---

# ML optimization program (goal: best-in-class SOC performance)

## Plan
- [ ] 1) Define measurable head-to-head targets in our context (precision/recall, PR-AUC, FPR/day, MTTD, explainability quality) instead of vendor-name claims.
- [ ] 2) Build an offline benchmark harness from replay corpora + adversarial simulations and establish current baseline metrics.
- [ ] 3) Improve model pipeline in three tracks: feature quality, calibration/thresholding, and ensemble fusion robustness.
- [ ] 4) Add SOC explainability outputs for every ML alert (top features, process chain, ATT&CK context, baseline delta reason, confidence band).
- [ ] 5) Add safe rollout controls (shadow mode, 1/5/20/100 canary, rollback/kill switch) and automated regression gates.
- [ ] 6) Validate on lab endpoints + production-like replay, then document evidence in `docs/baseline-ml-production-acceptance.md` and `docs/operations-guide.md`.

## Check-in
- Plan written. Awaiting approval before implementation per workflow rule.

---

# Baseline+ML completion pass (grpc fleet cache + shard bulk apply + E2E loop test)

## Plan
- [x] 1) Remove HTTP-only dependency for fleet seed fetch in gRPC mode by caching fleet baselines from heartbeat responses.
- [x] 2) Optimize L3 seed propagation by applying anomaly baselines to shards in bulk instead of per-key RPC loops.
- [x] 3) Strengthen agent baseline persistence observability with compaction-aware size/reclaim stats in logs.
- [x] 4) Add end-to-end test for learn/upload/fetch/seed path in agent-core lifecycle tests.
- [x] 5) Re-verify Rust/Go test suites.

## Review
- Updated `crates/grpc-client`:
  - gRPC heartbeat now caches `fleet_baseline` rows in client state.
  - `fetch_fleet_baselines()` in gRPC mode now returns cached heartbeat fleet rows.
  - Added test: `fetch_fleet_baselines_grpc_uses_cached_heartbeat_fleet_report`.
- Updated `crates/agent-core`:
  - `SharedDetectionState` now supports `set_anomaly_baselines_bulk` for atomic shard fanout in one command per shard.
  - `seed_anomaly_baselines()` now uses bulk apply path.
  - `BaselineStore` adds storage stats (`snapshot/journal size`, `compaction_count`, `last_compaction_reclaimed_bytes`).
  - Runtime baseline save logs now emit compaction-aware structured stats.
  - Added integration-style lifecycle test: `baseline_e2e_upload_fetch_seed_flow_works`.
- Updated acceptance doc:
  - `docs/baseline-ml-production-acceptance.md` bumped to v1.3 with grpc-cache + e2e evidence notes.
- Verification:
  - `cd /home/dimas/eguard-agent && cargo test -p baseline` ✅
  - `cd /home/dimas/eguard-agent && cargo test -p grpc-client` ✅
  - `cd /home/dimas/eguard-agent && cargo test -p agent-core` ✅
  - `cd /home/dimas/fe_eguard/go/agent/server && go test ./...` ✅
  - `cd /home/dimas/fe_eguard/go/cmd/eg-agent-server && go test ./...` ✅

---

# Baseline+ML rollout hardening pass (canary gates + shard bulk + persistence observability)

## Plan
- [x] 1) Add canary rollout gates for upload/fleet-seed paths (env + policy overrides).
- [x] 2) Remove per-key shard fanout overhead by applying anomaly baselines in bulk.
- [x] 3) Add baseline compaction-aware persistence stats and structured logs.
- [x] 4) Add agent-core end-to-end + canary-disable test coverage.
- [x] 5) Re-run baseline/grpc-client/agent-core/server tests.

## Review
- `crates/agent-core/src/lifecycle/runtime.rs`
  - Added runtime canary config fields:
    - `baseline_upload_canary_percent`
    - `fleet_seed_canary_percent`
  - Added env parsing:
    - `EGUARD_BASELINE_UPLOAD_CANARY_PERCENT`
    - `EGUARD_FLEET_SEED_CANARY_PERCENT`
- `crates/agent-core/src/lifecycle/control_plane_pipeline.rs`
  - Added deterministic agent-id bucket rollout helper for canary gating.
  - Upload/fetch due checks now enforce canary percent gates.
  - Policy JSON supports live canary updates:
    - `baseline_upload_canary_percent`
    - `fleet_seed_canary_percent`
- `crates/agent-core/src/detection_state.rs` + `crates/agent-core/src/lifecycle/baseline.rs`
  - Added `set_anomaly_baselines_bulk()` and switched baseline seeding to bulk shard apply.
- `crates/baseline/src/lib.rs` + `crates/agent-core/src/lifecycle/response_actions.rs`
  - Added `BaselineStorageStats` (snapshot/journal sizes, compaction_count, reclaimed bytes).
  - Baseline persistence logs now include compaction-aware stats.
- `crates/agent-core/src/lifecycle/tests_baseline_seed_policy.rs`
  - Added:
    - `baseline_upload_canary_zero_disables_upload_path`
    - `fleet_seed_canary_zero_disables_fetch_path`
    - `baseline_e2e_upload_fetch_seed_flow_works`
- `docs/operations-guide.md`
  - Added env + policy docs for canary rollout fields.
- `docs/baseline-ml-production-acceptance.md`
  - bumped to v1.4 and updated implementation/validation notes.
- Verification:
  - `cd /home/dimas/eguard-agent && cargo test -p baseline` ✅
  - `cd /home/dimas/eguard-agent && cargo test -p grpc-client` ✅
  - `cd /home/dimas/eguard-agent && cargo test -p agent-core` ✅
  - `cd /home/dimas/fe_eguard/go/agent/server && go test ./...` ✅
  - `cd /home/dimas/fe_eguard/go/cmd/eg-agent-server && go test ./...` ✅

---

# Lab production-readiness validation (server + linux agent + windows)

## Plan
- [x] 1) Build latest artifacts locally (`eg-agent-server` binary, frontend dist, linux `eguard-agent` binary).
- [x] 2) Deploy to eGuard server VM (`103.49.238.102`) with backups and service restart.
- [x] 3) Deploy linux agent binary to agent VM (`103.183.74.3`) and restart service.
- [x] 4) Execute baseline loop simulation (high-cardinality process activity -> upload -> aggregate -> fleet seed consume) and collect log/DB evidence.
- [x] 5) Validate MDM/EDR operator flows in GUI via agent-browser (human-like checks + screenshots).
- [x] 6) Run cross-host smoke checks (linux + windows endpoint visibility/heartbeat) and summarize confidence gaps.

## Review
- Build/deploy:
  - Built:
    - `/tmp/eg-agent-server.new`
    - `/tmp/egapp-dist.tgz`
    - `/home/dimas/eguard-agent/target/release/agent-core`
  - Deployed to server:
    - binary: `/usr/local/eg/sbin/eg-agent-server` (sha256 matches local build)
    - frontend: `/usr/local/eg/html/egappserver/root/dist` (`last-modified: 2026-02-28 14:44:45 GMT`)
    - services: `eguard-agent-server` + `eguard-api-frontend` active
  - Deployed to linux agent:
    - binary: `/usr/bin/eguard-agent` (sha256 matches local build)
    - service: `eguard-agent` active
  - Follow-up production parity fix:
    - rebuilt linux agent with `--features platform-linux/ebpf-libbpf` after validation uncovered `feature 'ebpf-libbpf' is disabled` warning.
    - post-redeploy logs confirm probes attached (`objects=9 attached=9`) and runtime eBPF initialization success.

- Baseline production-loop validation evidence:
  - Upload path observed in live agent logs:
    - `uploaded baseline profile batch ...`
  - Server ingest + aggregation live-run:
    - POST `/api/v1/endpoint/baseline/batch` for 3 synthetic agents
    - POST `/api/v1/endpoint/baseline/aggregate` => `aggregated: 2`
    - GET `/api/v1/endpoint/baseline/fleet?limit=20` => 2 `fleet_aggregated` rows
  - gRPC fleet-seed consume validated with canary policy flip:
    - live policy update log: `updated fleet-seed canary percent from policy fleet_seed_canary_percent=100`
    - live seed-apply log: `applied fleet baseline seed profiles ... seeded_profiles=1`
  - DB evidence:
    - `fleet_baseline` rows present (`python3:bash`, `powershell.exe:services.exe`)
    - seeded key uploaded back into endpoint baseline rows for `agent-31bbb93f38b4`

- GUI/operator validation (agent-browser, human-like):
  - Inventory page: `/admin#/endpoint-inventory`
    - screenshot: `/tmp/inventory-prodready-20260228.png`
    - body dump confirms latest windows entries now `Windows Server 2019 Standard 1809` (legacy `Windows (AMD64)` remains only in historical rows).
  - NAC page: `/admin#/endpoint-nac`
    - isolate/status screenshot: `/tmp/nac-isolated-prodready-20260228.png`
    - allow/status screenshot: `/tmp/nac-allowed-prodready-20260228.png`
    - body dump confirms `NAC Status: ✅ ALLOWED`
  - Audit page: `/admin#/endpoint-audit`
    - inline row expansion validated (`▶` -> `▼`)
    - screenshot: `/tmp/audit-inline-prodready-20260228.png`
  - Whitelist page smoke:
    - screenshot: `/tmp/whitelist-prodready-20260228.png`

- Cross-host smoke:
  - Linux agent inventory row current and healthy (`agent-31bbb93f38b4`, `eg-agent`).
  - Windows endpoint current in inventory (`agent-4412`, `Windows Server 2019 Standard 1809`).
  - Windows service health checked via SSH/PowerShell (`eGuardAgent` running) and telemetry send lines observed in `C:\ProgramData\eGuard\logs\agent.log`.

- Cleanup after canary validation:
  - Linux override returned to original skip-learning setting (`EGUARD_BASELINE_SKIP_LEARNING=1`).
  - temporary fleet canary env override removed from service override file.
  - agent policy assignment restored to `default` for `agent-31bbb93f38b4`.

- Remaining production-readiness gaps observed in lab (non-baseline wiring):
  - Linux agent logs still report threat-intel bundle signature/count mismatch on existing staged bundle (`/var/lib/eguard-agent/rules-staging/2026.02.19.1131.bundle.tar.zst`).
  - Linux agent runs without mTLS files in this lab (`/etc/eguard-agent/tls/agent.crt` missing), so transport is currently non-mTLS.

---

# ML Ops operator manual authoring (master guide)

## Plan
- [x] 1) Consolidate implemented ML+baseline capabilities and operator controls into one dedicated manual.
- [x] 2) Write end-to-end runbook sections: deployment, canary, kill-switch, validation, rollback, troubleshooting, and evidence queries.
- [x] 3) Add AC-BML-oriented operational checklist + production readiness criteria for go-live signoff.
- [x] 4) Link the new manual from docs index for discoverability.

## Review
- Added new operator manual:
  - `docs/ml-ops-operations-manual.md`
- Manual content includes:
  - architecture and live wiring summary,
  - deployment/day-1 runbooks,
  - canary rollout playbook (0/1/5/20/100),
  - kill-switch and rollback playbook,
  - API/DB/log/UI evidence checklist,
  - dashboard/SLO signals,
  - troubleshooting matrix (including eBPF build parity, bundle signature mismatches, mTLS readiness),
  - production sign-off checklist + policy templates.
- Updated docs index:
  - `docs/README.md` now links `docs/ml-ops-operations-manual.md`.

---

# Production ML implementation pass (hardware-adaptive training)

## Plan
- [x] 1) Implement hardware-aware ML training planner in `signature_ml_train_model.py`.
- [x] 2) Add deterministic stratified downsampling to keep training stable on modest nodes (e.g., 4 vCPU / 6 GB).
- [x] 3) Wire effective training-plan telemetry into model/metadata artifacts for auditability.
- [x] 4) Update ML Ops manual with operational command and tuning behavior.
- [x] 5) Validate script syntax and execute end-to-end sample training run.

## Review
- Updated `threat-intel/processing/signature_ml_train_model.py`:
  - Added resource profiles: `tiny`, `modest`, `balanced`, `high` (+ `auto` detection).
  - Added host hardware detection (CPU + RAM) with Linux + portable fallback paths.
  - Added adaptive training-plan resolver for:
    - `max_iter`,
    - `holdout_ratio`,
    - `l2_grid_points`,
    - `max_samples`,
    - `cv_folds` (guarded to minimum 5).
  - Added deterministic stratified downsampling with `sample_id` hash ordering.
  - Added adaptive auto L2 grid shaping when explicit `--l2-grid` is not provided.
  - Added new CLI options:
    - `--resource-profile`
    - `--max-samples`
    - `--cv-folds`
    - `--l2-grid-points`
  - Added artifact diagnostics fields in model + metadata:
    - `resource_profile`, hardware detection, effective params, `sampled_from_rows`.
- Updated `docs/ml-ops-operations-manual.md`:
  - Added section `5.1 Nightly model retraining on modest hardware` with concrete command and behavior.

## Verification
- `python3 -m py_compile threat-intel/processing/signature_ml_train_model.py` ✅
- Synthetic end-to-end run with sampling and modest profile:
  - model + metadata generated successfully,
  - printed effective resource profile and training plan,
  - `training_samples` and `sampled_from_rows` reflected downsampling correctly. ✅

