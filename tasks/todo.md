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
- [ ] 1) Re-run backend sanity checks for server package (`go test ./...`) to confirm local-only enforcer compiles and passes.
- [ ] 2) Execute browser-driven (human-like) NAC workflow in live GUI: login → select endpoint → isolate → status verify → allow → status verify.
- [ ] 3) Spot-check adjacent endpoint UX impacted by recent rollout (Audit inline details + Inventory filters page loads) to ensure no regressions.
- [ ] 4) Capture fresh validation evidence screenshot(s) and summarize outcomes/errors in review notes.

