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
- [ ] 1) Baseline `crates/platform-windows/` quality gates: run targeted tests/checks and collect current warnings/hotspots.
- [ ] 2) Perform static audit across ETW/inventory/response/service/self-protect modules for reliability + security hardening opportunities.
- [ ] 3) Implement focused code hardening/polish fixes with minimal blast radius, prioritizing input validation, error handling, and safe defaults.
- [ ] 4) Add/expand unit tests for newly hardened paths and regression-prone behavior.
- [ ] 5) Run verification (`fmt`, targeted tests/checks) and document concrete review findings + residual E2E gaps.

## Acceptance Criteria
- [ ] AC-WIN-HARDEN-001 No new clippy/test regressions in touched crates.
- [ ] AC-WIN-HARDEN-002 Hardened code paths have explicit tests or rationale for why not testable locally.
- [ ] AC-WIN-HARDEN-003 Audit summary includes risk findings, applied remediations, and remaining E2E-on-Windows actions.

## Review
- Pending
