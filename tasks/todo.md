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
