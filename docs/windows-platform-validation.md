# Windows Platform Validation Snapshot

Date: 2026-02-20
Reference commit: `f88fde706155e110fc007d3c0bcf83bf778870cc`
Reference design: `/home/dimas/fe_eguard/docs/eguard-agent-design.md` (sections 30.1-30.12)
Reference AC: `/home/dimas/fe_eguard/docs/ACCEPTANCE_CRITERIA.md` (AC-WIN)

## Summary

Current codebase now provides **scaffolding-plus integration** Windows support:
- `crates/platform-windows` compiles and has ETW mapping/unit-test coverage, including replay-queue polling behavior and parser-backed process/network/user enrichment helpers for deterministic local validation.
- WFP scaffolding now includes deterministic filter lifecycle behavior (engine handle allocation, filter add/remove registry, host-isolation filter rollbacks) with Windows `netsh` rule wiring.
- Forensics scaffolding now includes command-backed minidump execution and parsed process-handle summary enrichment.
- `agent-core` includes a target-gated platform abstraction module (`src/platform.rs`) so Linux-only hard links are removed from the primary runtime path.
- Initial Windows response-action behavior now exists for process termination (`taskkill`), quarantine/restore path handling (timestamped quarantine buckets + metadata sidecar), and command-backed host-isolation rule orchestration (`netsh advfirewall`), replacing pure no-op stubs.
- `crates/response` now compiles for Windows targets via target-gated Unix dependencies/APIs and Windows-safe fallbacks in kill/quarantine helpers (Linux behavior retained with existing tests).
- Initial Windows service lifecycle command wiring now exists (`sc.exe` create/start/stop/delete + recovery policy setup) replacing pure no-op service stubs; lifecycle now includes deterministic service-state parsing/polling helpers.
- Initial Windows Event Log emission wiring now exists via `eventcreate` command path (info/warn/error + source registration helper), plus critical-detection event ID normalization into the 4000-4099 range.
- Initial Windows compliance probe wiring now exists for UAC, Firewall, Defender, BitLocker, Credential Guard, ASR, and update metadata using command/registry-backed parsing paths (with unit-tested parser coverage).
- Windows-focused Sigma coverage pack now exists for key ATT&CK patterns (PowerShell download cradle, Run-key persistence, LSASS dump/access, lateral movement/service exec, UAC bypass) with explicit `mitre_techniques` mapping metadata for benchmark accounting.
- Initial AMSI scanner behavior now includes deterministic script-pattern heuristics rather than always returning `NotDetected`.
- Initial self-protect behavior now includes explicit anti-debug signal handling, executable hash verification, and command-backed ACL hardening scaffolding.
- Initial Windows inventory wiring now exists for hardware/software/network snapshots via PowerShell/CIM parsing paths (unit-tested parser coverage).
- Remaining `TODO:` stubs in `crates/platform-windows/src` have been eliminated in this pass (`rg "TODO:" crates/platform-windows/src` returns no matches).

Full Windows runtime/service/MSI integration is still pending.
(A WiX MSI source scaffold now exists at `installer/windows/eguard-agent.wxs` and a bootstrap install script scaffold at `installer/windows/install.ps1`, but production build/sign/e2e validation is still open.)

## What is validated now

- `cargo check --target x86_64-pc-windows-msvc -p platform-windows` passes.
- `cargo test -p platform-windows` passes.
- `cargo check -p response` and `cargo test -p response` pass after Windows portability gating changes.
- `cargo check -p agent-core` passes with the new platform abstraction wiring.
- `./scripts/check_agent_core_windows_xwin.sh` passes on this Linux host (wrapper-assisted `cargo xwin check --cross-compiler clang --target x86_64-pc-windows-msvc -p agent-core`).
- Plain `cargo check --target x86_64-pc-windows-msvc -p agent-core` remains environment-sensitive on Linux hosts without explicit xwin/zig wrapper wiring.
- ETW codec unit tests validate canonical file-event mappings and Kernel-General -> ModuleLoad mapping.
- Windows benchmark artifact evaluator is now available via `scripts/run_windows_competitive_eval.py` with profile scaffold `benchmarks/competitive_profiles/windows-crowdstrike-parity.example.json`.
- Local benchmark artifact sample (`artifacts/detection-benchmark-windows/competitive-eval.json`) currently evaluates to `pass` for the profile's wall-clock + reference coverage checks (artifact-only signal; not a production claim).
- Windows enrichment tests validate payload metadata parsing for command-line/path and TCP endpoint attribution (`dst_ip`/`dst_port`) in `EnrichedEvent`.
- `platform-windows` parser/unit test suite currently passes with 39 tests (ETW codec/session/replay consumer behavior, AMSI registration/scanner guards, self-protect helpers, service lifecycle/eventlog helpers, enrichment process/network/user parsers, compliance parsers, inventory parsers, WFP filter lifecycle, forensics parser coverage).

## AC-WIN status (high level)

- **Partially addressed**:
  - AC-WIN-001 (platform crate compile target validation).
  - Platform abstraction blocker reduced via target-gated `agent-core/src/platform.rs` wiring (precondition toward AC-WIN phase progression).
  - Early groundwork for AC-WIN-002/010/040/041/042/043/080 via command-backed service lifecycle wrappers, process kill wrappers, quarantine/restore filesystem flow, event-log emission wrappers, WFP filter lifecycle scaffolding, and forensics command integration (still pending full native API hardening + Windows-host validation).
  - AC-WIN-028/077 benchmark-accounting posture improved via Windows Sigma technique coverage metadata and workflow artifact generation (`mitre-coverage.json`, `competitive-eval.json`), but this remains a **coverage signal** rather than full adversary-simulation proof.
- **In progress / not yet complete**: AC-WIN-002..090 (service install, ETW runtime hardening on real Windows host, response, AMSI/WFP enforcement, compliance probes, MSI lifecycle, E2E harness).

## Notes on CI workflow posture

- `release-agent-windows.yml` publishes **preview artifacts** (validation report + unsigned preview MSI built from `installer/windows/eguard-agent.wxs`) instead of claiming a full signed Windows agent package, and includes Windows-target `agent-core` compile/build validation.
- `detection-benchmark-windows.yml` validates `platform-windows` compile/tests plus Windows-target `agent-core` compile before benchmark steps, and now emits an artifact-only competitive evaluation verdict (`competitive-eval.json`) from benchmark + MITRE coverage artifacts.

## Next engineering step

Complete real Windows runtime parity on top of the new abstraction layer:
1. Replace ETW shim behavior with full event stream integration in live service mode.
2. Implement Windows service lifecycle + enrollment/bootstrap persistence flow.
3. Land WiX MSI assets/signing pipeline, then upgrade preview workflow to full release packaging.
