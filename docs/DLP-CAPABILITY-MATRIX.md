# eGuard DLP Capability Matrix

> Status: discovery baseline
> Scope: `fe_eguard` + `../eguard-agent`
> Rule: capability disebut **available** hanya jika ada implementasi dan jalur test yang dapat dijalankan.

## Evidence yang diperiksa

- Agent runtime/config: `../eguard-agent/crates/agent-core/src/config/types.rs`
- Agent lifecycle: `../eguard-agent/crates/agent-core/src/lifecycle.rs`
- Threat-intel bundle loading: `../eguard-agent/crates/agent-core/src/lifecycle/rule_bundle_loader.rs`
- Bundle signature verification: `../eguard-agent/crates/agent-core/src/lifecycle/rule_bundle_verify.rs`
- Hot reload: `../eguard-agent/crates/agent-core/src/lifecycle/threat_intel_pipeline/reload.rs`
- Tray bridge: `../eguard-agent/crates/agent-core/src/lifecycle/tray_integration.rs`
- Windows file enrichment/ETW: `../eguard-agent/crates/platform-windows/src/enrichment/file.rs`, `etw/`
- Linux eBPF: `../eguard-agent/crates/platform-linux/src/ebpf/`
- macOS ESF: `../eguard-agent/crates/platform-macos/src/esf/mod.rs`
- Existing event builders: `../eguard-agent/crates/agent-core/src/lifecycle/feature_events.rs`
- Server proto: `go/api/agent/v1/agent.proto`, `telemetry.proto`

## Status meanings

- **Available**: implementation exists and can be exercised now.
- **Partial**: foundation exists, but DLP behavior or coverage is incomplete.
- **Audit-only**: event/metadata can be observed, but blocking is not proven.
- **Not available**: no verified implementation.
- **Unknown**: requires an OS/runtime test, entitlement, privilege, or fixture not available during discovery.

## Platform matrix

| Capability | Windows | macOS | Linux | Current evidence | MVP decision |
|---|---|---|---|---|---|
| Agent runtime/config | Available | Available | Available | Shared Rust `AgentConfig`; `telemetry_file_events` and `detection_scan_on_create` exist | Reuse existing config/policy path |
| File event collection | Partial | Audit-only / partial | Partial | Windows has ETW modules and file enrichment; macOS ESF falls back to process polling without ESF/eslogger; Linux eBPF engine exists but probe coverage must be verified | File write/close is MVP only where an end-to-end event test passes |
| File content read/scan | Not available as DLP | Not available as DLP | Not available as DLP | Existing Windows file module computes metadata/hash only; no DLP text scanner found | Add minimal text-like scanner in Agent after schema/fixtures |
| Existing file integrity event | Partial | Partial | Partial | `build_fim_event` exists, but its callers and platform coverage must be traced | Reuse event envelope shape; do not treat FIM as content DLP |
| Removable-media detection | Partial | Unknown | Partial | USB event builder and Linux/Windows platform foundations exist; end-to-end write-to-removable path not proven | Start with audit/alert; block only after Windows test proves enforcement |
| Clipboard monitoring | Unknown | Unknown | Unknown | No DLP clipboard path found in inspected files | Out of MVP until a platform hook and test exist |
| Browser/cloud upload interception | Not available | Not available | Not available | No verified upload interception path found | Out of MVP; file-write detection must not be advertised as upload blocking |
| Network/HTTP body inspection | Not available as endpoint DLP | Not available | Not available | Existing ZTNA/CASB plans are design material, not verified DLP enforcement | Out of MVP; no SSL inspection |
| Windows block action | Unknown | N/A | N/A | Existing response/WFP/quarantine foundations exist, but DLP-specific file operation block path is not proven | Must run a dedicated Windows integration test before `block` support |
| macOS block action | N/A | Not available | N/A | ESF fallback explicitly degrades to process events only | Audit-only until Endpoint Security entitlement/hook is implemented and tested |
| Linux block action | N/A | N/A | Unknown | eBPF/LSM capability fields exist, but DLP file-write enforcement is not proven | Audit-only until LSM/write enforcement test passes |
| Offline event buffering | Available | Available | Available | Agent has offline buffer config and telemetry pipeline | Reuse existing bounded buffer |
| Event deduplication/coalescing | Partial | Partial | Partial | `coalesce_file_event_key` exists in lifecycle; DLP detection key not defined | Reuse helper, add DLP fields and tests |
| Redacted evidence | Not available as DLP | Not available as DLP | Not available as DLP | Existing event payloads include paths/metadata; no DLP redaction contract found | Define redaction before any content telemetry |
| Capability reporting | Partial | Partial | Partial | `AgentCapabilities` currently reports eBPF/LSM/YARA and heartbeat status | Extend with DLP capability fields only after contract ownership is confirmed |
| Tray local bridge | Available for ZTNA | Available for ZTNA | Available for ZTNA | Agent-owned JSON cache/queue in `tray_integration.rs` | Reuse bridge; DLP summary only, never raw content |
| Tray DLP status/notification | Not available | Not available | Not available | Existing Tray UI exposes detection policy toggles but no DLP state/detection workflow | Add after Agent event/state contract exists |

## Distribution and policy matrix

| Capability | Current status | Reuse candidate | Required DLP work |
|---|---|---|---|
| Signed bundle verification | Available for EDR bundle | `rule_bundle_verify.rs` | Define DLP bundle manifest/signature domain and avoid mixing EDR contents |
| Bundle hot reload | Available for EDR detection state | `threat_intel_pipeline/reload.rs` | Add a separate DLP compiled state and last-known-good rollback |
| Bundle staging/atomic swap | Partial/available in EDR path | Existing threat-intel pipeline | Verify that DLP bundle cannot replace EDR active state |
| Bundle download RPC | Available generically | `DownloadRuleBundle` | Add DLP bundle identity/type/version or a separate explicit contract |
| Policy sync | Available | `GetPolicy`, heartbeat `PolicyUpdate` | Add DLP policy fields without breaking old agents |
| Custom tenant rules | Not available as DLP | Existing policy/store patterns | Add server-side validation, scope, exception, expiry, and audit |
| DLP detection persistence | Not available as DLP | Existing telemetry/event stores | Store rule ID, action, confidence, hash/redacted evidence, not raw content |

## Verified MVP boundary

### Include

1. Synthetic fixture-driven text-like content scanning.
2. File write/close detection only where the platform event path is verified.
3. Removable-media observation and alerting; Windows block only after integration proof.
4. Signed/versioned DLP bundle as a separate artifact.
5. Audit/alert events with redacted evidence and offline buffering.
6. Agent capability reporting and Tray summary state.

### Exclude until separately proven

- Clipboard monitoring.
- Browser/cloud upload blocking.
- HTTP body inspection and SSL interception.
- OCR, NLP/ML, archive extraction, and recursive scanning.
- macOS/Linux block claims.
- Blocking based only on a keyword or an unvalidated 16-digit number.

## Required discovery tests before T02/T03 are considered complete

- Replay a synthetic file event through each platform telemetry adapter and confirm event fields/path semantics.
- Confirm whether Windows ETW/AMSI can provide the needed content timing without adding a new privileged hook.
- Confirm Linux eBPF/LSM support and whether write denial is possible in the supported kernel/build matrix.
- Confirm macOS Endpoint Security entitlement and whether file events are available outside the current process-poll fallback.
- Trace `DownloadRuleBundle` server implementation and agent download path to identify the smallest DLP bundle discriminator.
- Trace `coalesce_file_event_key` callers and define a DLP deduplication key that excludes raw content.

## Gate

Do not implement DLP block behavior or claim all-platform enforcement until the required discovery tests produce platform-specific evidence. The next implementation task can now define the schema and fixtures against this bounded capability surface.

## Revision

- Created during T01 discovery on branch `feat/dlp`.
- Unrelated working-tree changes intentionally untouched: `html/egappserver/root/vue.config.js` and untracked `NUL`.
- Agent repository remains on its existing branch and was not modified by this discovery task.
