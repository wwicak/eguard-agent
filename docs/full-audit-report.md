# eGuard Agent & Server — Full Security Audit Report

**Date**: 2026-02-20
**Scope**: Complete codebase audit of `eguard-agent` (Rust, 13 crates) and `fe_eguard` (Go server, EDR/MDM)
**Audited by**: 6 parallel review agents covering all source files

---

## Executive Summary

> **Important**: the counts below are the **initial baseline snapshot** from the first full audit pass. They are not the current post-remediation live status.

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 15 | Production blockers, RCE vectors, authentication bypass |
| HIGH | 18 | Credential exposure, integrity failures, security bypass |
| IMPORTANT | 39 | Race conditions, resource leaks, logic errors, robustness gaps |
| MODERATE | 9 | Edge cases, false positives, minor correctness issues |
| **Total** | **81** | |

**Top 5 systemic themes (baseline):**
1. **No authentication on the server** — all HTTP/gRPC endpoints are fully open (3 findings across EDR+MDM audits)
2. **TLS/mTLS not enforced** — HTTP client ignores configured TLS, gRPC fallback strips mTLS, TOFU CA pinning
3. **Input validation gaps** — path traversal, command injection, template injection, TOML injection across agent+server
4. **In-memory mode fragility** — unbounded growth, TOCTOU races, dropped data, token bypass when DB is absent
5. **Platform stubs masking security gaps** — Windows anti-debug is env-var-only, quarantine doesn't restrict reads, file hash cache never invalidated

### Validation Addendum (2026-02-20, post-remediation verification)

Validated against current code + targeted tests in both repos (`eguard-agent`, `fe_eguard`).

**Verified resolved (sampled high-impact findings):**
- Rust agent: `AC-1`, `AC-2`, `AC-3`, `AC-4`, `AC-6`, `AC-7`, `AC-8`, `AC-9`, `AC-12`, `AC-13`, `AC-14`
- Detection/response: `DRC-1`, `DRC-8`
- Platform Linux: `PL-1`, `PL-3`, `PL-4`
- gRPC/TLS/client: `SG-1`, `SG-2`, `SG-9`, `SG-12`, `SG-15`
- Go server: `EDR-1`, `EDR-2`, `EDR-6`, `EDR-7`, `EDR-11`, `MDM-2`, `MDM-3`, `MDM-5`, `MDM-8`

**Partially mitigated (not full closure yet):**
- `EDR-3` / `MDM-1`: token-based HTTP/gRPC auth middleware/interceptors now exist, but full JWT/session RBAC model remains pending.
- `EDR-4`: `approved_by` now binds to authenticated principal when auth enforced; weaker fallback behavior remains when auth is disabled/permissive.
- `EDR-8` / `MDM-4` / `EDR-10`: command/response routes are auth-gated, but still rely on shared agent-token model (no per-agent cryptographic identity binding yet).
- `EDR-13`: server-side Ed25519 bundle verification is enforced when verification key env is configured.
- `SG-3`: bundle download size cap + same-origin default are in place; end-to-end client-side digest/signature validation is still incomplete.

**Still open (confirmed):**
- `AC-5`, `AC-10`, `AC-11`, `AC-15`, `DRC-2`, `DRC-3`, `PL-2`, `PL-6`, `PL-8`.

**Verification commands run (representative):**
- Rust:
  - `cargo test -p agent-core sanitize_profile_id_rejects_path_traversal_sequences -- --nocapture`
  - `cargo test -p agent-core sanitize_apt_package_ -- --nocapture`
  - `cargo test -p detection sigma_yaml_file_path_predicate_compiles_and_fires -- --nocapture`
  - `cargo test -p response nonblocking_pipe_capture_returns_without_blocking_when_writer_is_open -- --nocapture`
  - `cargo test -p grpc-client configure_tls_rejects_missing_pin_by_default -- --nocapture`
  - `cargo test -p grpc-client send_events_grpc_clears_forced_http_fallback_after_successful_grpc_retry -- --nocapture`
  - `cargo test -p platform-linux parses_structured_tcp_connect_payload -- --nocapture`
- Go:
  - `go test ./server -run 'TestDecodeJSON|TestEnrollmentRejectsUnknownTokenWhenStoreIsEmpty' -count=1`
  - `go test ./server -run 'TestHTTPAdminEndpointRequiresAdminTokenWhenAuthEnforced|TestHTTPAgentEndpointRequiresAgentTokenWhenAuthEnforced|TestHTTPCommandApproveUsesAuthenticatedPrincipalWhenAuthEnforced|TestGRPCHeartbeatRequiresAgentTokenWhenAuthEnforced' -count=1`
  - `go test ./server -run 'TestTelemetryAsyncPipelineWaitDoesNotStallAfterWorkerPanic|TestSaveTelemetryAppliesInMemoryCap|TestSaveResponseAppliesInMemoryCap' -count=1`
  - `go test ./server -run 'TestSanitizeHeartbeatTimestamp|TestValidateEnrollmentTokenValue' -count=1`
  - `go test ./server -run 'TestSaveComplianceBatchDoesNotMutateStoreWhenPersistenceFails|TestSaveComplianceBatchStoresPerCheckRecordsInMemoryMode|TestUpdateAgentPostureFromComplianceLockedOverridesPolicyAssignment' -count=1`

---

## Part 1: eguard-agent (Rust Workspace)

### 1.1 agent-core — Lifecycle, Config, Main Binary

#### CRITICAL

| # | Conf | File | Issue |
|---|------|------|-------|
| AC-1 | 95% | `lifecycle/command_pipeline.rs:322` | **Path traversal via `profile_id`** — server-supplied `profile_id` used directly in `format!("/var/lib/eguard-agent/profiles/{}.json", payload.profile_id)`. Value like `../../etc/cron.d/backdoor` writes attacker-controlled JSON to arbitrary root paths. |
| AC-2 | 90% | `lifecycle/command_pipeline.rs:549` | **Command injection via `package_name`/`version`** — passed directly to `apt-get`. While `Command::args()` prevents shell injection, crafted `version` like `pkg -o APT::Update::Pre-Invoke::=/evil` can inject apt options. |

#### HIGH

| # | Conf | File | Issue |
|---|------|------|-------|
| AC-3 | 88% | `lifecycle/enrollment.rs:134` | **Enrollment token persisted in plaintext TOML** to `agent.conf`. Should be deleted post-enrollment or encrypted. |
| AC-4 | 85% | `main.rs:56` | **`tick()` error terminates agent** — `?` propagates any error from tick through main, silently killing the EDR agent. Buffer drain errors, serialization failures, etc. cause immediate exit. |
| AC-5 | 82% | `config/paths.rs:88` | **TOCTOU on config file resolution** — `exists()` check followed by `read_to_string()` allows symlink race by local attacker. |
| AC-6 | 80% | `config/crypto.rs:53` | **Config encryption key derived from world-readable `/etc/machine-id`** — any local user can compute the decryption key. Single-pass SHA-256, no salt, no proper KDF. |
| AC-7 | 82% | `lifecycle/command_pipeline.rs:210` | **Hardcoded Linux paths in `apply_device_wipe`** — `/var/lib/eguard-agent/quarantine` used unconditionally, fails silently on Windows where data dir is `C:\ProgramData\eGuard\`. |

#### IMPORTANT

| # | Conf | File | Issue |
|---|------|------|-------|
| AC-8 | 85% | `lifecycle/timing.rs:52` | **Clock skew triggers scan storm** — any backwards clock movement (NTP, resume from sleep) fires ALL interval-based operations simultaneously. |
| AC-9 | 88% | `lifecycle/runtime.rs:169` | **Debug command injection hook in production binary** — `EGUARD_ENABLE_BOOTSTRAP_TEST_COMMAND=1` env var injects mock commands. Not gated by `#[cfg(test)]`. |
| AC-10 | 83% | `lifecycle/threat_intel_pipeline/reload.rs:141` | **Threat-intel bundle corroboration mismatches are warn-only** — mismatched IOC/CVE counts never cause rejection. Supply chain integrity gap. |
| AC-11 | 80% | `lifecycle/telemetry_pipeline.rs:176` | **Only 1 of 256 polled eBPF events processed per tick** — at 10 events/sec max, detection rules miss events during high-activity periods. |
| AC-12 | 86% | `main.rs:47` | **No SIGTERM handler** — only handles `Ctrl+C` (SIGINT). `systemctl stop` sends SIGTERM which is ignored; process is SIGKILL'd after 90s timeout, no graceful shutdown. |
| AC-13 | 80% | `lifecycle/enrollment.rs:180` | **Config file written with default umask** — `agent.conf.tmp` created with 0644 permissions (world-readable) before rename. Contains enrollment token. |
| AC-14 | 82% | `config/util.rs:29` | **Hardcoded `"agent-dev-1"` fallback ID** — when `HOSTNAME` env var unset (containers), all agents register as same ID causing server-side identity collisions. |
| AC-15 | 80% | `lifecycle/self_protect.rs:35` | **False-positive tamper detection on first tick permanently disables agent** — self-protection runs before startup completes; if files not yet in place, `tamper_forced_degraded` is set permanently. |

#### MODERATE

| # | Conf | File | Issue |
|---|------|------|-------|
| AC-16 | 80% | `lifecycle/threat_intel_pipeline/state.rs:326` | State HMAC falls back to known constant `"eguard-agent-unknown-machine"` when machine-id unreadable. |
| AC-17 | 80% | `lifecycle/rule_bundle_loader.rs:236` | Recursive rule scan follows symlinks after archive extraction. |
| AC-18 | 82% | `lifecycle/detection_event.rs:94` | `FileWrite`/`FileRename`/`FileUnlink` all mapped to `FileOpen` event class — ransomware detection rules miss write-specific signals. |

---

### 1.2 detection + response + compliance

#### CRITICAL

| # | Conf | File | Issue |
|---|------|------|-------|
| DRC-1 | 88% | `detection/src/layer2/predicate.rs:97` | **`file_path_any_of` case mismatch** — rule values are lowercased via `normalize_path_needle` but event paths are compared raw. Windows paths with mixed case always produce false negatives. |
| DRC-2 | 85% | `response/src/quarantine.rs:76` | **Windows quarantine doesn't block reads** — `set_readonly(true)` only prevents writes. Original file remains fully readable by any process during the entire zero-and-delete sequence. Unix side has a permission-set-before-open race. |
| DRC-3 | 82% | `response/src/kill.rs:51` | **Protected process check uses `/proc/[pid]/comm`** — kernel truncates to 15 chars. Process names like `containerd-shim-runc-v2` truncated to `containerd-shi`, failing exact-match protection regex `^containerd$`. |

#### IMPORTANT

| # | Conf | File | Issue |
|---|------|------|-------|
| DRC-4 | 83% | `detection/src/layer2/engine.rs:178` | **Stage-0 restart destroys in-progress multi-stage detection chain** — spurious re-trigger of common stage-0 events mid-chain silently discards partial matches, causing false negatives. |
| DRC-5 | 80% | `detection/src/layer2/engine.rs:461` | **`DefaultHasher` collision risk** — identity fingerprint uses non-collision-resistant hash. Two distinct process identities can produce same hash, causing false-positive correlation. |
| DRC-6 | 85% | `compliance/src/lib.rs:1282` | **`?` in `parse_password_policy` short-circuits entire function** — malformed `PASS_MAX_DAYS` line causes whole password policy check to return `None` (non-compliant). |
| DRC-7 | 85% | `compliance/src/lib.rs:966` | **Remediation hardcoded to `apt-get`** — fails silently on RPM-based systems (RHEL, Fedora, SUSE). No OS detection. |
| DRC-8 | 90% | `response/src/capture.rs:34` | **Blocking pipe read in stdin capture** — reading `/proc/[pid]/fd/0` when it's a pipe blocks indefinitely if write end is open. Stalls entire response action including the kill. |
| DRC-9 | 85% | `detection/src/yara_engine.rs:273` | **Condition-only YARA rules cause hard load failure** — fallback backend rejects rules without string literals (e.g., `filesize > 1MB`), failing the entire ruleset load. |
| DRC-10 | 82% | `compliance/src/lib.rs:1140` | **Firewall check false positive** — reports enabled when iptables module is loaded but all chains are ACCEPT-all (no actual filtering). |

---

### 1.3 platform-linux + platform-windows

#### CRITICAL

| # | Conf | File | Issue |
|---|------|------|-------|
| PL-1 | 95% | `platform-linux/src/ebpf/codec.rs:167` | **IPv4 address byte-order inverted** — `read_u32_le` on big-endian network addresses + `to_be_bytes()` reverses IPs (1.2.3.4 becomes 4.3.2.1). Tests pass because replay codec applies inverse transformation. Real kernel events produce wrong IPs. |
| PL-2 | 92% | `platform-linux/src/ebpf/codec.rs:45` | **eBPF binary header uid at wrong offset** — 4-byte gap at offset 5-9 undocumented. If kernel struct layout differs from codec assumption, uid/timestamp fields parse garbage. No compile-time layout assertion. |

#### HIGH

| # | Conf | File | Issue |
|---|------|------|-------|
| PL-3 | 97% | `platform-linux/src/ebpf/libbpf_backend.rs:67` | **`failed_probes` silently discarded** — passed as throwaway `Vec::new()`. `EbpfStats::failed_probes` always reports empty even when critical probes (LSM hooks) failed to attach. |
| PL-4 | 88% | `platform-linux/src/lib.rs:132` | **Stale process cache → PID-reuse misattribution** — no TTL or mtime check. If `ProcessExit` event dropped (ring buffer overflow), stale exe/cmdline from previous process with same PID returned indefinitely. |
| PL-5 | 88% | `platform-windows/src/wfp/isolation.rs:65` | **Block rules installed before allow rules** — race window cuts off management server traffic between block-all and per-IP allow installation. |
| PL-6 | 95% | `platform-windows/src/self_protect/anti_debug.rs:18` | **Windows anti-debug is env-var-only** — no `IsDebuggerPresent()`, no `NtQueryInformationProcess`. Any real debugger goes undetected. |
| PL-7 | 85% | `platform-windows/src/self_protect/integrity.rs:84` | **Single-quote injection in PowerShell Authenticode path** — path with `'` breaks PS string literal, bypassing signature verification. |

#### IMPORTANT

| # | Conf | File | Issue |
|---|------|------|-------|
| PL-8 | 90% | `platform-windows/src/lib.rs:145` | **File hash cache never invalidated on Windows** — `mtime_secs: 0` stored for all entries, no freshness check. Modified DLLs return stale pre-modification hash. |
| PL-9 | 85% | `platform-windows/src/enrichment/process.rs:93` | **13 PowerShell spawns per event enrichment** — parent chain walk spawns full `powershell.exe` per ancestor (up to depth 12). Severe performance issue under load. |
| PL-10 | 87% | `platform-windows/src/wfp/isolation.rs:124` | **Partial deactivation leaves orphaned block filters** — `?` on first failed `remove_filter` causes early return; remaining block rules stay installed permanently. |
| PL-11 | 85% | `platform-linux/src/container.rs:374` | **Container escape detection false-positives** — in privileged sidecar deployments, `HOST_PID_NS` is set to container's PID namespace, causing all same-namespace processes to be flagged. |

#### MODERATE

| # | Conf | File | Issue |
|---|------|------|-------|
| PL-12 | 82% | `platform-windows/src/compliance/registry.rs:85` | Registry value parser fragile for multi-word names or space-containing values. |
| PL-13 | 80% | `platform-windows/src/response/quarantine.rs:77` | Non-Windows stub returns invalid empty-filename path for root/`..` inputs. |
| PL-14 | 81% | `platform-windows/src/service/eventlog.rs:143` | Detection event ID collisions for codes >= 100 (`4000 + code % 100`). |

---

### 1.4 self-protect + baseline + nac + grpc-client

#### CRITICAL

| # | Conf | File | Issue |
|---|------|------|-------|
| SG-1 | 95% | `grpc-client/src/client.rs:504` | **TOFU CA pinning** — first-seen CA automatically trusted and pinned without verification. Attacker intercepting first connection permanently pins their CA. Logs `info!` not `warn!`. |
| SG-2 | 92% | `grpc-client/src/client.rs:64` | **HTTP client ignores configured TLS** — `reqwest::Client` built once at construction before `configure_tls()` is called. Never rebuilt with mTLS identity or custom CA. All HTTP transport paths send without client cert. |

#### HIGH

| # | Conf | File | Issue |
|---|------|------|-------|
| SG-3 | 90% | `grpc-client/src/client_http.rs:243` | **Bundle download unbounded, no integrity check** — entire response buffered in memory with no size limit. SHA-256 and signature from `ThreatIntelVersionEnvelope` never validated. Server can redirect to arbitrary URL (SSRF). |
| SG-4 | 88% | `self-protect/src/hardening.rs:17` | **All hardening controls disableable via env vars** — `PR_SET_DUMPABLE`, ptrace restriction, `NO_NEW_PRIVS`, seccomp all toggled by `EGUARD_SELF_PROTECT_*` env vars with no privilege check. Not gated by `cfg(debug_assertions)`. |
| SG-5 | 85% | `self-protect/src/integrity.rs:23` | **Integrity baseline from potentially-tampered disk** — baseline hash computed from on-disk binary which may already be replaced if agent started after tampering. |
| SG-6 | 90% | `baseline/src/lib.rs:140` | **Baseline file has no integrity protection** — serialized to disk with no HMAC/signature. Attacker with filesystem access can substitute forged baselines. |
| SG-7 | 82% | `nac/src/policy.rs:138` | **`now_unix: 0` default means dead-agent quarantine never triggers** — `AccessContext::default()` sets `now_unix: 0`, causing `saturating_sub` to produce 0 for any heartbeat time, never exceeding the dead threshold. |

#### IMPORTANT

| # | Conf | File | Issue |
|---|------|------|-------|
| SG-8 | 85% | `grpc-client/src/client.rs:552` | **Retry logic retries non-retryable errors** — `ALREADY_EXISTS`, `INVALID_ARGUMENT`, `UNAUTHENTICATED` all retried. Enrollment token re-sent on permanent failures. |
| SG-9 | 87% | `grpc-client/src/client.rs:124` | **gRPC→HTTP fallback is permanent and strips mTLS** — once set, `grpc_reporting_force_http` never cleared. Transient gRPC failure permanently downgrades all security-sensitive data to unverified HTTP. |
| SG-10 | 83% | `nac/src/network_profile.rs:168` | **PSK/password in plaintext nmconnection** — no directory ownership check before writing credentials to NetworkManager keyfile. |
| SG-11 | 80% | `baseline/src/lib.rs:123` | **TOCTOU race in `load_or_new`** — `exists()` then `read()` allows swap between check and open. |
| SG-12 | 84% | `grpc-client/src/client_grpc.rs:390` | **New TLS handshake per RPC call** — no channel reuse. Full mTLS handshake on every heartbeat, event batch, compliance report. |
| SG-13 | 82% | `self-protect/src/hardening.rs:265` | `PR_SET_PTRACER` comment says "restricted to self (pid 0)" but arg 0 means "no ptracer" — future regression risk. |
| SG-14 | 81% | `nac/src/network_profile.rs:160` | **nmconnection injection** — `escape_nm_value` doesn't escape `=`, `;`, `#`. Server-pushed SSID/identity with these chars injects into NetworkManager config. |

#### MODERATE

| # | Conf | File | Issue |
|---|------|------|-------|
| SG-15 | 80% | `grpc-client/src/buffer.rs:82` | SqliteBuffer file created with default umask (world-readable). Contains security events. |
| SG-16 | 80% | `self-protect/src/debugger.rs:136` | Timing probe trivially bypassed on VMs/containers; silent failure on non-x86 (ARM). |
| SG-17 | 80% | `baseline/src/lib.rs:154` | `sample_count` can saturate (`u64::MAX`) and diverge from distribution counts, corrupting entropy baselines. |

---

## Part 2: fe_eguard (Go Server)

### 2.1 EDR Implementation

#### CRITICAL

| # | Conf | File | Issue |
|---|------|------|-------|
| EDR-1 | 100% | `enrollment_token.go:360` | **Token bypass: any token accepted when in-memory store is empty** — `validateEnrollmentToken` returns `true` when no tokens exist. Open enrollment with no opt-in flag. |
| EDR-2 | 100% | `http.go:9` | **No HTTP request body size limit** — `json.NewDecoder(r.Body).Decode(dst)` on unbounded body. Multi-GB requests cause OOM. gRPC has 16 MiB limit; HTTP has zero. |
| EDR-3 | 100% | `server.go:124` | **Zero authentication on all 40+ HTTP endpoints** — no API key, no mTLS check, no session validation. Any network-reachable client can enqueue `wipe_device`, create/revoke tokens, approve commands, read audit logs. `X-Eguard-UserName` header is trusted without verification. |
| EDR-4 | 95% | `command_ack_approve.go:94` | **Command approval has no identity/RBAC check** — `approved_by` taken from request body, not authenticated session. Anyone can approve destructive commands by posting `{"approved_by":"admin","approval_status":"approved"}`. |

#### IMPORTANT

| # | Conf | File | Issue |
|---|------|------|-------|
| EDR-5 | 90% | `grpc_agent_control.go:75` | **TOCTOU race on token validate→consume** — in-memory path releases lock between validate and consume. Two concurrent requests with `MaxUses=1` token both succeed. |
| EDR-6 | 95% | `telemetry.go:26` | **Unbounded in-memory growth** — `store.events` and `store.responses` append-only, never evicted. At 200 events/sec × 500 bytes = 360 MB/hour/agent. OOM in hours. |
| EDR-7 | 85% | `grpc_agent_control.go:151` | **Agent-supplied timestamps accepted without validation** — `SentAtUnix` from agent used directly for `LastHeartbeat`. Attacker can keep stale agent appearing alive or corrupt liveness state with future timestamps. |
| EDR-8 | 88% | `command_delivery.go:33` | **Unauthenticated GET marks commands completed** — any caller knowing `agent_id` and `command_id` can suppress pending commands (wipe, isolate) by marking them done before agent receives them. |
| EDR-9 | 85% | `list.go:289` | **`decommissionAgentHandler` enqueues `uninstall` without required `auth_token`** — bypasses `validateUninstallCommandPayload` which mandates `auth_token`. Agent receiving this command will reject it. |
| EDR-10 | 90% | `response.go:36` | **Response reports accepted from any caller** — anyone can POST fake response records claiming agent X quarantined file Y. Corrupts audit trail. |
| EDR-11 | 83% | `telemetry_pipeline.go:64` | **Panic in worker leaves WaitGroup stuck** — `p.pending.Done()` never called on panic, blocking graceful shutdown forever. |
| EDR-12 | 85% | `correlator.go:257` | **Fragile nested lock order** — `series.mu` → `iocMu` acquisition order undocumented. Future callers holding `iocMu` first will deadlock. |
| EDR-13 | 88% | `grpc_rule_bundle.go:61` | **Rule bundle Ed25519 signature never server-side verified** — signature file read errors silently swallowed. `Verified: false` sent to agents. Tampered bundles accepted. |

---

### 2.2 MDM Implementation

#### CRITICAL

| # | Conf | File | Issue |
|---|------|------|-------|
| MDM-1 | 100% | `server.go:114` | **No authentication on gRPC endpoints** — `grpc.NewServer()` created with no interceptors. Combined with HTTP finding (EDR-3), entire management plane is open. |
| MDM-2 | 88% | `enrollment_token.go:348` | **TOCTOU in in-memory token validate-then-consume** — separate RLock/Lock acquisitions. Certificate issuance (potentially slow SCEP proxy) occurs between validate and consume, widening race window. |

#### HIGH

| # | Conf | File | Issue |
|---|------|------|-------|
| MDM-3 | 90% | `compliance.go:113` | **`saveComplianceBatch` partial write with no rollback** — in-memory state mutated before DB writes. DB error on record 3/10 leaves in-memory showing new posture but DB with only 2 records. Post-restart data inconsistency. |
| MDM-4 | 85% | `command_delivery.go:33` | **Unauthenticated command completion marking** — any caller can mark any agent's commands as completed. (Same as EDR-8, cross-referenced for MDM impact: suppresses compliance remediation commands.) |
| MDM-5 | 82% | `persistence_compliance.go:140` | **Policy-ID drift undetected** — `policy_id` only set when empty, never overwritten. Agent reassigned to new policy continues reporting against old policy. No server-side validation that reported `policy_id` matches assigned policy. |

#### IMPORTANT

| # | Conf | File | Issue |
|---|------|------|-------|
| MDM-6 | 82% | `agent_lifecycle_policy.go:44` | **Auto-purge deletes manually-set inactive agents** — `DELETE WHERE lifecycle_state='inactive'` after 7 days includes agents manually decommissioned by admins. No `manually_decommissioned` flag. |
| MDM-7 | 80% | `enrollment.go:132` | **Full internal agent record leaked to enrolling agent** — HTTP enrollment response includes `ComplianceStatus`, `PolicyID`, `PolicyHash` from stored record. |
| MDM-8 | 80% | `enrollment_token.go:453` | **Custom enrollment tokens bypass entropy requirements** — only checks length (1-128 chars). Tokens like `"1"`, `"admin"`, `"test"` accepted. Auto-generated tokens are 32 bytes hex (secure). |
| MDM-9 | 88% | `compliance.go:125` | **No-DB mode drops individual compliance check records** — only overall summary stored in memory. Compliance UI expects per-check granularity, shows single row per agent. |

---

## Part 3: Cross-Cutting Systemic Issues

### 3.1 Authentication Architecture (CRITICAL — Systemic)

The server has **zero authentication** on both HTTP and gRPC paths. This is the single most impactful finding across the entire audit. Every management operation — enrollment, command dispatch, command approval, compliance reporting, telemetry ingestion, policy assignment, lifecycle management — is accessible to any network-reachable client.

**Affected findings**: EDR-3, EDR-4, EDR-8, EDR-10, MDM-1, MDM-4

**Recommendation**: Implement a layered authentication model:
1. **Agent-to-server**: mTLS with client certificates issued during enrollment. Agent ID derived from cert CN, not from request body.
2. **Admin-to-server**: Bearer token (JWT) or session-based auth with RBAC. Destructive operations (wipe, isolate, approve) require elevated roles.
3. **Enrollment**: Token-based (already exists) but must be enforced in all modes, not bypassed when token store is empty.

### 3.2 TLS/mTLS Chain (CRITICAL — Systemic)

The TLS security model has multiple breaks:
- **SG-1**: First-seen CA pinned without verification (TOFU)
- **SG-2**: HTTP client never rebuilt with TLS config after `configure_tls()`
- **SG-9**: gRPC failure permanently downgrades to unverified HTTP
- **SG-12**: New TLS handshake per RPC call (no channel reuse)

**Net effect**: Even when mTLS certificates are correctly provisioned, the transport layer has paths where they are silently not used.

### 3.3 In-Memory Mode Fragility (HIGH — Systemic)

When `EGUARD_AGENT_SERVER_DSN` is unset, the server operates with an in-memory store that has fundamental issues:
- **EDR-1**: Token validation bypassed (any token accepted when store empty)
- **EDR-5/MDM-2**: TOCTOU race on token consume
- **EDR-6**: Events/responses grow without bound (OOM)
- **MDM-3**: Compliance batch partial writes with no rollback
- **MDM-9**: Individual compliance checks silently dropped

**Recommendation**: In-memory mode should either be removed for production use (start requiring a database), or hardened with proper caps, atomic operations, and feature-parity with the DB path.

### 3.4 Event Processing Throughput (HIGH — Agent)

The agent has a critical bottleneck in event processing:
- **AC-11**: Only 1 of 256 polled eBPF events processed per tick (10 events/sec max)
- **PL-1**: IPv4 addresses inverted in real kernel events (all network detection rules produce wrong IPs)
- **PL-3**: Failed eBPF probes invisible (stats always show empty)
- **PL-4**: Stale process cache on PID reuse when exit events dropped

**Net effect**: Under real-world load, the detection engine misses the vast majority of events, operates on incorrect IP addresses, and may attribute events to wrong processes.

### 3.5 Windows Platform Maturity (HIGH — Agent)

The Windows platform has significant gaps that would prevent effective EDR operation:
- **PL-6**: Anti-debug is env-var-only (no real debugger detection)
- **PL-8**: File hash cache never invalidated (stale hashes for modified files)
- **PL-9**: 13 PowerShell spawns per event enrichment (severe performance)
- **PL-5**: WFP isolation installs block before allow rules (management traffic cut off)
- **DRC-2**: Quarantine doesn't restrict reads on Windows
- **AC-18**: FileWrite/FileRename mapped to FileOpen (ransomware detection impaired)

---

## Part 4: Priority Fix Roadmap

### P0 — Must Fix Before Any Production Deployment

| # | Finding | Effort | Rationale |
|---|---------|--------|-----------|
| 1 | EDR-3/MDM-1: Add authentication to all endpoints | 1-2 weeks | Everything else is moot without auth |
| 2 | EDR-2: Add `http.MaxBytesReader` | 1 hour | Trivial fix, prevents OOM DoS |
| 3 | SG-2: Rebuild HTTP client after `configure_tls()` | 2 hours | mTLS is broken without this |
| 4 | PL-1: Fix IPv4 byte order in eBPF codec | 2 hours | All network detection rules produce wrong IPs |
| 5 | AC-1: Sanitize `profile_id` for path traversal | 1 hour | RCE via server-controlled input |
| 6 | EDR-1: Don't accept arbitrary tokens when store empty | 1 hour | Enrollment bypass |
| 7 | AC-4: Catch `tick()` errors instead of terminating | 2 hours | Agent self-termination on transient errors |

### P1 — Fix Before Production (1-2 weeks)

| # | Finding | Effort | Rationale |
|---|---------|--------|-----------|
| 8 | SG-1: Remove TOFU CA pinning | 4 hours | First-connection MITM |
| 9 | AC-11: Process batch of events per tick, not just 1 | 4 hours | 10 events/sec is unusable |
| 10 | AC-12: Add SIGTERM handler | 2 hours | Graceful shutdown under systemd |
| 11 | DRC-1: Fix `file_path_any_of` case handling | 2 hours | Windows detection false negatives |
| 12 | DRC-8: Non-blocking pipe read in capture | 2 hours | Response action deadlock |
| 13 | AC-6: Replace machine-id-derived encryption key | 4 hours | Config decryptable by local users |
| 14 | EDR-4: Derive `approved_by` from authenticated session | 4 hours | Command approval bypass |
| 15 | SG-9: Make gRPC→HTTP fallback temporary | 2 hours | Permanent mTLS downgrade |
| 16 | PL-3: Propagate `failed_probes` into `EbpfStats` | 1 hour | Failed probes invisible |
| 17 | EDR-6: Cap in-memory event/response store size | 2 hours | OOM in hours |
| 18 | SG-4: Remove env-var toggles for hardening in release | 2 hours | Attacker disables protections |
| 19 | AC-9: Gate debug hook behind `cfg(debug_assertions)` | 30 min | Test code in production |
| 20 | MDM-3: Wrap compliance batch in DB transaction | 2 hours | Data inconsistency |

### P2 — Fix Within Quarter

| # | Finding | Effort | Rationale |
|---|---------|--------|-----------|
| 21 | PL-4: Add TTL to process cache | 4 hours | PID reuse misattribution |
| 22 | AC-3: Don't persist enrollment token post-enrollment | 1 hour | Credential exposure |
| 23 | SG-3: Add bundle size limit + SHA-256 verification | 4 hours | Supply chain integrity |
| 24 | DRC-3: Supplement `/proc/comm` with `/proc/exe` | 4 hours | Protected process bypass |
| 25 | SG-6: Add HMAC to baseline store | 4 hours | Baseline tampering |
| 26 | PL-8: Implement file hash freshness check on Windows | 2 hours | Stale hashes |
| 27 | PL-9: Replace PowerShell spawns with native API | 1-2 weeks | Performance |
| 28 | AC-18: Add FileWrite/FileRename event classes | 4 hours | Ransomware detection |
| 29 | SG-12: Implement gRPC channel reuse | 4 hours | Performance + resource usage |
| 30 | AC-14: Use `gethostname(2)` instead of hardcoded fallback | 1 hour | Identity collisions |

---

## Appendix: Finding Cross-Reference by File

<details>
<summary>eguard-agent files (click to expand)</summary>

| File | Findings |
|------|----------|
| `agent-core/src/main.rs` | AC-4, AC-12 |
| `agent-core/src/config/crypto.rs` | AC-6 |
| `agent-core/src/config/paths.rs` | AC-5 |
| `agent-core/src/config/util.rs` | AC-14 |
| `agent-core/src/lifecycle/command_pipeline.rs` | AC-1, AC-2, AC-7 |
| `agent-core/src/lifecycle/detection_event.rs` | AC-18 |
| `agent-core/src/lifecycle/enrollment.rs` | AC-3, AC-13 |
| `agent-core/src/lifecycle/runtime.rs` | AC-9 |
| `agent-core/src/lifecycle/self_protect.rs` | AC-15 |
| `agent-core/src/lifecycle/telemetry_pipeline.rs` | AC-11 |
| `agent-core/src/lifecycle/threat_intel_pipeline/reload.rs` | AC-10 |
| `agent-core/src/lifecycle/threat_intel_pipeline/state.rs` | AC-16 |
| `agent-core/src/lifecycle/timing.rs` | AC-8 |
| `agent-core/src/lifecycle/rule_bundle_loader.rs` | AC-17 |
| `baseline/src/lib.rs` | SG-6, SG-11, SG-17 |
| `compliance/src/lib.rs` | DRC-6, DRC-7, DRC-10 |
| `detection/src/layer2/engine.rs` | DRC-4, DRC-5 |
| `detection/src/layer2/predicate.rs` | DRC-1 |
| `detection/src/yara_engine.rs` | DRC-9 |
| `grpc-client/src/buffer.rs` | SG-15 |
| `grpc-client/src/client.rs` | SG-1, SG-2, SG-8, SG-9 |
| `grpc-client/src/client/client_grpc.rs` | SG-12 |
| `grpc-client/src/client/client_http.rs` | SG-3 |
| `nac/src/network_profile.rs` | SG-10, SG-14 |
| `nac/src/policy.rs` | SG-7 |
| `platform-linux/src/container.rs` | PL-11 |
| `platform-linux/src/ebpf/codec.rs` | PL-1, PL-2 |
| `platform-linux/src/ebpf/libbpf_backend.rs` | PL-3 |
| `platform-linux/src/lib.rs` | PL-4 |
| `platform-windows/src/compliance/registry.rs` | PL-12 |
| `platform-windows/src/enrichment/process.rs` | PL-9 |
| `platform-windows/src/lib.rs` | PL-8 |
| `platform-windows/src/response/quarantine.rs` | PL-13 |
| `platform-windows/src/self_protect/anti_debug.rs` | PL-6 |
| `platform-windows/src/self_protect/integrity.rs` | PL-7 |
| `platform-windows/src/service/eventlog.rs` | PL-14 |
| `platform-windows/src/wfp/isolation.rs` | PL-5, PL-10 |
| `response/src/capture.rs` | DRC-8 |
| `response/src/kill.rs` | DRC-3 |
| `response/src/quarantine.rs` | DRC-2 |
| `self-protect/src/debugger.rs` | SG-16 |
| `self-protect/src/hardening.rs` | SG-4, SG-13 |
| `self-protect/src/integrity.rs` | SG-5 |

</details>

<details>
<summary>fe_eguard files (click to expand)</summary>

| File | Findings |
|------|----------|
| `go/agent/server/server.go` | EDR-3, MDM-1 |
| `go/agent/server/http.go` | EDR-2 |
| `go/agent/server/enrollment_token.go` | EDR-1, MDM-2, MDM-8 |
| `go/agent/server/enrollment.go` | MDM-7 |
| `go/agent/server/grpc_agent_control.go` | EDR-5, EDR-7 |
| `go/agent/server/command_delivery.go` | EDR-8, MDM-4 |
| `go/agent/server/command_ack_approve.go` | EDR-4 |
| `go/agent/server/compliance.go` | MDM-3, MDM-9 |
| `go/agent/server/persistence_compliance.go` | MDM-5 |
| `go/agent/server/agent_lifecycle_policy.go` | MDM-6 |
| `go/agent/server/telemetry.go` | EDR-6 |
| `go/agent/server/response.go` | EDR-10 |
| `go/agent/server/telemetry_pipeline.go` | EDR-11 |
| `go/agent/server/correlator.go` | EDR-12 |
| `go/agent/server/grpc_rule_bundle.go` | EDR-13 |
| `go/agent/server/list.go` | EDR-9 |

</details>

---

## Part 5: Strategic Improvements to Surpass CrowdStrike

### Context: What CrowdStrike Is (Feb 2026)

CrowdStrike Falcon is the market leader in endpoint security (~$4B ARR). Its architecture:

- **Windows**: Ring-0 kernel driver (ELAM + minifilter + callbacks), WHQL-signed, ETW supplementary
- **Linux**: eBPF mode (preferred) + legacy kernel module
- **macOS**: Endpoint Security Framework (user-space, Apple mandate)
- **Cloud**: Threat Graph processes 1+ trillion events/day across 15+ PB, correlated fleet-wide
- **Detection**: IOA-first (behavioral) + on-sensor ML + cloud ML, 1000+ kill-chain patterns
- **Response**: Real Time Response (RTR) remote shell, one-click network isolation, Falcon Fusion SOAR (included)
- **Intelligence**: 265+ tracked adversaries, millions of IOCs, STIX/TAXII feeds
- **Compliance**: Zero Trust Assessment, Spotlight (vuln management), CIS benchmarks
- **Integrations**: 500+ marketplace ISV connectors, LogScale (petabyte SIEM)
- **AI (2025)**: Charlotte AI agentic SOC, 7 mission-ready AI agents, natural-language playbooks, MCP federation
- **Coverage**: Windows/Linux/macOS/ChromeOS/iOS/Android, containers, cloud workloads (CNAPP)
- **Pricing**: $60-185/device/year base; full platform significantly higher; modules sold separately

**Key vulnerability**: The July 2024 global outage (8.5M devices BSOD'd, ~$10B damages) exposed that kernel-mode architecture + rapid content updates = systemic risk. Microsoft is pushing vendors toward user-mode APIs. CrowdStrike's cloud dependency is also a weakness for air-gapped/sovereignty-conscious environments.

---

### 5.1 Where eGuard Already Leads (Amplify These)

These are genuine technical advantages eGuard has over CrowdStrike today. The strategy is to amplify them into market-differentiating features.

#### A. Mathematical Detection Rigor (Unique Moat)

**What eGuard has**: A 5-layer detection engine with provable statistical foundations that CrowdStrike cannot match:

| Layer | Technique | CrowdStrike Equivalent |
|-------|-----------|----------------------|
| Layer 1 | Aho-Corasick prefiltered IOC matching | Threat Graph indicator lookup |
| Layer 2 | Sigma YAML temporal rules (open standard) | Proprietary JSON rules (closed) |
| Layer 3 | KL divergence anomaly detection (information-theoretic) | Black-box statistical models |
| Layer 4 | Kill-chain graph templates | ML-ranked kill-chain patterns |
| Layer 5 | Pre-trained ML scoring | Cloud-retrained ML models |
| Behavioral | CUSUM change-point detection (minimax optimal per Lorden's theorem) | Proprietary behavioral analysis |

**CUSUM advantage**: eGuard's behavioral engine uses CUSUM detectors calibrated for ARL₀ ≈ 10,000 (1 false alarm per ~2.7 hours), with Wasserstein distance, Rényi entropy, conformal prediction, and Bonferroni/Benjamini-Hochberg multi-test correction. This is **provably the fastest possible detector** for mean-shift changes in a process's behavior — a mathematical guarantee CrowdStrike's ML cannot provide.

**Action — Amplify**:
1. **Publish the math**: Write a technical whitepaper on CUSUM-based endpoint detection. Academic-grade detection theory applied to EDR is unprecedented. This positions eGuard as "the detection engine that can prove its detection latency bounds."
2. **Add detection SLA guarantees**: Because CUSUM has provable detection delay bounds, eGuard can contractually guarantee "behavioral anomaly detected within N events of onset" — something no other EDR vendor can claim.
3. **Real-time detection metrics dashboard**: Surface CUSUM state, KL divergence, entropy values, and p-values in the admin UI. Security teams can see *why* an alert fired, not just *that* it fired.
4. **Open-source the detection math**: Release `crates/detection/src/behavioral.rs` and `layer3.rs` as standalone crates. Academic and community adoption creates a network effect.

**Impact**: Positions eGuard as "the EDR you can prove works" — a powerful differentiator for regulated industries (finance, government, healthcare) that require explainable security controls.

#### B. eBPF-Native Linux Sensor (Technical Advantage)

**What eGuard has**: The Linux sensor is eBPF-first, written in Zig+Rust with native ring buffer integration. CrowdStrike adopted eBPF in ~2023 but still ships a legacy kernel module as fallback.

**Advantages over CrowdStrike**:
- **No kernel module risk**: After CrowdStrike's July 2024 kernel-mode BSOD, eBPF-only is a selling point. eBPF programs are verified by the kernel before execution — they cannot crash the system.
- **CO-RE potential**: Compile Once, Run Everywhere eliminates CrowdStrike's kernel version matrix problem.
- **Smaller binary**: No need to ship pre-compiled modules for every kernel version.

**Action — Amplify**:
1. **Adopt BTF/CO-RE**: Currently the eBPF programs are built for specific kernel versions. Switch to CO-RE (`bpf_core_read()`) so a single eBPF binary runs on all kernels ≥ 5.8 without recompilation.
2. **Add eBPF-based network policy enforcement**: Replace iptables/nftables for host isolation with `TC` and `XDP` eBPF programs. This is faster, more precise, and cannot be bypassed by containers.
3. **Container escape detection hardening**: The existing `detect_container_escape()` works via namespace comparison. Add eBPF-based detection of `setns(2)`, `unshare(2)`, and `mount(2)` abuse for real-time escape detection.
4. **Market the BSOD-proof angle**: Every sales conversation should reference the July 2024 outage. "eGuard uses eBPF — mathematically verified by your kernel. It cannot BSOD your fleet."

**Impact**: Captures the post-CrowdStrike-outage market sentiment. Linux-first organizations (cloud, DevOps, containers) are actively seeking alternatives that don't require kernel modules.

#### C. Open Detection Rules (Community Moat)

**What eGuard has**: Detection rules are Sigma YAML — an open standard used by Splunk, Elastic, Microsoft Sentinel, and 50+ SIEM products. CrowdStrike's rules are proprietary.

**Action — Amplify**:
1. **Publish eGuard's rule library**: Release all Sigma rules as open-source. Security researchers contribute rules, eGuard benefits from community detection coverage.
2. **Sigma rule marketplace**: Allow customers to import/export rules in standard Sigma format. Rules tested on one platform work everywhere.
3. **MITRE ATT&CK mapping**: Every rule tagged with ATT&CK technique IDs. Dashboard shows coverage matrix (which techniques are detected, which have gaps).
4. **Rule testing framework**: `eguard-agent test-rules --replay events.ndjson` — validate rules against captured event streams. CrowdStrike has no equivalent.

**Impact**: Creates a flywheel: more rules → better detection → more users → more rules. This is how Linux won against proprietary Unix.

#### D. Compliance-Integrated EDR (Combined Value)

**What eGuard has**: Built-in compliance assessment (`crates/compliance/`) with auto-remediation, grace periods, and per-check specifications. CrowdStrike sells compliance (Spotlight) as a separate add-on module.

**Action — Amplify**:
1. **Expand CIS Benchmark coverage**: Add CIS Level 1 and Level 2 benchmarks for Ubuntu 22.04/24.04, RHEL 9, and Windows Server 2022. Each benchmark has 200+ checks — this is table-stakes for enterprise compliance.
2. **Continuous compliance mode**: Instead of periodic scans, detect compliance drift in real-time via eBPF file monitoring on `/etc/ssh/sshd_config`, `/etc/pam.d/`, etc. Alert within seconds of a drift event.
3. **Compliance-as-Code**: Allow customers to define compliance policies in YAML, version-controlled alongside their infrastructure. This appeals to DevOps/IaC teams.
4. **Unified dashboard**: Single pane showing "endpoint X has 3 critical detections AND 2 compliance violations" — correlated risk score combining security + compliance posture.

**Impact**: Reduces tool sprawl. Customers buy one agent instead of EDR + compliance scanner + vulnerability manager. CrowdStrike charges separately for each.

---

### 5.2 Critical Gaps to Close (Must-Have for Enterprise)

These are features CrowdStrike has that eGuard must implement to be competitive. Without them, enterprise procurement will not consider eGuard.

#### E. Windows Platform: From Scaffold to Production

**Current state**: `platform-windows` has 41 files, compiles on Linux, but ETW/AMSI/WFP/compliance checks are stubs returning hardcoded values. Response actions are non-functional. This is the single largest gap.

**Why it matters**: Windows is 70-80% of enterprise endpoints. An EDR that doesn't work on Windows is not an EDR.

**Phased plan**:

| Phase | Scope | Effort | Deliverable |
|-------|-------|--------|------------|
| Phase 1 | ETW event collection (real events, not stubs) | 2-3 weeks | Process, file, network events flowing through detection layers |
| Phase 2 | AMSI integration (wire scanner to detection engine) | 1-2 weeks | PowerShell/JScript/VBScript fileless attack detection |
| Phase 3 | Response actions (WinAPI process kill, file quarantine) | 1-2 weeks | Kill process tree via `TerminateProcess`, quarantine via ACL + MoveFile |
| Phase 4 | WFP network isolation (production-ready) | 2-3 weeks | One-click host isolation, allow-only management server traffic |
| Phase 5 | Self-protection (real anti-debug, ACL hardening) | 1-2 weeks | `IsDebuggerPresent`, `NtQueryInformationProcess`, restricted file ACLs |
| Phase 6 | Compliance probes (real WMI/registry queries) | 2-3 weeks | BitLocker, Defender, Firewall, UAC, Updates, Credential Guard checks |
| Phase 7 | Code signing + MSI packaging | 1 week | EV code-signed binary, MSI for GPO/Intune deployment |

**Total**: ~3-4 months of focused development to reach Windows parity with Linux.

**Critical implementation notes**:
- Phase 1 is the foundation — everything else depends on real ETW events flowing. The ETW codec (`etw/codec.rs`) must correctly decode provider-specific event schemas (each provider has unique field layouts).
- Phase 2 requires COM initialization (`CoInitializeEx`) and AMSI provider registration. The AMSI content must be fed into YARA + Sigma rules for detection.
- Phase 4 must fix the block-before-allow race (finding PL-5) and handle partial deactivation (PL-10).
- Phase 7 requires an EV Code Signing Certificate (~$400/year) and WiX v5 project. Without code signing, SmartScreen blocks the binary and enterprise GPO rejects it.

#### F. macOS: Endpoint Security Framework

**Current state**: `platform-macos` is a stub (`platform_name() -> "macos"`). Zero detection capability.

**Why it matters**: 15-30% of enterprise endpoints are Macs (especially in tech, design, and executive teams — high-value targets).

**Implementation plan**:
1. Apple Endpoint Security Framework (`es_new_client()`) for process/file/network events — this is Apple's mandated API, no kernel extensions allowed
2. System Extension packaging (`.systemextension` bundle)
3. MDM profile for System Extension approval (enterprises deploy via Jamf/Mosyle)
4. Map ESF event types to existing `EventType` enum for cross-platform rule compatibility
5. Compliance checks: SIP (System Integrity Protection), FileVault, XProtect, Gatekeeper

**Effort**: 1-2 months for basic coverage (process + file + network events with detection).

#### G. Authentication & Authorization (Server)

**Current state**: Zero authentication on all 40+ HTTP endpoints and gRPC services (finding EDR-3, MDM-1). Any network-reachable client can wipe devices, approve commands, read telemetry.

**Why it matters**: This is a hard blocker for any deployment. An unauthenticated management plane is an RCE vector.

**Implementation plan**:

| Layer | Mechanism | Protects |
|-------|-----------|----------|
| Agent → Server | mTLS (client certificates from enrollment) | Telemetry, heartbeats, command ack |
| Admin → Server | JWT/OAuth2 with RBAC (Admin/Analyst/ReadOnly roles) | All management HTTP endpoints |
| Enrollment | Token-based (already exists, needs enforcement) | Initial agent registration |
| Command approval | Multi-party (proposer ≠ approver, both authenticated) | Destructive commands (wipe, isolate) |

**Effort**: 2-3 weeks. This is the #1 priority across the entire roadmap.

#### H. Network Isolation (One-Click Contain)

**Current state**: Linux has no isolation capability. Windows WFP is a stub. CrowdStrike's one-click isolation is one of its most-used features during incident response.

**Implementation plan**:
- **Linux**: eBPF XDP program for packet filtering (fastest possible — runs before the kernel network stack). Allow only management server IP. Alternative: nftables rules via `nft` command.
- **Windows**: WFP filters (already scaffolded, needs real implementation)
- **Both**: Persist isolation across reboots, provide de-isolation via server command AND local admin escape hatch, log all blocked connections for forensics.

**Effort**: 2-3 weeks (parallel Linux + Windows development).

#### I. SIEM/SOAR Integration (Enterprise Table-Stakes)

**Current state**: No log forwarding, no webhook notifications, no third-party integrations.

**Why it matters**: Every enterprise buyer's first question is "does it integrate with our SIEM?" If the answer is no, the conversation ends.

**Implementation plan**:
1. **Syslog/CEF output**: Forward detection events in CEF (Common Event Format) over syslog. Compatible with Splunk, QRadar, Sentinel, ArcSight.
2. **Webhook notifications**: POST JSON to configurable URLs on detection events. Enables SOAR integration (Cortex XSOAR, Swimlane, Tines).
3. **REST API documentation**: OpenAPI/Swagger spec for the existing HTTP endpoints. Enables programmatic access.
4. **Pre-built connectors**: Start with Splunk HEC (HTTP Event Collector) and Microsoft Sentinel — these cover ~60% of enterprise SIEMs.

**Effort**: 2-3 weeks for syslog + webhooks + API docs.

---

### 5.3 Leapfrog Opportunities (Where to Lead, Not Follow)

These are areas where eGuard can establish capabilities that CrowdStrike either doesn't have or can't easily build — creating genuine competitive moats.

#### J. BSOD-Proof Architecture (Post-Outage Market)

**Opportunity**: The July 2024 CrowdStrike outage is the most significant cybersecurity industry event in a decade. 8.5M Windows devices crashed. Airlines, hospitals, banks halted. The market is actively seeking alternatives with architecturally safer designs.

**eGuard's position**: eBPF on Linux is already BSOD-proof (kernel verifier prevents crashes). On Windows, eGuard uses ETW (user-mode) — it cannot crash the kernel.

**Action**:
1. **Commit to user-mode-only architecture**: Publicly commit that eGuard will never install a kernel driver on Windows. This is a bold but defensible position — Microsoft's new Windows Resilience Platform APIs (private preview mid-2025) are designed to enable user-mode security.
2. **Adopt Microsoft VBS (Virtualization-Based Security)**: When available, use VBS enclaves for tamper-proof detection. This provides kernel-equivalent visibility without kernel-mode risk.
3. **Content update safety**: Implement staged rollout for rule updates (canary → 1% → 10% → 100%) with automatic rollback on crash/error. CrowdStrike's content update was the root cause — eGuard must have better content update hygiene.
4. **System impact SLA**: Guarantee < 1% CPU, < 50MB RAM, zero kernel panics. Publish real benchmarks.

**Impact**: Directly addresses the #1 concern of every CrowdStrike customer: "will this crash my fleet?"

#### K. On-Premises / Air-Gapped Deployment (Sovereignty)

**Opportunity**: CrowdStrike requires cloud connectivity. Governments, military, critical infrastructure, and data-sovereignty-conscious organizations (EU GDPR, China's CSL) cannot or will not send security telemetry to a US-based cloud.

**eGuard's position**: The server component (`fe_eguard`) runs on-premises. No cloud dependency required.

**Action**:
1. **Position as "sovereign EDR"**: Deploy entirely within customer's network boundary. No data leaves the perimeter.
2. **Air-gapped mode**: Agent + server operate without internet. Rule updates via USB/sneakernet. Threat intel bundles synced manually.
3. **Data residency guarantees**: All telemetry stored in customer-controlled infrastructure. Compliance with EU GDPR, Schrems II, and national data sovereignty laws.
4. **Government/defense certifications**: Target Common Criteria EAL4+ and FedRAMP (self-hosted variant). CrowdStrike has FedRAMP for its cloud — eGuard can offer FedRAMP for customer-controlled deployment.

**Impact**: Opens an entire market segment (government, defense, critical infrastructure, EU enterprise) that CrowdStrike cannot serve well. This is estimated at 15-20% of the enterprise endpoint security market.

#### L. Transparent/Auditable Detection (Trust Architecture)

**Opportunity**: CrowdStrike's detection logic is a black box. Customers cannot inspect why an alert fired at a technical level. Post-outage, trust in opaque security vendors is at an all-time low.

**eGuard's position**: Open Sigma rules, auditable CUSUM math, explainable kill-chain templates.

**Action**:
1. **Per-alert evidence chain**: Every detection includes the full reasoning path — which layer triggered, which rule matched, what the CUSUM state was, what the KL divergence was. Exportable as structured JSON.
2. **Rule audit mode**: Run detection against historical events to validate rule effectiveness before deployment. "Would this rule have caught last month's incident?"
3. **Third-party audit program**: Offer source code access to qualified security auditors. Publish audit reports. CrowdStrike cannot do this — their detection IP is proprietary.
4. **Customer-extensible detection**: Allow customers to write their own Sigma/YARA rules and deploy them to their fleet. CrowdStrike offers limited custom IOC capability but not custom behavioral rules.

**Impact**: Appeals to CISOs who demand explainability and auditability. The question "can you explain why this alert fired?" is unanswerable with CrowdStrike — eGuard can answer it mathematically.

#### M. Agent-Side Threat Intelligence at the Edge

**Opportunity**: CrowdStrike requires cloud connectivity for full detection. Edge detection (on the agent itself) reduces latency and works in intermittent connectivity scenarios.

**eGuard's position**: Layer 1 IOC matching runs entirely on-agent with Aho-Corasick multi-pattern matching. Behavioral detection (CUSUM) runs on-agent. Kill-chain detection runs on-agent.

**Action**:
1. **Bloom filter IOC matching**: Push large IOC sets (millions of hashes) to agents via compact bloom filters. O(1) lookup with configurable false positive rate. Agent checks every file hash, network connection, DNS query locally — no cloud roundtrip.
2. **Edge-first detection**: All 5 detection layers run on the agent. Server correlation is additive, not required. Agent can detect and respond in complete isolation.
3. **Bandwidth-efficient sync**: Delta-compressed rule bundles (already implemented via semantic versioning). On a 56kbps satellite link, eGuard still updates.
4. **Offline forensics**: If connectivity is lost, agent buffers events locally (SQLite buffer exists) and replays through detection on reconnect.

**Impact**: Works in challenging environments (ships, aircraft, remote sites, battlefield networks) where CrowdStrike's cloud-dependent model fails.

#### N. Lightweight Pricing (Market Disruption)

**Opportunity**: CrowdStrike pricing is $60-185/device/year base, with add-on modules pushing total cost to $300-500/device/year for full platform. This prices out SMBs and mid-market.

**eGuard's position**: Self-hosted, no per-device licensing for the server component.

**Action**:
1. **Flat-rate or open-core pricing**: Base EDR + compliance included. Advanced features (threat intel, SOAR, managed response) as add-ons.
2. **Community edition**: Free for < 50 endpoints. This builds adoption and creates upsell pipeline.
3. **MSP/MSSP program**: Multi-tenant server for managed service providers. Per-tenant pricing, not per-endpoint.
4. **Total cost comparison**: Publish TCO calculator showing eGuard vs CrowdStrike for 100/1000/10000 endpoints including infrastructure costs.

**Impact**: Captures the 60% of the market that cannot afford CrowdStrike. SentinelOne and Cortex XDR compete on features — eGuard can compete on value.

#### O. Automated Response Playbooks (SOAR-Integrated)

**Opportunity**: CrowdStrike's Falcon Fusion SOAR is powerful but complex. Many organizations have SOAR tools (Cortex XSOAR, Swimlane) but struggle to integrate EDR.

**eGuard's position**: The response crate already has `PlannedAction` with confidence-based escalation. Auto-isolation has configurable thresholds.

**Action**:
1. **YAML playbook engine**: Define response workflows in version-controlled YAML:
   ```yaml
   playbook: ransomware_response
   trigger:
     layer4_template: killchain_ransomware
     confidence: ">= high"
   actions:
     - kill_process_tree: true
     - quarantine_file: true
     - isolate_host:
         if: confidence >= definite
     - notify:
         webhook: https://slack.example.com/hook
         message: "Ransomware detected on {{ hostname }}"
   ```
2. **Dry-run mode**: Test playbooks against historical events before enabling autonomous response.
3. **Human-in-the-loop gates**: Configurable approval requirements for destructive actions. "Isolate requires SOC analyst approval within 5 minutes, auto-isolate after timeout."
4. **Playbook versioning and audit trail**: Full history of every playbook execution with outcome.

**Impact**: Bridges EDR and SOAR. Reduces MTTR from minutes to seconds for known attack patterns without requiring a separate SOAR platform.

#### P. Cross-Endpoint Correlation (EDR → XDR)

**Opportunity**: CrowdStrike's Threat Graph correlates events across millions of endpoints. eGuard's server-side correlator already exists but is limited to per-agent analysis.

**Action**:
1. **Multi-agent campaign detection**: The replay module (`detection/src/replay.rs`) already has `correlate_campaign_iocs()` and `CampaignIncident` with severity levels (Advisory/Elevated/Outbreak). Wire this into the server's live telemetry pipeline.
2. **Lateral movement correlation**: "If agent A sees outbound SMB to agent B's IP, AND agent B sees new service creation within 5 minutes, escalate to Outbreak."
3. **Fleet-wide behavioral baselines**: Compute normal behavior distributions across all agents. Detect individual agents that deviate from the fleet norm (compromised or misconfigured).
4. **Attack timeline visualization**: Render multi-host attack chains as a directed graph in the admin UI. Show the kill chain across endpoints, not just within one.

**Impact**: This is the transition from EDR to XDR. It's the most-requested enterprise feature and the highest-value differentiation.

---

### 5.4 Priority Roadmap: Path to CrowdStrike Parity and Beyond

#### Phase 1: Foundation (Months 1-2) — "Can We Be Deployed?"

| # | Item | Effort | Rationale |
|---|------|--------|-----------|
| 1 | Authentication on all server endpoints (G) | 2-3 weeks | Hard blocker for any deployment |
| 2 | Fix P0 audit findings (Part 4) | 1-2 weeks | Security bugs that would fail any pentest |
| 3 | SIEM integration: syslog/CEF + webhooks (I) | 2-3 weeks | Enterprise procurement requirement |
| 4 | Fix event processing bottleneck (AC-11: 10 events/sec) | 4 hours | Agent misses majority of events under load |
| 5 | Fix IPv4 byte order in eBPF codec (PL-1) | 2 hours | All network detection rules produce wrong IPs |

**Milestone**: eGuard can be deployed in a Linux-only environment with basic SIEM integration and authenticated management.

#### Phase 2: Windows Production (Months 2-4) — "Can We Protect Windows?"

| # | Item | Effort | Rationale |
|---|------|--------|-----------|
| 6 | Windows ETW real event collection (E, Phase 1) | 2-3 weeks | Foundation for all Windows detection |
| 7 | Windows AMSI → detection engine (E, Phase 2) | 1-2 weeks | Fileless malware detection |
| 8 | Windows response actions (E, Phase 3) | 1-2 weeks | Kill, quarantine, forensic capture |
| 9 | Windows WFP network isolation (E, Phase 4 + H) | 2-3 weeks | One-click host containment |
| 10 | Windows code signing + MSI (E, Phase 7) | 1 week | Enterprise deployment via GPO/Intune |
| 11 | Network isolation on Linux (eBPF XDP) (H) | 1-2 weeks | Feature parity across platforms |

**Milestone**: eGuard protects both Linux and Windows endpoints with detection, response, and isolation capabilities.

#### Phase 3: Differentiation (Months 4-6) — "Why Choose Us Over CrowdStrike?"

| # | Item | Effort | Rationale |
|---|------|--------|-----------|
| 12 | BSOD-proof marketing + content update safety (J) | 1-2 weeks | Post-outage market positioning |
| 13 | Transparent detection evidence chains (L) | 2-3 weeks | Explainability differentiator |
| 14 | YAML response playbooks (O) | 2-3 weeks | Automated SOAR without separate platform |
| 15 | Cross-endpoint correlation — MVP (P) | 3-4 weeks | EDR → XDR transition |
| 16 | eBPF CO-RE + container hardening (B) | 2-3 weeks | Modern Linux infrastructure leadership |
| 17 | Sovereign/air-gapped deployment mode (K) | 2-3 weeks | Government/defense market access |

**Milestone**: eGuard has clear differentiators vs CrowdStrike in transparency, reliability, and sovereignty.

#### Phase 4: Platform Expansion (Months 6-12) — "Full Enterprise Coverage"

| # | Item | Effort | Rationale |
|---|------|--------|-----------|
| 18 | macOS Endpoint Security Framework (F) | 1-2 months | Third platform coverage |
| 19 | Windows compliance probes (real WMI/registry) | 2-3 weeks | CIS benchmark compliance on Windows |
| 20 | Behavioral ML retraining pipeline | 1-2 months | Keep Layer 5 model current against novel threats |
| 21 | Detection rule marketplace (C) | 1 month | Community-driven detection content |
| 22 | Multi-tenant server (K) | 2-3 months | MSSP/SaaS delivery model |
| 23 | Advanced forensics (memory dump, registry capture) | 1 month | Incident response depth |

**Milestone**: Full enterprise EDR platform competitive with CrowdStrike on features, differentiated on architecture.

---

### 5.5 Competitive Positioning Summary

| Dimension | CrowdStrike | eGuard (Current) | eGuard (After Roadmap) | eGuard Advantage |
|-----------|------------|-------------------|----------------------|------------------|
| **Detection math** | Black-box ML | 5-layer with provable bounds | Same + published proofs | Explainability, auditability |
| **Kernel safety** | Ring-0 driver (BSOD risk) | eBPF (Linux), ETW (Windows) | Same, committed user-mode | Cannot crash the OS |
| **Detection rules** | Proprietary | Sigma (open standard) | + marketplace + community | Portability, community |
| **Compliance** | Separate add-on ($) | Built-in with auto-remediation | + CIS benchmarks + real-time drift | Included, not upsold |
| **Deployment** | Cloud-only SaaS | Self-hosted | + air-gapped + sovereign | Data sovereignty |
| **Pricing** | $60-500/device/year | Self-hosted (infra cost) | + community edition | 3-10x cheaper |
| **Transparency** | Closed source | Open rules, auditable math | + evidence chains + audit program | Full explainability |
| **Windows** | Production (Ring-0) | Scaffold (stubs) | Production (ETW + AMSI + WFP) | User-mode only (safer) |
| **macOS** | Production (ESF) | Stub | Production (ESF) | Parity |
| **Cloud/XDR** | Threat Graph (1T events/day) | Basic correlator | Cross-endpoint + campaign | Smaller scale but sufficient |
| **AI/Automation** | Charlotte AI (7 agents) | CUSUM + kill-chain | + YAML playbooks + SOAR | Deterministic, auditable |
| **Post-outage trust** | Damaged, recovering | No kernel risk | Marketed explicitly | Architecture advantage |

**Strategic narrative**: *"eGuard is the endpoint security platform that can prove its detection works, cannot crash your operating system, keeps your data in your infrastructure, and costs a fraction of the alternatives. Built on open standards, mathematically rigorous detection, and an architecture designed for the post-CrowdStrike-outage world."*
