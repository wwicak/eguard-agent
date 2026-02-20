# eGuard Agent & Server — Full Security Audit Report

**Date**: 2026-02-20
**Scope**: Complete codebase audit of `eguard-agent` (Rust, 13 crates) and `fe_eguard` (Go server, EDR/MDM)
**Audited by**: 6 parallel review agents covering all source files

---

## Executive Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 15 | Production blockers, RCE vectors, authentication bypass |
| HIGH | 18 | Credential exposure, integrity failures, security bypass |
| IMPORTANT | 39 | Race conditions, resource leaks, logic errors, robustness gaps |
| MODERATE | 9 | Edge cases, false positives, minor correctness issues |
| **Total** | **81** | |

**Top 5 systemic themes:**
1. **No authentication on the server** — all HTTP/gRPC endpoints are fully open (3 findings across EDR+MDM audits)
2. **TLS/mTLS not enforced** — HTTP client ignores configured TLS, gRPC fallback strips mTLS, TOFU CA pinning
3. **Input validation gaps** — path traversal, command injection, template injection, TOML injection across agent+server
4. **In-memory mode fragility** — unbounded growth, TOCTOU races, dropped data, token bypass when DB is absent
5. **Platform stubs masking security gaps** — Windows anti-debug is env-var-only, quarantine doesn't restrict reads, file hash cache never invalidated

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
