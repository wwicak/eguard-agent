# Throughput work: follow-ups

Context: branch `perf/tick-drain` (ecc269a..ec0c9d2). Local benchmark
(`lifecycle::bench_eval_throughput`, ignored test) at 50 events/tick:
82 -> 394 sustainable events/s, overflow drops 8454 -> 0. Lab soak (4625336):
server events/s 11 -> 48 at ~500/s offered. Reports: `/home/dimas/eguard-lab-soak/`.

## F1 (security): EGUARD_INTERNAL_SUBPROCESS env marker is an evasion path
Any process can set `EGUARD_INTERNAL_SUBPROCESS=1` in its own environment before
exec; `is_marked_internal_process` (lifecycle/telemetry_pipeline.rs) then
suppresses all of its events. Fix direction: only honour the marker when the
process (or its ancestor chain) is a child of the agent PID, or replace the env
marker with agent-owned state (e.g. PIDs recorded at spawn by
`mark_internal_command`).

## F2 (observability): heartbeat hides telemetry outages
During a lab run the agent was degraded with `events_sent=0` for two full soak
steps while heartbeat stayed fresh. Server needs an "events stopped arriving"
signal per agent (and the agent could report `buffer_pending` / degraded cause
in heartbeat).

## F3 (reliability): tamper-degraded after enrollment rewrites agent.conf
Observed once on a fresh Ubuntu 24.04 install: enrollment rewrote `agent.conf`
after the config-integrity baseline was taken, so the agent flagged tampering.
Likely a race between enrollment persistence and the integrity baseline.

## F4 (performance): remaining per-event cost
At 2000 events/s the agent still drops most raw events. Remaining cost is spread
across evaluate_raw_event (baseline learn_event JSON serialization, enrichment,
envelope build) and repeated `k=v` payload parsing (`parse_payload_field`).
Next structural step: typed RawEvent fields instead of the payload string.
Measure with the benchmark before/after.

## F5 (tooling): clippy blocked
Pre-existing `clippy::modulo_one` errors in `lifecycle/rule_bundle_loader.rs`
block `cargo clippy -p agent-core --all-targets`.

## F6 (review should-fix #5): drain budgets are not hard bounds
40ms/512 limits are checked only between returned events; one poll can preprocess
thousands of records and one dequeue can scan a long run of filtered entries before the
control-plane stage. Pass a deadline/candidate budget through poll/ingest/dequeue.

## F7 (review should-fix #6): no cap on tick-local telemetry vector
A policy with >2048 unique noncompliant checks clears dedupe state per evaluation, so
compliance alerts can be regenerated repeatedly within one drain tick. Reject over-limit
policies and cap tick_telemetry (spill to offline buffer).

## F8 (review nit #7): metrics/semantics
last_send_event_batch_micros measures an in-memory push until flush; draining is now
unconditional rather than gated by strict_budget_mode; old per-drain log removed.

## F9 (pre-existing, reviewer escalation): offline buffer is not ownership-preserving
SQLite drain_batch deletes+commits rows before the network send (grpc-client/src/buffer.rs
~153-197): a crash/reboot between drain and requeue loses the batch; a failed enqueue loses
that event. Same behaviour on 9cdb193. Fix direction: peek/ack (lease) API for the offline
buffer, SQLite-backed tests. Also: terminal commands should require durable storage when
the memory-buffer fallback is active.
Also F9: on a failed send, the drained batch (up to EVENT_BATCH_SIZE oldest rows) is requeued at the tail, behind any older rows still in the buffer (same as 9cdb193). Fix belongs to the peek/ack redesign.

## F10 (pre-existing test failures, reproduced on 9cdb193)
async_worker_queue_dispatches_response_reports; degraded_tick_executes_local_response_and_preserves_response_report_queue;
command_pipeline_executes_offline_and_caps_completed_cursor; async_worker_queue_dispatches_control_plane_sends;
default_buffer_cap_matches_acceptance_limit. Also workspace fmt diffs in proto_tests.rs and Windows screen_lock.rs.

## F11 (pre-existing, same on 9cdb193): unbounded per-evaluation fanout
One evaluation can overflow drop-oldest queues by itself: a playbook with >128 alert/log
actions (response report queue, cap 256) or >512 matched signatures (IOC buffer, cap 1024).
Fix: hard-cap per-evaluation fanout (playbook actions, matched signatures kept as IOCs).

## F12 (edge, bounded): offline-retention guard starts only in Degraded mode
While still Connected but failing sends, a tick's end-of-tick batch (<= EVENT_BATCH_SIZE
drained envelopes) is requeued into the offline buffer and can evict oldest rows if it is
full. Bounded to DEGRADE_AFTER_SEND_FAILURES (3) ticks before the degraded guard applies.
Fix option: also apply the headroom guard when consecutive_send_failures > 0.

## F13 (security, pre-existing): payload delimiter injection forges trusted fields
Linux codec (platform-linux/src/ebpf/codec.rs ~142-150) emits `path=` unescaped before
`ppid=`; parse_payload_field takes the first match. openat("/tmp/x;ppid=<agent-pid>")
makes malware look like an agent child -> suppressed 15 min with descendants. Same in
Windows ETW codec (platform-windows/src/etw/codec.rs ~150-179). In progress.

## F14 (security, pre-existing): PID reuse inherits internal-process suppression
suppressed_internal_process_pids is keyed by PID only, 15-min TTL; Linux has no exit
probe, so a reused PID of a finished agent child stays trusted. In progress.
## F15 (security, residual of F14 on Linux): generation bound at consumption, not emission
Tracked-PID start time is read from /proc when the event is processed; if an internal child
exits and its PID is reused before its queued event is consumed, the new process's start time
is trusted. Proper fix: capture task start_time (child and parent) in the eBPF record
(zig/ebpf + codec), cache that identity. Needs lab validation.

## F16 (security, pre-existing): Windows PID reuse inherits internal-process suppression
Non-Linux generation is always 0; ETW ProcessStop can drop (etw/consumer.rs ~233) leaving the
PID trusted 15 min. Fix: bind to ETW ProcessStart CreateTime (parsed but discarded in
etw/codec.rs ~81-90) + GetProcessTimes on lookup. Requires Windows lab validation.

## STATUS (closing round, pushed ci/macos-signing 0333176; server followups/telemetry-health ae39798)
- DONE: F1, F13, F14 (earlier); F2 (server ae39798 + agent test ef8c428); F3 (9ea9e9e); F5/F10 (6a37b49); F7/F8/F12 (de6d978); F9 peek/ack + safe dir perms (6c866af); F11 (2a11015); F15 kernel generations, lab PASS (297cf44); F16 Windows ETW v3-v5 + macOS pidversion (aad1c6a).
- WONT-FIX: F6 dequeue budget: filtered candidates are consumed once (bounded by raw backlog cap); a budget only defers work and increases overflow loss.
- OPEN: F4 typed RawEvent (remove k=v payload strings). F17 base-identical failures: alternate_grpc_server_addr_switches_known_agent_ports, runtime_bootstrap_restores_last_known_good_bundle_after_restart, acceptance lib test missing ResponseReport.action_type_label. F18 fe_eguard agent/server full suite fails with NAC enabled (fingerbank) - base-identical. F19 server stores agent-reported heartbeat time; store receipt time. F20 native validation: Windows (ETW v3-v5, GetProcessTimes) and macOS (eslogger pidversion). F21 SQLite init fallback to volatile memory buffer. F22 monitored-path aliasing in self-protect. F23 slow enroll-race tests (hash /proc/self/exe).

## F25 (base-identical): failing tests found during F4a validation
- lifecycle::tests_pkg_contract::package_build_harness_executes_and_emits_metrics_with_mocked_toolchain fails at 0333176 in isolation (status.success() at tests_pkg_contract.rs:754).
- memory_layout_ledger_sums_to_target_rss_envelope fails in isolation (ledger 18.3 MiB < required 20 MiB), byte-identical at base.
- config::util identity tests are flaky only under parallel execution (shared env vars).
- full acceptance suite: 7 failures reproduced on base (F17 lane evidence).

## F26: self-protect config-permission enforcement uses hard-coded paths
crates/agent-core/src/lifecycle/self_protect.rs ~186-190 enforces permissions on hard-coded /etc/eguard-agent/agent.conf, bootstrap.conf and certs/* instead of the configured paths, so it cannot be redirected in tests and ignores non-default install locations.

## F4 — DONE (pushed ci/macos-signing 1224af4)
- F4a+F4b (Linux typed RawEventFields, hot paths typed-first): merged 831eb20. F4c (Windows/macOS): merged 1224af4.
- Parity: tag-baseline goldens byte-identical (F4c: 1,299 records, sha256 5c5cb662...); differential matrices incl. 3,104 binary records.
- Windows typed hints only for Kernel-Process start v0-5 / stop v0-2 and Security 4688 v0-2 (allowlist platform-windows/src/lib.rs:882). macOS EventTxn keys stay payload-derived. Replay/offline JSON never typed.

## F27 — OPEN: native validation of Windows non-process ETW schemas
- File/Network/DNS/General/Image-Load are payload-only until their provider/opcode/version layouts are validated on a native Windows lab host; then extend the allowlist with per-version tests.
- Also still unverified natively: F4c on real ETW/eslogger collectors, and throughput on Windows/macOS.

## Post-v15.0.18 (pushed ci/macos-signing 18efb79, NOT tagged)
- b3c9dbb ebpf-check header test built for baseline CPU (cached native binary SIGILL on older CI runner).
- f682d84 deb install non-interactive (--force-confdef --force-confold, stdin closed) in self-update worker, apply-agent-update.sh, install-eguard-agent.sh. Lab upgrade 0.1.0 -> 15.0.18 hit the agent.conf conffile prompt, left the package half-configured, and systemd looped on the old unit (203/EXEC).
- 18efb79 compliance systemctl probe drops NOTIFY_SOCKET (systemd 255 systemctl sends EXIT_STATUS; 3 "reception only permitted for main PID" warnings per start).
- egclient01 (agentless lab VM): F20 had enabled Process Creation auditing and ProcessCreationIncludeCmdLine_Enabled (4719 event and key write both at 2026-09-29T15:06:11); both reverted. Note: the Windows agent enables these and never restores them on uninstall (product behaviour, open decision).

## F28 — OPEN (pre-existing): compliance::tests::unsupported_windows_legacy_checks_are_not_applicable fails at tests.rs:378 (result.status != "not_applicable"), also fails without the 18efb79 change.
## F29 — OPEN: soak at 2000 ev/s on v15.0.18 = 21.4 srv/s vs 36.6 for e86fc2d (first run, host load 12-16/16). Rerun was invalid (lab server stall 08:27-08:50). Re-measure that step on a quiet server; bisect only if it reproduces.
## F27 — BLOCKED: no Windows host approved for agent install (egclient01 is agentless-only).

## Closing round 3 (pushed ci/macos-signing 5f98e6a, NOT tagged; latest release still v15.0.18)
- F28 DONE 703b8e6: stale test; overall status for an all-N/A policy is "compliant" (wire enum has no NOT_APPLICABLE; others map to ERROR).
- F21 DONE 5f98e6a: release build 15.3-16.7s total (3/3 pass, load 10-12); debug budget 45s (still < 60s watchdog), release keeps 15s; bundled SQLite optimized in dev profile.
- F29 DONE: rate2000 rerun on quiet server: 35.3 / 31.6 srv/s vs 36.6 (e86fc2d); agent sent/s 29.5 / 27.2 vs 22.5. No regression; the first run's 21.4 was the server stall. Note RSS ~83 MB vs 75 MB.
- Lab: 192.168.122.25 known_hosts replaced (fingerprint verified via guest agent; backup known_hosts.bak-lab25). Lab SSH: root@192.168.122.25 with EGUARD_LAB_SSH_PASS (lab-ssh.sh). EG35_* vars are for the customer box 103.26.13.35, not the lab.
- Worktrees wt-f25, wt-f26, wt-i, wt-integ removed (clean and merged).
- F27 remains BLOCKED (no Windows host approved for agent install).

## v15.0.19 RELEASED (tag on 5f98e6a; release run 36950479100, all jobs green)
- Lab: RC .deb build + Debian 12 fresh install + upgrade on eg-ubuntu-soak keeps modified agent.conf (rc15019/report.md). Published 15.0.18 -> 15.0.19 server-pushed update PASS with server_addr :50053 (rc15019/push50053/). Manifest checksums verified for deb/rpm/exe/msi/pkg; macOS pkg notarized (Accepted) and stapled after the Apple agreement was renewed.
## F30 — OPEN: server-pushed update fails when server_addr uses port 50052
- update_agent/request.rs resolve_update_base_url: a relative package_url with server_addr host:50052 becomes https://host:50052/... (gRPC port, not HTTPS) -> curl fails. :50053 -> http://host:50053 works; no port -> https://host:1443 (needs a trusted cert). Pre-existing (same in 15.0.18). Customer installs default to :50053. Fix: map 50052 to http://host:50053 (sha256 from the command still verified).
- F30 FIX (ci/macos-signing, not tagged): a relative package_url now uses the gRPC client's scheme (https only when TLS certs are configured; 50053 stays http). Stock server 50052 is a plaintext h1/h2c Caddy proxy (api.conf), where http://host:50052/api/v1/agent-install/... returned 200 in the lab. Tests: request.rs relative_linux_update_urls_* (3 pass), update suite 30/30.
## Windows audit-policy restore on uninstall — DECIDED: keep current behaviour
- The agent does not record the prior Process Creation / command-line audit settings, so reverting at uninstall could disable auditing the customer enabled themselves. Revisit only if the installer starts saving the prior state.
- F30 LAB PASS (2026-10-02): 5c4c7a6 built as 15.0.18.1 on eg-ubuntu-soak (server_addr :50052, no TLS); server push of published 15.0.19 (command 6953b8ab) completed via http://192.168.122.25:50052/api/v1/agent-install/linux-deb?version=15.0.19; installed binary = published (1169a091...); agent.conf unchanged; server heartbeat 15.0.19. Evidence rc15019/f30/. Ships with the next tag (v15.0.20), no rush.
