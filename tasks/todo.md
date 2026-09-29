# F15 review follow-up — Linux 5.4 and time namespaces

- [x] Guard modern task start field with CO-RE existence and fall back to Linux 5.4 real_start_time.
- [x] Normalize raw boot nanoseconds with the proc reader's time-namespace offset; fail visible on ambiguous/unreadable offsets.
- [x] Wire host header checks into Zig and Linux 5.4 target-BTF relocation checks into CI.
- [x] Prove regressions, run touched module/required suites, commit and refresh export.

Design: exact event/event generations remain raw; only raw/proc comparisons apply the namespace offset. A different time_for_children namespace cannot supply a trustworthy reader offset and fails visible. Linux 5.4 compatibility checks use upstream libbpf relocation logic against the checksum-pinned Ubuntu 5.4.0-26-generic BTF image, without privileged attachment. Also declare the common header as a Zig system-command input: otherwise a header-only change reuses stale objects.

Review validation: `zig build agent-artifacts ebpf-check -Dlinux54-btf=/tmp/5.4.0-26-generic.btf` passes the host harness and all 18 ring/perf objects against actual Ubuntu Linux 5.4 BTF. The new `core_generation.c` regression fails its required-existence/legacy-read assertion on separately compiled objects from both fb-start-b1-generation and first-pass HEAD (exit 134); no privileged load is claimed. The injected-offset regression fails on the first-pass conversion through a test-only adapter (200 ticks vs expected 901), then passes restored; base predates this cross-clock conversion, so namespace proof specifically targets the introduced first-pass regression. The original task's base suppression/codec proofs above remain valid.

Rust validation: agent policy 111/111, reviewfix 13/13, payload_integrity 9/9, telemetry_pipeline 17/17, injected offset 1/1; platform-linux default 99/99. Optional libbpf feature build passes; feature tests 101 pass and one pre-existing ungated `from_elf_requires_feature_flag_when_disabled` fails (function byte-identical to base); skipping that one yields 101/101. Agent fmt, Zig fmt, shell syntax and diff checks pass. Workspace fmt still fails only the two reviewed baseline-identical grpc-client/proto_tests.rs and platform-windows/compliance/screen_lock.rs blobs. No unrelated fixes.

Residual/follow-up: privileged 5.4/live time-namespace attachment remains untested; the BTF check validates libbpf relocations and the host harness exercises both accessor branches, not the kernel verifier. Different time/time_for_children namespaces deliberately fail visible. CI downloads a checksum-pinned 5.4 BTF archive and needs network availability plus existing libbpf build prerequisites. Detailed second-pass logs: /tmp/b1-second-*.log (copied to followups validation directory).

# F15 — emission-time process generations (b1-generation)

- [x] Version shared eBPF header; capture TGID/real-parent leader generations via CO-RE.
- [x] Extend typed RawEvent identities across producers and legacy/v2 codecs.
- [x] Bind suppression to emitted identities, with proc clock-tick compatibility for legacy records.
- [x] Prove delayed PID, parent mismatch, tick fallback, codec and worker-leader regressions fail on the base tag.
- [x] Finish broader suites, record build/format results, commit and export.

Design approved with supervisor: event PID and parent PID are TGIDs, so generation reads follow group_leader (not worker task start). V2 sets event-type high bit and appends two u64s; old 21-byte records remain readable with None generations. Tests use exact nanoseconds for two emitted identities, and CLK_TCK granularity only when crossing to proc ticks.

Baseline proof: stashed implementation and transplanted tests onto fb-start-b1-generation (30305f1), adding only inert RawEvent/C struct fields and default constructor fields to compile. delayed_event_cannot_bind_reused_pid_generation, delayed_parent_event_requires_emitted_parent_generation, and event_generation_fallback_compares_proc_at_clock_tick_granularity failed suppression assertions (6 existing tests passed). generation_header_round_trips_and_preserves_legacy_records failed its v2 version-bit assertion. The host header harness failed its leader-generation assertion with only C struct schema transplanted (version-bit assertion omitted for that baseline run). Restored implementation: all pass. Logs: /tmp/b1-baseline-{agent,codec,header}.log.

Validation so far: zig build agent-artifacts passes for all 18 ring/perf objects; all contain start_boottime BTF and process_exec has BTF.ext. Host C worker/parent-leader harness passes. Linux 99, macOS 44, Windows 116 tests pass; Windows GNU and macOS aarch64 cross-checks pass. Required agent filters: policy 111, reviewfix 13, payload_integrity 9 pass. Touched-crate fmt passes except the unchanged Windows screen_lock.rs:34 baseline formatting; touched Windows files pass rustfmt. Acceptance tests were attempted but cannot compile because baseline tests_rsp_contract.rs ResponseReport lacks action_type_label (verified unchanged in base tag). No unrelated fix included. Live privileged BPF attachment remains unvalidated (host EPERM). Legacy/missing generations intentionally retain proc/other-platform fallback limitations.

Final module sweep: 90 passed, 3 failed, 1 ignored in 1362s. Failures are the two listed async-worker queue tests and memory_layout_ledger_sums_to_target_rss_envelope; the latter was reproduced on pristine fb-start-b1-generation (fixed budgets total 18.3 MiB, asserted minimum 20 MiB). The long observability_snapshot_reports_bounded_command_backlog_progress test eventually passed; isolated on pristine base with timeout 300, --test-threads=1 --nocapture it times out (124), proving pre-existing scan-fixture slowness. A filtered sweep excluding those four tests passes 89 tests (+1 ignored benchmark). The optional full-agent sweep was interrupted after 145 passing tests to focus on touched modules. No test process remains running. Baseline evidence: /tmp/b1-baseline-memory.log and /tmp/b1-baseline-slow.log. Final validation logs are exported under /home/dimas/eguard-lab-soak/followups/b1-generation-validation/; patch: fb-start-b1-generation.patch. Follow-up: privileged kernel smoke/soak with the newly built objects, and independent fixes for the pre-existing test/format blockers.

# F13/F14 — decoded fallback follow-up

- [x] Add a regression proving naked escaped paths remain opaque (verify failure first).
- [x] Remove decoded fallback KV reparsing; audit Linux/Windows decoder callers.
- [x] Run requested Linux/agent tests and formatting; commit and export patch.

Review: both new regressions failed on b9a497b, then passed after removing Linux fallback KV reparsing (FileOpen/FileWrite/FileUnlink and FileRename). Full platform-linux: 98 passed; agent tests_payload_integrity: 6 passed; platform-linux fmt check passed. Cargo commands used timeout 1500 and the assigned target directory. Agent tests emitted nonfatal libbpf EPERM warnings; live privileged BPF was not validated.

Caller audit: Linux parse_payload_metadata -> decode -> parse_payload_fallback now consumes opaque values; Linux parse_kv_fields decodes only after raw splitting. Windows parse_payload_metadata -> decode -> parse_payload_fallback already consumes opaque values; Windows parse_kv_fields decodes only after raw splitting; Windows enrich_event_with_cache ModuleLoad fallback decodes then normalizes a path only. No other callers found by grep of parse_payload_fallback/decode_payload_value in both crates (apart from a Linux decoder assertion). Windows unchanged; its tests were not required/rerun. FileRename naked fallback still produces no metadata, as before for ordinary opaque inputs. Patch export: /home/dimas/eguard-lab-soak/f13-f14.patch.

# F13/F14 — payload integrity and process generations

- [x] Audit all producers/consumers; escape Linux/Windows values and decode before detection/telemetry.
- [x] Reject ambiguous security fields and bind Linux tracked PIDs to proc start times.
- [x] Add codec, ingest, compatibility, and PID-reuse regressions; run requested suites.
- [x] Prepare commit/export and document platform limits and producer inventory.

Review: see `tasks/f13-f14-review.md` for full producer/consumer inventory, design, results and residual risks. New agent suite 6/6, Linux 96/96, host Windows 116/116, policy 111/111; all requested agent filters pass; Windows GNU cross-check passes. Agent/Linux fmt and touched Windows rustfmt pass; full Windows fmt has a proven pre-existing screen_lock.rs:34 failure.

Plan checked with supervisor: raw ModuleLoad fallback must decode; macOS sanitation remains unchanged by explicit scope decision. Final audit identified macOS JSON fallback ancestry injection; a supervisor-approved platform-agnostic guard rejects JSON ancestry without changing telemetry.

# F1 — authenticate internal subprocess suppression

- [x] Audit marker launch sites and remove spoofable parent-name authentication.
- [x] Gate Linux markers on root systemd service membership; retain negative cache and PID ancestry.
- [x] Cover forged real-process marker, forged parent comm, direct-child preservation, and cgroup hierarchy parsing.
- [x] Run requested regression filters, formatting, and scoped clippy review; export committed patch.

Review: marker recognition now requires exact numeric `eguard-agent-update-*.service` or `eguard-agent-self-restart-*.service` beneath `/system.slice/`. Unified hierarchy takes precedence; supervisor-approved legacy `name=systemd` fallback preserves update/restart suppression on cgroup-v1 hosts. Direct Command children retain the agent PPID; tracked descendants remain unchanged. No launcher changes needed.

Validation: internal_process 5/5, suppress 8/8, negative 2/2, priority 9/9, tests_reviewfix 13/13, tests_ebpf_policy 111/111; agent-core fmt and diff checks pass. Clippy is blocked by pre-existing modulo-one errors in rule_bundle_loader.rs:245,270; touched file warnings concern unchanged question-mark/collapsible-if code only. Tests run without privileged eBPF loading (EPERM diagnostics).

Residual: root attackers remain outside the trust model. Missing/unreadable proc files fail toward visibility; nested/delegated cgroups are not accepted. Non-Linux marker behavior remains false. Actual systemd transient-unit integration was not exercised in this environment. Existing comm-based narrow noise filters are outside this all-process-suppression fix.

# Reviewfix3 — send before control plane

- [x] Restore first-evaluation flush before scheduling; restore base command dispatch.
- [x] Bound additional evaluations by response capacity and envelope batch size.
- [x] Replace obsolete barrier tests with failure/recovery, terminal ordering, and response-capacity regressions.
- [x] Run requested suites and benchmark five interleaved memory rounds; commit/export accompanies this entry.

Review: telemetry stage flushes the first evaluation before control-plane scheduling; only additional evaluations queue for the final send (at most two sends). Empty end-of-tick queues do not retry buffered telemetry. Command dispatch and config parsing are byte-identical to 9cdb193; terminal spool barrier/classification removed. Additional drain stops at half response capacity or a full envelope batch; shared response budget and attempt-all recovery remain.

Validation: reviewfix 9/9; all five new failure/recovery/terminal/capacity regressions fail on actual 1467a58 with test-only seams. Policy 111/111; drain 4/4, batch 7/7, priority 6/6, dequeue 2/2, negative cache 1/1, scheduler 6/6, agent buffer 4/4. Response 44 pass/1 known fail; command 70 pass/1 known fail/1 ignored; control plane 25 pass/1 known fail; grpc buffer 11 pass/1 known fail. The previously failing degraded response test passed this run. Agent-core fmt, non-test cargo check, release build, diff check pass. Full command suite completed in 1025 seconds. Archived validation and red-test shims: `/home/dimas/eguard-lab-soak/bench/validation-reviewfix3.md`.

Benchmark: final-source binary, five interleaved memory rounds per batch versus ec0c9d2: median µs/raw-consumed +7.42% (50), -1.42% (200). An earlier equivalent-guard spelling measured +24.81%/-3.11%; retained separately, not discarded. Mixed/noisy results do not establish no-regression. Report: `/home/dimas/eguard-lab-soak/bench/results-reviewfix3.md`; patch: `/home/dimas/eguard-lab-soak/reviewfix3.patch`.

Residual: F9 buffer durability/failed-enqueue/old-tail ordering limitations unchanged; capacity guards apply between evaluations (one policy evaluation can emit multiple actions/alerts). The benchmark is degraded/local-only, not connected transport validation.

# Reviewfix2 — terminal-only spooling and FIFO recovery

- [x] Read re-review and narrow spool failure gating to terminal command dispatch (including config self-restart).
- [x] Hold new overflow until send outcome; attempt all recovery enqueues in old-batch/new-overflow order.
- [x] Add SQLite FIFO, event-bearing maintenance, and terminal side-effect/failure regressions.
- [x] Run requested regression suites and verify existing failures on 9cdb193.
- [x] Benchmark ec0c9d2 versus fixed code, export patch and results.

Review: final-source reviewfix tests 6/6, policy 111/111, priority 6/6, dequeue 2/2, negative cache 1/1, connected tick 1/1, scheduler 6/6, agent buffer 3/3. Response 42 pass/2 fail; command 70 pass/1 fail/1 ignored; control plane 26 pass/1 fail; grpc buffer 11 pass/1 fail. All five failures reproduce on 9cdb193. Agent-core fmt and diff check pass; workspace fmt has the same two unrelated baseline diffs (grpc proto tests and Windows screen lock).

Benchmark: five interleaved memory rounds per batch; median cost change +7.13% (50), -9.16% (200), noisy/mixed. One isolated SQLite pair: +5.47% cost at 200, diagnostic only, both database files verified non-empty and no fallback warning. Report: `/home/dimas/eguard-lab-soak/bench/results-reviewfix2.md`; patch: `/home/dimas/eguard-lab-soak/reviewfix2.patch`. Benchmark binaries precede only the final connected-success send-duration metric placement correction (and test/documentation refinements); that path is not exercised by the degraded fixture. Supervisor accepted measurements without rerun; exact binary SHA-256 provenance is in the report.

Scope: F9 remains deferred (failed-item loss, destructive drain crash window, old-tail requeue order, memory fallback durability); no buffer API redesign. Supersedes B1 stage-wide gating described below.

# Throughput review blockers

- [x] Spool tick telemetry before control-plane execution (B1).
- [x] Attempt every buffering operation and count send failures before recovery (B2/B3).
- [x] Share one response execution budget across a tick (B4).
- [x] Add four regressions and validate requested suites; all four fail on ec0c9d2 with test-only injection/extraction shims.
- [ ] Compare five interleaved benchmark rounds and export patch (external report: `/home/dimas/eguard-lab-soak/bench/results-reviewfix.md`).

Review: four new tests, 111 eBPF policy tests (including connected batching/drain), four priority tests, dequeue sampling, negative-cache and three agent-core buffer tests pass. Response filter: 42 pass, two fail; child-kill passes isolated, async-worker dispatch reproduces on ec0c9d2. Command filter: 70 pass, one ignored, offline isolation failure reproduces on ec0c9d2. Extra grpc-client buffer suite: 11 pass, default-cap mismatch reproduces on ec0c9d2. Fmt passes; Clippy has identical baseline warning counts and two existing modulo_one errors (no new touched-file warnings). Recovery preserves order inside each batch but the existing tail-requeue ordering caveat remains. Failed individual enqueues are counted/logged, not retained by a new buffer API. B1 deliberately gates all control-plane work on successful spooling; it adds buffer writes before commands rather than changing command semantics.

# Priority parsing hotspot (perf/tick-drain)

- [x] Verify profile: stable comparison sort repeatedly parses FileOpen payloads via raw_event_priority.
- [x] Cache priority keys for the batch sort; preserve stable ordering and all detection decisions.
- [x] Add counted-key regression, run requested tests/fmt/Clippy, commit and export patch.

Review: regression fails with comparison sorting (some events classified 258 times), passes with cached keys (once/event), and checks stable ties. Requested connected/drain tests pass individually; 111 eBPF policy tests, module test, 6 telemetry tests and fmt pass. Clippy remains blocked by existing rule_bundle_loader modulo_one errors; no new touched-file warnings (existing warnings at telemetry_pipeline lines 561 and 1020 are unchanged). No events skip evaluation; exec/new binaries and IOC files retain existing behavior. Cached sort adds O(batch size) temporary key storage. Production 500/s soak throughput remains to be measured.

# Connected tick telemetry batching (perf/tick-drain)

- [x] Collect connected event envelopes and compliance alerts in a tick-local runtime vector; flush once after evaluation drain.
- [x] Bound each flush to EVENT_BATCH_SIZE, retain overflow, and buffer collected events on early error or degraded transition.
- [x] Preserve send timeout/failure handling and add 50-tick pipeline stats.
- [x] Add connected multi-event failure regression; confirm it fails against ecc269a.
- [x] Validate targeted tests, telemetry tests, eBPF policy suite, formatting, and touched-file Clippy diagnostics.

Review: agent-core is a binary-only package, so requested `--lib` commands have no target; equivalent binary tests pass (1 new regression, 1 drain regression, 5 telemetry, 111 policy tests). Existing Clippy modulo_one errors remain; no new touched-file warnings after adjusting the stats cadence check. No tasks/threads/channels introduced. Connected alerts wait until end of tick; transport remains bounded by the existing five-second timeout.

# Task Plan — macOS real-bundle startup/restart readiness

## Objective
Restore as much post-restart macOS detection coverage as possible with the real threat-intel bundle enabled, without cheating on the benchmark and without regressing steady-state resource targets.

## Current validated baseline
- Async real-bundle agent base: `4993bc3`
- Benchmark-best ingest branch remains **25/25** on the standard battery
- Mechanism: source-level eslogger high/low priority ingest split + targeted suppression of obviously low-value low-priority macOS indexing/cache churn
- Stricter forced startup-bootstrap harness (valid seeded local last-known-good archive): now also **25/25**, reproduced on two consecutive clean-restart runs, using a dedicated **ProcessExec reserve lane** ahead of the existing high/low lanes
- Remaining concern is no longer the old `M17/M18` detection gap; it is now **resource variance**, especially CPU burstiness under the strict startup-bundle harness

## Hypothesis for this loop
- Generic restart-readiness on the benchmark path is solved by the ingest changes.
- The honest strict startup-bundle path is now also solved for detection count by reserving ProcessExec continuity, which proved more stable than blanket shared-high-lane inflation.
- Before chasing CPU variance or LKG persistence further, the normal-path baseline must be made trustworthy again: two unvalidated local diffs in `tick.rs` and `telemetry_pipeline.rs` are still present and likely contaminating results.
- If reverting those files restores the expected benchmark behavior, the next loop can return to the real remaining issues: LKG persistence/correctness and eslogger CPU.

## Plan
- [x] Keep the current 25/25 source-ingest branch as the working baseline.
- [x] Use the seeded local last-known-good archive harness when testing long-term real-bundle startup behavior.
- [x] Investigate the prior forced-startup-bootstrap misses and confirm they were tied to a ~27s process-exec hole.
- [x] Discard blunt shared-high-lane inflation (`ESLOGGER_HIGH_PRIORITY_CAP=8192`) as unstable.
- [x] Validate a dedicated ProcessExec reserve lane as the strongest current strict-harness path.
- [ ] Revert the unvalidated local diffs in `crates/agent-core/src/lifecycle/tick.rs` and `crates/agent-core/src/lifecycle/telemetry_pipeline.rs`.
- [ ] Rebuild/redeploy the restored baseline and re-run the normal benchmark path.
- [x] Only after baseline hygiene is re-established, continue on LKG persistence / eslogger CPU investigations.
- [ ] Test whether dropping `fork` from the default macOS eslogger subscription reduces high-lane noise / eslogger CPU without sacrificing real detections.
- [ ] Update `autoresearch.ideas.md` with the baseline-hygiene finding and prune stale/shared-high-lane tuning.

## Review Log
- Resumed from compacted context.
- Re-read `autoresearch.md`, `autoresearch.ideas.md`, recent git history, and recent experiment log entries.
- Reconfirmed that `bundle_path = ""` in live `agent.conf`, so the remaining startup issue is not a synchronous config-driven bundle load in `AgentRuntime::new()`.
- Reconfirmed that representative missed post-restart commands are often absent from backend process telemetry entirely, which points to capture/backpressure rather than pure rule semantics.
- Observed recent backend noise dominated by low-value macOS Spotlight `mds_stores` file events.
- Tested `.noindex` extraction dirs for bundle unpack worktrees; deployment worked, but the primary metric regressed to 13/25.
- Tested raw Spotlight/system noise suppression before backlog enqueue; result stayed at 13/25 and shifted detections later instead of fixing the restart window.
- Confirmed a more structural live-state issue: `rules-staging` can contain the preserved bundle archive plus replay-floor state while `threat-intel-last-known-good.v1.json` is still missing.
- Manually seeded a valid `threat-intel-last-known-good.v1.json` on the VM as a diagnostic. That improved restart coverage only modestly (14/25, early M2-M7 recovered) and was then removed for environment hygiene.
- Tested extra per-tick backlog drain under backpressure; it regressed to 12/25 and was discarded.
- Current code hypothesis in flight: if a local bundle archive exists but last-known-good state is missing, startup should fall back to the replay-floor archive automatically.
- Proved an additional control-plane issue: with transport mode `grpc`, the endpoint could stay healthy while never materializing `rules-staging`; switching the VM to `http` transport immediately restored bundle download/extraction.
- A source-level gRPC->HTTP threat-intel fetch fallback reproduced that bundle materialization under gRPC mode too, but once the real bundle came back the benchmark regressed to 11/25, so startup/restart readiness under real load is still the main bottleneck.
- Startup-grace tuning around extracted-tree reuse is now effectively ruled out as a main path: 15s improved one run only to 13/25, a 10s variant matched 15/25 once, then regressed to 10/25 on confirmation.
- Archive-only and extracted-tree reuse both help too little on their own. The remaining cost is likely rule/model compilation or restart-window event readiness, not decompression alone.
- Tested faster plain rule-loader pacing (100ms after every 8 rule files instead of 2s after every rule). Initial warmup looked better, but the full battery regressed sharply to 10/25.
- Tested a state-based startup gate for bundle reload start (heartbeat attempt + low raw backlog). That improved over the aggressive loader-only branch but still only reached 12/25.
- New concrete evidence from the state-gated run: once the real bundle actually loads, the macOS IOC exact-store can balloon to roughly 552MB on disk (`ioc-exact-store-14728.sqlite`). Rebuilding that artifact on restart is now a top suspect.
- While prototyping bundle-scoped exact-store reuse, verified that the current real bundle carries roughly 361 SIGMA files and 2891 YARA files. With the current 2s-per-file yield cadence, the loader can spend on the order of ~1.8 hours before even reaching IOC loading, which explains why short warmups never exercised the exact-store reuse path cleanly.
- Tested dynamic backpressure-aware pacing of the existing full startup bootstrap, exercised with a valid seeded local last-known-good archive so the path definitely ran. It still regressed badly to 9/25, which means smarter pacing of the same monolithic load is not enough.
- Implemented source-level eslogger high/low priority ingest splitting and recovered the entire post-M5 `M1-M15` cluster, reaching 22/25.
- Added targeted suppression of obviously low-value low-priority macOS indexing/cache churn on top of that ingest split and reproduced 25/25 on two consecutive clean-restart runs.
- Follow-up fairness tweaks did not beat the 25/25 keep: bigger low/file queues, selective file promotion, and stale-age tuning only rotated which part of the battery was sacrificed.
- Integrity-checked the winning ingest branch under a stricter real-startup-bootstrap harness by seeding a valid local last-known-good archive. That initially improved the honest startup-bundle path to 23/25, but still left later misses.
- Backend analysis of that stricter harness found a real ~27s process-exec hole around the missing `M17/M18` pair, which shifted the next hypothesis from low-file-lane tuning to process-exec continuity.
- Tested a blunt shared-high-lane expansion (`ESLOGGER_HIGH_PRIORITY_CAP=8192`): it restored 25/25 once under the strict harness, but regressed to 21/25 on confirmation by sacrificing the early `M1-M4` cluster, so it was discarded.
- Tested a narrower dedicated ProcessExec reserve lane ahead of the existing high/low lanes. That reproduced 25/25 on two consecutive seeded-LKG forced-startup-bootstrap runs, making exec-specific reservation the strongest current path for the honest startup-bundle case.
- Characterized idle CPU on the exec-reserved-lane variant under the seeded-LKG strict harness: roughly 13.7% at 2m, 8.4% at 5m, and 15.4% at 8m, with RSS staying around 92-93MB. Detection is now stable there, but CPU still exceeds the long-term <5% target.
- Validated that the always-on ProcessExec reserve lane and the conditional reserve-lane variants are both not safe as general replacements for the normal path; they regressed to 21/25 and 23/25 respectively.
- After restoring the intended baseline source path to the VM, a hygiene validation still landed at 24/25 with only M17 missing.
- Live diagnostics after that run showed two important signals:
  - `eslogger` itself was the hottest process in `ps` (far above `eguard-agent` in the same snapshot)
  - the newest extracted bundle worktree sat unchanged for at least 120s at 3321 files while `threat-intel-last-known-good.v1.json` still remained absent
- That shifts the next likely product issue from queue topology alone toward either (a) LKG persistence/correctness or (b) eslogger event-volume/resource behavior while real bundle activity is present.
- Tested a simpler normal-path change: removed `fork` from the default macOS eslogger subscription. That reproduced 25/25 on two consecutive standard non-seeded runs, making it the strongest current simplification on the normal path.
- The next unresolved question is whether that same no-`fork` variant also holds up under the stricter seeded-LKG startup-bundle harness.

---

## Task Plan — Windows stable agent identity across restarts

## Objective
Fix the Windows root cause that creates multiple agent identities for the same host across service restarts, so the server/UI sees one stable endpoint identity instead of PID-based ghost rows.

## Hypothesis
- The Windows agent currently falls back to PID-based `agent-<pid>` identity when `HOSTNAME` and Linux machine-id sources are unavailable.
- Enrollment currently also derives hostname from `HOSTNAME`, so Windows can enroll with an unstable hostname fallback as well.
- Because server-side dedup keys off hostname + OS, missing/unstable Windows hostname at enrollment lets each restart create a new row.

## Plan
- [ ] Inspect Windows identity generation and enrollment hostname resolution paths.
- [ ] Make Windows identity/hostname resolution use a stable Windows source (`COMPUTERNAME`) before PID fallback.
- [ ] Add regression tests covering Windows-style env resolution.
- [ ] Build and, if needed, deploy to the lab VM to verify repeated restarts keep one agent identity.

## Windows self-protect fix release update 2026-05-10T07:58Z
- Pushed `release/v15.0.0-clean` with commit `19ee55e fix(self-protect): keep timing anomalies non-terminal`.
- Triggered GitHub Actions `Release Agent (All Platforms)` run `25623002992` for `version=v15.0.0`; Windows package artifacts were produced and downloaded to `/home/dimas/eguard-agent/artifacts/fixed-windows-25623002992`.
- Fixed Windows artifacts staged into the eGuard server package directories on eg-1 and eg-2:
  - `/usr/local/eg/var/agent-packages/windows/eguard-agent-15.0.0-x64.msi`
  - `/usr/local/eg/var/agent-packages/windows/eguard-agent-15.0.0.exe`
  - `/usr/local/eg/var/agent-packages/msi/eguard-agent-15.0.0-x64.msi`
  - `/usr/local/eg/var/agent-packages/exe/eguard-agent-15.0.0.exe`
- Normal MSI upgrade on stale WINAD2022 failed because the old protected service could not stop (`Error 1921`), proving a separate maintenance/upgrade self-protection seam remains.
- Bounded endpoint-only forced remediation installed the fixed MSI successfully and restored live Windows heartbeat:
  - `msiexec_exit=0`
  - service running with `CanStop=True`
  - server DB row `WINAD2022 active` with fresh ~30s heartbeats
  - eg-1 tcpdump captured live Windows gRPC traffic to `192.168.122.25:50053`
- Evidence lives in `/home/dimas/fe_eguard/tasks/evidence/`:
  - `windows-fixed-agent-upgrade-20260510T074307Z/`
  - `windows-fixed-agent-forced-remediation-20260510T074925Z/`
  - `final-agent-live-snapshot-20260510T075714Z.txt`
- Remaining product follow-up: make self-protection/installer maintenance mode allow supported stop/upgrade/uninstall without a forced process kill, while preserving tamper resistance outside maintenance.

## Plan — Windows supported maintenance upgrade path

## Objective
Allow trusted Windows MSI/installer upgrades to stop and replace `eGuardAgent` without ad hoc `taskkill`, while preserving self-protection/tamper resistance during normal operation.

## Current evidence
- Normal MSI upgrade of the stale lab agent failed with `Error 1921` because service `eGuardAgent` could not be stopped.
- Old service state before forced remediation: `CanStop=False`, `Status=Running`.
- Forced endpoint-only remediation succeeded by disabling service start, killing old PID, running MSI, restoring automatic start/failure actions.
- Fixed post-install service reports `CanStop=True`, so the latest MSI/service configuration may already improve this seam, but we still need source-level confirmation and a supported test path.

## Work items
- [ ] Wait for `code-explorer` and `security-reviewer` subagent reports:
  - `/home/dimas/eguard-agent/tasks/subagent-windows-maintenance-upgrade-code-map.md`
  - `/home/dimas/eguard-agent/tasks/subagent-windows-maintenance-mode-security.md`
- [ ] Inspect Windows service registration in MSI/WiX/scripts and runtime service control handler behavior.
- [ ] Determine whether `CanStop=True` after fixed MSI is intentional, sufficient, and safe.
- [ ] If source change is needed, implement minimal maintenance-mode support with tests.
- [ ] Validate with a normal MSI reinstall/repair or upgrade path on WINAD2022 without forced process kill.
- [ ] Document final supported operator procedure and security assumptions.

## Windows maintenance upgrade investigation result 2026-05-10T08:08Z
- Security reviewer completed: `/home/dimas/eguard-agent/tasks/subagent-windows-maintenance-mode-security.md`.
- Code explorer stalled and was interrupted; direct code map written: `/home/dimas/eguard-agent/tasks/windows-maintenance-upgrade-code-map-direct.md`.
- Current fixed MSI/runtime already supports normal SCM Stop:
  - `crates/agent-core/src/main.rs` advertises STOP by default via `resolve_windows_service_stop_control_policy_fast() -> true`.
  - `installer/windows/eguard-agent.wxs` uses `ServiceControl Stop="both" Wait="yes"`.
- Lab proof after fixed MSI:
  - `Stop-Service eGuardAgent` succeeded without `taskkill`.
  - `Start-Service eGuardAgent` succeeded.
  - `CanStop=True` after restart.
  - server heartbeats/compliance resumed.
  - evidence in `/home/dimas/fe_eguard/tasks/evidence/windows-fixed-agent-supported-restart-20260510T080201Z/` and `/home/dimas/fe_eguard/tasks/evidence/windows-supported-restart-followup-20260510T080635Z.txt`.
- Interpretation:
  - old `CanStop=False` state was a stale/wedged installed product problem requiring one-time endpoint remediation.
  - current fixed package does not require a new source patch to support normal SCM stop/start.
- Remaining follow-ups:
  - remove or gate `taskkill /F` fallback in `crates/agent-core/src/lifecycle/command_pipeline/update_agent/worker_windows.rs`.
  - avoid temporary SCM failure-action/start-mode mutation during updater flow where possible.
  - add tests/docs for Windows service stop policy and supported MSI maintenance workflow.
  - add fe_eguard server tests/docs for package alias precedence or migrate to a single package layout.

---

## Task Plan — Protected-path hardening for autonomous quarantine

## Objective
Prevent autonomous quarantine from damaging core Linux OS files through direct paths, usr-merge aliases, intermediate symlinks, or runtime/state roots.

## Plan
- [x] Read the hardening spec and relevant response/quarantine code before editing.
- [x] Review prior protected-path commit `ece5d48` before editing.
- [x] Extend Linux protected paths for usr-merge aliases, pseudo/runtime roots, eGuard state, and critical `/var/lib` state without protecting all `/var` or `/home`.
- [x] Canonicalize existing quarantine source paths at the destructive primitive and re-check protection before move/copy.
- [x] Add regression coverage for `/etc/fstab`, alias roots, protected state roots, intermediate symlink bypass, and ordinary quarantine behavior.
- [x] Apply security-review additions for lib variants, `/root`, Debian package state roots, canonical report path, and unprotected intermediate-symlink happy path.

## Checks
- [x] `cargo test -p response default_linux_protected_paths_match_acceptance_baseline` — passed.
- [x] `cargo test -p response quarantine_rejects_intermediate_symlink_into_protected_root` — passed.
- [x] `cargo test -p response quarantine_allows_intermediate_symlink_to_unprotected_target_and_reports_canonical_path` — passed.
- [x] `rustfmt --edition 2021 --check crates/response/src/lib.rs crates/response/src/quarantine.rs crates/response/src/tests.rs crates/response/src/quarantine/tests.rs` — passed.
- [x] `cargo test -p agent-core response_pipeline::tests` — passed.
- [x] `cargo fmt --all -- --check` — failed on unrelated pre-existing formatting in `crates/agent-core/src/lifecycle/command_pipeline/update_agent/worker_macos.rs` and `crates/platform-windows/src/compliance/screen_lock.rs`; not changed for this task.
- [x] `cargo test -p response` — failed on unrelated pre-existing expectations/permissions tests; targeted hardening tests passed.

## Review Result
- Minimal response-only hardening implemented; security-review protected-root and canonical-report fixes applied.
- No deployment or commit performed.


---

## Task Plan — Quarantine rate limit circuit breaker

## Objective
Enforce the configured per-minute quarantine limit before destructive quarantine filesystem mutation.

## Plan
- [x] Add `max_quarantines_per_minute` to response config with default `5`.
- [x] Parse/persist the limit from TOML, environment, enrollment snapshots, and policy sync.
- [x] Reuse the existing rolling one-minute limiter for an independent quarantine quota.
- [x] Reject rate-limited quarantine attempts before mutation with `quarantine_skipped:rate_limited`.
- [x] Add focused config, persistence, policy, and action tests.

## Checks
- [x] `rustfmt --edition 2021 --check` on changed Rust files — passed.
- [x] `cargo test -p agent-core file_config_is_loaded` — passed.
- [x] `cargo test -p agent-core env_overrides_file_config` — passed.
- [x] `cargo test -p agent-core persist_runtime_config_snapshot_writes_restart_safe_values` — passed.
- [x] `cargo test -p agent-core policy_response_overrides_update_runtime_response_config` — passed.
- [x] `cargo test -p agent-core quarantine_rate_limiter_skips_second_file_without_consuming_kill_quota` — passed.
- [x] `cargo test -p agent-core response_pipeline::tests` — passed.
- [x] `git diff --check` — passed.

## Review Result
- Minimal quarantine circuit breaker implemented; existing protected-path hardening diff preserved.
- Broader pre-existing failures from prior report were not rerun: `cargo fmt --all -- --check` had unrelated formatting failures in `crates/agent-core/src/lifecycle/command_pipeline/update_agent/worker_macos.rs` and `crates/platform-windows/src/compliance/screen_lock.rs`; `cargo test -p response` had unrelated pre-existing response expectation/permission failures.
- No deployment or commit performed.

## Bounded dequeue sampling
- [x] Cap sampling candidate examinations at twice the skip budget; preserve high priorities/order.
- [x] Prove regression test fails unbounded implementation; run requested tests, fmt and clippy.
- [ ] Commit minimal fix, benchmark three revisions interleaved, publish patch/results externally.
Review: regression measured 4007 classifications before, at most 14 after (stride 8).
All requested tests pass, including 111 eBPF policy tests; fmt passes. Clippy has
only pre-existing touched-file warnings and the two known rule_bundle_loader modulo-one errors.

## Local eval throughput benchmark
- [x] Add portable ignored fixture; verify baseline APIs.
- [x] Build four release binaries and run interleaved batches 50/200.
- [x] Review sanity/noise, commit fixture, publish external results.

Baseline release sanity passed: 10 ticks, 15 dequeued raw events, 10 telemetry events.
Approved validity adjustments: cfg(test) shim exercises actual ingest/sort/cap (enqueue alone does not);
detached sleep PIDs avoid automatic agent-child suppression and retain real /proc parent lineage.
Primary cost includes separately measured ingest + tick; requested tick-only metrics remain available.

Review: all four release/offline builds and 40 interleaved runs passed. External runner,
raw JSON, binary hashes, load samples, and median/min-max tables are in
`/home/dimas/eguard-lab-soak/bench/` (`results.md`). Cached-sort vs batch-send total
median cost changed +0.25% (batch 50) and -1.87% (batch 200): no measurable end-to-end
change and no evidence of the claimed 70% regression. Current medians are 5,105.67 and
15,678.28 us/consumed raw event respectively. Cached batch-50 spread is 16.9% (noisy);
drain batch-200 spread is 15.1%. Other groups are below 15%. Consumption includes
sampling; baseline strict-mode extras explain >1 raw event/tick. Separate ingest timing
does not debit the production drain budget, so delivered-rate ceilings remain synthetic.
No production behavior/dependency changes and no /proc caching implementation.

## Reviewfix4
- [x] Read final review and inventory event-fed drop-oldest queues.
- [x] Restore per-envelope first-stage sends and guard all event-fed queues.
- [x] Add discriminating tests, run requested regressions/fmt (no benchmark).
- [x] Commit and export reviewfix4.patch.

Review: tests_reviewfix 12/12, tests_ebpf_policy 111/111, priority_tests 4/4;
fmt and diff whitespace checks pass. Replacing only production files with a74205c
made all three new tests fail (first batches [258] instead of [257,2], report
queue 256 instead of 128, IOC guard consumed an event instead of stopping).
Additional-drain guards cover response actions, response reports and IOC signals.
Control-plane tasks/sends and completed-command cursor are not evaluation-fed;
raw backlog is ingress-fed and separately capped. Half-capacity guards leave
headroom, but cannot bound arbitrary fanout within a single evaluation.
Validation logs and queue inventory: /home/dimas/eguard-lab-soak/validation-reviewfix4.md.

# Offline drain retention (reviewfix5)

- [x] Add degraded-only byte headroom guard without changing first evaluation.
- [x] Add sentinel FIFO regression; prove failure on 26d0bbd.
- [x] Run requested suites and fmt; commit and export patch.

Review: degraded_drain_preserves_oldest_buffered_sentinels failed against unchanged
26d0bbd production code (oldest retained sentinel was 14, not 0). With the guard,
tests_reviewfix 13/13, tests_ebpf_policy 111/111, priority_tests 4/4 and fmt pass.
Only one pending_bytes query is made before degraded draining; actual enqueued
envelope estimates account for added bytes. Connected and first-evaluation paths
retain their behavior. Supervisor approved threshold-only protection: an oversized
single envelope exceeding the 10% reserve can still evict. No benchmark run.
Patch: /home/dimas/eguard-lab-soak/reviewfix5.patch.

## b2-windows: generation-bound suppression
- [x] Inspect ETW creation identity, suppression lookup, and macOS ES representation.
- [x] Carry Windows creation times and revalidate tracked identities with an injectable reader.
- [x] Prove focused regressions against baseline; run host and cross-target checks.
- [x] Commit and export follow-up patch (commit SHA recorded in followups/STATUS.md).

Design: reuse typed generation fields with Windows Unix-epoch nanoseconds (checked FILETIME conversion); fail open to telemetry when parent identity is unknown or a live query fails. macOS unchanged: the current JSON ES decoder extracts audit-token PID/UID, not creation time. Live Windows validation remains a follow-up.

Review: platform-windows 117 tests passed; telemetry_pipeline 19 passed; tests_payload_integrity 11 passed; tests_ebpf_policy 111 passed; tests_reviewfix 13 passed. Windows GNU cross-check passed without extra features. Touched-crate fmt check reports only the known untouched screen_lock.rs difference; git diff --check passed. Baseline proof restored telemetry_pipeline.rs and codec.rs from fb-start-b2-windows in this worktree, retaining new tests and inert test-only runtime selector: both Windows suppression regressions failed at their security assertions, and the codec regression failed with None vs Some(12345678900). Restored implementation passes all three. Logs: /tmp/b2-{baseline-agent,baseline-codec,payload,pipeline,ebpf,review,win-test,cross,fmt}.log. No dependencies added. Residual: native Windows ETW/GetProcessTimes soak is not performed; unavailable process queries intentionally increase visible telemetry.

## b2-windows second pass
- [x] Carry ETW schema version and test old/current identity layouts.
- [x] Replace undefined exit FILETIME liveness with documented wait state.
- [x] Avoid live reads for unauthenticated candidates; prove regressions and run required validation.

Review: platform-windows 119/119; telemetry_pipeline 20/20 (including payload integrity 12/12); tests_ebpf_policy 111/111; tests_reviewfix 13/13. Windows GNU check passed without features. Changed-file rustfmt and diff checks passed; touched-crate cargo fmt reports only baseline-identical screen_lock.rs:34 (git diff against fb-start is empty). Logs: /tmp/b2-second-{win,cross,payload,pipeline,ebpf,review,fmt}.log.

Differential proof: versioned fixture with version-discarding compatibility adapters fails on fb-start (missing generation) and cb027c3 (v3 sequence mistaken for creation), /tmp/b2-second-{baseline,parent}-codec.log. Query-avoidance test fails with cb027c3 production pipeline restored, /tmp/b2-second-parent-syscalls.log; it intentionally restores original baseline performance, so cannot fail fb-start. First-pass baseline generation/missing/unknown-parent failures remain recorded in /tmp/b2-baseline-{agent,codec}.log. Host liveness test exercises live/dead wait-state policy; native API wait behavior remains a Windows follow-up, not a claimed host integration test.

Pre-existing schema issues left unchanged: baseline codec treats ProcessStart v0 image as offset 24 (manifest v0 has no Flags, image offset 20); Stop v0/v1 image as UTF-16 at 24 (manifest uses ANSI at 48/76). Evidence: git show fb-start-b2-windows:crates/platform-windows/src/etw/codec.rs, and airbus-cert/etl-parser e9ad559f8ba2cd192a1c6be2011f514dad46c3a2 Microsoft_Windows_Kernel_Process.py lines 12–46 and 72–111. Generation offsets are unaffected. New v3 Start/v2 Stop paths decode their own image fields correctly. macOS remains unchanged. Native Windows ETW and process-handle wait validation is out of scope; unavailable query/synchronize access fails toward visible telemetry.

## b2 current-schema follow-up
- [x] Accept known Windows Start v3-v5 and preserve unknown-version visibility without identity trust.
- [x] Decode macOS audit-token pidversion with fixture tests; document opaque semantics.
- [x] Prove v4 regression on ca522d1, validate, commit and export patch.

Review: Start v3/v4/v5 synthetic fixtures follow the cited 24H2/26H1 manifests, including appended SecurityMitigations, PartitionID and ProcessMachine. Unknown Start >5 and Stop >2 remain visible even for short payloads, never carry either generation, and warn at most once per version per process. The modern SID/image lookup no longer drops truncated records.

macOS now takes process and parent pidversion from exec.target (not the pre-exec actor) or process for exit/other events. Reduced realistic eslogger fixtures cover exec/exit and missing-generation behavior; start_time strings are deliberately not mixed with opaque counters. Pipeline tracked-generation comparisons use same-variant equality; live macOS revalidation remains unchanged because this Linux host has no host-testable native audit-token reader. This corrects earlier notes claiming eslogger identity is unavailable.

Validation: platform-windows 120/120; platform-macos 45/45 (Linux-host tests only); Windows GNU cross-check passed; agent-core tests_payload_integrity 12/12, tests_reviewfix 13/13, tests_ebpf_policy 111/111. Final v3/v4/v5 test fails with ca522d1 production restored (v4 returns None, exit 101), then passes with the fix. Logs: /tmp/b2-third-{fail-proof,windows,platforms,cross,tests_payload_integrity,tests_reviewfix,tests_ebpf_policy,fmt}.log. Touched-file rustfmt and diff check pass; cargo fmt --check still reports only baseline-identical untouched compliance/screen_lock.rs:34. Residual: no native Windows/macOS validation, live macOS identity revalidation remains a follow-up, legacy Windows image-offset issues remain unchanged.
