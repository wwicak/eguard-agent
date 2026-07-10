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
