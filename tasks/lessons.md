# Lessons Learned

## Breakout-Loop Discipline
When the user sets an explicit breakout condition (e.g., “continue until all blockers pass and surpass competitor”), do not pause with a completion-style response. Keep shipping incremental blocker reductions with fresh verification evidence every turn, and only call success signaling when objective proof exists.

## Re-read Updated Audit Docs Fully Before Continuing Implementation
When the user says a report/doc was updated, re-open the file and read it to the end (including offset continuation for truncated reads) before coding. Reconcile new sections (e.g., strategic roadmap updates) with the current task plan so fixes align with the latest source-of-truth, not stale context.

## Acceptance Criteria Must Be Updated And Referenced In Tests For New Audit Fixes
When implementing audit-driven behavior changes, update `ACCEPTANCE_CRITERIA.md` if criteria are missing and tag/align relevant tests to those AC IDs. Do not treat code-only fixes as complete without AC traceability.

## Threat-Intel Counts Must Not Depend On External Manifest Asset
Release assets may omit a standalone `manifest.json` even when the bundle contains
`./manifest.json` with full counts. Ingest logic must fallback to parsing the bundle
manifest itself; otherwise Sigma/YARA/IOC/CVE counters silently become 0/null.

## "No Stub" Means Closing Runtime + CI Loop, Not Just Source Patches
When users ask for polish/no-stub, do not stop at source commits. Push through to:
1) strict CI/workflow validation on latest main, 2) live runtime deployment where required,
3) post-deploy behavior proof (HTTP status, endpoint auth semantics, and end-to-end ingest logs).
A fix that exists only in code but not in running services is still incomplete.

## Corroboration Checks Should Run Once Per Reload, Then Enforce Shard Parity
If detection reload is sharded, expected-count corroboration against server metadata should happen
on the primary summary only. Additional shards should only be checked for deterministic parity
against shard 0. Otherwise the same mismatch warning/error is multiplied by shard count and
creates noisy, low-signal logs.

## Corroboration Must Respect Count Semantics Per Family
Do not use one-size-fits-all equality for all intel families. Current semantics differ:
- YARA manifest count behaves like file-level/source count while runtime tracks loaded rule count
  (runtime can legitimately be higher),
- IOC/CVE counts are stable and should remain exact-match checked,
- SIGMA exact count checks are unreliable until runtime dialect parity is implemented.
Use lower-bound checks where semantics require it and keep strict checks where data models align.

## Posture "n/a" Requires Data-Path Verification + E2E Coverage
When users report `n/a` in Endpoint posture fields, don't stop at UI inspection.
Trace the full path (enrollment/compliance/policy -> stored agent state -> detail API -> view)
and add an integration test that asserts key posture fields (`compliance_detail`, `policy_id`)
are populated under realistic agent-report flows. Keep in-memory behavior aligned with
persistence so local tests catch regressions before deploy.

## Live Runtime Can Drift From Repo DAL Models
A `n/a` in table columns can come from stale deployed DAL metadata, not missing DB values.
Always verify the live file under `/usr/local/eg/lib/eg/dal/*.pm` matches repo definitions
before assuming ingestion gaps.

## Normalize API Boolean-Like Values Before UI Rendering
For fields like `disk_encrypted`, APIs may send `0/1`, `"0"/"1"`, or real booleans.
Do not use strict `=== true/false` checks on raw payloads; normalize first, then render
`yes/no/n/a` consistently.

## Struct Field Changes Cascade
When adding fields to a widely-used struct (like `EventEnvelope`), search the
entire workspace for every constructor site. Use `rg 'StructName {' --glob '*.rs'`
and fix ALL of them before attempting to compile.

## Enum Ordering Matters for Derive
When adding `PartialOrd`/`Ord` to enums, the discriminant order determines the
comparison. List variants from lowest to highest (None, Low, Medium, High, VeryHigh,
Definite) to get natural ordering. Custom `Ord` impl is safer when semantics differ.

## Compression Ratio on Short Strings
LZ77-style compression gives ratio > 1.0 for very short strings (overhead > savings).
Gate information-theoretic analysis behind minimum length (≥20 bytes) to avoid
false signals.

## CUSUM False Alarms During Warmup
CUSUM detectors need a stabilization period. Don't feed behavioral CUSUM alarms
directly into anomaly signals without a magnitude threshold. Use `magnitude > 1.0`
for medium anomaly and `magnitude > 2.0` for high to avoid warmup FPs.

## Test Data Must Match IOC Database
Benchmark tests creating malicious events must seed the detection engine with
matching IOCs. `default_with_rules()` has minimal seed IOCs — use `load_ips()`,
`load_domains()`, `load_string_signatures()` in test setup.

## ts_unix is i64, not u64
The TelemetryEvent timestamp field is `i64` (signed). Always check field types
in the source struct before using them in new code.

## ML Should Only Escalate, Not Override
ML confidence should never downgrade deterministic decisions (IOC matches,
temporal rules). Design: `ml_enhanced_confidence(base, ml_score)` can only
move None→Medium, Low→Medium, Medium→High, High→VeryHigh when ML agrees
with high confidence. Never touches Definite/VeryHigh.

## Don't Plant IOCs In Benchmarks
Seeding the detection engine with the same IPs/domains used in test events
is circular testing — proves nothing except string matching works. Honest
benchmarks use `default_with_rules()` with zero planted IOCs and let the
engine detect through structural signals (entropy, port risk, uid=0, etc).

## CI Model Format ≠ Runtime Model Format
The Python training pipeline (`signature_ml_train_model.py`) outputs
`weights: {name: float}` + `feature_scales: {name: float}` (dict format).
The Rust runtime uses `weights: [float]` (positional array). Added
`CiTrainedModel` struct + `from_json_auto()` to bridge the two formats
in `layer5.rs`. Also wired `load_ml_model()` into `rule_bundle_loader.rs`.

## EICAR Test File and Shell Echo
`echo` adds a trailing newline which changes the SHA-256 hash.
Use `printf` instead: `printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-...'`

## VM Test With 9p Virtfs
QEMU 9p virtfs shares require `security_model=mapped-xattr` and the VM
must `mount -t 9p -o trans=virtio <tag> /mnt/<dir>`. Works well for
injecting agent binaries without modifying the base image.

## Layer 1 String Signature Result Must Be Set
**CRITICAL BUG FIXED**: `check_event()` in `layer1.rs` called `check_text()`
for `command_line` and `file_path` but only stored matches in
`matched_signatures` — it never set `hit.result = Layer1Result::ExactMatch`.
This meant `z1_exact_ioc` was false for ALL string signature matches.
Only hash/IP/domain matches were setting the result via `apply_result()`.
**Impact**: 0% → 80.8% TPR on 26 replay events after fix.
**Rule**: When adding new match paths in `check_event()`, always verify
the `result` field is upgraded, not just the match lists.

## Mock Server Flags
The Go mock `eg-agent-server` uses `-listen` (not `--listen-addr`), no
`-data-dir` or `--enrollment-token` flags. Check `--help` before scripting.

## Agent Logs Go To Stdout
The agent's tracing subscriber writes to stdout by default, not stderr.
Redirect stdout when capturing agent logs: `> log 2>&1`

## process_exe Fallback for Replay Events
For ProcessExec events, `process_exe` comes from `/proc/<pid>/exe` via
the enrichment cache. For replay PIDs that don't exist, this is `None`,
making `detection_event.process = "unknown"`. Fix: fall back to
`payload_meta.file_path` (which contains the executable path from
the binary payload's `path=` field) when `entry.process_exe` is None.

## Baseline Learning Disables Autonomous Response
`effective_response_config()` sets `autonomous_response = false` when
`baseline_store.status == Learning`. This means `plan_action()` always
returns `AlertOnly` during the learning phase. Detection still fires
(z1=true, confidence=Definite) but no kill/quarantine happens.
This is correct CrowdStrike-style behavior — learn first, enforce later.

## Heredoc $$ In VM Scripts
When generating VM scripts with nested heredocs, `$$` inside single-quoted
heredoc (`<< 'TAG'`) is literal and NOT expanded by bash. However, the
JSON parser in the agent sees `$$` as invalid JSON (not a number).
Use fixed PIDs (1001, 1002, etc.) instead.

## grep -c Returns Exit Code 1 When Count Is 0
`grep -c 'pattern' file || echo 0` produces "0\n0" because grep exits 1
when no matches. Use: `VAL=$(grep -c ... 2>/dev/null) || VAL=0`

## Cargo Env Not Loaded
If `cargo` is missing, source `"$HOME/.cargo/env"` before rerunning tests.

## Warn Before Ignoring Legitimate Request
When a user asks to "beat" a competitor, respond with scope-safe language
focused on defensive quality improvements. Don't interpret it as evasion or
offensive bypass. Keep guidance on reliability, accuracy, and safety.

## Acceptance Criteria Must Be Enforced
When the user emphasizes acceptance criteria, add or update tests tagged with
AC-\* identifiers and ensure CI gates fail on violations. Never ship changes
without updating acceptance/contract tests when behavior changes.

## Bundle Loading Was Not Wired Into Agent Startup
The `load_bundle_full()` and `load_bundle_rules()` functions existed in
`rule_bundle_loader.rs` but were NEVER called from `AgentRuntime::new()`.
The agent only used `build_detection_engine()` which loads hardcoded rules
from `detection_bootstrap.rs`. Fix: Added `detection_bundle_path` config
field + `EGUARD_BUNDLE_PATH` env var, and wired `load_bundle_full()` into
the shard builder closure in `new()`.

## ML Model Path in Bundle vs Runtime
CI `build_bundle.py` puts the ML model at `bundle/signature-ml-model.json`.
Agent `load_ml_model()` looked for `bundle_dir/signature-ml-model.json`.
When using separate dirs (rules/ml/), the model wasn't found. Fix: Added
fallback paths `ml/signature-ml-model.json` and `models/signature-ml-model.json`.

## Rust Borrow Checker — Self + Field Mut Borrow
`self.push_baseline(&mut self.info_entropy_baseline, value)` fails because
it borrows `self` mutably twice. Fix: Extract `push_baseline()` as a free
    function that takes `&mut VecDeque<f64>` instead of `&mut self`.

## Cross-Platform Path Heuristics
Detection logic must not hardcode Linux-only paths like `/home/`. Use
cross-platform path heuristics (Linux, macOS, Windows) and explicit
system/temp exclusions when gating file activity.

## Verify Repo Ownership Before Wiring Changes
When working across multiple repos, confirm which repo hosts the server
implementation before assuming locations or making wiring changes. Use the
path the user specifies (e.g., `/home/dimas/fe_eguard`) as the source of truth
and align integration notes and fixes to that repo.

## Avoid Baked Server IPs
Do not embed server IPs in agent binaries or default configs. Always rely on
bootstrap enrollment (`bootstrap.conf`), environment overrides, or DNS names
so deployments can change server addresses without rebuilding agents.

## Honor Advanced ML Requests
When the user asks for advanced/sophisticated ML math, do not keep a minimal
"lightweight" optimizer. Upgrade to stronger optimization (e.g., Newton/IRLS
or L-BFGS), add calibration/metrics, and document the advanced approach in the
training pipeline.

## Do Not Run Tests On User VM
When asked to verify or test, do not execute services or tests directly on the
user's VM. Use QEMU or another isolated environment for validation unless the
user explicitly approves running locally.

## Keep Test Imports Updated After Refactors
When refactoring modules and moving types (e.g., `AgentConfig`), update test
imports to use the new re-exports (e.g., `use crate::AgentConfig;`). Re-run
`cargo check` to catch E0433 errors early.

## Always Import Test Helper Types Explicitly
If LSP or rustc flags missing types in tests (e.g., `SharedDetectionState`,
`PathBuf`), add explicit `use` statements at the top of the test module.

## Avoid Re-exporting Private Helpers
When tests need helper types, import them directly from their module instead of
re-exporting from the root. If re-exporting is required, ensure the item is
public enough (or make it public) to avoid E0365.

## Run Test Compiles After Refactors
After refactoring a large module, run `cargo check --tests` and fix test-only
visibility/import issues (`pub(super)` helpers, missing std imports) early to
avoid a cascade of E0433/E0624 errors.

## Check Test Fixtures For Duplicate Fields
When editing structs in tests, avoid copy/paste duplication of fields (e.g.,
container_* entries in TelemetryEvent). Duplicate fields can mask real failures
and break compilation.

## Always Add Acceptance Criteria For New Work
When starting a new plan or integration audit, define or update acceptance
criteria (AC-GRP/AC-TST/AC-VER) before adding tests or wiring changes so
requirements are explicit and enforceable.

## Cover All Requested Platforms In Design Updates
If a design update spans multiple OSes, do not stop at Linux. Add Windows
and macOS sections with equivalent depth (checks, evidence, remediation),
so the design is cross-platform and complete.

## Avoid CI Dependencies On Optional Tools
CI runners may not have `rg` installed. When scripts only need simple
pattern checks, use `grep -E` or provide a fallback to avoid hard
failures in verification scripts.

## Docker Compose Build Context Must Be Repo Root
When Docker Compose files live under `tests/`, `context: .` resolves to
`tests/` and breaks COPY paths that expect the repo root. Use `context: ..`
(or an absolute path) so Dockerfiles can copy the full repository.

## YAML Heredoc Indentation
When embedding heredocs inside GitHub Actions `run: |` blocks, ensure every
line is indented to the block level. Unindented heredoc content breaks YAML
parsing. Use consistent indentation so YAML strips it correctly and the
shell receives valid scripts.

## CI Docker Builds Need Updated Rust Toolchains
Rust 2024 edition crates (e.g., time 0.3.47) require newer toolchains than
Rust 1.78. When Dockerfiles build in CI, pin to a recent Rust (>=1.88) to
avoid edition parsing errors.

## Avoid network_mode service for short-lived containers
`network_mode: service:<container>` fails if the target container exits
quickly (namespace removed). Prefer a single container or shared network
unless the target container stays alive.

## Verify Build Artifact Version Before Install Testing
Before starting system E2E on VMs, verify package artifact versions match the
requested release line (e.g., v15.x vs v14.x). Do not proceed with install
or rollout steps if artifacts are from the wrong major/minor stream.

## Detection Quality Trend Gates Should Track Enforcement Tiers
When trend gates monitor regression, focus on enforcement confidences
(focus/definite/very_high). High/medium tiers are advisory and can
introduce noisy regressions; keep them opt-in via env overrides.

## Adversary Emulation Baselines Must Match Corpus
When gating adversary emulation scores, compare against a baseline with
matching corpus signature (name/scenarios/events). Otherwise score drops
are false regressions. Reset baseline when corpus changes.

## Adversary Emulation Scores Should Weight Enforcement Tiers
Adversary emulation quality should prioritize focus/definite/very_high
confidence tiers. Keep the high tier weight at 0 unless explicitly
needed for advisory scoring.

## Do Not Bypass Configurator DB Bootstrap
For fresh eGuard installs, avoid manually creating app DB/user (`eg`) before
Configurator completes MySQL root setup. Manual bootstrap can desync expected
root/password flow and trigger "incorrect MySQL root password" errors in UI.
Use configurator-driven DB provisioning unless explicitly doing recovery work.

## Resolve Perl Runtime Deps From Official eguard-perl Package
When Perl compile/runtime errors mention missing/empty base modules (e.g.
`Net::Netmask`), verify and install dependencies from the release repo package
(`eguard-perl` for the target release) instead of assuming local env parity.

## Always Rebuild + Redeploy After Go Source Changes
Any edits under `fe_eguard/go/**` do nothing on VM until `go build` is rerun,
the new binary is copied to target (`/usr/local/eg/sbin/eg-agent-server`), and
the service is restarted. Treat this as mandatory after each Go patch.

## Edge-Case Validation Must Use Live Flows, Not Synthetic Stubs
When asked to continue E2E/edge-case testing, execute scenarios against the
real VM stack (actual API auth, DB persistence, live agent runs) and avoid
mock-only checks. Record concrete HTTP/DB evidence for each edge case.

## Be Proactive About VM Provisioning Ownership
If the user allows autonomous provisioning, do not wait for them to prep the
VM. Immediately verify topology, provision required runtime pieces (service,
proxy, configs), and continue E2E/edge validation end-to-end.

## Do Not Document Manual DB Seeding As Required Behavior
If an enrollment flow fails because a related record is missing (e.g. `node.mac`),
fix the persistence path to handle the edge case automatically. Documentation
must describe hardened product behavior, not temporary operator workarounds.

## Avoid Hardcoded Token Workflows In Docs/UI
Enrollment tokens must be org-specific and operator-provided at runtime.
Never publish hardcoded token examples as default workflow; provide token
selection/generation UX and variable-based command templates instead.

## UI Is A Product Requirement, Not Optional Polish
For every working feature/data path, ship a discoverable, responsive, intuitive
UI path (navigation, filters/actions, and clear operator workflows), not only
API/backend completion.

## Validate UI With Real Browser Automation
When user asks for UI E2E/hardening, run browser automation (browser-use) on
live routes and validate interaction edge cases (copy/selection/disabled states),
not only route/API checks.

## Clipboard APIs Need Permission-Denied Fallback
`navigator.clipboard.writeText` can fail in headless/automation contexts even
when UI is correct. Always add fallback copy path (`execCommand('copy')`) before
showing copy failure to users.

## If User Asks Full Product UI, Do Not Scope Down To MVP
When user explicitly asks for a fully-fledged UI, do not propose/ship an MVP.
Deliver complete operator workflows (CRUD, persistence, route/nav wiring,
edge-case handling, and real browser-E2E validation evidence).

## Apply Requested Design Skill + Existing Design System
When user asks to use frontend-design skill and align with existing style,
follow the skill process and map new UI to current design tokens/components
(`soc-*` system here) instead of introducing mismatched light-theme blocks.

## Optional/Absent Config Endpoints Must Fail Quietly (Only After Verifying Ownership)
If a deployment does not expose certain config endpoints (e.g.
`config/traffic_shaping_policies`), use quiet API calls for discovery/list
requests and explicitly handle `404/405/501` in store actions to avoid noisy
operator-facing "Unknown path" alerts.
But first verify whether the endpoint is truly unsupported vs accidentally
broken routing/wiring. Do not suppress errors that indicate a regression.

## MDM UX Is Not Complete Without Dedicated Operator Surfaces
Do not claim MDM delivery when only backend/API/plumbing exists. Ship explicit
MDM-first UI surfaces (dashboard, report view, and actionable data tables)
with route/nav discoverability so operators can immediately see and use MDM data.

## When User Provides Live Credentials, Execute Full Live Validation Immediately
If the user gives deployment access + credentials, do not stop at local build
claims. Deploy to the live host, log in with provided credentials, and run a
button/filter/pagination validation matrix in browser-use before declaring UI done.

## Always Update OpenAPI For Every API Endpoint Change
When adding, modifying, aliasing, or fixing API endpoints, update OpenAPI docs
in the same task (paths + schemas/responses/parameters + generated spec files)
before declaring work complete.

## Keep Slash/Hyphen Alias Endpoints Contract-Compatible
If API aliases exist (e.g. `/endpoint/...` and `/endpoint-...`), ensure payload
contracts and behavior are equivalent. Do not let one alias accept object JSON
while another only accepts string JSON; this breaks fallback clients and creates
silent policy assignment regressions.

## Don’t Stop At Frontend Mitigation When Backend Alias Is Missing
If an "Unknown path" error is caused by route-variant mismatch, frontend fallback
is only a temporary mitigation. Ship backend route parity (collection + resource
handlers) and then keep frontend fallback as resilience, not as the primary fix.

## Never `IFNULL` DATETIME To String In Go SQL Scan Paths
For MySQL datetime columns consumed by Go (`time.Time` / `sql.NullTime`), avoid
`IFNULL(col, '0000-00-00 00:00:00')` in SELECT lists. It changes column typing
and can trigger scan failures (`failed_load_*` at runtime). Prefer nullable
datetime scanning (`approved_at` -> `sql.NullTime`) and handle validity in code.

## Self-Protection Runtime Config Baseline Must Exclude Ephemeral Bootstrap Files
`/etc/eguard-agent/bootstrap.conf` is consumed after successful enrollment, so it
must not be part of default runtime tamper baseline. Only durable config paths
(e.g. `agent.conf`) should be monitored by default, otherwise post-enrollment
runs generate false-positive `agent_tamper` events.

## Verify Live Runtime Module Drift Before Debugging API Logic
When a live endpoint returns generic 500 (`Unknown error`) but local code looks
correct, compare deployed module checksums/content on the server against repo
files first. Route/controller/API module drift can leave routes registered in
`custom.pm` while handler methods are missing in older controller/API modules,
causing runtime 500 until those exact files are redeployed and service restarted.

## When User Points To A Branch Fix, Merge It First Before Redesigning
If the user says the fix already exists in a specific branch, do not iterate a
new design path first. Compare branch deltas immediately, merge/cherry-pick the
proven frontend/backend fixes into the target branch, then rebuild + redeploy.
This avoids repeated regressions and unnecessary workaround churn.

## Host/Agent Dropdowns Must Be Backed By Fresh Agent Presence, Not Event IDs
For operator-facing Host/Agent selectors, do not merge in agent IDs from event
history alone. Event streams preserve historical/test IDs and will inflate
dropdowns beyond actually installed endpoints. Build host choices from recent
agent presence windows (heartbeat/enroll grace), and keep stale cleanup policy
(online window + inactive grace + hard purge) explicit.

## Warnings Are Real Work, Not Cosmetic Noise
When CI surfaces Rust warnings (`unused_imports`, `dead_code`), treat each as a
root-cause decision: either wire the code path so fields/imports are meaningful,
or delete the dead stub. Do not silence warnings by leaving semantic placeholders
that parse payloads but never use them.

## Revalidate Threat-Intel UI With The Same Role As The Reporter
If a user reports "no bundle in UI", rerun browser E2E using the same operator role
(e.g., `admin`, not internal `system`) and confirm both config-save + sync actions.
Also verify live Perl route/controller parity (`/api/v1/threat-intel/sync`) and
frontend asset freshness before concluding ingestion is broken.

## When User Provides A Dependency Artifact, Attempt It Immediately And Report Privilege Limits Explicitly
If a user gives a concrete package URL to unblock validation, run it right away
(download + install attempt), then document exact blockers (e.g. sudo/password,
remaining runtime deps/config assumptions). Do not stop at the original missing
module error if follow-up evidence shows the blocker has changed.

## Token-Gated Install Tests Must Seed A Valid Token Explicitly
Do not assume token validation passes in-memory by default. For install endpoint
unit tests with `EGUARD_AGENT_INSTALL_REQUIRE_TOKEN=enabled`, create a known token
in test setup before asserting tokened requests return 200. This avoids environment-
dependent false failures.
