# Lessons Learned

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

## Detection Quality Trend Gates Should Track Enforcement Tiers
When trend gates monitor regression, focus on enforcement confidences
(focus/definite/very_high). High/medium tiers are advisory and can
introduce noisy regressions; keep them opt-in via env overrides.
