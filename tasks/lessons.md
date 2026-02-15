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
