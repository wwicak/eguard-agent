# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Workflow Orchestration
### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update 'tasks/lessons.md' with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- Use SOLID principles, avoid create god class file
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests -> then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Task Management
1. Plan First: Write plan to 'tasks/todo.md' with checkable items
2. Verify Plan: Check in before starting implementation
3. Track Progress: Mark items complete as you go
4. Explain Changes: High-level summary at each step
5. Document Results: Add review to 'tasks/todo.md'
6. Capture Lessons: Update 'tasks/lessons.md' after corrections

## Core Principles
- Simplicity First: Make every change as simple as possible. Impact minimal code.
- No Laziness: Find root causes. No temporary fixes. Senior developer standards.
- Minimal Impact: Changes should only touch what's necessary. Avoid introducing bugs.

When you need to call tools from the shell, use this rubric:

- Find files by file name: `fd`
- Find files with path name: `fd -p <file-path>`
- List files in a directory: `fd . <directory>`
- Find files with extension and pattern: `fd -e <extension> <pattern>`
- Find Text: `rg` (ripgrep)
- Find Code Structure: `ast-grep`
    - Default to TypeScript when in TS/TSX repos:
        - `.ts` → `ast-grep --lang ts -p '<pattern>'`
        - `.tsx` (React) → `ast-grep --lang tsx -p '<pattern>'`
    - Other common languages:
        - Python → `ast-grep --lang python -p '<pattern>'`
        - Bash → `ast-grep --lang bash -p '<pattern>'`
        - JavaScript → `ast-grep --lang js -p '<pattern>'`
        - Rust → `ast-grep --lang rust -p '<pattern>'`
        - JSON → `ast-grep --lang json -p '<pattern>'`
- Select among matches: pipe to `fzf`
- JSON: `jq`
- YAML/XML: `yq`

## Project Overview

eGuard Agent is a production-grade **Endpoint Detection and Response (EDR)** agent. Rust workspace (13 crates) with Zig (eBPF probes + ASM acceleration) and Go (server-side, in separate repo at `/home/dimas/fe_eguard/`). Design doc: `/home/dimas/fe_eguard/docs/eguard-agent-design.md`.

## Build Commands

### Prerequisites
- Rust 1.82+ (stable), Zig 0.14.x, nfpm 2.x (packaging)

### Build Zig artifacts first (required before Rust build)
```bash
zig build agent-artifacts          # All (eBPF + ASM)
zig build asm-artifacts            # ASM libraries only
zig build ebpf-artifacts           # eBPF probes only
```

### Rust build
```bash
cargo build -p agent-core                                           # Debug
cargo build --release -p agent-core                                 # Release
cargo build --release --target x86_64-unknown-linux-musl -p agent-core  # Static musl
cargo check --target x86_64-pc-windows-msvc -p platform-windows     # Windows cross-check
```

### Tests
```bash
cargo test --workspace                    # All crates
cargo test -p detection                   # Single crate
cargo test -p detection test_name -- --exact  # Single test
cargo test -p acceptance                  # E2E (requires running agent + server)
```

### Lint
```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo audit
```

### Fuzz / Miri (nightly)
```bash
cargo +nightly fuzz run protobuf_parse -- -max_total_time=30 -verbosity=0
cargo +nightly fuzz run detection_inputs -- -max_total_time=30 -verbosity=0
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p detection --lib -- --test-threads=1
```

### Packaging
```bash
VERSION=0.1.0 nfpm package --packager deb
VERSION=0.1.0 nfpm package --packager rpm
```

## Architecture

### Crate Dependency Graph

```
agent-core (binary, lifecycle, config)
├── detection (multi-layer threat detection, platform-agnostic)
├── response (kill/quarantine/capture actions)
├── compliance (policy assessment)
├── baseline (anomaly baselines per process)
├── platform-linux (eBPF engine, /proc enrichment, container detection)
├── platform-windows (ETW engine, Windows API, service management)
├── platform-macos (stub)
├── grpc-client (HTTP + gRPC dual-mode comms)
├── self-protect (integrity checks, debugger detection)
├── nac (network anomaly correlation)
└── crypto-accel (SHA-256/AES via Zig ASM)

acceptance (E2E tests, separate from main dependency tree)
```

`agent-core` has a hardcoded dependency on `platform-linux`. Windows/macOS are compile-checked but not linked into the binary yet.

### Event Pipeline (per 100ms tick)

```
Kernel (eBPF probes) → RawEvent
  → enrich_event_with_cache() → EnrichedEvent (proc info, hashes, parent chain, container)
    → to_detection_event() → TelemetryEvent
      → DetectionEngine.process_event() → DetectionOutcome (confidence + signals)
        → plan_action() → PlannedAction (AlertOnly/Kill/Quarantine/Isolate)
          → EventEnvelope → EventBuffer → send to server
```

### Detection Engine Layers

`DetectionEngine` (`crates/detection/src/engine.rs`) has 7 layers evaluated per event:
1. **Layer 1 (IOC)**: Aho-Corasick exact match on hashes/domains/IPs → early Definite
2. **Layer 2 (Temporal)**: Sigma rule AST evaluation against event stream
3. **Layer 3 (Anomaly)**: Shannon entropy deviation from learned baselines
4. **Layer 4 (Kill-chain)**: ATT&CK-style predicate matching on process trees
5. **Layer 5 (ML)**: XGBoost-style scoring
6. **Behavioral**: Memory patterns, syscall sequences
7. **Yara**: Binary pattern matching on files/memory

Confidence levels: `None < Low < Medium < High < VeryHigh < Definite` (numeric 0-5).

### Sharded Detection State

`SharedDetectionState` (`crates/agent-core/src/detection_state.rs`) runs N shards (CPU-count based), each with its own `DetectionEngine` thread. Events route via `session_id % shard_count`. Communication via `mpsc` channels with `ShardCommand` enum. Engine swaps (for bundle updates) are atomic via `Arc<ArcSwap<T>>`.

### Platform Abstraction

All three platform crates export the same public types:
- `EventType` enum: ProcessExec, ProcessExit, FileOpen, FileWrite, FileRename, FileUnlink, TcpConnect, DnsQuery, ModuleLoad, LsmBlock
- `RawEvent`, `EnrichedEvent`, `EnrichmentCache` structs
- `enrich_event()`, `enrich_event_with_cache()`, `platform_name()` functions

**Linux**: eBPF via libbpf + ring buffer, `/proc` introspection, cgroup-based container detection.
**Windows**: ETW, Registry/WMI, AMSI, Windows Service API.
**macOS**: Stub only (`platform_name() → "macos"`).

### AgentRuntime Lifecycle

`AgentRuntime` (`crates/agent-core/src/lifecycle/runtime.rs`) is the central state machine. Main loop selects on 100ms tick interval or shutdown signal. Each `tick(now_unix)` runs: self-protection → event evaluation → telemetry/compliance/response/control-plane stages. Modes: Learning, Active, Degraded (N consecutive send failures trigger degraded; recovery via periodic probe).

### gRPC / HTTP Communication

`GrpcClient` (`crates/grpc-client/`) supports dual transport. Proto definitions in `proto/eguard/v1/`. Services: AgentControl (enroll, heartbeat, threat-intel), Telemetry (streaming events), Command (server→agent control), Compliance, Response. Enrollment flow: `bootstrap.conf` → EnrollRequest → receive cert → persist to `agent.conf`.

### Response System

Confidence-based: Definite→kill+quarantine+capture, VeryHigh→configurable, High→capture only, Medium→no action. Kill uses `SIGKILL` to process tree (respects `ProtectedList` regex patterns). Rate-limited (default 10 kills/min). Auto-isolation triggers after N high-confidence detections in T seconds.

## Key Config Paths

- Linux: `/etc/eguard-agent/agent.conf`, data at `/var/lib/eguard-agent/`
- Windows: `C:\ProgramData\eGuard\agent.conf`, data at `C:\ProgramData\eGuard\`
- Constants: `crates/agent-core/src/config/constants.rs` (cfg-gated per platform)
- Config load order: `EGUARD_AGENT_CONFIG` env → platform default → `./conf/agent.conf` → `./agent.conf` → env overrides

## Conventions

- Platform-specific code uses `#[cfg(target_os = "...")]` gates
- eBPF probe objects live in `zig-out/ebpf/*.o` after build
- ASM acceleration libraries in `zig-out/lib/libeguard_*.a`
- CI scripts in `scripts/` (37 scripts, mostly `run_*_ci.sh` pattern)
- Release profile: `codegen-units=1`, `lto="thin"`, `panic="abort"`, `strip="symbols"`
- Workspace dependencies centralized in root `Cargo.toml` `[workspace.dependencies]`
