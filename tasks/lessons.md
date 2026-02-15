# Lessons

## 2026-02-13
- When the user asks to use multiple sub-agents, start parallel sub-agent execution immediately for independent workstreams (analysis + implementation) instead of doing sequential local-only work.
- For sandbox-sensitive test work, assign one sub-agent to implementation and one to coverage-gap analysis, then integrate both outcomes in the main branch.
- When the user corrects repository/doc location, immediately switch all discovery and planning references to the corrected path (e.g., `fe_eguard/docs/eguard-agent-design.md`) before continuing analysis.
- When the user explicitly asks for full-batch implementation ("implement all of it"), avoid single-slice pacing: convert all remaining TODO items into one execution batch plan and deliver them in the same pass with full verification.

## 2026-02-14
- When the user prioritizes outcome quality over footprint, remove hard binary-size gates in CI/harnesses and keep binary size as an observed metric rather than a release-blocking threshold.
- When the user says to keep polishing after an initial CI gate implementation, add layered guardrails in the same pass (collector-level minimums, bundle-level minimums, freshness checks, and regression checks) instead of stopping at absolute count thresholds.
- When Rust toolchain commands fail in this environment, source cargo env first (`source $HOME/.cargo/env`) before rerunning `cargo` commands so validation can proceed without user interruption.
- When warnings appear only in Miri due to test-module gating, prefer precise `cfg(all(test, not(miri)))` scoping over `allow(dead_code)` so real dead code still fails loudly.
- For long-running CI-style scripts, run them in tracked background mode (`current-run.pid` + `current-run.logpath` + `current-run.exit`) and report incremental log progress instead of waiting silently.
- For verification parity with workflow security posture, include bundle-signature contract checks (build fixture bundle, sign, verify, and tamper rejection) in the runnable verification suite rather than only in release workflows.
- When a Rust test consumes artifact paths from env vars, pass absolute paths from CI/shell scripts (`${GITHUB_WORKSPACE}` or repo-root absolute) because unit-test working directories can resolve relative paths against crate roots.
- When the user emphasizes bundle↔agent integration, enforce a CI contract that tests agent ingestion against the freshly produced signed bundle artifact (path + pubkey wiring), not only standalone bundle validation.
- When upgrading to `tonic` 0.14, migrate build scripts from `tonic-build::configure()` to `tonic_prost_build::configure()`, add `tonic-prost` runtime dependency for generated codecs, and align any standalone fuzz/proto crates to the same `prost` major to avoid trait-version mismatch.

## 2026-02-15
- When the user asks for a broad repo health scan (especially with many edits), report both file-level churn (`git status`/`diff --stat`) and markdown/contract state together so implementation and planning drift are visible in one snapshot.
- After AC document edits, always regenerate acceptance generated artifacts before claiming green; otherwise `generated_id_list_matches_acceptance_document` can fail despite most tests passing.
- On hosts without `x86_64-linux-musl-gcc`, musl package builds can be recovered by using Zig wrappers for cc-rs/ring compilation and rust-lld for final musl linking; using Zig as both compiler and linker can trigger duplicate CRT symbol failures.
- Zig-produced static archives may contain nested member paths (e.g., `.zig-cache/.../*.o`); package-stage archive extraction must create member directories before `ar x` and repack objects recursively, otherwise asm bundles can silently collapse to zero-byte archives.
- When workflows/scripts rely on newly added files (fuzz harnesses, CI helper scripts, threat-intel gates), ensure those files are staged/tracked explicitly; leaving them untracked can create false-local-green runs that fail in CI/release branches.
