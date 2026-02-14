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
