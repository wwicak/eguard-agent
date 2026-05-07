# Todo
- [x] Inspect CI zig setup for build-bundle workflow.
- [x] Remove unintended ZTNA feature from v15.0.0 main line.
- [x] Keep CI Zig linker fix.
- [x] Run targeted checks locally.
- [ ] Trigger GitHub Action and monitor with gh.

## Review
- Removed ZTNA crate, tray crate, proto, agent/grpc references from v15 main.
- Added Zig linker PATH verification and clearer zig-cc failure.
- Verified: no live ZTNA references; `cargo test -p agent-core --bin agent-core --no-run`; `cargo test -p grpc-client --no-run`.
