# F4a validation

Baseline: `i2-start-f4a-fields` (`0333176`). No dependencies added.
All cargo runs used `CARGO_TARGET_DIR=$PWD/target` and `timeout 1500`;
build/test/check commands used `--offline`.

## Passing

- `cargo check --offline -p platform-linux -p agent-core`
- `cargo test --offline -p platform-linux -p platform-windows -p platform-macos`:
  Linux 101, Windows 120, macOS 45 tests.
- `cargo test --offline -p agent-core tests_ebpf_policy -- --test-threads=4`: 111.
- `cargo test --offline -p agent-core tests_reviewfix -- --test-threads=4`: 21.
- `cargo test --offline -p agent-core tests_payload_integrity -- --test-threads=4`: 12.
- `cargo check --offline -p platform-windows -p agent-core --target x86_64-pc-windows-gnu`:
  passed with existing unused-code warnings.
- `cargo test --offline -p platform-macos`: 45.
- `cargo test --offline -p platform-linux tests_fields -- --test-threads=4`: 2.
- `cargo test --offline -p agent-core f4a_legacy_envelope_and_detection_golden -- --test-threads=1`: 1.
- `cargo fmt --all --check`; `git diff --check`.
- Manual script confirms all three RawEventFields declarations are identical,
  with 23 Option fields. Existing literals received 243 mechanical default
  initializers; Linux binary decode supplies its populated fields instead.

## Baseline proof

See `crates/agent-core/tests/fixtures/f4a-legacy.md` for fixture generation.
The final harness (including real EventEnvelope serde) was run at the baseline
in a detached scratch worktree; its output compares byte-identically to the
committed 30-record fixture. The scratch worktree was removed.

The baseline-compatible per-event regression compiled and failed at runtime
at the tag: all ten typed maps were absent/null. The same test passes at HEAD.
The additional direct-binary test covers legacy exec/open layouts, IPv6,
192-byte rename halves, invalid UTF-8, NUL-separated cmdline and short records.
Proof logs: `/home/dimas/eguard-lab-soak/followups/f4a-red-proof.log` and
`f4a-baseline-golden.log`.

## Full agent suite observations

`cargo test --offline -p agent-core` reached the 1500-second timeout (exit 124):
552 passes, 11 failures and 2 ignored tests were observed; the remaining
`observability_snapshot_reports_bounded_command_backlog_progress` never finished.
The full run therefore is not green. In addition to the supplied known bootstrap
failure, the run exposed:

- Three parallel config identity failures (`default_agent_id_uses_machine_id_when_hostname_missing`,
  `default_agent_id_uses_windows_computername_when_hostname_missing`,
  `generated_agent_id_is_random_format_and_persists`). All five `config::util::tests`
  pass in an isolated serial run. Config identity code/tests were not changed.
- `memory_layout_ledger_sums_to_target_rss_envelope` also fails in isolation:
  its constant ledger totals 18.3 MiB while requiring >=20 MiB. A comparison
  against the tag proves the entire test function and `zig/ebpf/bpf_helpers.h`
  are byte-identical. This is not a RawEvent-size regression.

- The parallel full run also reported failures in four network-profile tests,
  the package-build harness, and the golden test after the shared-env bootstrap
  failure. The focused golden passes; its lock acquisition now tolerates
  poisoning rather than cascading another test's panic. A final paired run
  (`runtime_bootstrap_restores_last_known_good_bundle_after_restart` plus
  `f4a_legacy_envelope_and_detection_golden`, four threads, nocapture) confirms
  the known bootstrap assertion fails while the golden still passes.
- `cargo test --offline -p acceptance` reproduces the supplied base compile
  failure: `ResponseReport` initializer lacks `action_type_label` at
  `crates/acceptance/src/tests_rsp_contract.rs:326`.

No unrelated test expectations or memory policy were weakened.

## Residual risks

Consumers still parse payload by design: full inventory is in
`docs/f4a-payload-consumers.md`. Windows/macOS typed fields remain all None.
Typed strings temporarily duplicate legacy payload data; allocation/performance
optimization belongs to later F4 tasks. Kernel eBPF loading and native Windows/
macOS sensor execution were not validated here; replay/binary parsing, native
host unit tests and Windows cross-compilation were validated.
