# Acceptance Criteria Tests

This crate hosts generated tests for `ACCEPTANCE_CRITERIA.md`.

## Regenerate

Run:

```bash
./scripts/generate_acceptance_tests.py
```

The generator rewrites:

- `crates/acceptance/tests/acceptance_criteria_generated.rs`
- `crates/acceptance/tests/ac_runtime_stubs_generated.rs`
- `crates/acceptance/tests/ac_tst_runtime_stubs.rs`
- `crates/acceptance/tests/ac_ver_runtime_stubs.rs`

To generate done/not-done status:

```bash
./scripts/generate_acceptance_status_report.py
```

This writes:

- `crates/acceptance/AC_STATUS.md`

## Run

```bash
cargo test -p acceptance
```

The suite includes:

- one integrity test that ensures the generated AC ID list exactly matches IDs extracted from `ACCEPTANCE_CRITERIA.md`
- one criterion presence test per AC ID (`AC-...`)
- one ignored runtime-validation stub per AC ID (`*_runtime_validation_stub`)
- focused ignored runtime stubs for `AC-TST-*` and `AC-VER-*`
