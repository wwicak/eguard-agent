# eGuard EDR Hardening Tracker

Last updated: 2026-02-14

## Goal

Raise threat-intel and agent reliability with fail-closed integrity, stronger feed correctness, and measurable CI gates.

## Execution Plan

| Phase | Focus | Status |
| --- | --- | --- |
| P0 | Pipeline correctness and integrity (must-have) | Completed |
| P1 | Database/query performance and observability | In Progress |
| P2 | Sensor depth and cross-platform parity | In Progress |

## P0 Todo

| ID | Task | Repo | Status | Notes |
| --- | --- | --- | --- | --- |
| P0-01 | Harden SIGMA parser for non-dict/null status docs | `eguard-agent` | Done | Added robust first-doc validation and tests |
| P0-02 | Harden YARA FP scan error handling | `eguard-agent` | Done | Scan errors now reject rules and are reported |
| P0-03 | Fix IOC tier/confidence mapping and source coverage | `eguard-agent` | Done | OTX/AlienVault moved to Tier 4; PhishTank added |
| P0-04 | Enforce strict collector artifact checks in bundle workflow | `eguard-agent` | Done | Required artifacts and minimum content checks added |
| P0-05 | Run threat-intel tests in CI gate | `eguard-agent` | Done | Added pytest threat-intel tests to CI workflows |
| P0-06 | Make server threat-intel signature verification fail-closed | `fe_eguard` | Done | Empty signing key now aborts ingestion |
| P0-07 | Canonicalize emergency command type to `emergency_rule_push` | `fe_eguard` | Done | Perl API + command issue path normalized |

## P1 Todo

| ID | Task | Repo | Status | Notes |
| --- | --- | --- | --- | --- |
| P1-01 | Replace synthetic rule-push SLO harness with measured local probes | `eguard-agent` | Done | Added dispatch and transfer probe metrics with conservative rollout gating |
| P1-02 | Upgrade eBPF resource budget harness with real probe command execution | `eguard-agent` | Done | Detection + LSM probe wall-clock metrics and probe status emitted |
| P1-03 | Add DB indexes for hot command/event query paths | `fe_eguard` | Done | Added composite indexes for command polling and event filtering |
| P1-04 | Add threat-intel ingest provenance table | `fe_eguard` | Done | New `threat_intel_ingest_run` table in schema |
| P1-05 | Persist threat-intel ingest provenance per run status | `fe_eguard` | Done | `threat_intel_update` now writes best-effort run records |
| P1-06 | Add idempotent migration helper SQL for upgraded installs | `fe_eguard` | Done | `upgrade-agent-p1-hardening.sql` + upgrade script include |
| P1-07 | Expose threat-intel ingest run listing API | `fe_eguard` | Done | Added `ingest_runs` / `list_ingest_runs` in Perl API |
| P1-08 | Add query-plan verification helper for hot DB paths | `fe_eguard` | Done | Added SQL check + helper script under `addons/dev-helpers/bin` |
| P1-09 | Add scheduled CI workflow for query-plan verification helper | `fe_eguard` | Done | Added `.github/workflows/agent-query-plan-check.yml` |
| P1-10 | Add Go server ingest-runs endpoint and pagination query path | `fe_eguard` | Done | Added handler/route, persistence query builder, and tests |
| P1-11 | Surface ingest-run timeline in endpoint Threat Intel UI | `fe_eguard` | Done | Added API call + ingest run table/status badge in `ThreatIntel.vue` |
| P1-12 | Optimize release profile to satisfy binary size budget | `eguard-agent` | Done | Added release profile (`lto`, `strip`, `panic=abort`, `codegen-units=1`) |
| P1-13 | Add ingest-run filter controls in Threat Intel UI | `fe_eguard` | Done | Added source/status/version/date filter bar and parameterized fetch |
| P1-14 | Add Perl unit coverage for ingest-run API filtering/pagination contract | `fe_eguard` | Done | Added `t/unittest/api/threat_intel.t` with DAL stubs |
| P1-15 | Add allowlisted ingest-run sorting contract in Perl + Go APIs | `fe_eguard` | Done | Added `sort_by`/`sort_dir` support with deterministic fallback order |
| P1-16 | Add ingest-run pagination controls in endpoint UI | `fe_eguard` | Done | Added page/per-page controls and API metadata sync |
| P1-17 | Add server-side ingest-run CSV export endpoint | `fe_eguard` | Done | Added Unified API route/controller + Perl API CSV export generator |
| P1-18 | Add ingest-run CSV export action in endpoint UI | `fe_eguard` | Done | Added Export CSV button + download flow in `ThreatIntel.vue` |
| P1-19 | Persist ingest-run filter/sort/page state in URL query | `fe_eguard` | Done | Added route query hydrate/sync helpers for sharable triage links |
| P1-20 | Add ingest-run quick date preset actions in endpoint UI | `fe_eguard` | Done | Added Last 24h/7d/30d and Clear Date controls |
| P1-21 | Add CSV gzip export modes (`off`/`auto`/`force`) with auto threshold | `fe_eguard` | Done | Added gzip mode normalization and compression in Perl export API |
| P1-22 | Add Perl unit coverage for gzip export behavior | `fe_eguard` | Done | Added gzip auto/force/off assertions in `t/unittest/api/threat_intel.t` |
| P1-23 | Add server-side ingest range aliases in Perl + Go APIs | `fe_eguard` | Done | Added `range=24h|7d|30d` with explicit date precedence |
| P1-24 | Add Go ingest-run CSV export parity with streaming + gzip mode | `fe_eguard` | Done | Added `/ingest-runs/export` route and stream writer from DB rows |
| P1-25 | Align UI quick presets with server range alias | `fe_eguard` | Done | Presets now use `range` query parameter and keep URL state sync |
| P1-26 | Extend Perl unit tests for range alias + gzip export contract | `fe_eguard` | Done | Added range bind assertions and gzip behavior coverage |
| P1-27 | Add threat-intel export audit persistence table + write paths | `fe_eguard` | Done | Added `threat_intel_export_audit` schema and Perl/Go export audit writes |
| P1-28 | Add Go rate limiting for threat-intel ingest list/export endpoints | `fe_eguard` | Done | Added per-client query/export token-bucket limiters with 429 responses |
| P1-29 | Extend query-plan verification for export audit read paths | `fe_eguard` | Done | Added `EXPLAIN` checks for export audit backend/IP queries |
| P1-30 | Add export-audit browse API in Perl Unified API | `fe_eguard` | Done | Added `list_export_audits` with filter/sort/pagination + route/controller action |
| P1-31 | Add Export Audits admin table in Threat Intel UI | `fe_eguard` | Done | Added audit filter form, table, and pagination controls |
| P1-32 | Extend Perl unit coverage for export-audit browse contract | `fe_eguard` | Done | Added export-audit query/filter/sort assertions in `t/unittest/api/threat_intel.t` |
| P1-33 | Add Go endpoint for threat-intel export-audit listing | `fe_eguard` | Done | Added `/api/v1/endpoint/threat-intel/export-audits` route, handler, and persistence query path |
| P1-34 | Extend Go tests for export-audit listing and ingest/export rate-limit contracts | `fe_eguard` | Done | Added handler tests for pagination/filter validation, 429 responses, and gzip export headers |

## P2 Todo

| ID | Task | Repo | Status | Notes |
| --- | --- | --- | --- | --- |
| P2-01 | Add agent-core runtime observability snapshot (tick stage timings + degraded-cause counters + queue depth) | `eguard-agent` | Done | Added `RuntimeObservabilitySnapshot`, stage timing instrumentation, and AC-OBS tests |

## Acceptance Criteria

### Threat Intel Pipeline

- `AC-TI-001`: Bundle build fails when any critical artifact is missing (`sigma-filtered`, `yara-collected`, `ioc-curated`, `cve-extracted`).
- `AC-TI-002`: Build fails when critical artifact content is structurally empty (no rule files, missing IOC txt files, or empty CVE JSONL).
- `AC-TI-003`: Threat-intel processing scripts do not crash on malformed top-level SIGMA docs or null status values.
- `AC-TI-004`: YARA scan runtime errors are surfaced and the offending rule is excluded.
- `AC-TI-005`: IOC confidence assignment matches policy (single Tier-1 => high, Tier-4 OTX defaults handled, corroboration preserved).
- `AC-TI-006`: Threat-intel pytest suite runs in CI on push/PR.

### Server Integrity

- `AC-SRV-001`: `threat_intel_update` refuses release ingestion when `signing_public_key` is unset.
- `AC-SRV-002`: Bundle ingestion verifies detached signature before recording version rows.
- `AC-SRV-003`: Emergency rule command persisted from Perl API uses canonical `emergency_rule_push` type.
- `AC-SRV-004`: Legacy alias `push_emergency_rule` is normalized to canonical command type at issue time.

### P1 Database and Harness

- `AC-DB-001`: Command polling path has a composite index on `(agent_id, status, issued_at)`.
- `AC-DB-002`: Endpoint event filtering has indexes for `rule_name` and `agent_id+rule_name` time scans.
- `AC-DB-003`: Threat-intel ingestion persists run provenance (`source`, `version`, `status`, `detail_json`) in DB.
- `AC-DB-004`: Existing upgraded installs can apply P1 indexes/tables idempotently via migration helper SQL.
- `AC-DB-005`: Threat-intel ingest run listing supports pagination and source/status/version/date filters.
- `AC-DB-006`: Hot-path query-plan verification SQL exists for command polling, event timeline, and ingest provenance queries.
- `AC-DB-007`: Query-plan helper has a scheduled/manual CI workflow and degrades safely when DB credentials are unavailable.
- `AC-DB-008`: Threat-intel export audit records are persisted with filter fingerprint, actor/client metadata, and compression flags.
- `AC-API-001`: Threat-intel ingest runs are available through both Perl API and Go endpoint with pagination metadata.
- `AC-API-002`: Perl unit tests validate ingest-run SQL filter binding order, alias handling, and JSON decoding.
- `AC-API-003`: Ingest-run sorting accepts allowlisted fields only and falls back to deterministic defaults.
- `AC-API-004`: Ingest-run CSV export endpoint returns filtered/sorted data with bounded row limit.
- `AC-API-005`: Ingest-run CSV export supports `gzip` mode (`off`, `auto`, `force`) with deterministic fallback.
- `AC-API-006`: Ingest-run APIs support `range` aliases (`24h`, `7d`, `30d`) when explicit dates are absent.
- `AC-API-007`: Go endpoint `/api/v1/endpoint/threat-intel/ingest-runs/export` streams CSV exports with gzip mode support.
- `AC-API-008`: Go threat-intel ingest list/export endpoints enforce per-client rate limits and return HTTP 429 on exhaustion.
- `AC-API-009`: Perl Unified API exposes export-audit listing with allowlisted sorting and paginated filters.
- `AC-API-010`: Go endpoint `/api/v1/endpoint/threat-intel/export-audits` returns paginated export-audit payloads with allowlisted sorting and filter support.
- `AC-UI-001`: Endpoint Threat Intel UI displays recent ingest run status and details.
- `AC-UI-002`: Endpoint Threat Intel UI supports ingest-run filtering by source/status/version/date range.
- `AC-UI-003`: Endpoint Threat Intel UI supports ingest-run pagination (`page`, `per_page`) and keeps server-returned pagination state.
- `AC-UI-004`: Endpoint Threat Intel UI can export current ingest-run view to CSV.
- `AC-UI-005`: Endpoint Threat Intel UI persists ingest filters/sort/pagination in URL query parameters.
- `AC-UI-006`: Endpoint Threat Intel UI supports quick date-range presets for ingest run triage.
- `AC-UI-007`: Endpoint Threat Intel UI quick presets are represented as server-side `range` aliases in URL query state.
- `AC-UI-008`: Endpoint Threat Intel UI exposes an Export Audits table with backend/actor/client/date/gzip/compression filters.
- `AC-HAR-001`: Rule-push SLO harness emits measured dispatch/transfer probe metrics in addition to rollout estimates.
- `AC-HAR-002`: eBPF resource budget harness executes detection/LSM probe commands and publishes wall-clock and status fields.
- `AC-PKG-001`: Agent release binary is below the 10 MB budget in release profile checks.

### P2 Runtime Observability

- `AC-OBS-001`: Agent runtime exposes a snapshot API with per-tick stage timings including evaluate, connected/degraded pipeline, and send-batch execution.
- `AC-OBS-002`: Self-protection degraded transitions are counted separately from transport degraded transitions and expose the last degraded cause.
- `AC-OBS-003`: Send-failure degraded transition increments only on mode transition and records `send_failures` as degraded cause.
- `AC-OBS-004`: In degraded ticks, connected-only timing fields (`send_batch`, `command_sync`) remain zero while degraded stage timing is non-zero.
- `AC-OBS-005`: Snapshot includes current offline queue depth (`pending_event_count`, `pending_event_bytes`) and consecutive send-failure count.

## Verification Log

- `2026-02-13`: `pytest -q threat-intel/tests/test_bundle.py` => `11 passed, 7 skipped`.
- `2026-02-13`: `pytest -q` => `11 passed, 7 skipped`.
- `2026-02-13`: `python3 -m py_compile threat-intel/processing/sigma_filter.py threat-intel/processing/yara_validate.py threat-intel/processing/ioc_dedup.py` => pass.
- `2026-02-13`: `cargo test -p agent-core --bin agent-core lifecycle::tests_det_stub_completion::rule_push_slo_harness_executes_and_enforces_transfer_and_rollout_budgets -- --exact` => pass.
- `2026-02-13`: `cargo test -p agent-core --bin agent-core lifecycle::tests_ebpf_policy::ebpf_resource_budget_harness_executes_and_writes_limits_metrics_and_command_manifest -- --exact` => pass.
- `2026-02-13`: `cargo test -p agent-core --bin agent-core` => `84 passed, 0 failed`.
- `2026-02-13`: `cargo build --release -p agent-core && wc -c target/release/agent-core` => `10214448` bytes (~9.74 MB).
- `2026-02-13`: `bash scripts/run_rule_push_slo_ci.sh` => pass.
- `2026-02-13`: `bash scripts/run_ebpf_resource_budget_ci.sh` => pass with default limits after release-profile optimization.
- `2026-02-13`: `bash -n /home/dimas/fe_eguard/addons/dev-helpers/bin/run-agent-query-plan-check.sh` => pass.
- `2026-02-13`: `addons/dev-helpers/bin/run-agent-query-plan-check.sh` => graceful skip in this environment (`mysql` missing).
- `2026-02-13`: `perl t/unittest/api/threat_intel.t` => `77 passed`.
- `2026-02-13`: `perl t/unittest/api/endpoint_command.t` => `38 passed`.
- `2026-02-13`: `npm run lint -- --no-fix` in `html/egappserver/root` blocked in this environment (`vue-cli-service` not installed).
- `2026-02-13`: `perl -Ilib -c ...` in `fe_eguard` blocked in this environment (`Moose.pm` not installed).
- `2026-02-13`: `perl -Ilib -c lib/eg/UnifiedApi/Controller/ThreatIntel.pm` blocked in this environment (`Mojo::Base` not installed).
- `2026-02-13`: `go test ./go/agent/server -run ThreatIntelIngestRunsHandlerReturnsPaginatedPayload -count=1` blocked in this environment (`go` not installed).
- `2026-02-13`: `go test ./go/agent/server -run Command -count=1` blocked in this environment (`go` not installed).
- `2026-02-13`: `source ~/.profile && go version` => `go1.26.0` detected.
- `2026-02-13`: `source ~/.profile && go test ./agent/server -run ThreatIntelIngestRunsHandlerReturnsPaginatedPayload -count=1` => pass.
- `2026-02-13`: `source ~/.profile && go test ./agent/server -count=1` => pass.
- `2026-02-13`: `source ~/.profile && gofmt -w agent/server/{server.go,persistence.go,threat_intel.go,threat_intel_test.go,types.go,threat_intel_rate_limiter.go}` => applied.
- `2026-02-13`: `cargo test -p agent-core --bin agent-core lifecycle::tests_observability:: -- --nocapture` => `3 passed, 0 failed`.
- `2026-02-13`: `cargo test -p agent-core --bin agent-core lifecycle::tests::update_tls_policy_from_server_updates_pin_and_rotation_window -- --exact` => pass.
- `2026-02-13`: `cargo test -p agent-core --bin agent-core lifecycle::tests::parse_certificate_not_after_unix_reads_pem_validity -- --exact` => pass.
- `2026-02-13`: `cargo test -p agent-core --bin agent-core lifecycle::tests_baseline_seed_policy::apply_fleet_baseline_seeds_adds_missing_learning_profiles -- --exact` => pass.
- `2026-02-14`: `source ~/.profile && gofmt -w agent/server/{server.go,threat_intel.go,persistence.go,types.go,threat_intel_test.go}` => applied.
- `2026-02-14`: `source ~/.profile && go test ./agent/server -count=1` => pass.
