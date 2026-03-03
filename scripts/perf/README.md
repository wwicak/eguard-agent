# Perf Tooling (Phase-3)

This directory contains the phase-3 performance benchmark pipeline used by local runs and GitHub workflow automation.

## Core scripts

- `linux_phase3.sh` / `windows_phase3.ps1` — run scenario matrix and emit raw artifacts.
- `summarize.py` — aggregate raw artifacts into `summary.json` + `report.md`.
- `gate.py` — enforce profile thresholds and quality/sample constraints.
- `compare_trend.py` — compare multiple runs vs a selected baseline.
- `resolve_baseline.py` — resolve baseline from direct input and/or pointer file.
- `update_baseline_pointer.py` — write/update baseline pointer JSON.
- `promote_baseline.py` — promote a run/candidate pointer to active baseline with optional gate-pass enforcement.

## Typical flow

```bash
# 1) summarize one run
python3 scripts/perf/summarize.py --input-root artifacts/perf/<run-tag>

# 2) evaluate gate
python3 scripts/perf/gate.py \
  --summary artifacts/perf/<run-tag>/summary.json \
  --profile provisional

# 3) compare run against baseline
python3 scripts/perf/compare_trend.py \
  --input artifacts/perf/<run-tag> \
  --input artifacts/perf/<baseline-run-tag> \
  --baseline-run <baseline-run-tag> \
  --required-platforms linux,windows \
  --json-output artifacts/perf/<run-tag>/trend.json \
  --report-output artifacts/perf/<run-tag>/trend.md
```

## Baseline pointer convention

- Recommended pointer path: `.ci/perf-baseline.json`
- Example payload: `.ci/perf-baseline.example.json` (includes `summary_sha256` integrity field)

Update pointer after promoting a run:

```bash
python3 scripts/perf/update_baseline_pointer.py \
  --baseline-summary artifacts/perf/<run-tag>/summary.json \
  --workspace-root . \
  --pointer-path .ci/perf-baseline.json
```

Safe overwrite pattern (force + backup):

```bash
python3 scripts/perf/update_baseline_pointer.py \
  --baseline-summary artifacts/perf/<run-tag>/summary.json \
  --workspace-root . \
  --pointer-path .ci/perf-baseline.json \
  --force --backup-existing
```

By default unchanged pointers are not rewritten (prevents timestamp-only churn). Use `--rewrite-if-unchanged` to force rewrite.

Resolve pointer for tooling:

```bash
python3 scripts/perf/resolve_baseline.py \
  --baseline-pointer .ci/perf-baseline.json \
  --workspace-root .
```

Require that the resolved baseline run has `gate.json` status `pass`:

```bash
python3 scripts/perf/resolve_baseline.py \
  --baseline-pointer .ci/perf-baseline.json \
  --workspace-root . \
  --require-gate-pass
```

Optionally require both gate and trend pass:

```bash
python3 scripts/perf/resolve_baseline.py \
  --baseline-pointer .ci/perf-baseline.json \
  --workspace-root . \
  --require-gate-pass \
  --require-trend-pass
```

Promote a run as baseline (requires `gate.json` status `pass` by default):

```bash
python3 scripts/perf/promote_baseline.py \
  --run-tag <run-tag> \
  --workspace-root .
```

Require both gate + trend pass before promotion:

```bash
python3 scripts/perf/promote_baseline.py \
  --run-tag <run-tag> \
  --workspace-root . \
  --require-trend-pass
```

Preview promotion payload without writing pointer:

```bash
python3 scripts/perf/promote_baseline.py \
  --run-tag <run-tag> \
  --workspace-root . \
  --dry-run
```

Promote from a candidate pointer artifact:

```bash
python3 scripts/perf/promote_baseline.py \
  --candidate-pointer artifacts/perf/<run-tag>/perf-baseline.candidate.json \
  --workspace-root .
```

Force + backup when replacing an existing baseline pointer:

```bash
python3 scripts/perf/promote_baseline.py \
  --run-tag <run-tag> \
  --workspace-root . \
  --force --backup-existing
```

Like the updater, unchanged promotions are no-op by default; set `--rewrite-if-unchanged` when you intentionally want to refresh metadata.
