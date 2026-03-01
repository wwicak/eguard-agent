# eGuard ML Ops Operations Manual (Baseline + Fleet Seed)

**Version:** 2.0
**Last updated:** 2026-03-01
**Audience:** SOC operators, SRE, release engineers, blue-team leads  
**Scope:** Production operations for the implemented Baseline+ML learning loop in `eguard-agent` + `fe_eguard`

---

## Table of Contents

1. [What this manual covers](#1-what-this-manual-covers)
2. [System architecture (what is running now)](#2-system-architecture-what-is-running-now)
3. [Data flow and control points](#3-data-flow-and-control-points)
4. [Day-0 deployment checklist](#4-day-0-deployment-checklist)
5. [Day-1 go-live runbook](#5-day-1-go-live-runbook)
6. [Canary rollout playbook](#6-canary-rollout-playbook)
7. [Kill switch and rollback playbook](#7-kill-switch-and-rollback-playbook)
8. [Verification and evidence collection](#8-verification-and-evidence-collection)
9. [Dashboards and SLO signals](#9-dashboards-and-slo-signals)
10. [Troubleshooting guide](#10-troubleshooting-guide)
11. [Production readiness gate (sign-off)](#11-production-readiness-gate-sign-off)
12. [Appendix: policy and command templates](#12-appendix-policy-and-command-templates)

---

## 1) What this manual covers

This guide is for the **implemented (non-stub)** Baseline+ML operational loop:

- Endpoint learns local baseline profiles.
- Endpoint uploads baseline profiles to server (`/baseline/batch`).
- Server aggregates fleet baseline (`/baseline/aggregate`) and serves fleet seed (`/baseline/fleet`).
- Endpoints consume fleet seeds (learning/stale modes), merge safely, and push to detection shards.
- Runtime controls are available for:
  - `baseline_upload_enabled` / `fleet_seed_enabled`
  - `baseline_upload_canary_percent` / `fleet_seed_canary_percent`

This manual is focused on **operations** (rollout, safety, observability, rollback), not model-research theory.

---

## 2) System architecture (what is running now)

### 2.1 Planes

1. **Endpoint inference plane** (`agent-core`)
   - Real-time event processing and local anomaly baseline learning.
   - Baseline persistence: snapshot + journal.

2. **Fleet intelligence plane** (`eg-agent-server`)
   - Receives endpoint baseline uploads.
   - Aggregates fleet medians and serves fleet seed rows.

3. **Ops/governance plane**
   - Policy assignment and live toggles.
   - Canary percentages and kill switches.
   - Operational verification through API, DB, logs, and GUI.

### 2.2 Persistence model

Agent-side:
- Snapshot: `baselines.bin`
- Delta journal: `baselines.journal`
- Journal checkpoint metadata: `baselines.journal.meta`
- Compaction cadence: every 6h (or threshold-triggered)

Server-side:
- Per-endpoint rows: `endpoint_baseline`
- Fleet aggregate rows: `fleet_baseline`

---

## 3) Data flow and control points

### 3.1 Core loop

1. Endpoint observes events and updates local baseline.
2. Dirty baseline keys are tracked.
3. Upload scheduler runs (default every 15m, or immediately on large dirty backlog).
4. Server persists baseline rows idempotently.
5. Aggregation computes fleet medians (normalized sum ~= 1.0).
6. Endpoint fetches fleet rows (learning/stale), applies safe merge.
7. Updated baseline is pushed to all detection shards (bulk apply).

### 3.2 Runtime control flags

Environment (startup defaults):
- `EGUARD_BASELINE_UPLOAD_ENABLED`
- `EGUARD_FLEET_SEED_ENABLED`
- `EGUARD_BASELINE_UPLOAD_CANARY_PERCENT`
- `EGUARD_FLEET_SEED_CANARY_PERCENT`
- `EGUARD_BASELINE_UPLOAD_MAX_BYTES`

Policy (live override without restart):
- `baseline_upload_enabled`
- `fleet_seed_enabled`
- `baseline_upload_canary_percent`
- `fleet_seed_canary_percent`
- `baseline_mode` (`learning`, `force_active`, `skip_learning`)

### 3.3 Scheduling defaults

- Baseline upload interval: 900s
- Fleet seed fetch interval: 900s
- Baseline upload batch size: 128 profiles
- Baseline payload cap: 1,000,000 bytes (default)

### 3.4 Mathematical foundations of fleet aggregation

Three estimators underpin the aggregation pipeline:

1. **Coordinate-wise α-trimmed median (α = 0.05)**

   For each feature dimension *i*, given observations {p_i^(k)} across *K* reporting agents:

   ```
   μ̃ᵢ = median({p_i^(k) : k ∈ agents, excluding top/bottom α fraction})
   ```

   Breakdown point = α. The fleet tolerates up to 5% poisoned or compromised agents submitting adversarial baseline profiles (Byzantine robustness guarantee). This prevents a small number of compromised endpoints from skewing the fleet aggregate.

2. **Huber M-estimator for continuous features**

   Minimizes the Huber loss over all agent observations:

   ```
   minimize  Σ ρ_H(xᵢ − θ)

   where ρ_H(u) = { u²/2          if |u| ≤ k
                   { k·|u| − k²/2  if |u| > k

   k = 1.345
   ```

   At k = 1.345 the estimator achieves 95% asymptotic efficiency at the Gaussian model while remaining robust to heavy-tailed outliers. Used for continuous aggregation targets (e.g., mean inter-arrival time, mean payload size).

3. **Jensen-Shannon divergence for fleet health**

   Measures distributional distance between consecutive aggregation cycles P and Q:

   ```
   JS(P, Q) = ½ D_KL(P ‖ M) + ½ D_KL(Q ‖ M),   M = (P + Q) / 2
   ```

   Bounded ∈ [0, ln 2]. Symmetric and always finite (unlike raw KL). Operational threshold: **JS > 0.1** indicates significant fleet-wide drift requiring investigation.

### 3.5 Bayesian fleet seed framework (Dirichlet-Multinomial)

Fleet seeds act as informative priors for new or data-sparse agents via conjugate Bayesian updating:

1. **Fleet prior as Dirichlet**

   ```
   Dir(α₁, ..., αₖ)   where αᵢ = fleet_median_probability_i × κ
   ```

2. **Agent posterior after observing local counts n₁, ..., nₖ**

   ```
   θ̂ᵢ = (αᵢ + nᵢ) / (Σⱼ αⱼ + Σⱼ nⱼ)
   ```

3. **Concentration parameter κ = Σ αⱼ** controls fleet-vs-local balance:
   - New agent (few local samples): κ = 100 → posterior ≈ fleet prior
   - Mature agent (sample_count → 1000): κ → 0 → posterior ≈ local empirical distribution

The Dirichlet-Multinomial is a natural conjugate — posterior update is a single addition with no iterative optimization, making it suitable for real-time agent-side computation.

### 3.6 Drift detection procedures

#### Agent-side: Page-Hinkley test

Monitors per-process KL-divergence stream for upward drift:

```
mₜ = Σᵢ₌₁ᵗ (xᵢ − x̄ₜ − δ)

Alarm when:  max(mₜ) − mₜ > λ
```

- δ (tolerance) and λ (threshold) are tunable per sensitivity requirement.
- Complexity: O(1) per update, O(1) memory — suitable for per-process-key monitoring on resource-constrained endpoints.
- On alarm: triggers baseline re-learning for the affected process key.

#### Server-side: ADWIN on fleet aggregate JS-divergence

ADWIN (ADaptive WINdowing) maintains a variable-size window over the JS-divergence time series:

```
Alarm when:  |μ̂₁ − μ̂₂| ≥ √((1/2m) · ln(4/δ'))
```

where μ̂₁, μ̂₂ are the means of two sub-windows and δ' is the confidence parameter.

- Memory: O(log W) where W is the window size.
- On alarm: freeze canary progression, alert operators, investigate root cause.

#### Operational runbook for drift alarms

1. Drift alarm fires → freeze canary at current stage.
2. Investigate: is it organic workload shift or adversarial?
3. If organic: approve new baseline, resume canary.
4. If adversarial or unexplained: rollback fleet seed to last known-good, quarantine suspect agents.

### 3.7 Conformal prediction integration

Conformal prediction provides distribution-free finite-sample coverage guarantees for detection thresholds:

```
P(Y ∈ Cα(X)) ≥ 1 − α

Threshold = ⌈(1 − α)(n + 1)⌉ / n   quantile of calibration scores
```

- No distributional assumptions required — valid for any exchangeable data.
- Currently implemented in `detection/src/information/conformal.rs`.

#### Calibration procedure

1. Rebuild calibration set from last 30 days of labeled/adjudicated events.
2. Compute nonconformity scores on holdout.
3. Set threshold at the (1 − α) quantile (default α = 0.01 → 99% coverage).
4. Hot-reload threshold into running detection engine via threat-intel bundle update.

Recalibration is triggered on each model reload to maintain coverage guarantee under distribution shift.

---

## 4) Day-0 deployment checklist

## 4.1 Build artifacts

- Build server binary (`eg-agent-server`)
- Build frontend dist
- Build linux agent binary (`agent-core`)
  - **Production linux build must include eBPF libbpf feature**:
    - `cargo build --release -p agent-core --features platform-linux/ebpf-libbpf`

## 4.2 Deploy and restart services

Server host:
- Deploy `eg-agent-server` binary
- Deploy frontend `dist/`
- Restart:
  - `eguard-agent-server`
  - `eguard-api-frontend`

Linux endpoint host:
- Deploy `/usr/bin/eguard-agent`
- Restart `eguard-agent`

Windows endpoint host:
- Verify `eGuardAgent` service is running

## 4.3 Immediate post-deploy checks

- Service statuses are `active/running`
- Inventory API is healthy
- Latest endpoint rows are ingesting
- No fatal panic/crash loops in journals

---

## 5) Day-1 go-live runbook

1. Confirm all agents heartbeat and inventory are current.
2. Confirm baseline upload logs are present on canary cohort.
3. Run server aggregate once manually and inspect results.
4. Confirm fleet fetch path from canary agents.
5. Confirm seeded profiles are applied and re-uploaded.
6. Validate GUI operator workflows:
   - Inventory filters + OS fields
   - NAC isolate/allow/status
   - Audit row expansion + whitelist actions

### 5.1 Nightly model retraining on modest hardware (4 vCPU / 6 GB class)

`signature_ml_train_model.py` now supports **resource-aware auto-tuning** for heterogeneous hosts.

Recommended nightly command (same host allowed during low-traffic window):

```bash
python threat-intel/processing/signature_ml_train_model.py \
  --dataset bundle/signature-ml-features.ndjson \
  --feature-schema bundle/signature-ml-feature-schema.json \
  --labels-report bundle/signature-ml-label-quality-report.json \
  --model-version "rules-$(date +%Y.%m.%d).ml.v1" \
  --resource-profile auto \
  --model-out bundle/signature-ml-model.json \
  --metadata-out bundle/signature-ml-model-metadata.json
```

Resource-aware behavior:
- Detects CPU and RAM (`/proc/meminfo` fallback to `sysconf`).
- Resolves profile: `tiny` / `modest` / `balanced` / `high`.
- Auto-adjusts:
  - max training iterations,
  - holdout ratio,
  - L2 sweep width,
  - max sampled training rows,
  - CV fold guard (minimum 5).
- Uses deterministic stratified downsampling when dataset exceeds cap.

Key metadata emitted for auditability:
- `resource_profile`,
- `detected_cpu_count`, `detected_memory_gib`,
- `effective_max_iter`, `effective_max_samples`, `effective_l2_grid_points`,
- `sampled_from_rows`.

### 5.2 Runtime scheduler for closed-loop signature ML retraining (server-side)

Implemented in `fe_eguard` as an egcron task:
- Task id/type: `signature_ml_feedback_train`
- Module: `lib/eg/egcron/task/signature_ml_feedback_train.pm`
- Default schedule: `0 2 * * *` (local nightly)
- Default execution locality: `local=1`

What it does per run:
1. Queries live adjudicated feedback from server DB (`endpoint_event` + latest `alert_feedback` per event).
2. Builds external NDJSON signals with runtime-compatible L5 feature fields.
3. Runs processing pipeline scripts shipped on server package at `/usr/local/eg/threat-intel/processing/`
   (or external canonical repo when `EGUARD_ML_AGENT_REPO_PATH` is set):
   - `signature_ml_build_training_corpus.py`
   - `signature_ml_label_quality_gate.py`
   - `signature_ml_feature_snapshot_gate.py`
   - `signature_ml_train_model.py` (adaptive profile aware)
   - `signature_ml_offline_eval_gate.py`
4. Writes artifacts + run report under `EGUARD_ML_OUTPUT_ROOT` (default `/usr/local/eg/var/mlops/signature-ml-feedback`).

Runtime configuration knobs (environment):
- `EGUARD_ML_AGENT_REPO_PATH` (optional override for external canonical `eguard-agent` repo path)
- `EGUARD_ML_OUTPUT_ROOT`
- `EGUARD_ML_LOOKBACK_HOURS`
- `EGUARD_ML_QUERY_LIMIT`
- `EGUARD_ML_MIN_FEEDBACK_ROWS`
- `EGUARD_ML_SAMPLE_COUNT`
- `EGUARD_ML_EXTERNAL_SAMPLE_CAP`
- `EGUARD_ML_RESOURCE_PROFILE` (`auto`, `tiny`, `modest`, `balanced`, `high`)
- Optional trainer caps: `EGUARD_ML_MAX_SAMPLES`, `EGUARD_ML_CV_FOLDS`, `EGUARD_ML_L2_GRID_POINTS`
- Gate behavior: `EGUARD_ML_FAIL_ON_THRESHOLD`, `EGUARD_ML_FAIL_ON_REGRESSION`

Manual trigger options:
```bash
# API trigger (authenticated admin context)
POST /api/v1/config/maintenance_task/signature_ml_feedback_train/run

# Direct local trigger
/usr/local/eg/sbin/egcron signature_ml_feedback_train
```

Run artifacts to collect for evidence:
- `latest-report.json`
- `latest/pipeline.log`
- `latest/signature-ml-model.json`
- `latest/signature-ml-model-metadata.json`
- `latest/signature-ml-offline-eval-report.json`

### 5.3 C2 beaconing detection operations

C2 beaconing detection uses mutual information (MI) to identify periodic command-and-control communication patterns:

**Mutual information computation:**

```
I(X; Y) = Σ p(x, y) · log₂(p(x, y) / (p(x) · p(y)))
```

where X = inter-arrival time bucket, Y = payload size bucket.

**Quantization:** 8 time buckets × 8 size buckets (64-cell joint distribution), computed per destination (IP:port) pair over a sliding window.

**Detection logic:**
- High MI (> 0.5 bits) combined with regular periodicity in inter-arrival times indicates beaconing behavior.
- Wired to Layer 5 as feature #32 (`c2_beacon_mi`).
- Threshold is set via conformal calibration (Section 3.7) to bound false-positive rate.

**Operational notes:**
- MI computation runs in the agent's network telemetry path, not the process event path.
- Per-destination state is bounded by an LRU cache (max 1024 destinations tracked).
- Destinations with fewer than 20 observations in the window are excluded (insufficient statistical power).

Exit criteria:
- Upload, aggregate, fetch, seed, and re-upload loop proven by logs + DB.
- Runtime signature-ML nightly task reports `status=success` and emits fresh model metadata.
- No blocking runtime errors.

---

## 6) Canary rollout playbook

### 6.1 Strategy

Roll out in stages:

- Stage 0: 0% (disabled)
- Stage 1: 1%
- Stage 2: 5%
- Stage 3: 20%
- Stage 4: 100%

Canary eligibility is deterministic by `agent_id` hash bucket.

### 6.2 Rollout fields

Set via policy JSON:

- `baseline_upload_canary_percent`
- `fleet_seed_canary_percent`

Recommended sequence:

1. Set both to 1
2. Observe 30–60 minutes
3. Increase to 5
4. Increase to 20
5. Increase to 100

Do not advance if any stage has severe errors (data corruption, service instability, bad false-positive spike).

### 6.3 Validation per stage

For each stage, verify:

- Upload count increases only in eligible cohort.
- Fleet seed apply logs appear only in eligible cohort.
- Endpoint performance remains within budget.
- SOC queue quality does not degrade.

---

## 7) Kill switch and rollback playbook

## 7.1 Immediate live kill switch (no restart)

Set policy fields:

- `baseline_upload_enabled=false`
- `fleet_seed_enabled=false`

This immediately halts sync paths while keeping detection operational.

## 7.2 Startup hard disable (restart-based)

Set environment vars:

- `EGUARD_BASELINE_UPLOAD_ENABLED=false`
- `EGUARD_FLEET_SEED_ENABLED=false`

Restart agent service.

## 7.3 Rollback order

1. Disable upload/seed via policy (fast stop).
2. Reassign stable policy (`default` or last known-good).
3. Roll back binaries if needed.
4. Re-verify heartbeat/inventory/telemetry.
5. Re-enable incrementally with canary.

---

## 8) Verification and evidence collection

## 8.1 API checks (server)

- `GET /api/v1/endpoint/inventory`
- `POST /api/v1/endpoint/baseline/batch`
- `POST /api/v1/endpoint/baseline/aggregate`
- `GET /api/v1/endpoint/baseline/fleet?limit=...`
- `POST /api/v1/endpoint/policy`
- `POST /api/v1/endpoint/policy/assign`

## 8.2 DB checks (MySQL)

Required checks:

- Endpoint baseline row count growth
- Fleet baseline row presence
- Fleet key agent_count >= minimum cohort
- Latest endpoint inventory OS fields
- Policy assignment on canary agents

## 8.3 Agent log checks

Look for:

- `uploaded baseline profile batch`
- `applied fleet baseline seed profiles`
- `updated ... canary percent from policy`
- baseline persistence logs with compaction stats

## 8.4 GUI checks (human-like)

Required pages:

- `/admin#/endpoint-inventory`
- `/admin#/endpoint-nac`
- `/admin#/endpoint-audit`
- `/admin#/endpoint-whitelist`

Capture screenshots and keep in release evidence bundle.

---

## 9) Dashboards and SLO signals

Track the following minimum signals:

1. **Baseline Upload Throughput**
   - rows/min, agents uploading, rejected payload count
2. **Fleet Seed Effectiveness**
   - rows fetched, rows applied, seed hit rate
3. **Aggregation Health**
   - successful runs, duration, aggregated keys, skipped/removed counts
4. **Baseline State Health**
   - counts of Learning/Active/Stale agents
5. **Safety Signals**
   - canary coverage, kill switch state, rollback events
6. **Fleet JS-divergence trend**
   - JS(P_t, P_{t-1}) per aggregation cycle, plotted as time series
   - Alert threshold: JS > 0.1 sustained for 2 consecutive cycles
7. **ADWIN drift alarm count**
   - Count of ADWIN alarms fired per 24h rolling window
   - Alert threshold: > 3 alarms in 24h indicates systemic drift
8. **Conformal p-value distribution**
   - Distribution of conformal p-values across detection events (should be uniform under null hypothesis)
   - Alert threshold: KS-test p < 0.01 against uniform → recalibration needed
9. **C2 beaconing mutual information alerts**
   - Count of destinations exceeding MI threshold per agent per day
   - Alert threshold: > 5 unique high-MI destinations from a single agent
10. **Process tree anomaly rate**
    - Fraction of process trees flagged anomalous by L5 graph features
    - Alert threshold: rate > 2× rolling 7-day average

Recommended alert thresholds (baseline pipeline):

- Upload reject count > 0 sustained for 30 min
- Aggregation failures for 2 consecutive cycles
- Sudden spike in stale transitions
- Seed apply dropping to zero unexpectedly while fleet rows exist

---

## 10) Troubleshooting guide

### Symptom: `feature 'ebpf-libbpf' is disabled in this build`

Cause:
- Linux binary built without eBPF feature.

Fix:
- Rebuild with:
  - `cargo build --release -p agent-core --features platform-linux/ebpf-libbpf`
- Redeploy agent binary and restart service.
- Verify logs show probe attach success (`objects=... attached=...`).

### Symptom: baseline upload does not run

Checks:
- `baseline_upload_enabled`
- `baseline_upload_canary_percent` > 0
- dirty keys exist
- payload not rejected by cap

### Symptom: fleet seed never applies

Checks:
- `fleet_seed_enabled`
- `fleet_seed_canary_percent` > 0
- agent status is Learning/Stale
- server has rows in `fleet_baseline`

### Symptom: signature/count warnings from threat-intel bundle

Impact:
- Not baseline-loop fatal, but production hygiene issue.

Action:
- Replace staged bundle with valid signed artifact.
- Re-run bundle verification and count corroboration.

### Symptom: non-mTLS transport in production

Checks:
- TLS files exist and readable:
  - `EGUARD_TLS_CERT`
  - `EGUARD_TLS_KEY`
  - `EGUARD_TLS_CA`

Action:
- Provision certs/keys, restart, confirm mTLS channel startup.

---

## 11) Production readiness gate (sign-off)

Mark **READY** only when all are true:

- [ ] Upload → aggregate → fleet fetch → seed apply verified on real endpoints
- [ ] Canary progression 1%→5%→20%→100% completed without Sev-1/2 incident
- [ ] Kill switch tested and proven without restart
- [ ] Rollback tested and documented
- [ ] Dashboard/alerts configured and tested
- [ ] eBPF production build parity verified (linux)
- [ ] Threat-intel bundle signature path clean
- [ ] mTLS configured for production transport
- [ ] Evidence pack archived (logs, SQL outputs, screenshots)

---

## 12) Appendix: policy and command templates

## 12.1 Policy template (canary + toggles)

```json
{
  "policy_id": "mlops-rollout",
  "policy_version": "v1",
  "policy_json": {
    "baseline_upload_enabled": true,
    "fleet_seed_enabled": true,
    "baseline_upload_canary_percent": 5,
    "fleet_seed_canary_percent": 5,
    "baseline_mode": "learning"
  }
}
```

## 12.2 Assign policy to one agent

```json
{
  "agent_id": "agent-31bbb93f38b4",
  "policy_id": "mlops-rollout",
  "policy_version": "v1"
}
```

## 12.3 Emergency disable template

```json
{
  "policy_id": "mlops-killswitch",
  "policy_version": "v1",
  "policy_json": {
    "baseline_upload_enabled": false,
    "fleet_seed_enabled": false
  }
}
```

## 12.4 Minimal SQL verification set

```sql
SELECT COUNT(*) FROM endpoint_baseline;
SELECT COUNT(*) FROM fleet_baseline;
SELECT process_key, agent_count, computed_at FROM fleet_baseline ORDER BY computed_at DESC;
SELECT agent_id, os_version, collected_at FROM endpoint_inventory ORDER BY collected_at DESC LIMIT 20;
```

---

## Final note

This manual reflects the implemented baseline+ML wiring and lab validation state as of 2026-03-01.
Use it as the operational source of truth for rollout, monitoring, and incident-safe control of the baseline pipeline.
