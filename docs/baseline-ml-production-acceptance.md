# Baseline + ML Production Wiring — Acceptance Criteria

**Version:** 2.0
**Date:** 2026-03-01
**Scope:** eGuard agent (`eguard-agent`) + server (`fe_eguard`) baseline/ML data loop

---

## 0) Implementation Status (2026-02-28)

This acceptance contract is now wired to working code (no placeholder path) for baseline ingest/sync:

- Agent baseline loop implemented:
  - dirty-key tracking + periodic/bounded batch upload (`/api/v1/endpoint/baseline/batch`),
  - significant-change trigger (large dirty backlog uploads without waiting full interval),
  - learning/stale fleet-seed fetch + apply,
  - weak-local strengthening + mature-local protection,
  - shard reseed after fleet apply,
  - payload cap override (`EGUARD_BASELINE_UPLOAD_MAX_BYTES`) + reject counter path,
  - canary rollout gating for upload/fleet-seed paths (`*_CANARY_PERCENT` + policy overrides),
  - gRPC mode fleet-seed fetch uses heartbeat-delivered fleet baseline cache (no HTTP-only fallback dependency).
- Agent storage upgraded:
  - snapshot (`baselines.bin`) + append journal (`baselines.journal`) + metadata sidecar,
  - checksum-validated replay with corrupted-tail tolerance,
  - compaction trigger by age/size,
  - bounded profile cardinality with LRU eviction,
  - structured persistence logs include snapshot/journal sizes and compaction reclaimed bytes.
- Server ingest/aggregate path implemented:
  - baseline single + batch ingest,
  - fleet import endpoint with source/source-version provenance,
  - normalized median distributions,
  - idempotent persistence (upsert by key),
  - gRPC heartbeat now returns non-stub `fleet_baseline` report when fleet rows exist,
  - production baseline aggregation cadence moved to 6h default (`egcron`).
- Workflow bundle path implemented:
  - CI baseline aggregation script now performs real median aggregation and emits
    `artifacts/baseline-aggregation/fleet-baseline-bundle.json`.

Validation evidence:
- `cargo test -p baseline`
- `cargo test -p grpc-client`
- `cargo test -p agent-core`
- `go test ./...` in `go/agent/server`
- Agent-core tests:
  - `baseline_e2e_upload_fetch_seed_flow_works` validates learn/upload/fetch/seed path,
  - canary/kill-switch tests validate 0% rollout disables upload/fetch paths.

Runtime observability counters now include:
- baseline rows uploaded total,
- fleet seed rows applied total,
- baseline upload payload reject total,
- baseline stale transition total.

---

## 1) Objective

Define measurable production acceptance criteria for a fully wired learning loop:

1. Agent learns local behavioral baselines.
2. Agent uploads baseline snapshots/deltas to server.
3. Server aggregates fleet baselines.
4. Learning agents consume fleet seeds.
5. Detection layer (L3 anomaly) uses seeded+local data safely.

Includes a storage strategy that is efficient, durable, and rollback-safe.

Design as 3-plane ML system:

 1. Endpoint Inference Plane (real-time, low-latency)
     - Lightweight ensemble on agent:
           - sequence anomaly (process/syscall flow),
           - graph behavioral risk,
           - file/script risk scorer,
           - calibrated fusion model.
     - Deterministic rules stay as hard guardrails.
 2. Fleet Intelligence Plane (server)
     - Fleet baseline aggregation, drift analysis, campaign clustering.
     - Threat model retraining + calibration generation.
 3. Research/Offline Plane
     - Replay harness, adversarial simulation, ATT&CK coverage scoring.
     - Promotes only signed, gated artifacts.

 3) Close wiring gaps first (critical)

 Before adding fancy models, fix system plumbing end-to-end:

 - Agent uploads per-process baseline snapshots/deltas.
 - Server aggregates fleet baselines on schedule (not placeholder CI only).
 - Learning agents consume fleet seeds and apply to Layer3 immediately.
 - Configured learning windows are actually respected (not hardcoded constants only).
 - Model/baseline artifacts shipped in signed bundle with compatibility metadata.
 - Wired with bundle signature from daily build workflow. (ingest bundle, process in pipeline)

 This gives a real learning loop.

 ────────────────────────────────────────────────────────────────────────────────

 4) MLOps safety model (must-have)

 - Model registry: versioned, signed, immutable.
 - Promotion gates: PR-AUC/ROC-AUC/ECE/Brier + regression checks.
 - Shadow mode first, then canary (1% → 5% → 20% → 100%).
 - Auto rollback + kill switch for bad model versions.
 - Data drift + concept drift monitors with alerts.

 This is where many vendors fail.

 ────────────────────────────────────────────────────────────────────────────────

 5) SOC-grade explainability

 Every ML alert must include:

 - top contributing features,
 - correlated events/process chain,
 - ATT&CK mapping confidence,
 - why this is different from baseline,
 - recommended response confidence band.

 If analysts trust it, adoption skyrockets.

---

## 2) Storage Strategy (target)

### Agent-side (hot + compact)
- **Hot state:** in-memory process baseline map used by L3.
- **Durable state:** `baselines.bin` snapshot + append-only delta journal (`baselines.journal`) with periodic compaction.
- **Compaction rule:** compact when journal > 25% of snapshot size or every 6h.
- **Integrity:** checksum each journal segment; ignore corrupted tail segment and continue from last valid offset.

### Server-side (fleet scale)
- **Raw per-agent baseline:** `endpoint_baseline` (upsert by `agent_id + process_key`).
- **Fleet aggregate:** `fleet_baseline` (median distribution + stddev_kl + computed_at).
- **Retention:** keep only active-relevant baseline rows by heartbeat freshness policy.
- **Aggregation cadence:** every 6h (production), with stale fleet keys purged.

---

## 3) Acceptance Criteria

## A. Agent Learning & Runtime Safety

- **AC-BML-001 (Learning window behavior):**
  During `BaselineStatus=learning`, detections still execute all layers and telemetry is sent, but autonomous response is forced to `AlertOnly`.

- **AC-BML-002 (Transition correctness):**
  After learning window completion or policy force-active, status transitions to `active`, persisted to disk, and runtime mode updates without restart.

- **AC-BML-003 (Config-driven windows):**
  Learning/refresh/stale windows are controlled by agent config values (no hidden hardcoded durations in runtime behavior).

- **AC-BML-004 (Stale behavior):**
  Baseline transitions to `stale` after configured inactivity window and emits an operator-visible warning.

## B. Agent -> Server Baseline Upload Wiring

- **AC-BML-010 (Upload endpoint auth):**
  `POST /api/v1/endpoint/baseline` requires agent-scope auth and rejects unauthenticated writes.

- **AC-BML-011 (Delta upload schedule):**
  Agent uploads baseline deltas at fixed interval (default 15m) and on significant change trigger.

- **AC-BML-012 (Bounded payload):**
  Single upload payload is bounded (default <= 1 MB) and chunked/split if exceeded.

- **AC-BML-013 (Idempotent persistence):**
  Re-sending same baseline data does not duplicate rows; upsert remains deterministic by `agent_id + process_key`.

- **AC-BML-014 (Schema completeness):**
  Persisted rows include `event_distribution`, `sample_count`, `entropy_threshold`, and `learned_at`.

## C. Server Fleet Aggregation

- **AC-BML-020 (Production scheduler):**
  Fleet baseline aggregation runs from production scheduler (`egcron`) at configured cadence and logs summary (`updated/skipped/removed`).

- **AC-BML-021 (Median correctness):**
  Fleet aggregation computes element-wise median per process key and normalizes distribution sum to ~1.0 (tolerance ±0.001).

- **AC-BML-022 (Minimum cohort gate):**
  Fleet baseline published only when distinct active agents for process key >= configured minimum (default 3).

- **AC-BML-023 (Stale fleet cleanup):**
  Fleet baselines with insufficient active support are removed during aggregation cycle.

- **AC-BML-024 (Workflow database bundle ingestion):**
  Server supports importing fleet baseline bundles produced by CI/workflow pipelines via authenticated admin endpoint, with strict schema validation and source/version provenance persisted.

- **AC-BML-025 (Runtime signature-ML scheduler):**
  Server-side scheduler (`egcron`) runs closed-loop signature-ML retraining from live endpoint feedback (`endpoint_event` + `alert_feedback`) and writes model/eval artifacts locally for operator promotion.

## D. Fleet Seed Consumption (Server -> Agent)

- **AC-BML-030 (Learning-only seed pull):**
  Agent fetches fleet baselines while in `learning` (or stale-recovery mode), not continuously in normal active mode unless explicitly enabled.

- **AC-BML-031 (Seed apply rules):**
  Fleet seeds apply only to missing/weak local process profiles; never overwrite stronger local matured profiles unless policy allows.

- **AC-BML-032 (Shard propagation):**
  After seed apply, L3 anomaly baselines are pushed to all detection shards atomically.

- **AC-BML-033 (Fallback safety):**
  If fleet baseline fetch fails, agent continues local learning without blocking detection pipeline.

## E. Clever Storage / Efficiency

- **AC-BML-040 (Compaction):**
  Agent baseline journal compaction reduces on-disk delta size by >= 60% in steady-state benchmark vs naive full snapshot writes every interval.

- **AC-BML-041 (Bounded growth):**
  Agent baseline storage remains bounded under long-running load (no unbounded per-process cardinality growth; enforce key cap + LRU expiry policy).

- **AC-BML-042 (Crash recovery):**
  Abrupt process termination during baseline write recovers cleanly on next start without data corruption panics.

- **AC-BML-043 (Server retention):**
  Endpoint baseline and fleet baseline retention policies are enforced and query latency remains within SLO for top-N reads.

## F. Rollout Safety

- **AC-BML-050 (Feature flags):**
  Separate runtime flags for upload and fleet-seed consume (`upload_enabled`, `fleet_seed_enabled`) with default-safe values.

- **AC-BML-051 (Canary rollout):**
  Canary cohort deployment supports 1%/5%/20% staged rollout with explicit rollback trigger.

- **AC-BML-052 (Kill switch):**
  Operators can disable upload/seed paths without restarting all agents.

## G. Observability & SRE

- **AC-BML-060 (Core metrics):**
  Export metrics for baseline rows uploaded, seed rows applied, aggregation success/failure, stale transitions, and payload reject counts.

- **AC-BML-061 (Structured logs):**
  Structured logs include agent_id, baseline_status, uploaded_profile_count, seeded_profile_count, and compaction stats.

- **AC-BML-062 (Dashboards):**
  Dashboard panels exist for baseline pipeline health and seed effectiveness.

## H. Validation Gates

- **AC-BML-070 (Unit tests):**
  Tests cover transition logic, delta compaction, idempotent upsert, seed merge policy, and shard propagation.

- **AC-BML-071 (Integration tests):**
  End-to-end test validates learn → upload → aggregate → fetch → seed → detect path.

- **AC-BML-072 (Perf budget):**
  Baseline upload + apply overhead stays within CPU/memory budgets on reference workload.

- **AC-BML-073 (Backward compatibility):**
  Existing agents without new baseline payload fields continue heartbeat/compliance/telemetry without regression.

## I. Advanced ML Integration

- **AC-BML-080 (Bayesian fleet prior):**
  Agent uses Dirichlet-Multinomial conjugate prior derived from fleet seed during baseline merge. Concentration parameter κ decays with local sample count (κ = 100 for new agents, κ → 0 as sample_count → 1000). Posterior mean θ̂ᵢ = (αᵢ + nᵢ) / (Σαⱼ + Σnⱼ) converges to local empirical distribution as n → ∞.

  **Verification:** Unit test creates agent with zero local samples and confirms posterior equals fleet prior. Second test with 10,000 local samples confirms posterior within ε < 0.001 of local empirical distribution.

  **Expected behavior:** New agents bootstrap rapidly from fleet knowledge; mature agents are unaffected by fleet prior.

- **AC-BML-081 (Conformal calibration integration):**
  Layer 5 ML detection threshold is set via conformal prediction on a calibration holdout set. Provides finite-sample guarantee: FP rate ≤ α (default α = 0.01). Threshold = ⌈(1 − α)(n + 1)⌉ / n quantile of calibration nonconformity scores. Recalibrated on each model reload.

  **Verification:** Load model with known calibration set, verify computed threshold matches expected quantile. Inject synthetic events and confirm empirical FP rate ≤ α over 10,000 trials.

  **Expected behavior:** Detection threshold self-adjusts to maintain coverage guarantee regardless of underlying score distribution.

- **AC-BML-082 (Agent-side drift detection):**
  CUSUM/Page-Hinkley detector runs on per-process KL-divergence stream. Alarm fires when cumulative deviation exceeds threshold λ. On alarm, baseline re-learning is triggered for the affected process key. Detector uses O(1) memory per monitored process key.

  **Verification:** Feed synthetic KL-divergence stream with injected mean shift. Confirm alarm fires within expected detection delay. Confirm no false alarms on stationary stream over 10,000 updates.

  **Expected behavior:** Agent autonomously detects when a process behavior has drifted from its baseline and initiates re-learning without operator intervention.

- **AC-BML-083 (Fleet drift detection):**
  Server computes Jensen-Shannon divergence between consecutive fleet aggregation cycles. ADWIN algorithm monitors JS-divergence trend with O(log W) memory. Alert fires when sustained drift is detected (|μ̂₁ − μ̂₂| ≥ √((1/2m) · ln(4/δ'))).

  **Verification:** Simulate fleet aggregation cycles with gradual distribution shift. Confirm ADWIN detects drift within 3 cycles of onset. Confirm no false alarm over 100 stationary cycles.

  **Expected behavior:** Operators are alerted to fleet-wide behavioral changes before they impact detection quality.

- **AC-BML-084 (C2 beaconing detection):**
  Mutual information I(X;Y) computed on per-destination (IP:port) inter-arrival time and payload size pairs. Quantization: 8 time buckets × 8 size buckets. MI > threshold triggers Layer 5 feature activation (`c2_beacon_mi`, feature #32). Threshold set via conformal calibration.

  **Verification:** Generate synthetic beaconing traffic (fixed interval ± jitter, fixed size ± noise) and confirm MI exceeds threshold. Generate random traffic and confirm MI stays below threshold.

  **Expected behavior:** Periodic C2 communication patterns are detected with bounded false-positive rate regardless of specific beacon interval or payload size.

- **AC-BML-085 (Process tree graph features):**
  Layer 5 feature vector extended with 6 graph-derived features extracted from enriched event process chain: `tree_depth`, `tree_breadth`, `child_entropy`, `spawn_rate`, `rare_parent_child_score`, `c2_beacon_mi`. Total L5 feature count increases from 27 to 33.

  **Verification:** Construct process tree from test events, compute all 6 features, verify values match hand-calculated expected results. Confirm feature schema JSON includes all 33 features.

  **Expected behavior:** ML model receives richer structural context about process relationships, improving detection of living-off-the-land and lateral movement patterns.

- **AC-BML-086 (Online model warm-start):**
  New model hot-reloaded via threat-intel bundle inherits conformal calibration from previous calibration set until new calibration data accumulates. Fleet Dirichlet prior provides warm-start bias for new process keys not seen during offline training.

  **Verification:** Reload model mid-session, confirm detection continues without gap. Verify conformal threshold persists across reload. Verify new process key uses fleet prior immediately.

  **Expected behavior:** Model updates are seamless — no detection blind spot during transition, no cold-start penalty for new process keys.

- **AC-BML-087 (Memory budget compliance):**
  Total agent-side ML overhead (baseline maps + detection model + conformal calibration + drift detectors + beaconing state) ≤ 2 MB RSS. Server-side ML overhead (fleet aggregation state + ADWIN detectors + model registry cache) ≤ 100 MB for fleet of 20,000 agents.

  **Verification:** Run agent under reference workload (500 process keys, 1024 network destinations), measure ML-attributed RSS via `/proc/self/statm` delta. Run server aggregation for 20K synthetic agents, measure peak RSS.

  **Expected behavior:** ML subsystem fits within resource budget on production hardware without competing with core detection and telemetry paths.

---

## 4) Definition of Done

Implementation is accepted only when:

1. All AC-BML criteria above are mapped to automated tests or explicit production checks.
2. Canary rollout runs for 7 days with no severity-1/2 incidents.
3. Ops runbook documents toggles, rollback, and troubleshooting commands.
4. Validation artifacts (test logs + dashboard screenshots + sample DB queries) are attached.

---

## 5) Lab Validation Evidence (2026-02-28, VM simulation)

Environment:
- Server: `eguard@103.49.238.102`
- Linux agent: `agent@103.183.74.3` (`agent-31bbb93f38b4`)
- Windows endpoint: `administrator@103.31.39.30` (`agent-4412`)

Deployment verified:
- `eg-agent-server` deployed to `/usr/local/eg/sbin/eg-agent-server` (sha256 matched local build).
- Frontend dist deployed to `/usr/local/eg/html/egappserver/root/dist`.
- Linux agent binary deployed to `/usr/bin/eguard-agent` (sha256 matched local build).
- Services active after restart:
  - `eguard-agent-server`
  - `eguard-api-frontend`
  - `eguard-agent`

Baseline loop live evidence:
1. **Agent upload path** observed in Linux agent logs:
   - `uploaded baseline profile batch ...`
2. **Server aggregation path** validated via live API:
   - `POST /api/v1/endpoint/baseline/batch` (3 synthetic agents)
   - `POST /api/v1/endpoint/baseline/aggregate` → `aggregated: 2`
   - `GET /api/v1/endpoint/baseline/fleet?limit=20` → 2 fleet rows.
3. **Fleet seed consume in gRPC mode** validated with policy canary flip:
   - log: `updated fleet-seed canary percent from policy fleet_seed_canary_percent=100`
   - log: `applied fleet baseline seed profiles ... seeded_profiles=1`
4. **DB state confirms loop closure**:
   - `fleet_baseline` contains aggregated keys (`python3:bash`, `powershell.exe:services.exe`).
   - `endpoint_baseline` for linux agent contains seeded key (`powershell.exe:services.exe`) after apply+upload.

5. **Runtime signature-ML scheduler integration (AC-BML-025)**:
   - New production egcron task implemented: `signature_ml_feedback_train`.
   - Task sources labels/signals from live DB feedback tables and executes adaptive trainer pipeline from packaged server path `/usr/local/eg/threat-intel/processing` (non-GitHub path).
   - Egcron scheduler hardening applied to avoid nil-schedule panic and support legacy `@every Nd` cadence parsing.
   - Live validation command:
     - `sudo /usr/local/eg/sbin/egcron signature_ml_feedback_train`
   - Successful runtime evidence:
     - latest report: `/usr/local/eg/var/mlops/signature-ml-feedback/latest-report.json`
     - observed result: `run_id=20260228T210716Z`, `status=success`
   - Artifacts persisted under local ML ops output root (`latest/` symlink):
     - model, metadata, offline eval report/trend, corpus/labels/features, pipeline log.

GUI/operator validation (agent-browser):
- Inventory: `/admin#/endpoint-inventory` (advanced filters + data integrity)
  - screenshot: `/tmp/inventory-prodready-20260228.png`
- NAC: `/admin#/endpoint-nac` isolate → status → allow → status
  - screenshots:
    - `/tmp/nac-isolated-prodready-20260228.png`
    - `/tmp/nac-allowed-prodready-20260228.png`
- Audit: `/admin#/endpoint-audit` inline row expansion (`▶` to `▼`)
  - screenshot: `/tmp/audit-inline-prodready-20260228.png`
- Whitelist page smoke:
  - screenshot: `/tmp/whitelist-prodready-20260228.png`

Cross-host smoke:
- Inventory shows latest Windows OS entries as `Windows Server 2019 Standard 1809` (legacy `Windows (AMD64)` only on historical rows).
- Windows service `eGuardAgent` is running and actively sending telemetry (`mode=Grpc`) in `C:\ProgramData\eGuard\logs\agent.log`.

Post-validation cleanup:
- Linux override returned to original skip-learning setting (`EGUARD_BASELINE_SKIP_LEARNING=1`).
- Temporary fleet-seed canary env override removed.
- Linux agent policy assignment restored to `default`.

Additional hardening from validation findings:
- Linux agent was rebuilt/redeployed with `platform-linux/ebpf-libbpf` enabled after detecting a non-production build (`feature 'ebpf-libbpf' is disabled`) in lab logs.
- Post-fix logs confirm eBPF probes load/attach successfully (`objects=9 attached=9`).

Known lab hygiene gaps (outside baseline loop wiring):
- Existing staged threat-intel bundle on Linux host reports signature/manifest mismatch warnings.
- Lab host currently lacks mTLS cert files under `/etc/eguard-agent/tls/` (non-mTLS transport in this environment).
