{
  "id": "d7bea2f8",
  "title": "Implement remaining feedback roadmap (runtime ML hardening + model upgrade + sequence detection + ops polish)",
  "status": "completed",
  "created_at": "2026-03-03T10:40:12.335Z",
  "assigned_to_session": "a0049ac6-454f-41e1-a7f0-f5c9635ae10b",
  "steps": [
    {
      "id": 1,
      "text": "Finalize P0 runtime inference hardening in fe_eguard: enforce deterministic scoring parity, complete observability fields, and verify fallback semantics on invalid/missing models.",
      "done": true
    },
    {
      "id": 2,
      "text": "Validate P0 end-to-end on lab infrastructure: deploy eg-agent-server binary to eguard VM, trigger threat-intel sync, verify /state runtime model status and persisted ml_score on Linux/Windows endpoint telemetry.",
      "done": true
    },
    {
      "id": 3,
      "text": "Add acceptance-gate evidence pack in docs/operations-guide.md: commands, expected outputs, rollback flow, and edge-case handling for bad model payloads.",
      "done": true
    },
    {
      "id": 4,
      "text": "Design and implement P1 model abstraction in server runtime (logit + tree): add model_type loader, deterministic tree inference path, and backward-compatible fallback to current logistic model.",
      "done": true
    },
    {
      "id": 5,
      "text": "Upgrade training/export pipeline to produce tree model artifact in runtime-compatible JSON, plus CI gate comparing PR-AUC/ROC-AUC/recall-at-FPR against baseline with failure thresholds.",
      "done": true
    },
    {
      "id": 6,
      "text": "Implement real-telemetry-first training corpus controls: dataset composition checks, provenance fields, and synthetic-cap policy enforcement in CI and metadata outputs.",
      "done": true
    },
    {
      "id": 7,
      "text": "Expand feature surface toward 200+ with schema contract evolution, backward compatibility, and runtime feature extraction instrumentation.",
      "done": true
    },
    {
      "id": 8,
      "text": "Implement P2 sequence scoring: sliding-window host state machine, multi-step attack correlation output, and latency-budget metrics.",
      "done": true
    },
    {
      "id": 9,
      "text": "Add P3 adversarial robustness gate: transformation harness, regression thresholds, and promotion-blocking policy.",
      "done": true
    },
    {
      "id": 10,
      "text": "Run full regression and live validation: unit/integration tests, workflow checks, UI validation via agent-browser, then update tasks/todo.md and operations docs with final sign-off evidence.",
      "done": true
    }
  ]
}
