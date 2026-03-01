# eGuard Endpoint Agent

Initial workspace scaffold for the first-party endpoint agent described in
`docs/eguard-agent-design.md` from the main eGuard repository.

## Operator / tester guide

For deployment + E2E operations across `fe_eguard` and `eguard-agent`, see:

- `docs/EGUARD_PLATFORM_GUIDE.md`
- `docs/operations-guide.md`
- `docs/ml-ops-operations-manual.md` (Baseline+ML rollout, canary, kill-switch, rollback, evidence runbook)

## Detection Capabilities

Multi-layer detection engine with CrowdStrike-parity coverage. See
[operations-guide.md](operations-guide.md) for operational details.

| Layer | Technique | Notes |
|-------|-----------|-------|
| L1 — IOC | Hash/domain/IP exact match | Cuckoo prefilter, confidence escalation |
| L2 — SIGMA | Temporal rule correlation | 361 rules from 5 sources |
| L3 — Anomaly | KL-divergence + Shannon entropy + CUSUM drift | Per-endpoint adaptive baseline |
| L4 — Kill Chain | Graph matching against MITRE ATT&CK | Multi-stage attack detection |
| L5 — ML | 33-feature logistic regression + conformal calibration | Ensemble scoring |
| Behavioral | 9-dimensional CUSUM + Wasserstein + spectral analysis | Drift detection |
| YARA | File signature scanning | 2891 rules |
| CVE | Real-time vuln matching via CveDatabase | Against installed software |
| Beaconing | C2 detection via mutual information | Inter-arrival/size patterns |
| Campaign | Cross-endpoint IOC correlation | VeryHigh confidence escalation |
| Network IOC | DNS/IP matching | Confidence escalation to High |

**On-premise advantages vs cloud EDR:**

- Zero-latency fleet queries (<1ms LAN vs cloud RTT)
- Full data sovereignty — no data leaves premises
- Customer-specific homogeneous baselines (20K agents in one org)
- No cloud compute bills, no vendor lock-in

## Runtime configuration (current)

Default deployment mode expects the agent to receive `server_addr` during
install/enrollment (no baked IP). The installer writes `bootstrap.conf`; after
the first successful enrollment, agent-core now persists bootstrap-derived
`server_addr`/`enrollment_token`/`tenant_id` into `agent.conf` and then consumes
`bootstrap.conf` so restarts remain stable.

`agent-core` loads configuration from file, then environment overrides.

Config file lookup order:

1. `EGUARD_AGENT_CONFIG` (explicit path)
2. `/etc/eguard-agent/agent.conf`
3. `./conf/agent.conf`
4. `./agent.conf`

Example file template: `conf/agent.conf.example`

Policy refresh tuning:

- `[control_plane].policy_refresh_interval_secs` in config file
- `EGUARD_POLICY_REFRESH_INTERVAL_SECS` in environment
- default is `300` seconds

Environment overrides:

- `EGUARD_SERVER_ADDR` (preferred) or `EGUARD_SERVER` for server endpoint
- `EGUARD_AGENT_ID` for agent identifier
- `EGUARD_AGENT_MAC` for endpoint MAC address
- `EGUARD_AGENT_MODE` in `learning|active|degraded`
- `EGUARD_TRANSPORT_MODE` or `EGUARD_TRANSPORT` in `http|grpc`
- `EGUARD_AUTONOMOUS_RESPONSE` in `true|false`/`1|0`
- `EGUARD_BUFFER_BACKEND` in `sqlite|memory`
- `EGUARD_BUFFER_PATH` for sqlite file path
- `EGUARD_BUFFER_CAP_MB` for cap size in MB
- `EGUARD_TLS_CERT`, `EGUARD_TLS_KEY`, `EGUARD_TLS_CA` for mTLS material
- `EGUARD_POLICY_REFRESH_INTERVAL_SECS` for policy fetch cadence from server

Current precedence: defaults < config file < environment variables.

Current transport supports `http` and `grpc` modes.

Recommended install flow (no baked IP):

```bash
curl -fsSL https://<eguard-server>/install.sh | bash -s -- --server <eguard-server> --token <enrollment-token>
```

HTTP endpoints used in `http` mode:

- `POST /api/v1/endpoint/enroll`
- `POST /api/v1/endpoint/telemetry`
- `POST /api/v1/endpoint/heartbeat`
- `POST /api/v1/endpoint/compliance`
- `POST /api/v1/endpoint/response`
- `GET /api/v1/endpoint/command/pending?agent_id=...`
- `POST /api/v1/endpoint/command/ack`
- `GET /api/v1/endpoint/threat-intel/version?limit=1`
- `GET /api/v1/endpoint/state` (degraded-mode recovery probe)

Command handling currently supports stateful stubs for:

- `isolate` / `unisolate`
- `scan` / `update`
- `forensics` / `config_change` / `restore_quarantine` / `uninstall`
- `emergency_rule_push` (applies IOC/signature rule payload into live detection state)

In `grpc` mode, the client uses generated stubs from `proto/eguard/v1/*.proto`
and calls the control/telemetry/compliance/command/response services.

Current gRPC behavior:

- Telemetry uses client-streaming `StreamEvents` for batch sends
- Other RPCs use unary calls with retry/backoff reconnect attempts
- Command retrieval attempts `CommandChannel` first and falls back to poll endpoints
- mTLS channel credentials are loaded from configured cert/key/CA paths

Detection runtime behavior:

- Detection engine state is wrapped in `Arc<RwLock<...>>`
- Threat-intel version changes trigger background-safe rebuild + atomic engine swap

If `server_addr` has no scheme:

- uses `https://` when TLS cert/key/ca are configured
- otherwise uses `http://`
