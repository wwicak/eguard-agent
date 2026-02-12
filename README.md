# eGuard Endpoint Agent

Initial workspace scaffold for the first-party endpoint agent described in
`docs/eguard-agent-design.md` from the main eGuard repository.

## Runtime configuration (current)

`agent-core` loads configuration from file, then environment overrides.

Config file lookup order:

1. `EGUARD_AGENT_CONFIG` (explicit path)
2. `/etc/eguard-agent/agent.conf`
3. `./conf/agent.conf`
4. `./agent.conf`

Example file template: `conf/agent.conf.example`

Environment overrides:

- `EGUARD_SERVER_ADDR` (preferred) or `EGUARD_SERVER` for server endpoint
- `EGUARD_AGENT_ID` for agent identifier
- `EGUARD_AGENT_MAC` for endpoint MAC address
- `EGUARD_AGENT_MODE` in `learning|active|degraded`
- `EGUARD_TRANSPORT_MODE` in `http|grpc`
- `EGUARD_AUTONOMOUS_RESPONSE` in `true|false`/`1|0`
- `EGUARD_BUFFER_BACKEND` in `sqlite|memory`
- `EGUARD_BUFFER_PATH` for sqlite file path
- `EGUARD_BUFFER_CAP_MB` for cap size in MB
- `EGUARD_TLS_CERT`, `EGUARD_TLS_KEY`, `EGUARD_TLS_CA` for mTLS material

Current precedence: defaults < config file < environment variables.

Current transport supports `http` and `grpc` modes.

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
