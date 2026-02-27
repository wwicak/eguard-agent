# Lessons

- When a user adds perspective docs mid-task (e.g., operations/architecture guides), re-anchor implementation decisions to that document before coding.
- For broad platform-parity requests, always define explicit acceptance criteria up front and keep them tracked alongside the implementation checklist.
- **Bootstrap.conf requires `[server]` section header**: The INI parser in `crates/agent-core/src/config/bootstrap.rs` only processes keys inside a `[server]` section (line 170: `if section != "server" { continue; }`). Bare key-value pairs without the section header are silently ignored, causing "bootstrap config missing enrollment_token" errors. Always write bootstrap.conf as:
  ```
  [server]
  address = <host>
  grpc_port = <port>
  enrollment_token = <token>
  schema_version = 1
  ```
- **Server gRPC port is 50052 (Caddy), not 9999 (HTTPS)**: The agent's gRPC transport connects to the Caddy gRPC proxy on port 50052, not the HTTPS API port 9999. The `grpc_port` field in bootstrap.conf must be 50052. Port 9999 is for REST API / browser access only.
- **Windows agent console mode dies when SSH session closes**: When starting the agent via SSH with `EGUARD_WINDOWS_CONSOLE=1` and `start /b`, the process receives `CTRL_CLOSE_EVENT` when the SSH console closes, causing `tokio::signal::ctrl_c()` to trigger shutdown. The agent dies during `AgentRuntime::new()` initialization. Fix: use Windows Service mode (SCM), or keep the SSH session alive. Never use `start /b` for detached agent runs.
- **EGUARD_WINDOWS_CONSOLE machine env var prevents service mode**: If `EGUARD_WINDOWS_CONSOLE` is set at the Machine level (`[System.Environment]::SetEnvironmentVariable(..., "Machine")`), the Windows service will pick it up and go to console mode instead of SCM mode, causing error 1053 (service timeout). Always use per-process env vars, never machine-level.
- **Windows agent service name**: `eGuardAgent` (not `eguardagent` or `eguard-agent`). Binary path is configurable via `sc config eGuardAgent binPath= "..."`.
- **Windows E2E test results (Feb 2026)**: Agent enrolls, ETW consumer starts (`eGuardEtwSession`), events flow to server (~259 events in 5 min), Sigma rules fire (DNS TXT, Antivirus Path, Crypto Mining). Agent runs at ~130MB after bundle loading. Detection engine: 2 shards, 354 Sigma rules, 16904 YARA rules after bundle load.
