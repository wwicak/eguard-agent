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
- **Do not derive Windows `os_version` from CPU architecture env vars**: `PROCESSOR_ARCHITECTURE=AMD64` is not an OS version and led to misleading inventory (`Windows (AMD64)`). For inventory/compliance snapshots, prefer `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName` (+ optional DisplayVersion/ReleaseId) and only fallback to numeric kernel/build values.
- **PowerShell UTF-8 BOM breaks TOML parser**: Windows PowerShell 5.x's `Set-Content -Encoding UTF8` adds a BOM (`EF BB BF`). The agent's TOML parser (for bootstrap.conf) fails silently when the file starts with BOM. Fix: use `[System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))` instead.
- **Server install.ps1 had 3 mismatches**: service name was `eguard-agent` (should be `eGuardAgent`), config dir was `C:\ProgramData\eguard-agent` (should be `C:\ProgramData\eGuard`), and data subdirs (certs, rules-staging, quarantine, logs) were not created. All fixed.
- **When topology is contractually fixed, remove compatibility branches instead of preserving them**: if deployment guarantees same-host runtime (like `eg-agent-server` with local NAC modules), eliminate split-host/legacy HTTP paths (`mode=http`, `EGUARD_PF_*`) to avoid dead code and operator confusion. Keep only the required mode(s) and fail/force predictably for unsupported values.
- **When user asks to “fully implement (no stub)” against an acceptance doc, audit every integration seam for nil/placeholders**: specifically check transport responses (e.g., gRPC response fields), CI scripts that only emit contract text, and storage paths that look single-file but need journal/compaction behavior. Close those seams before declaring complete.
- **Closed-loop ML requirements must land in runtime orchestration, not only CI workflows**: if feedback-loop behavior is requested, prioritize server/agent scheduler wiring and local execution paths first; treat GitHub workflows as secondary tooling.
- **Clarify runtime script locality across repos early**: when server-side operators require self-contained execution, mirror required processing scripts into `fe_eguard` package/runtime paths instead of assuming external checkout dependencies.
- **Before re-triggering GitHub Actions repeatedly, run the same verification script locally first**: use `./scripts/run_verification_suite_ci.sh` (prefer `EGUARD_VERIFICATION_PROFILE=fast` for pre-push) to eliminate obvious clippy/test failures and reduce CI churn.
- **Never hardcode lab/real server IPs in tests**: use loopback (`127.0.0.1`) or clearly synthetic placeholders in test fixtures to avoid environment coupling and operator confusion.
- **Honor explicit CI runtime budgets**: if user sets a max pipeline time (e.g., 15 minutes), implement a strict fast profile and step timeout first, then keep heavy fuzz/Miri/guardrail checks in scheduled/release full profile.
