# eGuard Agent - Windows Installer (Preview)

## Current status

Windows packaging is currently in **preview scaffolding**.

What exists now:
- `platform-windows` crate scaffolding and CI target checks.
- `agent-core` target-gated platform abstraction (`src/platform.rs`) to decouple Linux-only imports from Windows builds.
- WiX MSI source scaffold: `installer/windows/eguard-agent.wxs`.
- PowerShell bootstrap installer scaffold: `installer/windows/install.ps1`.
- Workflow validation for:
  - `cargo check --target x86_64-pc-windows-msvc -p platform-windows`
  - `cargo check --target x86_64-pc-windows-msvc -p agent-core`
  - `cargo build --release --target x86_64-pc-windows-msvc -p agent-core`
  - `wix build installer/windows/eguard-agent.wxs -dAgentExePath=<agent-core.exe>` (preview MSI build artifact)

What is still open:
- Final `agent-core` Windows runtime wiring.
- Production MSI build/sign validation against the WiX source scaffold (`installer/windows/eguard-agent.wxs`).
- Production code-signing for MSI and release artifact hardening.
- Validation of `installer/windows/install.ps1` against live server endpoint + real Windows host install/upgrade/uninstall flows.

## Planned installer behavior (target state)

The final Windows installer will package the eGuard agent as an MSI using WiX Toolset v4+.
It is expected to:
- install `eguard-agent.exe`
- register service `eGuardAgent`
- support silent install properties (`ENROLLMENT_TOKEN`, `SERVER_URL`)
- support upgrade/uninstall while preserving enrollment state

## Intended silent install command

```powershell
msiexec /i eguard-agent_<version>_x64.msi /qn ENROLLMENT_TOKEN=<token> SERVER_URL=<url>
```

## Bootstrap install script scaffold

A preview bootstrap script is provided at `installer/windows/install.ps1`.

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\windows\install.ps1 \
  -ServerUrl https://server.example.com \
  -EnrollmentToken <token>
```

Optional integrity/transport overrides:
```powershell
# Explicit hash pin (skip hash-metadata fetch path)
powershell -ExecutionPolicy Bypass -File .\installer\windows\install.ps1 \
  -ServerUrl https://server.example.com \
  -EnrollmentToken <token> \
  -ExpectedHash <64-hex-sha256>

# Only for controlled test environments
# -AllowInsecureHttp: permit http:// server URL
# -AllowUnsignedMsi: do not fail closed on invalid Authenticode status
```

Script behavior (scaffold):
- enforces secure-by-default server URL policy (`https://`; `http://` requires `-AllowInsecureHttp`)
- downloads MSI from `GET /api/v1/agent-install/windows` using `X-Enrollment-Token`
- enforces fail-closed integrity:
  - resolves expected SHA-256 from `-ExpectedHash` or `GET /api/v1/agent-install/windows/sha256`
  - verifies local MSI hash before install
  - requires valid Authenticode signature unless `-AllowUnsignedMsi` is explicitly set
- writes `C:\ProgramData\eGuard\bootstrap.conf` and hardens ACLs to SYSTEM/Administrators
- installs MSI silently and starts `eGuardAgent`
- removes `bootstrap.conf` after successful start (unless `-KeepBootstrap`)

## Intended Windows layout

```text
C:\Program Files\eGuard\
  eguard-agent.exe

C:\ProgramData\eGuard\
  bootstrap.conf
  agent.conf
  certs\
  rules-staging\
  quarantine\
  buffer.db
  baselines.bin
  logs\eguard-agent.log
```

## Notes

This README is intentionally explicit to avoid claiming MSI/service parity before implementation lands.
Use `.github/workflows/release-agent-windows.yml` preview artifacts as the current CI signal.
