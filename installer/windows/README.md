# eGuard Agent - Windows Installer

## Current status

Windows packaging and runtime are now integrated into the main release path.

What exists now:
- `agent-core` runs as a real Windows Service (`eGuardAgent`) via SCM dispatch, with optional console-mode fallback (`EGUARD_WINDOWS_CONSOLE=1`).
- `platform-windows` telemetry/compliance/response modules are wired into the Windows runtime path.
- WiX MSI definition: `installer/windows/eguard-agent.wxs` (version passed from CI via `AgentVersion`).
- PowerShell bootstrap installer: `installer/windows/install.ps1`.
- Release workflow builds and publishes Windows artifacts:
  - `eguard-agent.exe`
  - `eguard-agent-<version>-x64.msi`
  - `install.ps1`

What is still open:
- Production code-signing policy enforcement for `.exe` and `.msi` artifacts.
- End-to-end install/upgrade/uninstall validation on fleet-like Windows environments.
- Optional hardening of MSI custom actions for enrollment bootstrap orchestration.

## Installer behavior

The Windows installer packages the eGuard agent as an MSI using WiX Toolset.
It supports:
- installing `eguard-agent.exe`
- registering service `eGuardAgent`
- silent install properties (`ENROLLMENT_TOKEN`, `SERVER_URL`)
- upgrade/uninstall while preserving enrollment state

## Intended silent install command

```powershell
msiexec /i eguard-agent_<version>_x64.msi /qn ENROLLMENT_TOKEN=<token> SERVER_URL=<url>
```

## Bootstrap install script

Bootstrap helper script: `installer/windows/install.ps1`.

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

Script behavior:
- enforces secure-by-default server URL policy (`https://`; `http://` requires `-AllowInsecureHttp`)
- downloads MSI from `GET /api/v1/agent-install/windows-exe` using `X-Enrollment-Token`
- enforces fail-closed integrity:
  - resolves expected SHA-256 from `-ExpectedHash` or `GET /api/v1/agent-install/windows-exe/sha256`
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

Primary CI signal for Windows artifacts is `.github/workflows/release-agent.yml` (windows job).
For production rollout, keep enforcing code-signing + staged rollout gates.
