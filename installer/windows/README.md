# eGuard Agent - Windows Installer

## Overview

The Windows installer packages the eGuard agent as an MSI using the WiX Toolset v4+. The MSI installs the agent binary, registers it as a Windows service, and configures initial enrollment parameters.

## Requirements

- WiX Toolset v4+ (`dotnet tool install --global wix`)
- .NET SDK 6.0+
- Built `eguard-agent.exe` binary (from `cargo build --release --target x86_64-pc-windows-msvc -p agent-core`)

## Build Process

```powershell
# 1. Build the agent binary
cargo build --release --target x86_64-pc-windows-msvc -p agent-core

# 2. Build the MSI package
wix build installer/windows/eguard-agent.wxs -o artifacts/windows/eguard-agent_0.1.0_x64.msi
```

## Silent Install Parameters

The MSI supports the following properties for unattended deployment:

| Property           | Description                          | Example                              |
|--------------------|--------------------------------------|--------------------------------------|
| `ENROLLMENT_TOKEN` | Agent enrollment token               | `abc123def456`                       |
| `SERVER_URL`       | eGuard server address                | `https://eguard.example.com:50052`   |
| `INSTALL_DIR`      | Custom install directory (optional)  | `C:\Program Files\eGuard`            |

```powershell
# Silent install with enrollment parameters
msiexec /i eguard-agent_0.1.0_x64.msi /qn ENROLLMENT_TOKEN=abc123 SERVER_URL=https://eguard.example.com:50052
```

## Enterprise Deployment

### Group Policy (GPO)

1. Copy the MSI to a network share accessible by target machines.
2. Create a GPO under **Computer Configuration > Software Installation**.
3. Add the MSI package as an **Assigned** application.
4. Use an MST transform or `ENROLLMENT_TOKEN`/`SERVER_URL` properties for site-specific configuration.

### SCCM / Microsoft Endpoint Manager

Create an application deployment with:
- Install command: `msiexec /i eguard-agent_0.1.0_x64.msi /qn ENROLLMENT_TOKEN=<token> SERVER_URL=<url>`
- Uninstall command: `msiexec /x eguard-agent_0.1.0_x64.msi /qn`
- Detection rule: file exists `C:\Program Files\eGuard\eguard-agent.exe`

### Microsoft Intune

1. Package the MSI as a Win32 app (`.intunewin`) using the Content Prep Tool.
2. Set install/uninstall commands as above.
3. Configure detection rules based on file presence or registry key.

## File Layout on Windows

```
C:\Program Files\eGuard\
  eguard-agent.exe          # Agent binary
  config\
    bootstrap.conf          # Bootstrap configuration (enrollment token, server)

C:\ProgramData\eGuard\
  bootstrap.conf            # Runtime configuration (post-enrollment)
  buffer.db                 # Telemetry buffer database
  baselines.bin             # Baseline snapshots
  rules\
    sigma\                  # Sigma detection rules
    yara\                   # YARA detection rules
    ioc\                    # Indicator of compromise feeds
  logs\
    eguard-agent.log        # Agent log output
```

## Windows Service Registration

The agent runs as a Windows service named `eGuardAgent`:

- **Service name**: `eGuardAgent`
- **Display name**: eGuard Security Agent
- **Startup type**: Automatic (Delayed Start)
- **Account**: Local System
- **Recovery**: Restart on failure (1 min / 5 min / 10 min delays)

Manual service management:

```powershell
# Register the service
sc.exe create eGuardAgent binPath= "C:\Program Files\eGuard\eguard-agent.exe" start= delayed-auto
sc.exe description eGuardAgent "eGuard endpoint detection and response agent"
sc.exe failure eGuardAgent reset= 86400 actions= restart/60000/restart/300000/restart/600000

# Start / stop
sc.exe start eGuardAgent
sc.exe stop eGuardAgent

# Remove
sc.exe delete eGuardAgent
```
