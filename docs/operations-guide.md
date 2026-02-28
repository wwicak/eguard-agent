# eGuard Agent -- Operations Guide

This guide covers the deployment, configuration, and day-to-day operation of the
eGuard EDR system. The target audience is SOC analysts and systems administrators
responsible for managing eGuard across a fleet of endpoints.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Installation & Enrollment](#2-installation--enrollment)
3. [Detection Engine](#3-detection-engine)
4. [Baseline Learning System](#4-baseline-learning-system)
5. [Response Actions](#5-response-actions)
6. [Threat Intelligence Bundles](#6-threat-intelligence-bundles)
7. [Policy Management](#7-policy-management)
8. [Detection Whitelist (False Positive Suppression)](#8-detection-whitelist-false-positive-suppression)
9. [Agent Release & Updates](#9-agent-release--updates)
10. [gRPC Reliability](#10-grpc-reliability)
11. [Firewall / iptables](#11-firewall--iptables)
12. [Configuration Reference](#12-configuration-reference)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Architecture Overview

eGuard is a three-tier system: the agent runs on each endpoint, the server
aggregates telemetry and manages policy, and the dashboard provides an operator
UI.

```
+---------------------+          +----------------------+         +-------------------+
|     Endpoint(s)     |          |    eGuard Server     |         |    Dashboard      |
|                     |          |                      |         |                   |
|  +--------------+   |  gRPC/   |  +---------------+  |  REST   |  +-------------+ |
|  | eGuard Agent |---+--------->|  | Agent Server  |--+-------->|  |   Vue.js    | |
|  |   (Rust)     |   |  HTTP    |  |    (Go)       |  |  API    |  |   Admin UI  | |
|  +--------------+   |          |  +---------------+  |         |  +-------------+ |
|        |            |          |        |             |         +-------------------+
|   eBPF Probes       |          |   MySQL / Storage    |
|     (Zig)           |          |                      |
+---------------------+          +----------------------+
```

### Event Pipeline

Each 100 ms tick on the agent processes events through the following stages:

```
Kernel (eBPF probes)
  |
  v
RawEvent
  |  enrich_event_with_cache()
  v
EnrichedEvent  (process info, file hashes, parent chain, container metadata)
  |  to_detection_event()
  v
TelemetryEvent
  |  DetectionEngine.process_event()
  v
DetectionOutcome  (confidence level + detection signals)
  |  plan_action()
  v
PlannedAction  (AlertOnly / Kill / Quarantine / Isolate)
  |
  v
EventEnvelope --> EventBuffer --> gRPC/HTTP send to server
```

### Communication Model

| Transport | Purpose | Port |
|-----------|---------|------|
| gRPC (primary) | Enrollment, heartbeat, telemetry streaming, commands, policy | 50052 (TLS via Caddy) or 50053 (direct) |
| HTTP (fallback) | Same RPCs via REST endpoints when gRPC is unavailable | 9999 (HTTPS) |

The agent uses gRPC as the primary transport and automatically falls back to
HTTP when gRPC connections fail. The fallback is transparent and the agent
re-attempts gRPC on subsequent ticks.

---

## 2. Installation & Enrollment

### 2.1 Server Setup

The eGuard server is a Go binary that runs as a systemd service.

```bash
# Enable and start the agent server
sudo systemctl enable eguard-agent-server.service
sudo systemctl start eguard-agent-server.service

# Verify it is running
sudo systemctl status eguard-agent-server.service
```

The server requires a MySQL database. Set the following environment variables
in the service unit or an override file:

```ini
# /etc/systemd/system/eguard-agent-server.service.d/override.conf
[Service]
Environment="EGUARD_DB_DSN=user:password@tcp(127.0.0.1:3306)/eguard"
Environment="EGUARD_GRPC_LISTEN_ADDR=:50053"
Environment="EGUARD_BUNDLE_PUBLIC_KEY_PATH=/etc/eguard-server/bundle-pubkey.hex"
```

### 2.2 Agent Installation

Packages are available for all supported platforms:

| Platform | Package Format | Install Command |
|----------|---------------|-----------------|
| Debian/Ubuntu | `.deb` | `sudo dpkg -i eguard-agent_<version>_amd64.deb` |
| RHEL/CentOS | `.rpm` | `sudo rpm -i eguard-agent-<version>.x86_64.rpm` |
| Windows | `.exe` | `.\install.ps1 -Server HOST -Token TOKEN` (see [Section 15.5](#155-windows-agent--installation--operations)) |
| macOS | `.pkg` | `sudo installer -pkg eguard-agent-<version>.pkg -target /` |

After installation the agent binary is at `/usr/bin/eguard-agent` (Linux) or
`C:\Program Files\eGuard\eguard-agent.exe` (Windows) and runs as a systemd
service (Linux) or Windows Service.

### 2.3 Enrollment Flow

Enrollment is the process by which the agent introduces itself to the server
and receives TLS certificates for subsequent communication.

```
1. Admin places bootstrap.conf on the endpoint
2. Agent reads bootstrap.conf (server address + enrollment token)
3. Agent sends EnrollRequest via gRPC/HTTP
4. Server validates the enrollment token
5. Server issues TLS certificate material (cert + key + CA)
6. Agent persists certificate to agent.conf and switches to mTLS
```

#### bootstrap.conf Format (INI -- canonical)

```ini
[server]
schema_version = 1
address = eguard-server.example.com
grpc_port = 50052
enrollment_token = your-enrollment-token-here
tenant_id = default
```

#### bootstrap.conf Format (JSON -- legacy, auto-migrated)

```json
{
  "address": "eguard-server.example.com",
  "grpc_port": 50052,
  "enrollment_token": "your-enrollment-token-here",
  "tenant_id": "default"
}
```

### 2.4 Key Files

| Platform | Config File | Bootstrap File | Data Directory |
|----------|------------|----------------|----------------|
| Linux | `/etc/eguard-agent/agent.conf` | `/etc/eguard-agent/bootstrap.conf` | `/var/lib/eguard-agent/` |
| Windows | `C:\ProgramData\eGuard\agent.conf` | `C:\ProgramData\eGuard\bootstrap.conf` | `C:\ProgramData\eGuard\` |
| macOS | `/Library/Application Support/eGuard/agent.conf` | `/Library/Application Support/eGuard/bootstrap.conf` | `/Library/Application Support/eGuard/` |

Config load order (first match wins):

1. `EGUARD_AGENT_CONFIG` environment variable
2. Platform default path (see table above)
3. `./conf/agent.conf`
4. `./agent.conf`
5. Environment variable overrides (`EGUARD_*`) applied last

---

## 3. Detection Engine

The detection engine (`DetectionEngine`) evaluates every telemetry event
through 7 independent layers, then aggregates the results into a single
confidence score.

### 3.1 Detection Layers

| Layer | Name | Technique | Output |
|-------|------|-----------|--------|
| 1 | IOC | Aho-Corasick exact match on hashes, domains, IPs | `ExactMatch` -> Definite confidence (early termination) |
| 2 | Sigma (Temporal) | Sigma rule AST evaluation against the event stream | Rule IDs of matched temporal patterns |
| 3 | Anomaly | Shannon entropy / KL-divergence deviation from learned baselines | `AnomalyDecision` (high/medium flags) |
| 4 | Kill-chain | ATT&CK-style predicate matching on process trees | Kill-chain stage hits |
| 5 | ML | XGBoost-style meta-scoring across all signal features | `MlScore` (0.0--1.0 with positive flag) |
| 6 | Behavioral | CUSUM, entropy, spectral analysis on syscall sequences and memory patterns | `BehavioralAlarm` list |
| 7 | YARA | Binary pattern matching on files and process memory | `YaraHit` list (capped at 50 hits to suppress FPs) |

Additionally, three specialized detectors run as part of signal aggregation:
- **Exploit detection**: Stack pivot, ROP gadget chains, shellcode patterns
- **Kernel integrity**: Hidden modules, syscall table hooks, unexpected changes
- **Tamper detection**: Agent binary modification, debugger attachment, config alteration

### 3.2 Confidence Levels

Confidence is a six-level enum with numeric ordering:

| Level | Numeric | Description |
|-------|---------|-------------|
| None | 0 | No signals fired |
| Low | 1 | Medium anomaly only (z3_anomaly_med) |
| Medium | 2 | High anomaly, kernel integrity hit, or ML escalation |
| High | 3 | Single high-grade signal (Sigma, kill-chain, exploit, tamper, or standalone YARA hit) |
| VeryHigh | 4 | Two or more high-grade signals, or YARA corroborated by another signal |
| Definite | 5 | Exact IOC match (Layer 1) |

ML can escalate confidence upward but never downgrade deterministic decisions:

| Base Confidence | ML Threshold | Escalated To |
|----------------|-------------|-------------|
| None | score >= 0.85 | Medium |
| Low | score >= 0.80 | Medium |
| Medium | score >= 0.90 | High |
| High | score >= 0.95 | VeryHigh |

### 3.3 Threat Categories

Detection outcomes are tagged with one or more threat categories:

- `ioc_match` -- Known-bad hash, IP, or domain
- `malware` -- YARA or behavioral match on malicious code
- `ransomware` -- Rapid file write/rename patterns exceeding threshold
- `exploit` -- Stack pivot, ROP, shellcode indicators
- `kernel_integrity` -- Hidden kernel module or syscall hook
- `tamper` -- Agent self-protection trigger
- `behavioral` -- CUSUM or spectral anomaly
- `anomaly` -- Statistical deviation from baseline

### 3.4 Detection Allowlist

The `DetectionAllowlist` in the engine allows suppressing detections for known-good
entities. When an event matches, the engine returns `Confidence::None` immediately
and skips all 7 layers. The agent process (`eguard-agent`) is always self-allowlisted
to prevent self-monitoring false positives.

### 3.5 Sharded Detection State

Detection runs on N shards (one per CPU core by default). Each shard owns its
own `DetectionEngine` instance and processes events routed by
`session_id % shard_count`. Communication uses `mpsc` channels. Engine reloads
(for bundle updates) are atomic via `Arc<ArcSwap<T>>`.

---

## 4. Baseline Learning System

The baseline system builds a statistical profile of normal behavior on each
endpoint before enabling autonomous response actions.

### 4.1 Learning Window

| Parameter | Value |
|-----------|-------|
| Learning duration | **7 days** (`LEARNING_WINDOW_SECS = 604800`) |
| Staleness threshold | **30 days** (`STALE_WINDOW_SECS = 2592000`) of no events |
| Persistence path | `/var/lib/eguard-agent/baselines.bin` (override: `EGUARD_BASELINE_PATH`) |
| Save interval | Every 300 seconds |

### 4.2 What It Learns

During the learning window the agent observes every `TelemetryEvent` and builds
a `ProcessProfile` per unique `(comm, parent_comm)` pair. Each profile records:

- **Event distribution**: Counts of each event class (process_exec, file_open,
  network_connect, dns_query, module_load, etc.)
- **Sample count**: Total observations for the process key
- **Entropy threshold**: Derived from sample count (`1.0 + log10(sample_count)`)

These profiles feed the Layer 3 (Anomaly) engine, which uses KL-divergence to
detect deviations from the learned distribution.

### 4.3 Behavior During Learning

- All detections produce `AlertOnly` actions (no kill, no quarantine).
- `autonomous_response` is forcibly set to `false` while
  `BaselineStatus::Learning` or `AgentMode::Learning`.
- Events are still sent to the server for visibility.

### 4.4 Behavior After Learning

Once 7 days have elapsed:

1. `BaselineStatus` transitions from `Learning` to `Active`.
2. Entropy thresholds are computed for every observed process profile.
3. `AgentMode` transitions to `Active` (unless in `Degraded`).
4. Autonomous response is enabled: kill and quarantine actions fire for
   `High+` confidence detections (subject to `ResponseConfig`).

### 4.5 Skip Learning

There are four ways to bypass the 7-day learning window:

| Method | How |
|--------|-----|
| **Agent environment variable** | Set `EGUARD_BASELINE_SKIP_LEARNING=1` before starting the agent |
| **Server-push via policy** | Set `baseline_mode: "force_active"` in the agent's policy JSON |
| **Dashboard** | Click "Force Active" on the agent posture panel |
| **HTTP API** | `POST /api/v1/endpoint/agents/baseline-mode` with body `{"agent_id": "...", "mode": "force_active"}` |

When learning is skipped, the baseline store is set to `Active` immediately and
entropy thresholds are derived from whatever observations exist (including
built-in seed profiles for common processes like bash, nginx, python3, apt, and
systemd).

### 4.6 Seed Baselines

On first start with an empty baseline store, the agent seeds 5 default process
profiles (bash:sshd, nginx:systemd, python3:bash, apt:systemd, systemd:kernel)
to provide reasonable anomaly thresholds before real observations accumulate.

The server can also push fleet-aggregated baselines via `FleetBaselineEnvelope`
to bootstrap new agents with statistical profiles from other endpoints running
the same workloads.

### 4.7 Staleness

If no events are observed for 30 consecutive days, the baseline transitions to
`Stale`. A stale baseline still allows autonomous response but triggers a
warning log (`baseline became stale; anomaly thresholds should be reviewed`).

---

## 5. Response Actions

The response system maps detection confidence levels to concrete local actions.
Actions are only taken when `autonomous_response` is enabled and the agent is
not in learning mode.

### 5.1 Response Policy Matrix

| Confidence | Kill | Quarantine | Capture Script | Conditions |
|-----------|------|-----------|---------------|------------|
| **Definite** | Yes | Yes | Yes | `autonomous_response=true`, not in learning |
| **VeryHigh** | Yes | Yes | Yes | Same |
| **High** | No | No | Yes | Same |
| **Medium** | No | No | No | Always alert-only |
| **Low** | No | No | No | Always alert-only |
| **None** | -- | -- | -- | No action |

When `autonomous_response=false` or the agent is in learning mode, all
confidence levels result in `AlertOnly`.

### 5.2 PlannedAction Enum

The `plan_action()` function returns one of:

| PlannedAction | Description |
|---------------|-------------|
| `None` | No signals fired |
| `AlertOnly` | Detection reported to server, no local action |
| `CaptureScript` | Capture `/proc/<pid>/exe`, stdin content for forensics |
| `KillOnly` | SIGKILL to process tree |
| `QuarantineOnly` | Copy malicious file to quarantine directory, remove original |
| `KillAndQuarantine` | SIGKILL + quarantine |

### 5.3 Protected Processes

The following processes are protected from kill actions by regex pattern
matching. Kill attempts against these processes are silently skipped.

**Linux:**
- `^systemd`, `init`, `sshd`, `dbus-daemon`, `journald`, `eguard-agent`,
  `containerd`, `dockerd`

**Windows:**
- `^System$`, `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`,
  `lsass.exe`, `svchost.exe`, `smss.exe`, `eguard-agent.exe`

**macOS:**
- `^launchd`, `kernel_task`, `sshd`, `coreaudiod`, `WindowServer`,
  `eguard-agent`, `mds`, `fseventsd`

Protected paths prevent quarantine of files under system directories:

- Linux: `/usr/bin`, `/usr/sbin`, `/lib`, `/usr/lib`, `/boot`, `/usr/local/eg`
- Windows: `C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\ProgramData\eGuard`
- macOS: `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/System`, `/Library/Application Support/eGuard`

### 5.4 Kill Rate Limiting

To prevent cascading kills from consuming system resources:

| Parameter | Default | Env Var |
|-----------|---------|---------|
| Max kills per minute | 10 | `EGUARD_RESPONSE_MAX_KILLS_PER_MINUTE` |

Kills exceeding the rate limit are skipped and logged as `kill_skipped:rate_limited`.
The agent also refuses to kill its own PID.

### 5.5 Auto-Isolation

Auto-isolation automatically disconnects the endpoint from the network when
repeated high-confidence detections occur in a short window.

| Parameter | Default | Env Var |
|-----------|---------|---------|
| Enabled | `false` | `EGUARD_RESPONSE_AUTO_ISOLATION_ENABLED` |
| Min incidents in window | 3 | `EGUARD_RESPONSE_AUTO_ISOLATION_MIN_INCIDENTS` |
| Window (seconds) | 300 | `EGUARD_RESPONSE_AUTO_ISOLATION_WINDOW_SECS` |
| Max isolations per hour | 2 | `EGUARD_RESPONSE_AUTO_ISOLATION_MAX_PER_HOUR` |

Only `Definite` and `VeryHigh` confidence events count toward the incident
threshold.

### 5.6 Quarantine

Quarantined files are copied to a platform-specific quarantine directory before
the original is removed:

| Platform | Quarantine Directory |
|----------|---------------------|
| Linux | `/var/lib/eguard-agent/quarantine/` |
| Windows | `C:\ProgramData\eGuard\quarantine\` |
| macOS | `/Library/Application Support/eGuard/quarantine/` |

Files are stored by their SHA-256 hash. Restore is available via the
`restore_quarantine` server command.

### 5.7 Script Capture

For script interpreter processes (bash, sh, python, python3, perl, ruby), the
agent captures `/proc/<pid>/exe` and stdin content when the planned action
includes capture. This enables forensic analysis of in-memory scripts and
piped payloads.

---

## 6. Threat Intelligence Bundles

Threat intelligence bundles package detection rules and indicators for
distribution from CI to the server and then to agents.

### 6.1 Bundle Format

Bundles are `tar.zst` archives with the following directory structure:

```
bundle-v1.0.0.tar.zst
  sigma/          # Sigma rules (.yml/.yaml)
  yara/           # YARA rules (.yar/.yara)
  ioc/            # IOC lists (hashes, IPs, domains)
  ml/             # ML model weights
```

Maximum bundle size: **256 MB** (`MAX_SIGNED_RULE_BUNDLE_BYTES`).

### 6.2 Ed25519 Signing

Bundles are signed with Ed25519 to ensure integrity and authenticity. The
signature is stored in a sidecar file (`bundle.tar.zst.sig`).

#### Key Generation

```bash
# Generate Ed25519 private key (keep secret -- CI only) THREAT_INTEL_ED25519_PRIVATE_KEY_PEM as variable
openssl genpkey -algorithm Ed25519 -out private.pem

# Extract raw 32-byte public key as hex
openssl pkey -in private.pem -pubout -outform DER | tail -c 32 | xxd -p -c 64 > pubkey.hex
```

#### Signing a Bundle

```bash
# Sign with the private key (produces .sig sidecar)
openssl pkeyutl -sign -inkey private.pem -rawin \
  -in bundle.tar.zst -out bundle.tar.zst.sig
```

#### Key Distribution

```
CI Pipeline (private key)
  |
  |  signs bundle
  v
GitHub Release (bundle.tar.zst + bundle.tar.zst.sig)
  |
  |  server polls daily
  v
Server (public key in env/config)
  |
  |  streams to agent via policy: bundle_public_key
  v
Agent (verifies signature before loading rules)
```

### 6.3 Agent-Side Verification

The agent resolves the public key from one of:

1. `EGUARD_RULE_BUNDLE_PUBKEY_PATH` -- path to a file containing the 32-byte
   key (raw binary or hex-encoded)
2. `EGUARD_RULE_BUNDLE_PUBKEY` -- inline hex-encoded public key in the
   environment variable
3. Policy field `bundle_public_key` (pushed by server)

Verification steps:

1. Read the bundle file (up to 256 MB)
2. Read the `.sig` sidecar file
3. Parse the Ed25519 public key (32 bytes)
4. Parse the Ed25519 signature (64 bytes)
5. Verify the signature against the bundle bytes
6. If verification fails, the bundle is rejected and a warning is logged

### 6.4 Update Flow

1. CI builds bundle from rule sources and signs with Ed25519 private key
2. CI publishes to GitHub Release as artifacts
3. Server's `AgentReleaseSyncer` polls GitHub Releases (daily)
4. Server downloads and stores bundles locally
5. Agent's periodic threat-intel refresh (every 150 seconds) checks for updates
6. Server streams bundle to agent via gRPC
7. Agent verifies signature, extracts rules, and hot-reloads detection engine

Rules are staged in `/var/lib/eguard-agent/rules-staging/` before being loaded.

---

## 7. Policy Management

Policies control agent behavior including compliance checks, detection
allowlists, baseline mode, and response configuration.

### 7.1 Delivery

```
Server (policy stored in DB)
  |  gRPC GetPolicy()
  v
Agent parses policy JSON
  |
  v
Applies: compliance checks, detection_allowlist, baseline_mode, bundle_public_key
```

### 7.2 Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `compliance_checks` | object | Compliance check configuration (firewall, SSH, packages, etc.) |
| `detection_allowlist` | object | Processes and path prefixes to exclude from detection |
| `baseline_mode` | string | `"learning"`, `"force_active"`, or `"skip_learning"` |
| `bundle_public_key` | string | Hex-encoded Ed25519 public key for bundle verification |
| `response` | object | Override autonomous response, dry_run, rate limits |

### 7.3 Refresh Interval

| Parameter | Default | Env Var |
|-----------|---------|---------|
| Policy refresh interval | 300 seconds | `EGUARD_POLICY_REFRESH_INTERVAL_SECS` |

### 7.4 Per-Agent Policy Assignment

Assign a policy to one or more agents via the server API:

```bash
curl -X POST https://server:9999/api/v1/endpoint/policy/assign \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "policy-123",
    "agent_ids": ["agent-abc", "agent-def"]
  }'
```

### 7.5 Policy API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/endpoint/policy?agent_id=...` | Fetch policy for an agent |
| `GET` | `/api/v1/endpoint/policy?list=true` | List all policies |
| `POST` | `/api/v1/endpoint/policy` | Create or update a policy |
| `POST` | `/api/v1/endpoint/policy/assign` | Assign policy to agent(s) |
| `POST` | `/api/v1/endpoint/policy/preview` | Preview hash/version for policy JSON |
| `POST` | `/api/v1/endpoint/policy/diff` | Diff two policy JSONs (returns changed keys) |

---

## 8. Detection Whitelist (False Positive Suppression)

The detection whitelist system suppresses specific detections to reduce false
positive noise.

### 8.1 Match Types

| Match Type | Field | Description |
|-----------|-------|-------------|
| `process` | Process name | Exact match on process comm name |
| `path_prefix` | File path prefix | Prefix match on file_path |
| `rule_name` | Detection rule ID | Suppress a specific Sigma/YARA rule by name |
| `sha256` | File hash | Suppress detections on a specific file hash |

### 8.2 Scope

| Scope | Configuration |
|-------|--------------|
| Global | `agent_id` field is empty -- applies to all agents |
| Per-agent | `agent_id` field is set -- applies to the specified agent only |

### 8.3 Delivery

Whitelist entries are managed on the server and injected into the policy JSON.
When the agent fetches its policy, whitelist entries are parsed and loaded into
the `DetectionAllowlist` on the detection engine. Updates take effect on the
next policy refresh cycle (default: every 300 seconds).

### 8.4 Expiry

Whitelist entries support an optional `expires_at` datetime field. Expired
entries are automatically ignored during policy evaluation.

### 8.5 API Endpoints

```bash
# List all whitelist entries
curl https://server:9999/api/v1/endpoint/whitelist

# Create a new whitelist entry
curl -X POST https://server:9999/api/v1/endpoint/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "match_type": "process",
    "value": "backup-tool",
    "agent_id": "",
    "reason": "Known backup agent, confirmed safe",
    "expires_at": "2026-06-01T00:00:00Z"
  }'

# Delete a whitelist entry
curl -X DELETE https://server:9999/api/v1/endpoint/whitelist/42
```

---

## 9. Agent Release & Updates

### 9.1 CI Build Pipeline

The release workflow builds packages for all supported platforms in a single run:

| Platform | Artifact | Build Target |
|----------|---------|-------------|
| Linux (Debian) | `.deb` | `x86_64-unknown-linux-musl` |
| Linux (RHEL) | `.rpm` | `x86_64-unknown-linux-musl` |
| Windows | `.exe` (MSI) | `x86_64-pc-windows-msvc` |
| macOS | `.pkg` | `aarch64-apple-darwin` |

Build commands for packaging:

```bash
# Build agent binary (release, static musl)
cargo build --release --target x86_64-unknown-linux-musl -p agent-core \
  --features platform-linux/ebpf-libbpf

# Package as .deb
VERSION=1.0.0 nfpm package --packager deb

# Package as .rpm
VERSION=1.0.0 nfpm package --packager rpm
```

**Important**: Always include `--features platform-linux/ebpf-libbpf` for
production Linux builds. Without it, the eBPF probes will not be compiled
into the binary and kernel-level event collection will be disabled.

### 9.2 Server-Side Package Management

The server's `AgentReleaseSyncer` polls GitHub Releases every 24 hours for new
agent packages.

Package storage directory structure:

```
/usr/local/eg/var/agent-packages/
  deb/        # .deb packages
  rpm/        # .rpm packages
  windows/    # .exe/.msi packages
  macos/      # .pkg packages
```

### 9.3 Agent Update Methods

| Method | Description |
|--------|-------------|
| `UpdateApp` server command | Server pushes update command; agent downloads and installs |
| Manual install | `dpkg -i`, `rpm -U`, or MSI installer |
| Package manager | `apt upgrade eguard-agent` if repo is configured |

### 9.4 Server Commands

The agent supports the following remote commands from the server:

| Command | Description |
|---------|-------------|
| `isolate` / `isolate_host` | Disconnect endpoint from network |
| `unisolate` / `unisolate_host` | Restore network connectivity |
| `scan` / `run_scan` | Trigger quick scan |
| `update` / `update_rules` | Check for rule/bundle updates |
| `forensics` / `forensics_collect` | Collect forensic snapshot |
| `config_change` | Apply configuration change |
| `uninstall` | Flag agent for uninstall |
| `restore_quarantine` | Restore a quarantined file |
| `emergency_rule_push` | Load emergency detection rule |
| `lock_device` / `wipe_device` / `retire_device` | MDM-style device actions |
| `restart_device` | Restart endpoint |
| `install_app` / `remove_app` / `update_app` | Application management |
| `apply_profile` | Apply configuration profile |

---

## 10. gRPC Reliability

The gRPC client is designed for unreliable networks with automatic recovery.

### 10.1 HTTP/2 Keepalive

| Parameter | Value |
|-----------|-------|
| Keepalive ping interval | 30 seconds |
| Keepalive timeout | 10 seconds |
| Keepalive while idle | Enabled |

These settings ensure that idle connections are probed regularly and stale
connections are detected quickly.

### 10.2 Channel Cache and Recovery

The gRPC `Channel` is cached and reused across calls. On connection errors:

1. The cached channel is invalidated
2. A new channel is established on the next call
3. If gRPC fails, the `grpc_reporting_force_http` flag is set
4. Subsequent calls use HTTP until gRPC is retried and succeeds

### 10.3 Retry Policy

| Parameter | Default |
|-----------|---------|
| Min backoff | 1 second |
| Max backoff | 30 seconds |
| Multiplier | 2x (exponential) |
| Max attempts | 3 |
| Jitter | +/- 20% symmetric |

Retry sequence: `~1s -> ~2s -> ~4s` (capped at 30s, with jitter applied).

### 10.4 Degraded Mode

After **3 consecutive send failures** (`DEGRADE_AFTER_SEND_FAILURES`), the
agent enters `Degraded` mode:

- Events are buffered locally in an SQLite offline buffer
- Default buffer capacity: 100 MB (`offline_buffer_cap_bytes`)
- Buffer path: `/var/lib/eguard-agent/offline-events.db`
- Periodic recovery probes attempt to restore connectivity
- On successful probe, the agent exits degraded mode and drains the buffer

### 10.5 Transport Fallback

```
gRPC send attempt
  |
  +-- Success --> done
  |
  +-- Failure --> set grpc_reporting_force_http=true
                    |
                    v
                  HTTP fallback
                    |
                    +-- next tick: try gRPC again
                          |
                          +-- Success --> clear force_http flag
                          +-- Failure --> remain on HTTP
```

### 10.6 Firewall Requirements

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 50052 | TCP | Agent -> Server | gRPC via Caddy TLS proxy |
| 50053 | TCP | Agent -> Server | Direct gRPC (no TLS proxy) |
| 9999 | TCP | Agent -> Server | HTTPS (HTTP fallback) |

---

## 11. Firewall / iptables

### 11.1 Auto-Managed Rules

The eGuard server uses `iptables.pm` service rules to automatically manage
firewall entries for its services. Ports are opened when services start and
closed when they stop.

### 11.2 Service Port Assignments

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| `eguard-agent-server` | 50052 | TCP | Caddy TLS proxy for gRPC |
| `eguard-agent-server` | 50053 | TCP | Direct gRPC endpoint     |
| `eguard-api-server`   | 22230 | TCP | REST API server          |

### 11.3 Manual iptables Rules

If automatic firewall management is not available, add rules manually:

```bash
# Allow agent gRPC connections (Caddy TLS proxy)
sudo iptables -A INPUT -p tcp --dport 50052 -j ACCEPT

# Allow direct gRPC connections
sudo iptables -A INPUT -p tcp --dport 50053 -j ACCEPT

# Allow API server
sudo iptables -A INPUT -p tcp --dport 22230 -j ACCEPT

# Persist rules
sudo iptables-save > /etc/iptables/rules.v4
```

### 11.4 Agent Host Isolation

When the agent receives an `isolate` command or auto-isolation triggers, it
modifies the host firewall to block all traffic except communication with
the eGuard server. The `unisolate` command restores the original rules.

---

## 12. Configuration Reference

### 12.1 Agent Environment Variables

All agent configuration can be overridden via environment variables. Set these
in the systemd unit file or an override:

```bash
sudo systemctl edit eguard-agent.service
```

```ini
# /etc/systemd/system/eguard-agent.service.d/override.conf
[Service]
Environment="EGUARD_SERVER_ADDR=eguard-server.example.com:50052"
Environment="EGUARD_AGENT_MODE=active"
```

#### Identity & Connection

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_AGENT_ID` | Auto-generated (`agent-<hostname-hash>`) | Agent identifier |
| `EGUARD_AGENT_MAC` | Auto-detected from primary NIC | MAC address |
| `EGUARD_SERVER_ADDR` / `EGUARD_SERVER` | `eguard-server:50052` | Server address (host:port) |
| `EGUARD_AGENT_MODE` | `learning` | Runtime mode: `learning`, `active`, `degraded` |
| `EGUARD_TRANSPORT_MODE` / `EGUARD_TRANSPORT` | `http` | Transport: `http` or `grpc` |
| `EGUARD_ENROLLMENT_TOKEN` | (none) | Enrollment token for initial registration |
| `EGUARD_TENANT_ID` | (none) | Tenant identifier for multi-tenant deployments |

#### TLS

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_TLS_CERT` | (none) | Path to client TLS certificate |
| `EGUARD_TLS_KEY` | (none) | Path to client TLS private key |
| `EGUARD_TLS_CA` | (none) | Path to CA certificate |
| `EGUARD_TLS_PINNED_CA_SHA256` | (none) | SHA-256 pin for CA certificate |
| `EGUARD_TLS_CA_PIN_PATH` | (none) | Path to file containing CA pin |
| `EGUARD_TLS_ROTATE_BEFORE_DAYS` | `30` | Days before cert expiry to request rotation |
| `EGUARD_TLS_BOOTSTRAP_PIN_ON_FIRST_USE` | (none) | Pin CA on first successful connection |

#### Response

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_AUTONOMOUS_RESPONSE` | `false` | Enable kill/quarantine actions |
| `EGUARD_RESPONSE_DRY_RUN` | `false` | Log actions without executing |
| `EGUARD_RESPONSE_MAX_KILLS_PER_MINUTE` | `10` | Kill rate limit |
| `EGUARD_RESPONSE_AUTO_ISOLATION_ENABLED` | `false` | Enable auto-isolation |
| `EGUARD_RESPONSE_AUTO_ISOLATION_MIN_INCIDENTS` | `3` | Incidents before isolating |
| `EGUARD_RESPONSE_AUTO_ISOLATION_WINDOW_SECS` | `300` | Incident window (seconds) |
| `EGUARD_RESPONSE_AUTO_ISOLATION_MAX_PER_HOUR` | `2` | Max isolations per hour |

#### Detection

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_BUNDLE_PATH` | (empty) | Path to pre-loaded threat intel bundle |
| `EGUARD_MEMORY_SCAN_ENABLED` | `false` | Enable in-memory YARA scanning |
| `EGUARD_MEMORY_SCAN_INTERVAL_SECS` | `900` | Memory scan interval |
| `EGUARD_MEMORY_SCAN_MODE` | `executable` | Scan mode: `executable`, `all` |
| `EGUARD_MEMORY_SCAN_MAX_PIDS` | `8` | Max PIDs to scan per interval |
| `EGUARD_KERNEL_INTEGRITY_ENABLED` | `true` | Enable kernel integrity checks |
| `EGUARD_KERNEL_INTEGRITY_INTERVAL_SECS` | `300` | Kernel integrity check interval |
| `EGUARD_RANSOMWARE_WRITE_THRESHOLD` | `25` | File writes in window to flag ransomware |
| `EGUARD_RANSOMWARE_WRITE_WINDOW_SECS` | `20` | Ransomware detection window |
| `EGUARD_RANSOMWARE_ADAPTIVE_DELTA` | `1e-6` | Adaptive threshold delta |
| `EGUARD_RANSOMWARE_ADAPTIVE_MIN_SAMPLES` | `6` | Min samples for adaptive threshold |
| `EGUARD_RANSOMWARE_ADAPTIVE_FLOOR` | `5` | Minimum adaptive threshold |
| `EGUARD_RANSOMWARE_LEARNED_ROOT_MIN_HITS` | `3` | Min hits to learn root path |
| `EGUARD_RANSOMWARE_LEARNED_ROOT_MAX` | `64` | Max learned root paths |
| `EGUARD_RANSOMWARE_USER_PATH_PREFIXES` | (empty) | CSV of user path prefixes |
| `EGUARD_RANSOMWARE_SYSTEM_PATH_PREFIXES` | (empty) | CSV of system path prefixes |
| `EGUARD_RANSOMWARE_TEMP_PATH_TOKENS` | (empty) | CSV of temp path tokens |

#### Baseline

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_BASELINE_PATH` | `/var/lib/eguard-agent/baselines.bin` | Baseline store file path |
| `EGUARD_BASELINE_SKIP_LEARNING` | `false` | Skip 7-day learning window |

#### Bundle Signing

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_RULE_BUNDLE_PUBKEY_PATH` | (none) | Path to Ed25519 public key file |
| `EGUARD_RULE_BUNDLE_PUBKEY` | (none) | Inline hex-encoded public key |

#### Storage & Buffering

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_BUFFER_BACKEND` | `sqlite` | Offline buffer backend |
| `EGUARD_BUFFER_PATH` | `/var/lib/eguard-agent/offline-events.db` | Offline buffer file path |
| `EGUARD_BUFFER_CAP_MB` | `100` | Max offline buffer size (MB) |

#### Compliance & Policy

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_COMPLIANCE_CHECK_INTERVAL_SECS` | `300` | Compliance check interval |
| `EGUARD_COMPLIANCE_AUTO_REMEDIATE` | `false` | Auto-fix compliance failures |
| `EGUARD_POLICY_REFRESH_INTERVAL_SECS` | `300` | Policy fetch interval |

#### Inventory & Self-Protection

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_INVENTORY_INTERVAL_SECS` | `3600` | Inventory report interval |
| `EGUARD_DEVICE_OWNERSHIP` | `unknown` | Device ownership classification |
| `EGUARD_SELF_PROTECTION_INTEGRITY_CHECK_INTERVAL_SECS` | `60` | Self-protection check interval |

#### Diagnostics

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_DEBUG_EVENT_LOG` | (none) | Set to any value to enable verbose event logging |
| `EGUARD_MACHINE_ID_PATH` | (none) | Override machine-id file path |
| `EGUARD_CONFIG_KEY_SEED_PATH` | (none) | Path to config encryption key seed |
| `EGUARD_CONFIG_TPM2_SEAL` | (none) | Enable TPM2-based config encryption |

### 12.2 Agent Internal Timing Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `HEARTBEAT_INTERVAL_SECS` | 30 | Heartbeat send interval |
| `COMPLIANCE_INTERVAL_SECS` | 60 | Compliance evaluation interval |
| `POLICY_REFRESH_INTERVAL_SECS` | 300 | Policy fetch interval |
| `THREAT_INTEL_INTERVAL_SECS` | 150 | Threat-intel check interval |
| `BASELINE_SAVE_INTERVAL_SECS` | 300 | Baseline persistence interval |
| `EVENT_BATCH_SIZE` | 256 | Max events per telemetry batch |
| `COMMAND_FETCH_INTERVAL_SECS` | 5 | Command poll interval |
| `COMMAND_FETCH_LIMIT` | 10 | Max commands per fetch |
| `DEGRADE_AFTER_SEND_FAILURES` | 3 | Consecutive failures before degraded mode |
| `MAX_SIGNED_RULE_BUNDLE_BYTES` | 256 MB | Max bundle file size |

### 12.3 Config Files

#### agent.conf

The agent config file is a JSON file containing all runtime configuration. It
is provisioned after enrollment with TLS certificate paths and agent identity.

```json
{
  "agent_id": "agent-abc123",
  "server_addr": "eguard-server.example.com:50052",
  "transport_mode": "grpc",
  "tls_cert_path": "/etc/eguard-agent/certs/agent.crt",
  "tls_key_path": "/etc/eguard-agent/certs/agent.key",
  "tls_ca_path": "/etc/eguard-agent/certs/ca.crt"
}
```

Config encryption is supported via the `eguardcfg:v1:` prefix. Encrypted configs
use AES with an AAD of `eguard-agent-config-v1`. Key material can come from
a seed file (`EGUARD_CONFIG_KEY_SEED_PATH`) or TPM2 (`EGUARD_CONFIG_TPM2_SEAL`).

#### bootstrap.conf

See [Section 2.3 -- Enrollment Flow](#23-enrollment-flow) for format details.

### 12.4 Systemd Service Override

Create a drop-in override to customize the agent service:

```bash
sudo mkdir -p /etc/systemd/system/eguard-agent.service.d
sudo tee /etc/systemd/system/eguard-agent.service.d/override.conf << 'EOF'
[Service]
Environment="EGUARD_SERVER_ADDR=eguard-server.example.com:50052"
Environment="EGUARD_TRANSPORT_MODE=grpc"
Environment="EGUARD_AUTONOMOUS_RESPONSE=true"
Environment="EGUARD_BASELINE_SKIP_LEARNING=1"
Environment="EGUARD_RULE_BUNDLE_PUBKEY_PATH=/etc/eguard-agent/bundle-pubkey.hex"
EOF
sudo systemctl daemon-reload
sudo systemctl restart eguard-agent.service
```

---

## 13. Troubleshooting

### 13.1 Bundle Signature Mismatch

**Symptom**: Log message `bundle signature verification failed` or
`rule bundle public key is not configured`.

**Resolution**:

1. Verify the public key is configured:
   ```bash
   # Check env var
   printenv EGUARD_RULE_BUNDLE_PUBKEY_PATH
   # Or check inline
   printenv EGUARD_RULE_BUNDLE_PUBKEY
   ```

2. Verify key alignment between CI and agent:
   ```bash
   # On the CI/signing machine, extract public key
   openssl pkey -in private.pem -pubout -outform DER | tail -c 32 | xxd -p -c 64

   # On the agent, read the configured key
   cat /etc/eguard-agent/bundle-pubkey.hex
   ```

3. Verify the `.sig` sidecar exists alongside the bundle file.

4. Re-sign the bundle if the key was rotated.

### 13.2 gRPC Connection Failures

**Symptom**: Log messages `gRPC telemetry send failed` or agent entering
degraded mode.

**Resolution**:

1. Check firewall ports from the agent host:
   ```bash
   # Test gRPC port (Caddy proxy)
   nc -zv eguard-server 50052

   # Test direct gRPC port
   nc -zv eguard-server 50053

   # Test HTTP fallback
   curl -k https://eguard-server:9999/health
   ```

2. Check TLS certificate validity:
   ```bash
   openssl x509 -in /etc/eguard-agent/certs/agent.crt -noout -dates
   ```

3. Verify the server is running:
   ```bash
   sudo systemctl status eguard-agent-server.service
   ```

4. Check DNS resolution:
   ```bash
   dig eguard-server
   ```

5. If the agent is in degraded mode, check the offline buffer:
   ```bash
   ls -la /var/lib/eguard-agent/offline-events.db
   ```

### 13.3 No Autonomous Response

**Symptom**: Detections fire but no kill/quarantine actions occur.

**Resolution**:

1. Check baseline status -- learning mode disables autonomous response:
   ```bash
   journalctl -u eguard-agent --grep "baseline" --since "1 hour ago"
   ```

2. Check if autonomous response is enabled:
   ```bash
   printenv EGUARD_AUTONOMOUS_RESPONSE
   # Should be "true" or "1"
   ```

3. Check if dry_run mode is active:
   ```bash
   printenv EGUARD_RESPONSE_DRY_RUN
   # Should be empty or "false"
   ```

4. Skip the learning window if needed:
   ```bash
   sudo systemctl set-environment EGUARD_BASELINE_SKIP_LEARNING=1
   sudo systemctl restart eguard-agent
   ```

5. Alternatively, use the API to force active mode:
   ```bash
   curl -X POST https://server:9999/api/v1/endpoint/agents/baseline-mode \
     -H "Content-Type: application/json" \
     -d '{"agent_id": "agent-abc123", "mode": "force_active"}'
   ```

### 13.4 Detection Not Firing

**Symptom**: Known-bad files or behaviors are not generating alerts.

**Resolution**:

1. Verify the threat-intel bundle is loaded:
   ```bash
   journalctl -u eguard-agent --grep "bundle" --since "1 hour ago"
   journalctl -u eguard-agent --grep "loaded.*rules\|sigma\|yara\|ioc" --since "1 hour ago"
   ```

2. Check if the process or path is in the detection allowlist:
   ```bash
   journalctl -u eguard-agent --grep "allowlist" --since "1 hour ago"
   ```

3. Enable debug event logging to see all detection evaluations:
   ```bash
   sudo systemctl set-environment EGUARD_DEBUG_EVENT_LOG=1
   sudo systemctl restart eguard-agent
   # Then review:
   journalctl -u eguard-agent --grep "detection\|confidence" --since "5 min ago"
   ```

4. Verify the eBPF probes are loaded (Linux only):
   ```bash
   journalctl -u eguard-agent --grep "ebpf\|probe" --since "boot"
   ```

### 13.5 High False Positives

**Symptom**: Too many detections on known-good applications.

**Resolution**:

1. Add processes to the detection allowlist via policy:
   ```bash
   curl -X POST https://server:9999/api/v1/endpoint/whitelist \
     -H "Content-Type: application/json" \
     -d '{
       "match_type": "process",
       "value": "known-good-app",
       "reason": "Verified safe, FP on YARA rules"
     }'
   ```

2. Add path prefixes for known-good directories:
   ```bash
   curl -X POST https://server:9999/api/v1/endpoint/whitelist \
     -H "Content-Type: application/json" \
     -d '{
       "match_type": "path_prefix",
       "value": "/opt/known-good-app/",
       "reason": "Application directory, all binaries verified"
     }'
   ```

3. Check for YARA false positives -- the engine caps YARA hits at 50 per event
   to suppress substring-based FPs on system binaries. If you see high hit
   counts, the YARA rules may need tuning.

4. Review the anomaly engine -- if the baseline was set during an unusual period,
   consider resetting the baseline:
   ```bash
   sudo rm /var/lib/eguard-agent/baselines.bin
   sudo systemctl restart eguard-agent
   ```

### 13.6 Agent Self-Monitoring FPs

**Symptom**: Detections triggered by the agent's own process (anomaly z3h, z3m).

**Resolution**: The agent process `eguard-agent` should be in the detection
allowlist. This is automatically handled by `load_from_lists()` which always
re-seeds `eguard-agent` as an allowed process. If FPs persist:

1. Verify the allowlist is being applied:
   ```bash
   journalctl -u eguard-agent --grep "allowlist.*eguard-agent"
   ```

2. Ensure the process name matches exactly (`eguard-agent`, not a wrapper script
   with a different name).

### 13.7 Memory and Resource Issues

**Symptom**: High memory or CPU usage.

**Resolution**:

1. Reduce memory scan scope:
   ```bash
   # Disable memory scanning
   Environment="EGUARD_MEMORY_SCAN_ENABLED=false"
   # Or reduce concurrent PIDs
   Environment="EGUARD_MEMORY_SCAN_MAX_PIDS=4"
   ```

2. Reduce offline buffer capacity:
   ```bash
   Environment="EGUARD_BUFFER_CAP_MB=50"
   ```

3. Check detection shard count -- the agent creates one shard per CPU core.
   On high-core-count servers this may be excessive.

### 13.8 Enrollment Failures

**Symptom**: Agent cannot enroll with the server.

**Resolution**:

1. Verify bootstrap.conf is valid:
   ```bash
   cat /etc/eguard-agent/bootstrap.conf
   ```

2. Check the enrollment token matches the server configuration.

3. Verify network connectivity to the server (see Section 13.2).

4. Check server-side enrollment logs:
   ```bash
   journalctl -u eguard-agent-server --grep "enroll" --since "1 hour ago"
   ```

---

## Appendix: Quick Reference

### Common Operations

```bash
# Start / stop / restart agent
sudo systemctl start eguard-agent
sudo systemctl stop eguard-agent
sudo systemctl restart eguard-agent

# View agent logs
journalctl -u eguard-agent -f

# Check agent status
sudo systemctl status eguard-agent

# View recent detections
journalctl -u eguard-agent --grep "confidence" --since "1 hour ago"

# Force baseline to active
sudo systemctl set-environment EGUARD_BASELINE_SKIP_LEARNING=1
sudo systemctl restart eguard-agent

# Enable autonomous response
sudo systemctl set-environment EGUARD_AUTONOMOUS_RESPONSE=true
sudo systemctl restart eguard-agent

# Enable debug event logging
sudo systemctl set-environment EGUARD_DEBUG_EVENT_LOG=1
sudo systemctl restart eguard-agent
```

### File Locations (Linux)

| Path | Purpose |
|------|---------|
| `/usr/bin/eguard-agent` | Agent binary |
| `/etc/eguard-agent/agent.conf` | Agent configuration |
| `/etc/eguard-agent/bootstrap.conf` | Bootstrap / enrollment config |
| `/etc/eguard-agent/certs/` | TLS certificates |
| `/var/lib/eguard-agent/baselines.bin` | Baseline store |
| `/var/lib/eguard-agent/offline-events.db` | Offline event buffer (SQLite) |
| `/var/lib/eguard-agent/quarantine/` | Quarantined files |
| `/var/lib/eguard-agent/rules/sigma/` | Sigma rules |
| `/var/lib/eguard-agent/rules/yara/` | YARA rules |
| `/var/lib/eguard-agent/rules/ioc/` | IOC lists |
| `/var/lib/eguard-agent/rules-staging/` | Bundle staging directory |
| `/etc/systemd/system/eguard-agent.service.d/override.conf` | Systemd overrides |

### File Locations (Windows)

| Path | Purpose |
|------|---------|
| `C:\Program Files\eGuard\eguard-agent.exe` | Agent binary |
| `C:\Program Files\eGuard\uninstall.ps1` | Uninstall script |
| `C:\ProgramData\eGuard\agent.conf` | Agent configuration |
| `C:\ProgramData\eGuard\bootstrap.conf` | Bootstrap / enrollment config |
| `C:\ProgramData\eGuard\certs\` | TLS certificates |
| `C:\ProgramData\eGuard\logs\agent.log` | Agent log file |
| `C:\ProgramData\eGuard\offline-events.db` | Offline event buffer (SQLite) |
| `C:\ProgramData\eGuard\quarantine\` | Quarantined files |
| `C:\ProgramData\eGuard\rules-staging\` | Bundle staging directory |

---

## 15. E2E Testing Notes (Feb 2026)

### 15.1 Server Setup Requirements

The agent server (`eg-agent-server`) requires these environment variables for
full functionality:

```bash
EGUARD_SERVER_AUTH_MODE=permissive          # or enforced with tokens
EGUARD_AGENT_SERVER_DSN=root:PASSWORD@unix(/var/run/mysqld/mysqld.sock)/eguard?parseTime=true
EGUARD_AGENT_PACKAGE_DIR=/usr/local/eg/var/packages
EGUARD_THREAT_INTEL_ED25519_PUBLIC_KEY_HEX=<bundle-signing-pubkey>
```

**Critical**: The DSN **must** include `?parseTime=true` for datetime column
scanning. Without it, `LoadAgents()` and other DB queries fail silently.

Service names on the eGuard server follow the `eguard-*` pattern:
`eguard-agent-server`, `eguard-mariadb`, `eguard-redis-cache`, etc.

### 15.2 Agent Deployment Findings

- The systemd service uses `Type=notify` but the agent does not send
  `sd_notify(READY=1)`. Override to `Type=simple` and `WatchdogSec=0`:
  ```ini
  # /etc/systemd/system/eguard-agent.service.d/override.conf
  [Service]
  Type=simple
  WatchdogSec=0
  ```
- The release build with `--features platform-linux/ebpf-libbpf` requires glibc.
  CI must build in a Debian 12 container to match target glibc 2.36.
- Enrollment tokens created via the admin GUI are stored in MariaDB. The agent
  server must have `EGUARD_AGENT_SERVER_DSN` configured to see them.
- After enrollment, `bootstrap.conf` is deleted and `agent.conf` is written.
  The agent does NOT re-enroll on restart if `agent.conf` exists.

### 15.3 Agent Update via Server

Push agent updates from the admin GUI (Response > Update Agent) or API:

```bash
curl -X POST http://SERVER:50053/api/v1/endpoint/command/enqueue \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-XXXX",
    "command_type": "update",
    "issued_by": "admin",
    "command_data": {
      "target_version": "0.2.3",
      "package_url": "http://SERVER:50053/api/v1/agent-install/linux-deb",
      "checksum_sha256": "<sha256-of-deb>"
    }
  }'
```

**Note**: The agent acknowledges the update command but self-update
(download + install + restart) is not yet fully implemented. The command
is recorded and the version is tracked server-side.

### 15.4 eBPF Probe Status

With the `ebpf-libbpf` feature enabled, all 9 eBPF probes load and attach:

| Probe | Kernel Hook | Event |
|-------|-------------|-------|
| `eguard_sched_process_exec` | `tracepoint/sched/sched_process_exec` | Process execution |
| `eguard_sys_enter_openat` | `tracepoint/syscalls/sys_enter_openat` | File open |
| `eguard_sys_enter_write` | `tracepoint/syscalls/sys_enter_write` | File write |
| `eguard_sys_enter_renameat2` | `tracepoint/syscalls/sys_enter_renameat2` | File rename |
| `eguard_sys_enter_unlinkat` | `tracepoint/syscalls/sys_enter_unlinkat` | File delete |
| `eguard_inet_sock_set_state` | `tracepoint/sock/inet_sock_set_state` | TCP connections |
| `eguard_udp_sendmsg` | `kprobe/udp_sendmsg` | DNS queries |
| `eguard_module_load` | `kprobe/__do_sys_finit_module` | Module loading |
| `eguard_bprm_check` | `LSM/bprm_check_security` | Binary check |

### 15.5 Windows Agent — Installation & Operations

#### Installation

The recommended install flow uses the server-hosted `install.ps1` script:

```powershell
# Download and run (from an elevated PowerShell prompt)
Invoke-WebRequest -Uri https://SERVER:9999/install.ps1 -OutFile install.ps1
.\install.ps1 -Server SERVER_HOST -Token ENROLLMENT_TOKEN -GrpcPort 50052
```

Or with explicit hash verification (offline/air-gapped):

```powershell
.\install.ps1 -Server http://SERVER:50053 -Token TOKEN -GrpcPort 50052 `
    -ExpectedSha256 <64-char-hex-hash>
```

**What the installer does:**

1. Downloads `eguard-agent.exe` from `/api/v1/agent-install/windows-exe`
2. Verifies SHA-256 integrity against server-provided hash
3. Installs binary to `C:\Program Files\eGuard\eguard-agent.exe`
4. Hardens directory ACLs (SYSTEM + Administrators only)
5. Creates data directories under `C:\ProgramData\eGuard\`
   (`certs\`, `rules-staging\`, `quarantine\`, `logs\`)
6. Registers Windows service `eGuardAgent` (auto-start, LocalSystem)
7. Configures service failure recovery (restart on crash: 5s/10s/30s)
8. Writes `C:\ProgramData\eGuard\bootstrap.conf` (consumed after enrollment)
9. Deploys `uninstall.ps1` alongside the binary
10. Registers in Add/Remove Programs (Settings > Apps)
11. Starts the service

#### Uninstallation

Users can uninstall via **Settings > Apps > eGuard Endpoint Security Agent > Uninstall**,
or from an elevated PowerShell prompt:

```powershell
& "C:\Program Files\eGuard\uninstall.ps1"

# Preserve config/certs for re-enrollment:
& "C:\Program Files\eGuard\uninstall.ps1" -KeepData
```

The uninstaller stops and removes the service, cleans the Add/Remove Programs
entry, removes the binary, and (unless `-KeepData`) removes all agent data.

#### Key Files (Windows)

| Path | Purpose |
|------|---------|
| `C:\Program Files\eGuard\eguard-agent.exe` | Agent binary |
| `C:\Program Files\eGuard\uninstall.ps1` | Uninstall script |
| `C:\ProgramData\eGuard\agent.conf` | Agent configuration (persisted after enrollment) |
| `C:\ProgramData\eGuard\bootstrap.conf` | Bootstrap config (consumed after enrollment) |
| `C:\ProgramData\eGuard\certs\` | TLS certificates |
| `C:\ProgramData\eGuard\logs\agent.log` | Agent log file (service mode) |
| `C:\ProgramData\eGuard\offline-events.db` | Offline event buffer (SQLite) |
| `C:\ProgramData\eGuard\quarantine\` | Quarantined files |
| `C:\ProgramData\eGuard\rules-staging\` | Threat-intel bundle staging |

#### Windows Service Management

```powershell
# Check service status
sc.exe query eGuardAgent

# Stop / start / restart
Stop-Service eGuardAgent
Start-Service eGuardAgent
Restart-Service eGuardAgent

# View recent logs
Get-Content C:\ProgramData\eGuard\logs\agent.log -Tail 50

# View detections
Select-String "confidence=" C:\ProgramData\eGuard\logs\agent.log | Select-Object -Last 20
```

The service name is `eGuardAgent` (not `eguard-agent`). Display name:
"eGuard Endpoint Security Agent". Runs as `LocalSystem` with auto-start.

#### ETW Telemetry (Windows Kernel Events)

On Windows, the agent uses ETW (Event Tracing for Windows) instead of eBPF.
The ETW session `eGuardEtwSession` enables 6 kernel providers:

| Provider | Events |
|----------|--------|
| Microsoft-Windows-Kernel-Process | ProcessExec, ProcessExit |
| Microsoft-Windows-Kernel-File | FileOpen, FileWrite, FileRename, FileUnlink |
| Microsoft-Windows-Kernel-Network | TcpConnect |
| Microsoft-Windows-DNS-Client | DnsQuery |
| Microsoft-Windows-Kernel-Registry | (reserved) |
| Microsoft-Windows-DiskIO | (reserved) |

The ETW consumer runs on a dedicated background thread. Events are decoded,
enriched, and fed into the same detection pipeline as Linux eBPF events.

**E2E verified results (Feb 2026, Windows Server 2019):**
- 451+ events captured in 10 minutes of normal operation
- 15 high-severity Sigma detections (DNS TXT, Antivirus Path, Crypto Mining patterns)
- 130 MB memory footprint after threat-intel bundle load (354 Sigma + 16,904 YARA rules)
- Detection engine: 2 shards, full 7-layer pipeline active

### 15.6 Windows Troubleshooting

#### bootstrap.conf UTF-8 BOM

**Symptom**: Service starts then immediately stops (exit code 1), agent.log is
0 bytes.

**Cause**: Windows PowerShell 5.x's `Set-Content -Encoding UTF8` adds a
UTF-8 BOM (`EF BB BF`) to the file. The agent's TOML parser cannot parse the
BOM prefix, causing a silent config load failure.

**Resolution**: The `install.ps1` script uses BOM-free UTF-8 encoding. If
writing bootstrap.conf manually, use:

```powershell
$content = @"
[server]
address = "server.example.com"
grpc_port = 50052
enrollment_token = "your-token"
"@
[System.IO.File]::WriteAllText(
    "C:\ProgramData\eGuard\bootstrap.conf",
    $content,
    (New-Object System.Text.UTF8Encoding($false))
)
```

Verify no BOM: `[System.IO.File]::ReadAllBytes("C:\ProgramData\eGuard\bootstrap.conf")[0]`
should be `0x5B` (`[`), not `0xEF`.

#### Console Mode Killed by SSH Disconnect

**Symptom**: Agent started via SSH with `EGUARD_WINDOWS_CONSOLE=1` and
`start /b` exits after a few seconds during initialization.

**Cause**: When the SSH session closes, Windows sends `CTRL_CLOSE_EVENT` to all
processes attached to the console. The agent's `tokio::signal::ctrl_c()` handler
fires, triggering shutdown while `AgentRuntime::new()` is still running.

**Resolution**: Always run the agent as a Windows Service (the default mode).
Do not use `EGUARD_WINDOWS_CONSOLE=1` for production deployments. If you need
console output for debugging, keep the SSH session alive:

```cmd
set EGUARD_WINDOWS_CONSOLE=1
C:\ProgramData\eGuard\eguard-agent.exe 2>> C:\ProgramData\eGuard\logs\agent.log
```

#### EGUARD_WINDOWS_CONSOLE Machine-Level Env Var

**Symptom**: Service fails to start with error 1053 (timeout).

**Cause**: `EGUARD_WINDOWS_CONSOLE` was set at the Machine level via
`[System.Environment]::SetEnvironmentVariable(..., "Machine")`. The service
inherits this, goes to console mode, and never registers with SCM.

**Resolution**: Remove the machine-level variable:

```powershell
[System.Environment]::SetEnvironmentVariable("EGUARD_WINDOWS_CONSOLE", $null, "Machine")
```

Never set this variable at the Machine level. Only use it per-process for
debugging.

#### Service Name Mismatch

The agent binary expects the Windows service name `eGuardAgent` (defined in
`main.rs`). Using a different name (e.g., `eguard-agent`) causes the service
dispatcher to fail. Always use:

```powershell
sc.exe create eGuardAgent binPath= "C:\Program Files\eGuard\eguard-agent.exe" start= auto
```

### 15.7 Known CI Issues (Windows)

- WiX v5 uses `-d Key=Value` (space after -d), not `-dKey=Value`
- Components with `Directory` as KeyPath need explicit GUIDs (not `Guid="*"`)
- Remove inline `<?define>` for variables passed via CLI `-d`
- Cross-compile with `x86_64-pc-windows-gnu` produces binaries that work on
  Windows Server 2019 without MinGW DLLs (Rust statically links the CRT)

---

## 16. MDM (Mobile Device Management) Commands

### 16.1 Command Reference

The agent supports 10 MDM commands, delivered via the server command pipeline.
All commands are enqueued via:

```bash
POST http://SERVER:50053/api/v1/endpoint/command/enqueue
Content-Type: application/json

{
  "agent_id": "agent-XXXX",
  "command_type": "<command>",
  "command_data": { ... },
  "issued_by": "admin"
}
```

The agent polls for commands every 5 seconds (`COMMAND_FETCH_INTERVAL_SECS`).

| Command | Description | Policy Gate | Windows Implementation |
|---------|-------------|-------------|----------------------|
| `lock_device` | Lock the workstation | Always allowed | `rundll32.exe user32.dll,LockWorkStation` |
| `locate_device` | Report device IP | Always allowed | Returns primary NIC IP |
| `lost_mode` | Enable lost mode marker | Always allowed | Creates `{data_dir}/lost_mode` file |
| `apply_profile` | Store/apply config profile | Always allowed | JSON storage + WiFi 802.1x XML |
| `install_app` | Install application | `EGUARD_MDM_ALLOW_APP_MANAGEMENT` | `winget install --id <pkg> --exact` |
| `remove_app` | Remove application | `EGUARD_MDM_ALLOW_APP_MANAGEMENT` | `winget uninstall --id <pkg> --exact` |
| `update_app` | Update application | `EGUARD_MDM_ALLOW_APP_MANAGEMENT` | `winget upgrade --id <pkg> --exact` |
| `wipe_device` | Remove agent data | `EGUARD_MDM_ALLOW_DESTRUCTIVE` | Removes quarantine, baselines, offline DB |
| `restart_device` | Reboot endpoint | `EGUARD_MDM_ALLOW_DESTRUCTIVE` | `shutdown /r /t 0 /f` |
| `retire_device` | Decommission agent | `EGUARD_MDM_ALLOW_DESTRUCTIVE` | Creates `retired` marker, stops enrollment |

### 16.2 MDM Policy Environment Variables

Destructive and app management commands are blocked by default. Set these
environment variables on the agent to enable them:

| Variable | Controls | Default |
|----------|----------|---------|
| `EGUARD_MDM_ALLOW_ALL` | All MDM actions | Not set (disabled) |
| `EGUARD_MDM_ALLOW_DESTRUCTIVE` | wipe, retire, restart | Not set (disabled) |
| `EGUARD_MDM_ALLOW_APP_MANAGEMENT` | install/remove/update app | Not set (disabled) |
| `EGUARD_MDM_ALLOW_LOCK` | lock_device (already always allowed) | N/A |
| `EGUARD_MDM_ALLOW_WIPE` | wipe_device only | Not set |
| `EGUARD_MDM_ALLOW_RESTART` | restart_device only | Not set |
| `EGUARD_MDM_ALLOW_RETIRE` | retire_device only | Not set |

**Windows Service Environment Variables**: On Windows, set env vars via the
service registry (Machine-level env vars are not inherited by services):

```powershell
# Set env vars on the Windows service
$envVars = @("EGUARD_MDM_ALLOW_DESTRUCTIVE=1", "EGUARD_MDM_ALLOW_APP_MANAGEMENT=1")
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\eGuardAgent" `
  -Name "Environment" -Value $envVars -Type MultiString

# Restart service to pick up changes
Restart-Service eGuardAgent
```

**Important**: Do NOT use `[System.Environment]::SetEnvironmentVariable(..., "Machine")`
for Windows service env vars. SCM does not inherit machine-level changes without a
full reboot. Always use the service registry `Environment` key.

### 16.3 Command Approval Workflow

Commands support an approval workflow with `requires_approval` flag:

```bash
# Enqueue with approval required
curl -X POST http://SERVER:50053/api/v1/endpoint/command/enqueue \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-XXXX",
    "command_type": "wipe_device",
    "command_data": {"reason": "Security incident"},
    "requires_approval": true,
    "issued_by": "soc-analyst"
  }'

# Approve the command
curl -X POST http://SERVER:50053/api/v1/endpoint/command/approve \
  -H "Content-Type: application/json" \
  -d '{
    "command_id": "<command_id>",
    "approval_status": "approved",
    "approved_by": "soc-manager"
  }'
```

Server-side env vars for automatic approval requirements:

| Variable | Effect |
|----------|--------|
| `EGUARD_COMMAND_APPROVAL_REQUIRED` | All commands require approval |
| `EGUARD_COMMAND_APPROVAL_DESTRUCTIVE` | wipe_device and retire_device require approval |

### 16.4 WiFi Profile Push (802.1x / WPA2-Enterprise)

The `apply_profile` command supports WiFi profiles with 802.1x enterprise
authentication. When the profile JSON contains an `ssid` field, the agent
generates a Windows WLAN profile XML and imports it via `netsh wlan add profile`.

**Supported security modes**: `open`, `wpa2_psk`, `wpa2_enterprise` (802.1x)

**Example: Push WPA2-Enterprise PEAP profile with CA certificate**:

```bash
curl -X POST http://SERVER:50053/api/v1/endpoint/command/enqueue \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-XXXX",
    "command_type": "apply_profile",
    "command_data": {
      "profile_id": "corp-wifi",
      "profile_json": "{\"ssid\": \"CorpSecure\", \"security\": \"wpa2_enterprise\", \"eap_type\": \"peap\", \"server_names\": \"radius.corp.local\", \"ca_cert_pem\": \"-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\", \"auto_connect\": true}"
    },
    "issued_by": "admin"
  }'
```

WiFi profile fields:

| Field | Required | Description |
|-------|----------|-------------|
| `ssid` | Yes | WiFi network name |
| `security` | Yes | `open`, `wpa2_psk`, `wpa2_enterprise` |
| `eap_type` | No | `peap` (default), `tls`, `ttls` |
| `psk` | WPA2-PSK only | Pre-shared key (8-63 chars) |
| `ca_cert_pem` | No | PEM-encoded CA certificate for 802.1x |
| `client_cert_pem` | No | PEM-encoded client certificate for EAP-TLS |
| `client_key_pem` | No | PEM-encoded client private key for EAP-TLS |
| `server_names` | No | RADIUS server name(s) for validation |
| `auto_connect` | No | Auto-connect to network (default: true) |

On Windows, the CA certificate is imported to the Root store via `certutil -addstore Root`.
Client certificates are imported via `certutil -user -importPFX`.

### 16.5 App Management Dependencies

| Platform | Package Manager | Required |
|----------|----------------|----------|
| Windows | `winget` (Windows Package Manager) | Not pre-installed on Windows Server 2019 |
| macOS | `brew` (Homebrew) | Must be installed separately |
| Linux | `apt-get` | Available on Debian/Ubuntu |

**Windows Server 2019**: `winget` is not available by default. Install the
[App Installer](https://github.com/microsoft/winget-cli/releases) MSIX bundle
or accept that `install_app`/`remove_app`/`update_app` will return
`"spawn failed: program not found"`.

### 16.6 MDM Command API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/endpoint/command/enqueue` | Enqueue a command |
| `POST` | `/api/v1/endpoint/command/approve` | Approve/reject a pending command |
| `GET` | `/api/v1/endpoint/commands?agent_id=...` | List commands for an agent |

---

## 17. MDM E2E Test Results (Feb 2026)

### 17.1 Test Environment

| VM | IP | OS | Agent ID |
|----|----|----|----------|
| Server | 103.49.238.102 | Debian 12 | N/A |
| Linux Agent | 103.183.74.3 | Debian 12 (6.1.0-43) | agent-31bbb93f38b4 |
| Windows Agent | 103.31.39.30 | Windows Server 2019 | agent-4412 |

### 17.2 MDM Command Test Results

| # | Command | Policy Gate | Result | Detail |
|---|---------|-------------|--------|--------|
| 1 | `locate_device` | Always allowed | **PASS** | Returned IP 10.6.108.110 |
| 2 | `lost_mode` | Always allowed | **PASS** | Marker file created with unix timestamp |
| 3 | `apply_profile` (JSON) | Always allowed | **PASS** | Stored at `profiles/e2e-test-wifi-profile.json` |
| 4 | `lock_device` | Always allowed | **PASS** | `rundll32.exe LockWorkStation` executed |
| 5 | `wipe_device` (blocked) | No env var | **PASS** | "device wipe blocked by policy" |
| 6 | `install_app` (blocked) | No env var | **PASS** | "app management blocked by policy" |
| 7 | `restart_device` (blocked) | No env var | **PASS** | "device restart blocked by policy" |
| 8 | `install_app` (injection) | Enabled | **PASS** | Sanitizer rejected `pkg;calc.exe` |
| 9 | `apply_profile` (traversal) | Always allowed | **PASS** | "path traversal segments are not allowed" |
| 10 | `install_app` (valid pkg) | Enabled | **PASS** | "spawn failed: program not found" (expected, no winget) |
| 11 | `wipe_device` (enabled) | ALLOW_DESTRUCTIVE | **PARTIAL** | offline-events.db locked by agent (os error 32) |
| 12 | `restart_device` (enabled) | ALLOW_DESTRUCTIVE | **PASS** | VM rebooted, service auto-started in ~30s |

### 17.3 Bugs Found

#### BUG-1: `wipe_device` fails on Windows — offline-events.db locked

**Severity**: Medium
**Impact**: Wipe command fails because the agent's own SQLite database
(`offline-events.db`) is held open by the event buffer.

**Root cause**: `apply_device_wipe()` tries to delete the offline buffer file
while the agent process has it open.

**Fix applied**: Changed `apply_device_wipe()` to continue removing other
targets (quarantine, baselines) even when one target fails, reporting partial
success instead of failing entirely.

#### BUG-2: Windows package name sanitizer rejects `+` character

**Severity**: Low
**Impact**: Winget package IDs containing `+` (e.g., `Notepad++.Notepad++`)
are rejected by the input sanitizer.

**Root cause**: `sanitize_windows_package_name()` only allowed
`alphanumeric + . _ -` but winget IDs commonly use `+`.

**Fix applied**: Added `b'+'` to the allowed character set.

#### BUG-3: Windows agent service stop hangs (StopPending indefinitely)

**Severity**: High
**Impact**: Service cannot be gracefully stopped via `Stop-Service` or
`net stop`. Requires `taskkill /F` to force-terminate.

**Root cause**: The Tokio runtime shutdown does not complete cleanly. The
service control handler sets the stop-pending state but the agent's main
loop or ETW consumer thread does not exit.

**Workaround**: Use `taskkill /F /IM eguard-agent.exe` followed by
`sc.exe start eGuardAgent`. The service auto-recovery (configured by
`install.ps1`) will restart the service after a forced kill.

#### BUG-4: Windows Machine-level env vars not inherited by services

**Severity**: Medium (Documentation gap)
**Impact**: Setting `EGUARD_MDM_ALLOW_*` via
`[System.Environment]::SetEnvironmentVariable(..., "Machine")` does not
take effect after `Restart-Service`. SCM caches the environment.

**Workaround**: Set env vars directly in the service registry:
```powershell
$envVars = @("EGUARD_MDM_ALLOW_DESTRUCTIVE=1")
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\eGuardAgent" `
  -Name "Environment" -Value $envVars -Type MultiString
Restart-Service eGuardAgent
```

### 17.4 Approval Workflow Test Results

| # | Test | Result | Detail |
|---|------|--------|--------|
| 1 | Enqueue with `requires_approval=true` | **PASS** | `approval_status=pending` |
| 2 | Agent doesn't receive pending command | **PASS** | No log entry during 15s wait |
| 3 | Approve command | **PASS** | Agent received and executed `locate_device` |
| 4 | Reject command | **PASS** | `status=failed, approval=rejected`, agent never received |

### 17.5 802.1x WiFi Profile Test Results

| # | Test | Result | Detail |
|---|------|--------|--------|
| 1 | PEAP profile JSON stored | **PASS** | `corp-wifi-peap.json` written |
| 2 | WLAN XML generated | **PASS** | `CorpSecure.xml` with EAP Type 25 (PEAP) |
| 3 | Server name validation | **PASS** | `<ServerNames>radius.corp.local</ServerNames>` |
| 4 | netsh import | **EXPECTED FAIL** | WLAN service not available on Server 2019 |

### 17.6 Compliance Reports (Windows)

The Windows agent reports compliance checks via the platform-windows compliance
module. Checks verified on Windows Server 2019:

| Check | Status | Detail |
|-------|--------|--------|
| `firewall_required` | FAIL | Firewall inactive on test VM |
| `antivirus_running` | PASS | Windows Defender detected |
| `disk_encryption` | Depends | BitLocker status varies |
| `screen_lock_enabled` | Depends | May fail on headless servers |

### 17.7 Server Infrastructure

**Critical**: The eGuard server VM (4GB RAM) runs many services (Apache/Perl,
MariaDB, Go servers, HAProxy, etc.) that consume ~3.5GB+ at steady state.
Without swap space, the system OOM-hangs under load.

**Fix applied**: Added 4GB swap file:
```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab
```

**Recommendation**: Production eGuard servers should have at least 8GB RAM or
4GB swap configured. Monitor memory via `eguard-netdata` service.
