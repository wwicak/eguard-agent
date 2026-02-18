# eGuard Platform Field Guide (Living Document)

> **Purpose**
>
> User-friendly, operator-focused guide for running and testing **eGuard server** + **eguard-agent** end-to-end.
>
> This document is intentionally **living**: append new sections as features are added and as real E2E test practices evolve.

---

## 1) Repository map (what lives where)

- **Server/control plane + API/UI**: `/home/dimas/fe_eguard`
  - Agent API handlers (enroll, policy, command, compliance, inventory, install endpoints)
  - Perl Unified API and UI
  - Service deployment runtime (Caddy/API frontend, Perl API, Go agent server)

- **Agent runtime**: `/home/dimas/eguard-agent`
  - Endpoint binary, lifecycle pipelines, command execution, policy/compliance/inventory/telemetry flows
  - Agent config parsing (`agent.conf`, env overrides)

---

## 2) Quick architecture overview

1. Agent enrolls (`/api/v1/endpoint/enroll`)
2. Agent fetches policy (`/api/v1/endpoint/policy?agent_id=...`)
3. Agent periodically sends:
   - telemetry
   - heartbeat
   - compliance
   - inventory
4. Server operators enqueue commands (`scan`, `isolate`, etc.)
5. Approval-gated commands are approved/rejected
6. Agent executes approved commands and ACKs completion

---

## 3) Prerequisites checklist

## Server side (eGuard)

- `eguard-agent-server` active
- `eguard-api-frontend` active
- `eguard-perl-api` active
- Enrollment token available (generated per organization/tenant)
- Package artifacts available (if using install endpoint), e.g.:
  - `/usr/local/eg/var/agent-packages/deb/*.deb`
  - `/usr/local/eg/var/agent-packages/rpm/*.rpm`

## Agent side

- Linux host reachable via SSH
- `systemd` available
- outbound connectivity to eGuard API endpoint (or local bridge/proxy configured)

---

## 4) Agent installation methods

### Token preparation (per organization)

Before installing an agent, generate an enrollment token for the target org/tenant
from eGuard UI/API (`/endpoint-enrollment-tokens`).

UI path (recommended):

- **Endpoint → Enrollment & Install**
- create/revoke tokens
- use built-in install command generator (server URL + token + package format/version)

Best practices:

- create **separate token sets per organization/tenant/environment**
- prefer short-lived tokens (`expires_at`) and bounded `max_uses`
- rotate/revoke tokens after rollout
- **never hardcode tokens in source code or committed config files**

## Method A (recommended): installer script

```bash
ENROLLMENT_TOKEN="<org-specific-enrollment-token>"
EGUARD_SERVER="https://<eguard-server>"

curl -fsSL "$EGUARD_SERVER/install.sh" | bash -s -- --server "$EGUARD_SERVER" --token "$ENROLLMENT_TOKEN"
```

When successful, this should install binary + service and enroll the endpoint.

## Method B: package endpoint + manual install

### Debian/Ubuntu

```bash
ENROLLMENT_TOKEN="<org-specific-enrollment-token>"
EGUARD_SERVER="https://<eguard-server>"

curl -fL -H "X-Enrollment-Token: $ENROLLMENT_TOKEN" \
  "$EGUARD_SERVER/api/v1/agent-install/linux-deb" \
  -o /tmp/eguard-agent.deb
sudo dpkg -i /tmp/eguard-agent.deb
sudo systemctl enable --now eguard-agent
```

### RPM-based distros

```bash
ENROLLMENT_TOKEN="<org-specific-enrollment-token>"
EGUARD_SERVER="https://<eguard-server>"

curl -fL -H "X-Enrollment-Token: $ENROLLMENT_TOKEN" \
  "$EGUARD_SERVER/api/v1/agent-install/linux-rpm" \
  -o /tmp/eguard-agent.rpm
sudo rpm -Uvh /tmp/eguard-agent.rpm
sudo systemctl enable --now eguard-agent
```

## Method C: binary + systemd fallback (lab/emergency)

1. Copy binary to `/usr/local/bin/eguard-agent`
2. Create `/etc/systemd/system/eguard-agent.service`
3. Create env/config file under `/etc/eguard-agent/`
4. `sudo systemctl daemon-reload && sudo systemctl enable --now eguard-agent`

---

## 5) Core runtime configuration

Config precedence:

1. defaults
2. `agent.conf`
3. environment variables

Common paths:

- `/etc/eguard-agent/agent.conf`
- `/etc/eguard-agent/bootstrap.conf`

Key settings:

- `EGUARD_SERVER_ADDR` / `EGUARD_SERVER`
- `EGUARD_AGENT_ID`, `EGUARD_AGENT_MAC`
- `EGUARD_TRANSPORT_MODE` (`http|grpc`)
- `EGUARD_ENROLLMENT_TOKEN`
- `EGUARD_POLICY_REFRESH_INTERVAL_SECS`

### Policy refresh tuning (new hardening)

- Config file: `[control_plane].policy_refresh_interval_secs`
- Env override: `EGUARD_POLICY_REFRESH_INTERVAL_SECS`
- Default: `300` seconds

Use lower values in lab for faster policy propagation validation.

### Agent config UI direction (growing feature)

Current state:

- core agent config is file/env driven (`agent.conf`, env overrides)
- enrollment-token lifecycle is already UI/API managed (`/endpoint-enrollment-tokens`)

Target state (recommended):

- add a dedicated **Agent Configuration** UI in eGuard to manage:
  - default transport mode
  - policy refresh cadence
  - compliance/inventory cadence
  - baseline learning parameters
- publish config profiles by org/tenant and apply profile at install/enroll time
- keep local file/env as emergency override layer

---

## 6) Enrollment and health verification

## Agent host checks

```bash
systemctl is-active eguard-agent
journalctl -u eguard-agent -n 100 --no-pager
```

## API checks (agent path)

```bash
curl -s "http://127.0.0.1:9080/api/v1/endpoint/state"
curl -s "http://127.0.0.1:9080/api/v1/endpoint/policy?agent_id=<agent_id>"
```

## Server DB checks (MySQL)

Validate row exists and timestamps move:

- `endpoint_agent.last_heartbeat`
- `endpoint_agent.last_compliance_check`
- `endpoint_agent.last_inventory_at`

---

## 7) Command approval workflow (operator view)

1. Enqueue command
2. If `requires_approval=true`, command stays hidden from pending delivery
3. Approve or reject via API/UI
4. Agent receives only approved command
5. Agent ACK updates status (`completed` / `failed`)

Expected semantics:

- approved response: `status="command_approved"`
- rejected response: `status="command_rejected"`
- rejected command remains non-deliverable

---

## 8) Policy assignment behavior (important)

- Assignment updates `endpoint_agent.policy_id/version/hash`
- Compliance reports must **not** regress assigned policy fields
- Agent compliance version may lag until next refresh cycle
  - default refresh interval: 300s

Operational guidance:

- For rapid rollout tests, temporarily lower policy refresh interval
- For production, keep interval aligned with load/cadence requirements

---

## 9) Install endpoint behavior matrix

`GET /api/v1/agent-install/linux-deb`

- Missing `X-Enrollment-Token` → `401 enrollment_token_required`
- Invalid token → `403 invalid_enrollment_token`
- Valid token + artifact present → `200` binary package
- Unknown `version` selector → `404 agent_package_not_found`

Artifact resolver behavior:

- no `version` query: newest package by modification time
- `?version=<substring>`: matches filename containing that version token

---

## 10) Known pitfalls and fast fixes

- **Enrollment fails with FK (`fk_endpoint_agent_node_mac`) on older builds**
  - Current hardened behavior auto-creates/updates the `node` row during enrollment.
  - If you still hit this error, upgrade to a build containing the enrollment-node upsert fix.

- **Install endpoint returns `agent_package_not_found`**
  - Publish package artifacts to `/usr/local/eg/var/agent-packages/<deb|rpm>/`.

- **Policy appears stale briefly**
  - This is often refresh cadence; verify policy endpoint output first, then compliance convergence.

- **Mixed route compatibility (`endpoint-nac` vs `endpoint/nac`)**
  - Ensure frontend fallback behavior is present in mixed deployments.

---

## 11) Real E2E regression checklist (recommended per release)

- [ ] Enrollment succeeds (and audit row created)
- [ ] Heartbeat/compliance/inventory timestamps advance
- [ ] Policy upsert + assign + fetch by `agent_id` are consistent
- [ ] Compliance rows carry expected `policy_version`
- [ ] Approved command completes; rejected command remains failed/rejected
- [ ] Install endpoints enforce token validation and serve package artifacts
- [ ] NAC false-positive guard (non-alert telemetry should not create NAC event)

---

## 12) Suggested section template for future additions

When adding new features/tests, append with this format:

```md
## Feature: <name>
- Summary:
- API/contracts touched:
- Agent behavior:
- E2E validation steps:
- Evidence snapshot (HTTP/DB/log):
- Known caveats:
```

---

## 13) Change log (guide itself)

- **2026-02-18**: Initial version created from live subnet E2E + hardening work:
  - install endpoint security matrix
  - package resolver/version selector behavior
  - policy refresh interval tuning guidance
  - command approval semantics and troubleshooting patterns
- **2026-02-18 (update)**:
  - org-specific token handling guidance hardened (no hardcoded token flow)
  - enrollment edge updated to auto-node upsert behavior
  - Endpoint “Enrollment & Install” UI workflow documented
