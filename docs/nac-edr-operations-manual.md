# eGuard NAC ↔ EDR/MDM Integration — Operations Manual

**Version**: 1.3  
**Date**: February 28, 2026  
**Audience**: SOC Analysts, System Administrators, Network Engineers  
**Last Validated**: February 28, 2026 (human-like GUI re-validation after local-only enforcer cleanup)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Prerequisites](#3-prerequisites)
4. [Web GUI Navigation](#4-web-gui-navigation)
5. [Viewing NAC Events](#5-viewing-nac-events)
6. [Manual Override: Isolate a Node](#6-manual-override-isolate-a-node)
7. [Manual Override: Allow a Node](#7-manual-override-allow-a-node)
8. [Checking NAC Status](#8-checking-nac-status)
9. [Quick-Allow from Events Table](#9-quick-allow-from-events-table)
10. [Understanding Security Events](#10-understanding-security-events)
11. [Auto-Detection Flow](#11-auto-detection-flow)
12. [Compliance Integration](#12-compliance-integration)
13. [NAC Admin: Security Events Configuration](#13-nac-admin-security-events-configuration)
14. [API Reference](#14-api-reference)
15. [Configuration Reference](#15-configuration-reference)
16. [Common Workflows](#16-common-workflows)
17. [Known Limitations & Edge Cases](#167-known-limitations--edge-cases)
18. [Troubleshooting](#17-troubleshooting)

---

## 1. Overview

The eGuard NAC ↔ EDR/MDM integration bridges endpoint detection capabilities
with network access control. When the eGuard agent detects a threat (malware,
C2, privilege escalation, etc.) or a compliance failure, the system
automatically triggers a NAC security event that can enforce network-level
actions such as VLAN isolation.

Administrators can also **manually override** network access for any endpoint:

- **🔒 Isolate** — Immediately move a node to the isolation VLAN
- **✅ Allow** — Close all security events and restore normal network access

---

## 2. Architecture

```
┌──────────────────┐     ┌──────────────────────────┐     ┌──────────────────────────┐
│  eGuard Agent    │     │  eGuard Agent Server (Go) │     │  eGuard NAC Runtime      │
│  (Rust, on host) │────→│  eg-agent-server           │────→│  (Perl NAC internals)    │
│                  │gRPC │  Port 50053               │local │  (same host, default)    │
│  Detections:     │     │                            │bridge│                          │
│  - YARA match    │     │  bridgeTelemetryToSecurity │     │  security_event_add()    │
│  - Sigma rule    │     │  Event()                   │     │  security_event_force_   │
│  - IOC hit       │     │           │                │     │  close()                 │
│  - Anomaly       │     │           ▼                │     │  reevaluate_access()     │
│                  │     │  nacEnforcer.ApplySecurity │     │         │                │
│  Compliance:     │     │  Event()                   │     │         ▼                │
│  - MDM checks    │     │           │                │     │  VLAN isolation /        │
│                  │     │           ▼                │     │  restoration             │
└──────────────────┘     │  security_event table      │     └──────────────────────────┘
                         │  (DB record)               │
                         └──────────────────────────┘

                         ┌──────────────────────────┐
                         │  Web GUI (Vue.js)         │
                         │  eGuard Admin Panel       │
                         │                            │
                         │  Manual Override:          │
                         │  POST /nac/override        │
                         │  {action: isolate/allow}   │
                         └──────────────────────────┘
```

---

## 3. Prerequisites

Before using NAC ↔ EDR integration:

1. **eGuard Agent Server** is running with NAC enforcer enabled (local required):
   ```
   Environment=EGUARD_NAC_ENFORCER_MODE=local
   ```

2. **Agents are enrolled** and appear in the `endpoint_agent` table with valid
   MAC addresses.

3. **Agents are registered as NAC nodes** in the `node` table
   (happens automatically during enrollment).

4. **Security events are enabled** in NAC admin
   (Configuration → Advanced Setting → Compliance → Security Events).

To verify:
```bash
# Check NAC enforcer mode is active
sudo journalctl -u eguard-agent-server --since "5 min ago" | grep "nac-enforcer"
# Expected (local mode): [nac-enforcer] mode=local enabled

# Check agents have MACs
sudo mysql -u root -p<password> eguard -e \
  "SELECT agent_id, mac, hostname FROM endpoint_agent"

# Check NAC nodes exist
sudo mysql -u root -p<password> eguard -e \
  "SELECT mac, status, device_type FROM node WHERE device_type='EDR Agent'"
```

**Latest live validation (2026-02-28, human-like GUI run):**
- Enforcer mode: `local` (HTTP bridge removed; local-only contract)
- GUI flow validated on `/admin#/endpoint-nac`:
  - manual **Isolate** (`reason: human-like revalidation isolate`) → banner `Node isolated — security event applied`
  - **Status** → `NAC Status: 🔒 ISOLATED ... Open events: Malware Detected`
  - manual **Allow** (`reason: human-like revalidation allow`) → banner `Node allowed — all eGuard security events closed`
  - **Status** → `NAC Status: ✅ ALLOWED ... No open security events`
- Adjacent endpoint UX smoke-checks passed:
  - `/admin#/endpoint-audit`: inline row-details toggle works (`▶` → `▼`), whitelist actions visible
  - `/admin#/endpoint-inventory`: advanced filters render and table loads
- Evidence artifacts:
  - `/tmp/nac-local-only-human-validate-20260228.png`
  - `/tmp/audit-inline-revalidate-20260228.png`
  - `/tmp/inventory-filters-revalidate-20260228.png`

---

## 4. Web GUI Navigation

### 4.1 eGuard Admin Panel Login

```
URL:  https://<server>:1443/admin#/login
User: admin
Pass: <your_admin_password>
```

### 4.2 NAC Enforcement Page

This is the primary page for NAC operations:

```
Path: Management → Endpoint Security → NAC tab

Direct URL: https://<server>:1443/admin#/endpoint-nac
Route path: /endpoint-nac
```

**How to get there:**
1. Log in to the eGuard admin panel
2. Click **Management** in the top navigation bar
3. Click **Endpoint Security** tab
4. Click the **NAC** pill/tab (blue highlighted)

### 4.3 Other Relevant Pages

| Page | Navigation Path | Direct URL |
|------|----------------|------------|
| **Agents List** | Management → Endpoint Security → Agents | `/endpoint-agents` |
| **Detection Dashboard** | Management → Endpoint Security → Detection | `/endpoint-detection-dashboard` |
| **Compliance** | Management → Endpoint Security → Compliance | `/endpoint-compliance` |
| **Response** | Management → Endpoint Security → Response | `/endpoint-responses` |
| **Telemetry** | Management → Endpoint Security → Telemetry | `/endpoint-events` |
| **Incidents** | Management → Endpoint Security → Incidents | `/endpoint-incidents` |
| **MDM Dashboard** | Management → Endpoint Security → MDM Dashboard | `/endpoint-mdm-dashboard` |
| **NAC Security Events Config** | Configuration → Advanced Setting → Compliance → Security Events | `/configuration/security_events` |
| **NAC Nodes** | Management → Client Devices Management → Search | (varies) |

---

## 5. Viewing NAC Events

### 5.1 Page Layout

The NAC Enforcement page has three sections:

1. **Manual Network Override** panel (top) — isolate/allow controls
2. **Filter bar** — filter by agent and event status
3. **Events table** — list of all NAC security events

### 5.2 Events Table Columns

| Column | Description |
|--------|-------------|
| **Agent** | Agent ID (e.g., `agent-31bbb93f38b4`) |
| **MAC** | Node MAC address (e.g., `aa:bb:cc:dd:ee:ff`) |
| **Event** | Human-readable event name (e.g., "Malware Detected") |
| **Status** | `open` (red badge) or `closed` (green badge) |
| **Start** | When the event was triggered |
| **Actions** | ✅ quick-allow button (for open events only) |

### 5.3 Expanding Event Details

Click any row to expand an inline detail panel showing:

- **Event Info**: Event ID, name, description, status
- **Network Identity**: Agent ID, MAC, ticket reference
- **Timeline & Notes**: Start date, release date, notes

### 5.4 Filtering Events

Use the **Filter Agent** dropdown and **Status** dropdown:

- **All agents** — show events for all agents
- **Specific agent** — show only that agent's events
- **Open** — show only active/unresolved events
- **Closed** — show only resolved events
- **All** — show both

Click **Apply** to filter. Click **Reset** to clear filters.

### 5.5 Refreshing Data

Click the **Refresh** button (top-right of the NAC panel) to reload events
from the server.

---

## 6. Manual Override: Isolate a Node

### When to Use

- Endpoint shows suspicious activity that needs immediate containment
- You want to preventively isolate a device during investigation
- Compliance failure requires network restriction

### Steps (Web GUI)

1. Navigate to **Management → Endpoint Security → NAC**
2. In the **Manual Network Override** panel:
   a. Select the target agent from the **Agent** dropdown
   b. (Optional) Enter a **Reason** — e.g., "Suspected ransomware — investigating"
   c. Click **🔒 Isolate** (red button)
3. Confirm the action in the dialog
4. A green success banner appears:
   > "ISOLATE: Node isolated — security event applied (agent: ...)"
5. The events table refreshes automatically, showing a new **Malware Detected** event with status `open`

### What Happens Behind the Scenes

1. Go server resolves agent ID → MAC address
2. Calls NAC enforcer `ApplySecurityEvent()` for event 1300010 (Malware Detected)
3. NAC runtime executes `reevaluate_access` (when configured) → node moves to **isolation VLAN**
4. Event recorded in `security_event` DB table with status `open`
5. Notes include `[manual-override]` prefix + your reason

### Choosing a Specific Event Type

By default, manual isolate uses event 1300010 (Malware Detected). To use a
different event (e.g., C2 Communication), use the API directly:

```bash
curl -X POST "http://<server>:50053/api/v1/endpoint/nac/override" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-31bbb93f38b4",
    "action": "isolate",
    "security_event_id": 1300013,
    "reason": "C2 beacon detected by SOC analyst"
  }'
```

---

## 7. Manual Override: Allow a Node

### When to Use

- Investigation complete — the detection was a false positive
- Remediation complete — the endpoint has been cleaned
- Compliance issue resolved — endpoint now meets policy
- Accidental isolation that needs to be reversed

### Steps (Web GUI)

1. Navigate to **Management → Endpoint Security → NAC**
2. In the **Manual Network Override** panel:
   a. Select the isolated agent from the **Agent** dropdown
   b. (Optional) Enter a **Reason** — e.g., "Investigated — false positive per SOC-2026-0142"
   c. Click **✅ Allow** (green button)
3. Confirm the action in the dialog
4. A green success banner appears:
   > "ALLOW: Node allowed — all eGuard security events closed (agent: ...)"
5. The events table refreshes — previously open events now show `closed`

### What Happens Behind the Scenes

1. Go server resolves agent ID → MAC address
2. Closes all open eGuard security events (1300010–1300017) in the DB
3. Calls NAC enforcer `CloseSecurityEvent()` for each open event
4. Calls NAC enforcer `ReevaluateAccess()` → node moves back to **normal VLAN**
5. Dedup cache is cleared, allowing fresh detections to re-trigger if needed

---

## 8. Checking NAC Status

### Steps (Web GUI)

1. Navigate to **Management → Endpoint Security → NAC**
2. Select the agent from the **Agent** dropdown in the override panel
3. Click **📊 Status** button
4. A blue info banner appears showing:
   - **ISOLATED**: `🔒 ISOLATED (MAC: aa:bb:cc:dd:ee:ff) — Open events: Malware Detected, Compliance Failure`
   - **ALLOWED**: `✅ ALLOWED (MAC: aa:bb:cc:dd:ee:ff) — No open security events`
   - **UNKNOWN**: `⚠️ UNKNOWN (MAC: not registered)` — agent has no MAC

### Via API

```bash
curl "http://<server>:50053/api/v1/endpoint/nac/status?agent_id=agent-31bbb93f38b4"
```

Response:
```json
{
  "agent_id": "agent-31bbb93f38b4",
  "mac": "aa:bb:cc:dd:ee:ff",
  "nac_status": "isolated",
  "open_events": [1300010, 1300014]
}
```

---

## 9. Quick-Allow from Events Table

For convenience, each **open** event in the table has a ✅ button in the
**Actions** column.

1. Scroll down to the events table
2. Find the open event you want to resolve
3. Click the ✅ button on that row
4. Confirm the dialog

This closes **all** open security events for that agent (not just the one
clicked), restoring normal network access.

> **Note**: Quick-allow always closes all eGuard events for the agent. You
> cannot selectively close individual events from the UI. Use the API for
> selective event management.

---

## 10. Understanding Security Events

### 10.1 eGuard Security Event IDs

| ID | Name | Severity | Actions | VLAN |
|----|------|----------|---------|------|
| **1300010** | Malware Detected | Critical | `reevaluate_access`, `email_admin` | **isolation** |
| **1300011** | Suspicious Behavior | High | `log`, `email_admin` | — |
| **1300012** | Unauthorized Module | High | `log`, `email_admin` | — |
| **1300013** | C2 Communication | Critical | `reevaluate_access`, `email_admin` | **isolation** |
| **1300014** | Compliance Failure | Medium | `log`, `email_admin` | — |
| **1300015** | Agent Tamper | Critical | `reevaluate_access`, `email_admin` | **isolation** |
| **1300016** | Lateral Movement | Critical | `reevaluate_access`, `email_admin` | **isolation** |
| **1300017** | Privilege Escalation | Critical | `reevaluate_access`, `email_admin` | **isolation** |

### 10.2 Action Types

- **`reevaluate_access`** — NAC runtime re-evaluates the node's VLAN assignment.
  If the event has `vlan=isolation`, the node is moved to the isolation VLAN.
- **`email_admin`** — Sends an email notification to the NAC admin. Typically
  combined with `reevaluate_access` or `log`.
- **`log`** — Event is recorded but no network enforcement occurs. Useful for
  monitoring without disrupting the user.

### 10.3 Upgrading an Event to Isolate

To make "Suspicious Behavior" (1300011) also trigger isolation:

**Via NAC Admin UI:**
1. Go to **Configuration → Advanced Setting → Compliance → Security Events**
2. Find event **1300011** ("Agent: Suspicious process behavior")
3. Click the edit (pencil) icon
4. Change **Actions** from `log` to `reevaluate_access`
5. Set **VLAN** to `isolation`
6. Save

**Via SQL:**
```sql
-- Add reevaluate_access action
INSERT INTO action (security_event_id, action) VALUES (1300011, 'reevaluate_access');
-- Remove log-only action
DELETE FROM action WHERE security_event_id = 1300011 AND action = 'log';
-- Set VLAN in the class table
UPDATE class SET vlan = 'isolation' WHERE security_event_id = 1300011;
```

---

## 11. Auto-Detection Flow

### 11.1 How Detections Become Security Events

```
Agent detects threat
  → Sends telemetry to server via gRPC StreamEvents()
    → Server calls bridgeTelemetryToSecurityEvent()
      → mapAlertToSecurityEvent() determines event ID
        → nacEnforcer.ApplySecurityEvent(mac, eventID, notes)
          → NAC runtime creates security_event + runs action
            → If action = reevaluate_access → VLAN isolation
```

> Enforcer mode is `EGUARD_NAC_ENFORCER_MODE=local` (direct local bridge to
> eGuard Perl NAC internals).

### 11.2 Mapping Rules

| Detection Type | Conditions | Security Event |
|---------------|------------|----------------|
| Agent tamper detection | `rule_name = "agent_tamper"` | 1300015 |
| Unauthorized kernel module | `rule_name = "unauthorized_kernel_module"` | 1300012 |
| YARA match | `rule_type = "yara"` + severity ≥ threshold | 1300010 |
| Sigma rule | `rule_type = "sigma"` + severity ≥ threshold | 1300011 |
| IOC + MITRE T1071 | `rule_type = "ioc"` + C2 technique | 1300013 |
| MITRE T1021/T1534 | Lateral movement techniques | 1300016 |
| MITRE T1548/T1068 | Privilege escalation techniques | 1300017 |

### 11.3 Severity Thresholds

Detections below the threshold are **not** forwarded to NAC:

| Setting | Default | Env Var |
|---------|---------|---------|
| Sigma minimum severity | `high` | `EGUARD_AGENT_SERVER_NAC_SIGMA_MIN_SEVERITY` |
| YARA minimum severity | `high` | `EGUARD_AGENT_SERVER_NAC_YARA_MIN_SEVERITY` |
| IOC without MITRE | disabled | `EGUARD_AGENT_SERVER_NAC_IOC_WITHOUT_MITRE_ENABLED` |
| IOC without MITRE min severity | `critical` | `EGUARD_AGENT_SERVER_NAC_IOC_WITHOUT_MITRE_MIN_SEVERITY` |

### 11.4 Dedup Behavior

To prevent flooding NAC enforcement with repeated detections from continuous
telemetry:

- Each (MAC, event_id) pair has a **5-minute cooldown** window
- During cooldown, duplicate events are silently dropped
- Manual overrides **clear** the cooldown, so re-isolation is immediate

---

## 12. Compliance Integration

### 12.1 Auto-Trigger on Compliance Failure

When an agent reports `non_compliant` status via the compliance API, the server
automatically triggers security event **1300014** (Compliance Failure).

### 12.2 Auto-Close on Compliance Restore

When the same agent later reports `compliant` status, the server automatically
closes event 1300014 via the NAC enforcer, restoring network access.

### 12.3 Manual Override for Compliance

If the default `log` action for compliance events is not sufficient, you can:

1. **Manually isolate** via the NAC page for non-compliant endpoints
2. **Upgrade** event 1300014 to `reevaluate_access` for automatic isolation
   (see Section 10.3)

---

## 13. NAC Admin: Security Events Configuration

### 13.1 Viewing eGuard Security Events

```
Path: Configuration → Advanced Setting → Compliance → Security Events
URL:  https://<server>:1443/admin#/configuration/security_events
```

**Steps:**
1. Click **Configuration** in the top nav
2. Click **Advanced Setting** tab
3. Click **Compliance** dropdown
4. Click **Security Events**
5. Scroll down to find IDs 1300010–1300017 (labeled "Agent: ...")

### 13.2 Editing an Event

1. Find the event in the list
2. Click the **pencil** (edit) icon on the right
3. Modify fields:
   - **Enabled**: Y/N
   - **Actions**: `log`, `reevaluate_access`, `email_admin`
   - **VLAN**: `isolation`, `normal`, `registration`
   - **Priority**: 1 (highest) to 10 (lowest)
   - **Grace period**: How long before the event can re-trigger
4. Save

### 13.3 Config File Location

The security events are defined in:
```
/usr/local/eg/conf/security_events.conf
```

eGuard events are at the bottom of the file, sections `[1300010]` through
`[1300017]`.

---

## 14. API Reference

All API endpoints are on the eGuard Agent Server (port 50053 by default).

### 14.1 Manual Override

**Endpoint**: `POST /api/v1/endpoint/nac/override`

**Request body:**
```json
{
  "agent_id": "agent-31bbb93f38b4",
  "action": "isolate",
  "reason": "Suspected compromise",
  "security_event_id": 1300010
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `agent_id` | ✅ | Target agent ID |
| `action` | ✅ | `"isolate"` or `"allow"` |
| `reason` | ❌ | Admin justification (logged) |
| `security_event_id` | ❌ | Event ID for isolate (default: 1300010) |

**Isolate response:**
```json
{
  "status": "ok",
  "message": "Node isolated — security event applied",
  "agent_id": "agent-31bbb93f38b4",
  "mac": "aa:bb:cc:dd:ee:ff",
  "action": "isolate",
  "event_id": 1300010
}
```

**Allow response:**
```json
{
  "status": "ok",
  "message": "Node allowed — all eGuard security events closed",
  "agent_id": "agent-31bbb93f38b4",
  "mac": "aa:bb:cc:dd:ee:ff",
  "action": "allow",
  "closed_events": [1300010, 1300011, 1300012, 1300013, 1300014, 1300015, 1300016, 1300017]
}
```

**Error responses:**

| Code | Error | Cause |
|------|-------|-------|
| 400 | `agent_id is required` | Missing agent_id |
| 400 | `action must be 'isolate' or 'allow'` | Invalid action |
| 405 | `method_not_allowed` | Used GET instead of POST |
| 422 | `agent has no valid MAC address` | Agent not enrolled or no MAC |
| 500 | `failed to resolve agent MAC` | DB error |

### 14.2 NAC Status

**Endpoint**: `GET /api/v1/endpoint/nac/status?agent_id=<id>`

**Response:**
```json
{
  "agent_id": "agent-31bbb93f38b4",
  "mac": "aa:bb:cc:dd:ee:ff",
  "nac_status": "isolated",
  "open_events": [1300010, 1300014]
}
```

| Field | Values |
|-------|--------|
| `nac_status` | `"isolated"` (has open events), `"allowed"` (no open events), `"unknown"` (no MAC) |
| `open_events` | Array of open security event IDs |

### 14.3 List NAC Events

**Endpoint**: `GET /api/v1/endpoint/nac`

**Query params:**

| Param | Description |
|-------|-------------|
| `agent_id` | Filter by agent ID |
| `status` | Filter by event status (`open`, `closed`) |
| `limit` | Max results (default: 200) |

**Response:**
```json
{
  "status": "ok",
  "events": [
    {
      "agent_id": "agent-31bbb93f38b4",
      "mac": "aa:bb:cc:dd:ee:ff",
      "security_event_id": 1300010,
      "status": "open",
      "notes": "[manual-override] Suspected compromise",
      "start_date": "2026-02-28T09:37:00Z"
    }
  ]
}
```

### 14.4 Trigger Security Event (Programmatic)

**Endpoint**: `POST /api/v1/endpoint/nac`

Used by the Go server internally and can be called manually for testing:

```json
{
  "agent_id": "agent-31bbb93f38b4",
  "rule_type": "yara",
  "severity": "critical",
  "notes": "YARA match: Trojan.Gen"
}
```

Or with explicit event ID:
```json
{
  "agent_id": "agent-31bbb93f38b4",
  "event_id": 1300013,
  "notes": "C2 beacon to known bad domain"
}
```

---

## 15. Configuration Reference

### 15.1 Agent Server Environment Variables

Set these in the systemd override file:
```
/etc/systemd/system/eguard-agent-server.service.d/override.conf
```

| Variable | Default | Description |
|----------|---------|-------------|
| `EGUARD_NAC_ENFORCER_MODE` | `local` | NAC execution mode: `local` (required) or `disabled` |
| `EGUARD_AGENT_SERVER_NAC_SIGMA_MIN_SEVERITY` | `high` | Min Sigma severity for NAC trigger |
| `EGUARD_AGENT_SERVER_NAC_YARA_MIN_SEVERITY` | `high` | Min YARA severity for NAC trigger |
| `EGUARD_AGENT_SERVER_NAC_IOC_WITHOUT_MITRE_ENABLED` | `false` | Allow IOC events without MITRE mapping |
| `EGUARD_AGENT_SERVER_NAC_IOC_WITHOUT_MITRE_MIN_SEVERITY` | `critical` | Min severity for unmapped IOCs |

**Example override.conf (local mode):**
```ini
[Service]
Environment=EGUARD_NAC_ENFORCER_MODE=local
Environment=EGUARD_AGENT_SERVER_NAC_SIGMA_MIN_SEVERITY=medium
```

> If `EGUARD_NAC_ENFORCER_MODE` is set to an unsupported value, agent-server
> logs a warning and forces `local` mode.

> **Note**: The override file may be named `e2e-override.conf` or similar in
> testing environments. Check with:
> ```bash
> ls /etc/systemd/system/eguard-agent-server.service.d/
> ```

After editing:
```bash
sudo systemctl daemon-reload
sudo systemctl restart eguard-agent-server
```

### 15.2 Security Events Config File

```
/usr/local/eg/conf/security_events.conf
```

Each eGuard event section looks like:
```ini
[1300010]
desc=eGuard: Malware Detected
priority=5
template=generic
actions=reevaluate_access,email_admin
auto_enable=Y
enabled=Y
grace=300s
vlan=isolation
trigger=internal::eguard_malware_detected
```

After editing, restart NAC config service:
```bash
sudo systemctl restart eguard-config
```

### 15.3 Database Tables

| Table | Purpose |
|-------|---------|
| `security_event` | Active and historical security events |
| `class` | Security event class definitions |
| `action` | Actions per security event class |
| `endpoint_agent` | Agent enrollment records (agent_id → MAC) |
| `node` | NAC node records (MAC → status, VLAN, etc.) |

---

## 16. Common Workflows

### 16.1 Responding to an Auto-Isolation

**Scenario**: SOC gets an alert that endpoint was auto-isolated.

1. Go to **Management → Endpoint Security → NAC**
2. Look at the **open** events at the top of the table
3. Click the event row to expand details — read the **Notes** field
4. Investigate the detection:
   - Check **Telemetry** tab for raw events
   - Check **Detection** tab for rule matches
   - Check **Incidents** tab for correlated alerts
5. If **false positive**:
   - Select the agent in the override panel
   - Enter reason: "Investigated — false positive, ticket SOC-XXXX"
   - Click **✅ Allow**
6. If **confirmed threat**:
   - Leave the node isolated
   - Perform remediation
   - After remediation, click **✅ Allow**

### 16.2 Preventive Isolation During Incident

**Scenario**: SOC suspects a group of endpoints may be compromised.

1. Go to **Management → Endpoint Security → NAC**
2. For each suspect endpoint:
   a. Select agent from dropdown
   b. Enter reason: "Preventive isolation — IR-2026-015"
   c. Click **🔒 Isolate**
3. Investigate in the **Telemetry** and **Incidents** tabs
4. After clearing each endpoint, select it and click **✅ Allow**

### 16.3 Compliance-Driven Isolation

**Scenario**: Policy requires endpoints without antivirus to be isolated.

1. Upgrade event 1300014 (Compliance Failure) to trigger isolation:
   - Go to **Configuration → Advanced Setting → Compliance → Security Events**
   - Edit event 1300014
   - Change actions to `reevaluate_access`
   - Set VLAN to `isolation`
2. Now any compliance failure auto-isolates the endpoint
3. When the endpoint becomes compliant, the event auto-closes and VLAN restores

### 16.4 Checking the Status of All Agents

**Via API** (for scripting/monitoring):
```bash
# Get all agents
agents=$(curl -s "http://localhost:50053/api/v1/endpoint/agents" | jq -r '.agents[].agent_id')

# Check each agent's NAC status
for agent in $agents; do
  status=$(curl -s "http://localhost:50053/api/v1/endpoint/nac/status?agent_id=$agent")
  nac=$(echo "$status" | jq -r '.nac_status')
  echo "$agent: $nac"
done
```

### 16.5 Bulk Operations

**Allow all agents** (emergency — use with caution):
```bash
# Close all eGuard security events in DB
sudo mysql -u root -p eguard -e "
  UPDATE security_event
  SET status='closed', release_date=NOW()
  WHERE security_event_id BETWEEN 1300010 AND 1300017
    AND status='open';
"
```

---

## 16.6 Verifying VLAN Configuration

After initial setup, verify that isolation events have the correct VLAN
assignment in the database:

```bash
sudo mysql -u root -p eguard -e "
  SELECT security_event_id, description, vlan
  FROM class
  WHERE security_event_id BETWEEN 1300010 AND 1300017;
"
```

**Expected output:**

| Event ID | Description | VLAN |
|----------|-------------|------|
| 1300010 | eGuard: Malware Detected | isolation |
| 1300011 | eGuard: Suspicious Behavior | NULL |
| 1300012 | eGuard: Unauthorized Module | NULL |
| 1300013 | eGuard: C2 Communication | isolation |
| 1300014 | eGuard: Compliance Failure | NULL |
| 1300015 | eGuard: Agent Tamper | isolation |
| 1300016 | eGuard: Lateral Movement | isolation |
| 1300017 | eGuard: Privilege Escalation | isolation |

If any VLAN values are NULL for isolation events, fix with:
```sql
UPDATE class SET vlan = 'isolation'
WHERE security_event_id IN (1300010, 1300013, 1300015, 1300016, 1300017);
```

---

## 16.7 Known Limitations & Edge Cases

### Multiple Agents Sharing the Same MAC

When multiple agent IDs are enrolled with the same MAC address (for example,
re-enrollment/testing artifacts), the NAC events list can show repeated rows
for the same MAC. This is usually a presentation issue from agent mapping,
not multiple physical nodes.

**Workaround**: Decommission stale agent records via Agents tab/API.

### Agents with Zero MAC (00:00:00:00:00:00)

Agents that haven't reported a valid MAC are not actionable for NAC override.
These agents:

- Cannot be isolated or allowed via NAC override (HTTP 422)
- Return `nac_status: "unknown"`
- Are excluded from VLAN enforcement

**Fix**: ensure heartbeat/inventory reports valid MAC data.

### Local Enforcer Behavior

- **Local mode (`EGUARD_NAC_ENFORCER_MODE=local`)** is the supported
  production mode.
- It calls local Perl NAC internals directly and does not depend on
  localhost TLS/API token flow.

### Duplicate Open Events Under Sustained Detections

The Go bridge has a 5-minute dedup window per `(mac,event_id)`. After the
window, sustained detections may legitimately create new rows over time.

This is expected: each row is a distinct occurrence; manual **Allow** closes
all open eGuard event IDs for the selected MAC.

### `reevaluate_access` in Lab Environments

In lab/demo setups without real switch/AP integration, `reevaluate_access`
may return 422 while DB status transitions still occur. This does not indicate
bridge failure; it indicates NAC backend cannot enforce network changes on that
lab topology.

---

## 17. Troubleshooting

### 17.1 Override Buttons Are Disabled

**Cause**: No agent selected in the override panel.  
**Fix**: Select a specific agent from the "Agent" dropdown (not "All agents").

### 17.2 "Agent has no valid MAC address" Error

**Cause**: Agent enrolled but hasn't reported a MAC, or MAC is `00:00:00:00:00:00`.  
**Fix**: Check `endpoint_agent` table:
```sql
SELECT agent_id, mac FROM endpoint_agent WHERE agent_id = 'agent-xxx';
```
If MAC is missing, the agent needs to send a heartbeat or inventory update.

### 17.3 Isolate Succeeds But Node Not Actually Isolated

**Cause**: Lab topology has no managed switch/AP integration for enforcement.  
**Verify**:
```bash
sudo journalctl -u eguard-agent-server --since "5 min ago" | grep -E "nac-override|reevaluate_access"
```
If `reevaluate_access` returns 422, DB state can still be correct while network
enforcement is unavailable in the lab.

### 17.4 Events Keep Flooding (Many Duplicates)

**Cause**: High-frequency telemetry on the same host/event pair.  
**Fix**:
- Dedup window is 5 minutes per `(mac,event_id)`
- Raise Sigma/YARA thresholds where needed
- Confirm NAC enforcer is active:
```bash
sudo journalctl -u eguard-agent-server --since "5 min ago" | grep "nac-enforcer"
```

### 17.5 Unsupported NAC Enforcer Mode Configured

**Cause**: `EGUARD_NAC_ENFORCER_MODE` set to an unsupported value.

**Fix**:
```bash
# Inspect current mode
sudo systemctl cat eguard-agent-server | grep EGUARD_NAC_ENFORCER_MODE

# Set supported value
# Environment=EGUARD_NAC_ENFORCER_MODE=local

sudo systemctl daemon-reload
sudo systemctl restart eguard-agent-server
```

**Expected logs**:
```text
[nac-enforcer] unsupported mode "<value>" in local-only deployment, forcing local
[nac-enforcer] mode=local enabled
```

### 17.6 Security Events Not Showing in NAC Config UI

**Cause**: event class entries missing in `security_events.conf` or DB/class mismatch.  
**Fix**:
```bash
sudo vi /usr/local/eg/conf/security_events.conf
# Ensure [1300010] through [1300017] exist
sudo systemctl restart eguard-config
```

### 17.6a VLAN Column is NULL for Isolation Events

**Cause**: `class.vlan` not set for isolation event IDs.  
**Fix**:
```sql
UPDATE class SET vlan = 'isolation'
WHERE security_event_id IN (1300010, 1300013, 1300015, 1300016, 1300017)
  AND (vlan IS NULL OR vlan = '');
```

### 17.6b Notes Missing After Manual Override

- In local mode, notes are written via `security_event_add(..., notes => ...)`.

**Verify**:
```sql
SELECT id, security_event_id, notes
FROM security_event
WHERE security_event_id BETWEEN 1300010 AND 1300017
ORDER BY id DESC LIMIT 10;
```

### 17.7 "Allow" Doesn't Restore VLAN

**Cause**: `reevaluate_access` requires active NAC network integration.  
**Verify DB close state**:
```bash
sudo mysql -u root -p eguard -e "
  SELECT id, security_event_id, mac, status
  FROM security_event
  WHERE mac = 'aa:bb:cc:dd:ee:ff'
    AND security_event_id BETWEEN 1300010 AND 1300017
  ORDER BY id DESC LIMIT 10;
"
```
If rows are `closed`, bridge logic is working; VLAN restoration depends on NAC
switch/RADIUS integration.

### 17.8 Log Locations

| Log | Location |
|-----|----------|
| Agent Server | `sudo journalctl -u eguard-agent-server -f` |
| NAC Enforcer Events | `sudo journalctl -u eguard-agent-server | grep nac-enforcer` |
| NAC Overrides | `sudo journalctl -u eguard-agent-server | grep nac-override` |
| Config Sync | `sudo journalctl -u eguard-config -f` |
| Security Events DB | `SELECT * FROM security_event ORDER BY id DESC LIMIT 20;` |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                     NAC QUICK REFERENCE                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  WEB GUI:                                                   │
│    Management → Endpoint Security → NAC                     │
│    URL: /admin#/endpoint-nac                                │
│                                                             │
│  ENFORCER MODE (recommended):                               │
│    EGUARD_NAC_ENFORCER_MODE=local                           │
│                                                             │
│  ISOLATE:  Select agent → 🔒 Isolate → Confirm             │
│  ALLOW:    Select agent → ✅ Allow → Confirm                │
│  STATUS:   Select agent → 📊 Status                        │
│                                                             │
│  API EXAMPLES:                                              │
│    Isolate:                                                 │
│      POST /api/v1/endpoint/nac/override                     │
│      {"agent_id":"...", "action":"isolate"}                 │
│                                                             │
│    Allow:                                                   │
│      POST /api/v1/endpoint/nac/override                     │
│      {"agent_id":"...", "action":"allow"}                   │
│                                                             │
│    Status:                                                  │
│      GET /api/v1/endpoint/nac/status?agent_id=...           │
│                                                             │
│  NAC SECURITY EVENTS CONFIG:                                │
│    Configuration → Advanced Setting → Compliance →          │
│    Security Events                                          │
│    IDs: 1300010-1300017                                     │
│                                                             │
│  ISOLATION EVENTS (auto-isolate):                           │
│    1300010 Malware | 1300013 C2 | 1300015 Tamper            │
│    1300016 Lateral Movement | 1300017 Priv Escalation       │
│                                                             │
│  LOG-ONLY EVENTS (alert, no VLAN change):                   │
│    1300011 Suspicious | 1300012 Module | 1300014 Compliance  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```
