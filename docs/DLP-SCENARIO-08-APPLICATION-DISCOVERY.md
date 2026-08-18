# DLP Scenario 08 — Endpoint Application Channel Discovery

**Status:** Discovery complete; no application-specific hook or enforcement added.
**Scope:** Windows-first metadata correlation; audit/alert-only.

## 1. Finding

The agent already has enough telemetry to identify the process responsible for a file event:

- executable path (`process_exe`)
- normalized process name
- process ID and parent chain
- command line when available
- file path and file-write metadata
- TCP destination IP/port and DNS domain for network events

The DLP policy engine already supports destination application matching through `destination.apps`; it compares configured app patterns with the event process identity. The current channel mapper returns:

- `file_share` for UNC paths
- `removable_media` for confirmed removable paths
- `file_write` for other file paths

Therefore application targeting can currently be represented as **process-constrained file DLP**, not as browser/WhatsApp/cloud upload interception.

## 2. Application matrix

| Application family | Identity available now | App-specific content/API hook | Safe current claim |
|---|---|---|---|
| Chrome | executable path/process identity | None verified | Process-constrained file event only |
| Microsoft Edge | executable path/process identity | None verified | Process-constrained file event only |
| Firefox | existing process/file enrichment supports identity when running | None verified | Process-constrained file event only |
| WhatsApp Desktop | executable path/process identity when running | No sanctioned message/media hook verified | Local file event correlation only |
| OneDrive / sync client | executable path/process identity when running | No cloud-upload/body hook verified | Local sync-file event correlation only |
| Google Drive / DriveFS | No process observed in this host snapshot; identity path is supported if installed/running | No cloud-upload/body hook verified | Local sync-file event correlation only |

The host snapshot observed Chrome, Edge, WhatsApp Desktop, and OneDrive processes. This is environment evidence, not a claim that other applications are unavailable.

## 3. Integration decision

Use the existing process identity path first:

```text
ProcessExec → cache pid → executable basename/path
FileOpen/FileWrite → resolve pid → DLP classifier + destination.apps
```

A policy may constrain an application using a stable process pattern such as:

```json
{
  "destination": {
    "apps": ["chrome.exe"]
  },
  "action": "audit"
}
```

The policy must not imply that the agent inspected a browser upload, WhatsApp message, or cloud request. It only means that a matching file event was associated with the selected process.

## 4. Privacy boundary

Allowed by default:

- normalized executable basename
- optional executable hash already present in the event model
- bounded PID/parent correlation for event linking
- file path only when required by the configured DLP source/destination scope
- destination IP/port/DNS metadata for network telemetry
- classifier ID and redacted evidence only

Not collected or claimed:

- browser DOM, upload body, cookies, tokens, or TLS plaintext
- WhatsApp message body, chat history, or media content through an undocumented hook
- Google Drive/OneDrive cloud request body or API tokens
- raw file contents in telemetry
- process command lines containing secrets; existing command-line sanitization remains the boundary

No process kill, network block, printer action, host isolation, firewall change, or Internet disruption is part of Scenario 08.

## 5. Synthetic test plan

The test uses harmless local fixtures and verifies correlation, not upload interception.

### A. Process identity

1. Start a supported application (Chrome, Edge, Firefox, WhatsApp Desktop, or OneDrive).
2. Confirm a ProcessExec event contains the executable path and PID.
3. Confirm the process cache resolves a subsequent file event to the same process identity.
4. Confirm the reported app identity is normalized to a basename or approved stable identifier.

### B. App-constrained file DLP

1. Configure an audit-only DLP policy with a synthetic classifier and `destination.apps` set to one test process.
2. Create a new fixture file through that process's normal local data path, or use a controlled helper whose process identity is explicitly the test target.
3. Verify a matching classifier event is attributed to the configured app.
4. Repeat with a different process and verify the app-constrained policy does not match.
5. Confirm the event contains only classifier ID and redacted evidence.

### C. Negative controls

- benign file through the target process → no DLP match
- sensitive fixture through a non-target process → no app-constrained match
- browser navigation/upload simulation without a local file event → do not report a DLP detection
- cloud sync activity without a verified local file event → do not report upload detection

## 6. Acceptance boundary

Scenario 08 can be marked complete for **application identity/process correlation** when the existing process enrichment and DLP destination-app tests pass. It must remain explicitly incomplete for:

- browser upload interception
- WhatsApp message inspection
- Google Drive/OneDrive cloud payload inspection
- TLS inspection or MITM
- application-specific blocking

Those require separately sanctioned OS/vendor APIs and a privacy review. The correct next implementation, if requested, is a small normalized `app_id` mapping over the existing process identity—not a new browser or chat interception subsystem.

## Evidence inspected

- `platform-windows`: `EventType`, `RawEvent`, `EnrichedEvent`, process enrichment/cache, executable path and command-line resolution.
- `agent-core/lifecycle/detection_event.rs`: process identity normalization and event correlation.
- `agent-core/lifecycle/dlp_policy_engine.rs`: `destination.apps` process matching.
- `agent-core/lifecycle/tick.rs`: DLP channel mapping and audit payload behavior.
- `docs/DLP-CAPABILITY-MATRIX.md`: browser/cloud upload interception is not available and must not be advertised.
- Local Windows snapshot: Chrome, Edge, WhatsApp Desktop, and OneDrive processes observed; no Google Drive/DriveFS process observed in the snapshot.

Skipped: app-specific browser/chat/cloud hooks and blocking. Add only after a vendor-supported API, privacy review, and a reproducible synthetic test exist.
.