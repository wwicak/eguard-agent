# eGuard DLP Operations

## Current scope

The current DLP implementation is **audit/alert only**. It scans bounded UTF-8 text files on file-write events, emits redacted detection metadata, and keeps the active scanner when a replacement pack is invalid.

Implemented channels:

- Agent file-write scan for configured text-like files.
- Versioned JSON rule pack loading.
- Context and validator checks.
- Redacted evidence in the existing telemetry envelope.
- `DLP_DETECTION` protobuf mapping with `DlpDetectionEvent`.
- Existing server event query filter: `event_type=dlp_detection`.
- Agent-owned Tray state file: `dlp-state.json`.

Not implemented or not proven:

- Windows blocking/file interception end-to-end.
- macOS/Linux blocking.
- Clipboard, browser upload, cloud upload, SSL inspection, OCR, and archive expansion.
- Tray notification and acknowledge UI.
- Full workspace test suite on Windows.

## Safe configuration

DLP is disabled by default. Enable it only with a validated rule pack:

```ini
dlp_enabled = true
dlp_rules_path = C:\\ProgramData\\eGuard\\dlp\\indonesia.json
dlp_max_file_scan_size_mb = 10
```

Equivalent environment variables:

```text
EGUARD_DLP_ENABLED=true
EGUARD_DLP_RULES_PATH=C:\\ProgramData\\eGuard\\dlp\\indonesia.json
EGUARD_DLP_MAX_FILE_SCAN_SIZE_MB=10
```

Keep the first rollout in `audit` or `alert`. Do not use `block` until a platform-specific enforcement path has a passing end-to-end test.

## Rule-pack replacement

1. Validate schema, regex compilation, and fixtures in CI.
2. Stage the new pack separately.
3. Load and compile it before activation.
4. If loading fails, keep the previous active scanner.
5. Confirm telemetry still contains only redacted evidence.

An unavailable, malformed, oversized, or invalid pack must not disable unrelated Agent behavior.

## Tray state

The Agent writes `dlp-state.json` in the existing Tray data directory. It contains only operational status:

```json
{
  "enabled": true,
  "scanner_loaded": true,
  "max_file_scan_size_mb": 10,
  "status": "active"
}
```

Possible status values are `disabled`, `active`, and `degraded`. The file must not contain raw content, matched values, evidence, or sensitive file paths.

## Detection query

Use the existing endpoint event API:

```text
GET /api/v1/endpoint/events?event_type=dlp_detection
GET /api/v1/endpoint/detection-stats?event_type=dlp_detection&period=24h
```

The UI's **DLP only** filter uses these parameters for both event rows and statistics.

## Verification

Focused checks currently used on Windows:

```bash
cd eguard-agent
cargo check -p agent-core
cargo test -p detection dlp
cargo test -p grpc-client client::tests_mappings::dlp_event_mapping_preserves_redacted_detail --no-default-features
git diff --check

cd ../fe_eguard/go
go test ./agent/server -run 'TestDetectionStatsFilterByDLPEventType|TestEventsFilterByDLPDetectionType|TestValidateDLPPolicyJSON' -count=1

cd ../../fe_eguard/html/egappserver/root
npx eslint src/views/endpoint/AgentConfig.vue src/views/endpoint/DetectionDashboard.vue src/views/endpoint/agentConfigProfiles.js src/views/endpoint/api.js
npm run build
```

The repository's canonical `make test` command cannot run on the current Windows environment because `make` is not installed. The existing Agent test binary also contains Linux-only test references and must be made target-portable before runtime reload tests can be green on Windows.

## Rollout gates

1. **Audit:** validate rule quality, redaction, latency, and false positives.
2. **Alert:** validate user experience, notification, acknowledge, and exception handling.
3. **Targeted block:** enable only after Windows enforcement is proven, with a kill switch and rollback.
