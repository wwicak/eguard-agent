# eGuard DLP Contract Draft

> Draft only. Canonical proto ownership and generated bindings are not changed in this task.

## Bundle identity

```json
{
  "bundle_type": "eguard-dlp-rules",
  "bundle_version": "1.0.0",
  "bundle_sha256": "sha256:<64 lowercase hex>",
  "signature_algorithm": "ed25519",
  "schema_version": "1",
  "pack_ids": ["indonesia"],
  "agent_compatibility": {"min_agent_version": "15.1.0"}
}
```

The DLP bundle is not an EDR threat-intel bundle. The server must not interpret an EDR version as a DLP version. A failed signature, hash, schema, compatibility, or compile check leaves the last-known-good DLP bundle active.

## Agent capability names

Use stable strings until the canonical proto is extended:

- `dlp.file_text_scan`
- `dlp.file_write_observe`
- `dlp.removable_media_observe`
- `dlp.removable_media_block`
- `dlp.clipboard_observe`
- `dlp.browser_upload_observe`
- `dlp.browser_upload_block`
- `dlp.content_redaction`
- `dlp.hot_reload`
- `dlp.trusted_label_observe`
- `dlp.structured_fingerprint_observe`
- `dlp.unstructured_fingerprint_observe`

Capabilities are reported per endpoint and must have an explicit state: `available`, `audit_only`, `unsupported`, or `degraded`.

## Policy payload

```json
{
  "schema_version": "1",
  "policy_id": "dlp-default",
  "policy_version": 1,
  "bundle_version": "1.0.0",
  "bundle_sha256": "sha256:<64 lowercase hex>",
  "scope": {"tenant_id": "tenant-1", "agent_ids": [], "groups": ["default"]},
  "channels": ["file_write", "removable_media"],
  "actions": {"default": "audit", "high_confidence": "alert"},
  "max_scan_size_bytes": 10485760,
  "scan_timeout_ms": 100,
  "redaction_mode": "mask_middle",
  "expires_at_unix": 0,
  "exceptions": [],
  "enabled": true
}
```

MVP actions are `audit` and `alert`. `block` is allowed only when the endpoint capability explicitly reports a tested block path and the policy is in targeted rollout.

## Classification extensions (Scenario 01–03)

The classification core is local-only and audit/alert-only.

- **Trusted labels/properties:** adapters may emit only an opaque Microsoft Purview/MIP or Office label identifier after the platform adapter verifies the source. Filenames, arbitrary sidecar files, and user-provided values are not trusted labels.
- **Structured fingerprints:** tenant tooling canonicalizes approved records and supplies only keyed SHA-256 fingerprints to the Agent. Raw structured records and tenant keys are not telemetry fields.
- **Unstructured fingerprints:** tenant tooling supplies bounded keyed five-word-shingle fingerprints. The Agent compares local text to those fingerprints; it never uploads the reference corpus or observed text.
- **Precedence:** accepted trusted label, structured fingerprint, and unstructured fingerprint are independent audit signals. A future policy may combine them, but none creates a block action.
- **Capability state:** these capabilities remain `unsupported` until a verified MIP/Office adapter and tenant-provisioned fingerprint pack are active; the core alone does not advertise them as available.

## Detection event

```json
{
  "event_type": "dlp_detection",
  "event_id": "stable-id",
  "agent_id": "agent-1",
  "policy_id": "dlp-default",
  "bundle_version": "1.0.0",
  "rule_id": "id.nik",
  "channel": "file_write",
  "action": "alert",
  "severity": "high",
  "confidence": 0.98,
  "file": {
    "path_hash": "sha256:<path hash>",
    "extension": ".csv",
    "size_bytes": 2048,
    "content_sha256": "sha256:<content hash>"
  },
  "evidence": {"mode": "redacted", "value": "3174********0001"},
  "observed_at_unix": 0
}
```

Raw file content, full sensitive values, and credentials are prohibited in telemetry by default. `path_hash` is preferred over the full path; a tenant policy may separately authorize a sanitized path prefix if operations require it.

## Sync behavior

1. Agent reports active DLP bundle version/hash and capability states during heartbeat.
2. Server returns policy only if the agent is authorized for its tenant/scope.
3. Agent downloads the declared DLP bundle through a discriminator that cannot accidentally select an EDR bundle.
4. Agent validates signature, hash, schema, compatibility, size, and compile result in staging.
5. Agent atomically activates the new state and reports success/failure plus the previous version.
6. Agent keeps the last-known-good state on any failure and reports `degraded`.

## Compatibility rule

Old agents that do not understand DLP fields continue operating with DLP disabled. The server must display this as unsupported/degraded, never as healthy enforcement.

## Open contract decisions

- Canonical proto owner: server `go/api/agent/v1` or agent `proto/eguard/v1`.
- Whether DLP uses a new `DownloadDlpBundle` RPC or a typed extension of `DownloadRuleBundle`.
- Whether path hashes are tenant-salted to prevent cross-tenant correlation.
- Whether `expires_at_unix=0` means no expiry or server-issued short-lived policy only.

## Review gate

Do not regenerate protobuf bindings or implement server handlers until the four decisions above are accepted and the event payload has an explicit redaction test.

## Revision

- Drafted during DLP T04 after capability discovery and T02/T03 fixture validation.
- No generated code, production proto, or Agent runtime changed.
- Existing unrelated working-tree state remains untouched.
2026-07-27

## Task status

T01, T02, and T03 complete. T04 contract draft pending canonical ownership decision.
