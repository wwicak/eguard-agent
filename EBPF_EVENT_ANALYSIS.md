# eBPF Event Processing Pipeline Analysis

## Executive Summary

Two critical issues in the eBPF event processing pipeline:

1. **dns_query events**: `event.dst_domain='sudo'` (process name) instead of actual DNS domain
2. **file_open events**: `event.file_path=null` while `event_txn.subject` retains the path

Both issues have root causes in different layers of the pipeline with minimal fixes required.

---

## Issue #1: DNS Query Domain Contamination

### Root Cause

**File**: `zig/ebpf/dns_query.c` (lines 24-25)

```c
SEC("kprobe/udp_sendmsg")
int eguard_udp_sendmsg(void *ctx)
{
    EGUARD_ALLOC_EVENT(dns_query_event, e);
    fill_hdr(&e->hdr, EVENT_DNS_QUERY);
    
    e->qtype  = 1;  /* A */
    e->qclass = 1;  /* IN */
    bpf_get_current_comm(e->qname, QNAME_SZ);  // ← PROBLEM: This fills qname with process name!
    
    EGUARD_SUBMIT_EVENT(ctx, e);
}
```

**The Problem**: The probe hooks `kprobe/udp_sendmsg`, which is a generic UDP send hook. To get the actual DNS query name, you'd need to parse the packet payload (UDP → DNS packet structure). Instead, the V1 implementation uses `bpf_get_current_comm()` as a placeholder, which fills the qname buffer with the sending process's command name (e.g., "sudo", "curl", "systemd-resolve").

### Pipeline Flow

1. eBPF probe: `bpf_get_current_comm(e->qname, 128)` → e.g., "sudo"
2. Codec (`crates/platform-linux/src/ebpf/codec.rs:176-184`):
   ```rust
   fn parse_dns_query_payload(raw: &[u8]) -> String {
       let qtype = read_u16_le(raw, 0).unwrap_or_default();
       let qclass = read_u16_le(raw, 2).unwrap_or_default();
       let qname = parse_c_string(slice_window(raw, 4, 128));  // ← Reads "sudo" from qname field
       format!("qname={};qtype={};qclass={}", qname, qtype, qclass)
   }
   ```
3. Enrichment (`crates/platform-linux/src/lib.rs:617`):
   ```rust
   dst_domain: fields
       .get("dst_domain")
       .cloned()
       .or_else(|| fields.get("domain").cloned())
       .or_else(|| fields.get("qname").cloned()),  // ← Extracts "sudo"
   ```
4. TelemetryEvent: `dst_domain = Some("sudo")`
5. JSON output: `"event": { ..., "dst_domain": "sudo" }`

### Minimal Fix

**File**: `zig/ebpf/dns_query.c`

Replace the placeholder logic with a no-op (zero the qname buffer):

```c
SEC("kprobe/udp_sendmsg")
int eguard_udp_sendmsg(void *ctx)
{
    EGUARD_ALLOC_EVENT(dns_query_event, e);
    fill_hdr(&e->hdr, EVENT_DNS_QUERY);
    
    e->qtype  = 1;  /* A */
    e->qclass = 1;  /* IN */
    // NOTE: Real DNS extraction requires skb parsing (TC/XDP, not kprobe).
    // For now, leave qname empty to avoid contamination with process names.
    // Agent-side parser can correlate via PID + port 53 filter.
    __builtin_memset(e->qname, 0, QNAME_SZ);  // ← FIX: Clear qname instead of filling with process name
    
    EGUARD_SUBMIT_EVENT(ctx, e);
}
```

Or simpler, just don't populate qname:

```c
SEC("kprobe/udp_sendmsg")
int eguard_udp_sendmsg(void *ctx)
{
    EGUARD_ALLOC_EVENT(dns_query_event, e);
    fill_hdr(&e->hdr, EVENT_DNS_QUERY);
    
    e->qtype  = 1;  /* A */
    e->qclass = 1;  /* IN */
    // qname left uninitialized/zeroed by EGUARD_ALLOC_EVENT
    
    EGUARD_SUBMIT_EVENT(ctx, e);
}
```

### Impact

- `event.dst_domain` will be `null` (empty qname) instead of process name
- Still allows port-based filtering (UDP port 53)
- Prevents false positives where "sudo" is mistaken for a domain
- Agent can still detect DNS activity by PID + port correlation

### Risk Level

**LOW** - The qname was placeholder data anyway. Detection via port 53 + PID is still valid.

---

## Issue #2: File Open Events Have Null file_path

### Root Cause

The issue manifests in two places with different root causes:

#### A. Missing Payload Extraction (Primary)

**File**: `crates/platform-linux/src/lib.rs:597-625` (parse_payload_metadata)

For `EventType::FileOpen`, the file_path is extracted from payload fields:

```rust
let mut metadata = PayloadMetadata {
    file_path: fields
        .get("path")     // ← Looks for "path=" field
        .cloned()
        .or_else(|| fields.get("file").cloned()),
    ...
};
```

But this only works if the payload is successfully parsed as key-value fields. If the payload is empty or malformed, parse_kv_fields returns an empty HashMap.

**File**: `crates/platform-linux/src/lib.rs:642-660` (parse_payload_fallback)

When the kv parsing fails, fallback logic is used:

```rust
fn parse_payload_fallback(event_type: &EventType, payload: &str) -> PayloadMetadata {
    match event_type {
        EventType::FileOpen | EventType::FileWrite => {
            let fields = parse_kv_fields(payload);
            if fields.is_empty() {
                return PayloadMetadata {
                    file_path: Some(payload.to_string()),  // ← Falls back to whole payload as path
                    file_write: matches!(event_type, EventType::FileWrite),
                    ..PayloadMetadata::default()
                };
            }
            ...
        }
        ...
    }
}
```

**Problem**: If the payload parsing succeeds but `fields.get("path")` returns None, then file_path is not set. This happens when:

1. Codec produces empty or whitespace-only path in the eBPF buffer
2. Codec produces malformed payload (missing "path=" key)
3. File path is longer than 256 bytes (truncated by eBPF, parsed_c_string stops at first null)

#### B. File Path Field Not Passed Through (Secondary)

**File**: `crates/platform-linux/src/lib.rs:394-395` (enrich_event_with_cache)

```rust
EnrichedEvent {
    ...
    file_path: payload_meta.file_path.or(payload_meta.file_path_secondary),
    ...
}
```

If `payload_meta.file_path` is None, it's not set even if it exists in the raw payload. The raw payload still has the data, but the extracted EnrichedEvent doesn't.

#### C. Blocking in to_detection_event (Tertiary)

**File**: `crates/agent-core/src/lifecycle/detection_event.rs:49-53`

```rust
let file_path = enriched
    .file_path  // ← If None from enrichment, stays None
    .clone()
    .filter(|path| !is_low_value_windows_pseudo_identity(path))
    .or(module_payload)
    .or_else(|| { ... });
```

There's no Linux-side fallback to extract from raw payload if enriched.file_path is None.

### Pipeline Flow for file_open

1. **eBPF Probe** (`zig/ebpf/file_open.c`): Correctly captures path in 256-byte buffer
2. **Codec** (`crates/platform-linux/src/ebpf/codec.rs:128-149`): Correctly extracts path from binary
3. **Enrichment** (`crates/platform-linux/src/lib.rs:395`): **May fail to set file_path if payload parsing fails**
4. **TelemetryEvent** (`crates/agent-core/src/lifecycle/detection_event.rs:49-53`): **Remains None**
5. **EventTxn from RawEvent** (`crates/agent-core/src/lifecycle/event_txn.rs:73-118`): **Still has path from payload**
6. **JSON output**:
   ```json
   {
     "event": { "file_path": null, ... },
     "event_txn": { "subject": "/path/to/file", "key": "...|...|/path/to/file|..." }
   }
   ```

### Minimal Fix #1: Fallback in to_detection_event

**File**: `crates/agent-core/src/lifecycle/detection_event.rs:25-62`

```rust
pub(super) fn to_detection_event(
    enriched: &crate::platform::EnrichedEvent,
    now_unix: i64,
) -> TelemetryEvent {
    // ... existing code ...
    
    let file_path = enriched
        .file_path
        .clone()
        .filter(|path| !is_low_value_windows_pseudo_identity(path))
        .or(module_payload)
        .or_else(|| {
            matches!(
                enriched.event.event_type,
                crate::platform::EventType::ProcessExec | crate::platform::EventType::ProcessExit
            )
            .then(|| enriched.process_exe.clone())
            .flatten()
        })
        // NEW: Add fallback to extract from raw payload for Linux file events
        .or_else(|| {
            matches!(
                enriched.event.event_type,
                crate::platform::EventType::FileOpen
                    | crate::platform::EventType::FileWrite
                    | crate::platform::EventType::FileRename
                    | crate::platform::EventType::FileUnlink
            )
            .then(|| {
                // Parse raw payload to get path as last resort
                // This handles cases where enrichment extraction failed
                parse_payload_field(&enriched.event.payload, "path")
                    .or_else(|| parse_payload_field(&enriched.event.payload, "file"))
            })
            .flatten()
        });
    
    // ... rest of function ...
}

// Add helper (or use existing one from event_txn.rs)
fn parse_payload_field(payload: &str, field: &str) -> Option<String> {
    payload
        .split([';', ','])
        .filter_map(|segment| segment.split_once('='))
        .find_map(|(key, value)| {
            if key.trim().eq_ignore_ascii_case(field) {
                let value = value.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                }
            } else {
                None
            }
        })
}
```

**Lines Changed**: ~18 (new `.or_else()` block + helper function)

### Minimal Fix #2: Ensure Payload Parsing in enrich_event_with_cache

**File**: `crates/platform-linux/src/lib.rs:394-396`

Add a fallback for file events that verifies the payload extraction worked:

```rust
let file_path = payload_meta.file_path.or(payload_meta.file_path_secondary)
    // Fallback: if no path was extracted, try parsing raw payload directly
    .or_else(|| {
        matches!(
            raw.event_type,
            EventType::FileOpen | EventType::FileWrite | EventType::FileRename | EventType::FileUnlink
        )
        .then(|| parse_payload_field(&raw.payload, "path")
            .or_else(|| parse_payload_field(&raw.payload, "file")))
        .flatten()
    });
```

**Lines Changed**: ~10

### Impact

- `event.file_path` will be populated from raw payload as fallback
- Maintains consistency with `event_txn.subject` (both have path)
- No changes to eBPF probe or binary format
- Safe: only activates if enrichment extraction failed

### Risk Level

**VERY LOW** - Fallback only, non-breaking, defensive.

---

## Recommended Minimal Fixes

### Fix #1: Clear DNS Query Name (Required)

**File**: `zig/ebpf/dns_query.c:25`

**Change**: Remove `bpf_get_current_comm(e->qname, QNAME_SZ);` 

**Impact**: Prevents "sudo" contamination in dst_domain

**Lines**: 1 line deletion

---

### Fix #2: Add File Path Fallback in to_detection_event (Recommended)

**File**: `crates/agent-core/src/lifecycle/detection_event.rs:49-53`

**Change**: Add `.or_else()` block to extract from raw payload if enriched.file_path is None

**Impact**: Ensures file_path is never null when data exists in payload

**Lines**: ~18 lines

---

### Fix #3: Add File Path Fallback in enrich_event_with_cache (Optional)

**File**: `crates/platform-linux/src/lib.rs:394-396`

**Change**: Add fallback parsing of raw payload for file events

**Impact**: Earlier failsafe, catches extraction issues at enrichment time

**Lines**: ~10 lines

---

## Testing Strategy

### For DNS Query Fix

```bash
# Test 1: Verify qname is empty
cat > /tmp/test_dns.sh <<'EOF'
# Inject dns_query event with empty qname
echo '{"event_type":"dns_query","pid":1234,"uid":0,"ts_ns":1000000,"qtype":1,"qclass":1,"qname":""}' | \
  /path/to/agent --replay

# Assert: event.dst_domain is null (not "bash" or process name)
EOF

# Test 2: Agent-side correlation still works
# curl google.com from "curl" process
# Assert: Process name is "curl", dst_port is 53 → recognized as DNS
```

### For File Open Fix

```bash
# Test 1: Verify file_path is populated
cat > /tmp/test_file_open.sh <<'EOF'
# Inject file_open event with path
echo '{"event_type":"file_open","pid":1234,"uid":0,"ts_ns":1000000,"path":"/etc/shadow"}' | \
  /path/to/agent --replay

# Assert: event.file_path = "/etc/shadow" (not null)
# Assert: event_txn.subject = "/etc/shadow" (matches)
EOF

# Test 2: File events are detected
# cat /sensitive_file.txt
# Assert: event.file_path and event_txn.subject both populated
```

---

## Detailed Analysis: Why event_txn Still Has Path

EventTxn is built two ways:

1. **EventTxn::from_raw()** - Direct payload parsing:
   ```rust
   let path = parse_payload_field(&raw.payload, "path");
   ```
   This always finds the path if it's in the raw payload.

2. **EventTxn::from_enriched()** - Uses TelemetryEvent:
   ```rust
   subject: event.file_path.clone()  // Uses enriched TelemetryEvent
   ```
   This only works if TelemetryEvent.file_path was populated.

**Why the asymmetry**:
- When EventTxn is created from EnrichedEvent → uses TelemetryEvent (may be None)
- When EventTxn is created from RawEvent → parses payload directly (has data)

The fixes above ensure both paths have data.

---

## Files to Modify (Summary)

| File | Issue | Fix | Lines |
|------|-------|-----|-------|
| `zig/ebpf/dns_query.c` | qname=process_name | Remove bpf_get_current_comm() | 1 |
| `crates/agent-core/src/lifecycle/detection_event.rs` | file_path=null | Add raw payload fallback | ~18 |
| `crates/platform-linux/src/lib.rs` | (Optional early fallback) | Add raw payload fallback | ~10 |

---

## References

- eBPF Probes: `/home/dimas/eguard-agent/zig/ebpf/*.c`
- Codec: `/home/dimas/eguard-agent/crates/platform-linux/src/ebpf/codec.rs`
- Enrichment: `/home/dimas/eguard-agent/crates/platform-linux/src/lib.rs`
- Event TXN: `/home/dimas/eguard-agent/crates/agent-core/src/lifecycle/event_txn.rs`
- Detection Event: `/home/dimas/eguard-agent/crates/agent-core/src/lifecycle/detection_event.rs`
- Telemetry JSON: `/home/dimas/eguard-agent/crates/agent-core/src/lifecycle/telemetry.rs`
