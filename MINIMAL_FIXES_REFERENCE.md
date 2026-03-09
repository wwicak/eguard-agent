# Minimal Fixes for eBPF Event Issues

## Quick Reference

### Issue 1: DNS Query Domain = Process Name ("sudo")

**Root Cause**: `bpf_get_current_comm()` fills qname with process name instead of DNS query

**Fix**: `zig/ebpf/dns_query.c` line 25 - DELETE THIS LINE:
```c
bpf_get_current_comm(e->qname, QNAME_SZ);  // ← REMOVE THIS
```

**Result**: `event.dst_domain` will be `null` instead of "sudo"

**Lines Changed**: 1 deletion

---

### Issue 2: File Open Has Null file_path

**Root Cause**: No fallback to raw payload when enrichment extraction fails

**Primary Fix**: `crates/agent-core/src/lifecycle/detection_event.rs` lines 49-62

Replace this block:
```rust
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
    });
```

With:
```rust
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
    // NEW: Fallback for file events when enrichment didn't extract path
    .or_else(|| {
        matches!(
            enriched.event.event_type,
            crate::platform::EventType::FileOpen
                | crate::platform::EventType::FileWrite
                | crate::platform::EventType::FileRename
                | crate::platform::EventType::FileUnlink
        )
        .then(|| extract_payload_field(&enriched.event.payload, "path")
            .or_else(|| extract_payload_field(&enriched.event.payload, "file")))
        .flatten()
    });
```

Add helper function after `confidence_to_severity()`:
```rust
fn extract_payload_field(payload: &str, field: &str) -> Option<String> {
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

**Result**: `event.file_path` will be populated from raw payload as fallback

**Lines Changed**: ~18 (14-line or_else block + 4-line function)

---

## Why These Fixes Work

### DNS Query Fix
- eBPF `kprobe/udp_sendmsg` captures ALL UDP sends, not just DNS
- Real DNS extraction requires packet parsing (XDP/TC, not kprobe)
- Using process name ("sudo") as placeholder is misleading
- Solution: Leave qname empty, correlate via port 53 + PID instead

### File Path Fix
- Codec correctly extracts path from eBPF probe binary
- Enrichment may fail to parse payload in edge cases
- Raw payload is in RawEvent, but TelemetryEvent has no fallback
- Solution: Add fallback to parse raw payload at detection event layer
- This ensures TelemetryEvent.file_path matches RawEvent.payload

---

## Testing Commands

```bash
# Test DNS fix
cd /home/dimas/eguard-agent
cargo test -p detection --test '*' -- dns_query --nocapture

# Test file fix  
cargo test -p agent-core --test '*' -- file_open --nocapture

# Full suite
cargo test --all
```

---

## Files to Modify (Summary)

| # | File | Function/Line | Change | Risk |
|---|------|---------------|--------|------|
| 1 | `zig/ebpf/dns_query.c:25` | `eguard_udp_sendmsg()` | Delete bpf_get_current_comm() | **NONE** |
| 2 | `crates/agent-core/src/lifecycle/detection_event.rs:49-62` | `to_detection_event()` | Add .or_else() + helper | **VERY LOW** |
| 3 | `crates/platform-linux/src/lib.rs:394-396` | `enrich_event_with_cache()` | (Optional) Add fallback | **LOW** |

---

## Expected Outcomes

### Before
```json
{
  "event": {
    "event_class": "dns_query",
    "dst_domain": "sudo"  // WRONG: Process name
  },
  "event_txn": {
    "subject": "sudo"
  }
}
```

### After (DNS Fix)
```json
{
  "event": {
    "event_class": "dns_query",
    "dst_domain": null  // Correct: No misleading process name
  },
  "event_txn": {
    "subject": null
  }
}
// Agent detects UDP port 53 + PID correlation instead
```

### Before
```json
{
  "event": {
    "event_class": "file_open",
    "file_path": null  // WRONG: Should have path
  },
  "event_txn": {
    "subject": "/etc/shadow",
    "key": "...|...|/etc/shadow|..."
  }
}
```

### After (File Path Fix)
```json
{
  "event": {
    "event_class": "file_open",
    "file_path": "/etc/shadow"  // Correct: Populated from fallback
  },
  "event_txn": {
    "subject": "/etc/shadow",
    "key": "...|...|/etc/shadow|..."
  }
}
```

---

## Related Documentation

See `EBPF_EVENT_ANALYSIS.md` for:
- Full root cause analysis
- Pipeline flow diagrams
- Testing strategy
- Edge case analysis
