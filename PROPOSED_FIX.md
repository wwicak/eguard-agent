# Proposed Fix: Bounded Record Sink

## Change Summary
Cap the userspace record sink at 8,192 entries to prevent unbounded memory growth during eBPF event floods.

---

## Implementation

### Option 1: Simple Vec-based (Low Risk)

**File**: `crates/platform-linux/src/ebpf/libbpf_backend.rs`

**Step 1**: Add constant after imports (~line 20)
```rust
/// Maximum pending eBPF event records in the sink before dropping oldest.
/// At ~10 KB average per record, caps at ~80-100 MB during sustained floods.
/// This matches kernel ring buffer overflow behavior.
const MAX_PENDING_RECORDS: usize = 8_192;
```

**Step 2**: Modify `push_raw_record()` function (~line 506-514)

**BEFORE**:
```rust
fn push_raw_record(raw: &[u8], records_sink: &RecordSink, pool_sink: &RecordPool) {
    let mut record = if let Ok(mut pool) = pool_sink.lock() {
        pool.pop().unwrap_or_default()
    } else {
        Vec::new()
    };
    record.clear();
    record.extend_from_slice(raw);

    if let Ok(mut guard) = records_sink.lock() {
        guard.push(record);
    }
}
```

**AFTER**:
```rust
fn push_raw_record(raw: &[u8], records_sink: &RecordSink, pool_sink: &RecordPool) {
    let mut record = if let Ok(mut pool) = pool_sink.lock() {
        pool.pop().unwrap_or_default()
    } else {
        Vec::new()
    };
    record.clear();
    record.extend_from_slice(raw);

    if let Ok(mut guard) = records_sink.lock() {
        if guard.len() >= MAX_PENDING_RECORDS {
            // Overflow: drop oldest record (ring buffer behavior)
            let _ = guard.remove(0);
        }
        guard.push(record);
    }
}
```

**Lines changed**: 3 (1 addition, 2 new)

---

### Option 2: VecDeque-based (Better Performance)

For O(1) removal from front instead of O(n), use `VecDeque`:

**Step 1**: Change type definition (~line 45)

**BEFORE**:
```rust
type RecordSink = Arc<Mutex<Vec<Vec<u8>>>>;
```

**AFTER**:
```rust
type RecordSink = Arc<Mutex<VecDeque<Vec<u8>>>>;
```

**Step 2**: Update initialization in `build_ring_buffer()` (~line 407)

**BEFORE**:
```rust
let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
```

**AFTER**:
```rust
let records = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
```

**Step 3**: Update initialization in `build_perf_buffers()` (~line 450)

**BEFORE**:
```rust
let records = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
```

**AFTER**:
```rust
let records = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
```

**Step 4**: Add constant (~line 20)
```rust
const MAX_PENDING_RECORDS: usize = 8_192;
```

**Step 5**: Modify `push_raw_record()` (~line 506)

```rust
fn push_raw_record(raw: &[u8], records_sink: &RecordSink, pool_sink: &RecordPool) {
    let mut record = if let Ok(mut pool) = pool_sink.lock() {
        pool.pop().unwrap_or_default()
    } else {
        Vec::new()
    };
    record.clear();
    record.extend_from_slice(raw);

    if let Ok(mut guard) = records_sink.lock() {
        if guard.len() >= MAX_PENDING_RECORDS {
            // Overflow: drop oldest record (ring buffer behavior)
            let _ = guard.pop_front();  // O(1) instead of O(n)
        }
        guard.push_back(record);
    }
}
```

**Step 6**: Update `drain_record_sink()` (~line 583)

**BEFORE**:
```rust
fn drain_record_sink(records: &RecordSink) -> Result<Vec<Vec<u8>>> {
    let mut guard = records
        .lock()
        .map_err(|_| EbpfError::Backend("failed to collect eBPF event records".to_string()))?;
    Ok(std::mem::take(&mut *guard))
}
```

**AFTER**:
```rust
fn drain_record_sink(records: &RecordSink) -> Result<Vec<Vec<u8>>> {
    let mut guard = records
        .lock()
        .map_err(|_| EbpfError::Backend("failed to collect eBPF event records".to_string()))?;
    Ok(guard.drain(..).collect())
}
```

**Lines changed**: ~15 (1 type change, 2 initializations, 1 const, 1 push_raw_record, 1 drain function)

---

## Recommendation

**Use Option 2 (VecDeque)** for production:
- O(1) pop_front vs O(n) remove(0)
- Cleaner semantics (FIFO ring buffer)
- Minimal additional complexity
- Better performance under sustained load

**Use Option 1 (Vec)** for quick mitigation:
- Zero additional dependencies
- Simpler to review
- O(n) removal is acceptable (only when overflow, rare)

---

## Testing

### Unit Test Addition

Add to `crates/platform-linux/src/ebpf/tests.rs`:

```rust
#[test]
fn test_record_sink_bounded() {
    use std::sync::{Arc, Mutex};
    use std::collections::VecDeque;
    
    const MAX_RECORDS: usize = 100;  // Use small size for test
    
    let records_sink: Arc<Mutex<VecDeque<Vec<u8>>>> = 
        Arc::new(Mutex::new(VecDeque::new()));
    
    // Fill sink to capacity
    for i in 0..MAX_RECORDS {
        let data = format!("event_{}", i).into_bytes();
        let mut guard = records_sink.lock().unwrap();
        
        if guard.len() >= MAX_RECORDS {
            let _ = guard.pop_front();
        }
        guard.push_back(data);
    }
    
    // Verify size didn't exceed max
    let guard = records_sink.lock().unwrap();
    assert_eq!(guard.len(), MAX_RECORDS);
    
    // Add one more and verify oldest was dropped
    drop(guard);
    let data = b"event_overflow".to_vec();
    let mut guard = records_sink.lock().unwrap();
    if guard.len() >= MAX_RECORDS {
        let dropped = guard.pop_front();
        assert!(dropped.is_some());
        assert!(dropped.unwrap().starts_with(b"event_0"));
    }
    guard.push_back(data);
    
    assert_eq!(guard.len(), MAX_RECORDS);
}
```

### Integration Test
```bash
# Flood test: sustained 10K events/sec
# Before: memory grows to GBs, CPU spikes
# After: memory caps at ~100 MB, CPU remains normal

# In tests/acceptance or performance test:
# 1. Generate 100K events in rapid succession
# 2. Measure heap size → should not exceed 200 MB
# 3. Verify no false negatives in detection
# 4. Confirm all drops were at ring buffer level (not userspace)
```

---

## Rollout Plan

### Phase 1: Code Review
- Review the 15 lines of changes
- Verify no lock contention issues
- Check for edge cases in drain_record_sink

### Phase 2: Testing
- Run existing eBPF unit tests
- Run acceptance tests
- Performance test with flood scenario

### Phase 3: Deployment
- Merge to main
- Include in next release notes: "Fixed memory exhaustion during high-rate event floods"
- Monitor production metrics for `pending_records_dropped` counter

---

## Metrics to Monitor

After deployment, add to observability:

```rust
pub struct EbpfStats {
    // Existing fields...
    
    /// Count of records dropped due to sink overflow (new)
    pub pending_records_dropped: u64,
}
```

Update telemetry to expose:
```rust
/// Track overflow drops
if guard.len() >= MAX_PENDING_RECORDS {
    let _ = guard.pop_front();
    stats.pending_records_dropped += 1;  // Expose this metric
}
```

**Dashboard Alert**: If `pending_records_dropped > 0` for sustained period, indicates system is overwhelmed and should trigger:
1. Increase sampling stride
2. Enable strict budget mode
3. Alert operator

---

## Impact Summary

| Aspect | Before | After |
|--------|--------|-------|
| Memory cap | Unbounded (GBs) | 80-100 MB |
| Drop location | Kernel only | Userspace + kernel |
| Code complexity | Simpler | +15 lines |
| Performance | Thrashing under load | Graceful degradation |
| Risk | High (OOM) | Low (drop older events) |

---

## References

- Investigation: `/home/dimas/eguard-agent/INVESTIGATION_FEDORA_FLOOD.md`
- Affected file: `crates/platform-linux/src/ebpf/libbpf_backend.rs`
- Related: Kernel ring buffer overflow counters (already tracked in `EbpfStats.events_dropped`)
