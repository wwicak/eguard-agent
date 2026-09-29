# RawEvent payload consumer inventory (F4b)

F4b migrates Linux enrichment and agent-core decision consumers to typed
`RawEventFields`. Each present field, including empty strings and zero, wins
without decoding or consulting its shadow payload key. Missing fields retain
legacy parsing for Windows/macOS producers, partial records and old replay.
Legacy payload serialization is unchanged (F4a golden remains the byte oracle).

## platform-linux/src/lib.rs — migrated
- `EnrichmentCache::prime_process_metadata` and `enrich_event_with_cache` use
  `raw_event_metadata`: typed paths, command/parent hints, PPID, destination,
  domain, size and independent flags/mode, with a lazily cached legacy fallback.
  ProcessExit `comm` remains identity-only, not a command-line hint: naked exits
  preserve legacy unknown process/absent command line when /proc is unavailable.
  An unmodified replay-to-detection regression covers this mapping (the F4a
  envelope golden intentionally replaces host-dependent process metadata).
- `parse_payload_metadata`, KV/endpoints/percent decoding and unstructured
  parsers are **fallback-only**. No producer or legacy rendering changes.

## agent-core/src/lifecycle/telemetry_pipeline.rs — migrated
- `should_drop_low_value_linux_raw_event`: typed path, comm, parent_comm, cmdline.
- Suppression/tracking: typed PPID is authoritative, including zero. JSON
  ancestry rejection applies only when PPID must come from payload. Duplicate
  PPID/parent_pid and cgroup keys validate only missing typed security fields;
  raw PID/UID are structured. All-None events retain the original duplicate-key
  validation, JSON rejection and parent PID aliases exactly.
- `raw_event_ingest_secondary_key`, `raw_event_priority`, and
  `is_high_value_linux_file_open_event`: typed path.
- `raw_file_open_access_intent`: independently typed flags and mode.
- Payload field/integer/parent PID parsers: **fallback-only** for decisions.
- `debug_trace_matching_raw_event`: **diagnostic-only legacy parsing retained**;
  this describes the legacy payload, not an input to suppression or filtering.

## agent-core/src/lifecycle/event_txn.rs — migrated
- `EventTxn::from_raw`: typed rename paths, destination IP/port, domain,
  process path, module name and file path; legacy aliases and unstructured
  decoding remain fallback-only. Partial typed endpoints fill only missing
  components from legacy dst/endpoint or dst_ip/ip plus dst_port/port.
- `coalesce_file_event_key`: uses the shared typed-first file-open access helper.
- Rename/field/percent/endpoint parsers: **fallback-only**.

## agent-core/src/lifecycle/detection_event.rs — migrated
- Module fallback: typed module/path before legacy unstructured decoding.
- `fallback_file_path_from_payload`: typed path before legacy path/file/src.
- Field/percent/quote helpers: **fallback-only**.

## Deferred platform-native consumers (F4c)
These are intentionally **legacy/fallback-only**, not migrated in F4b. Their
producers currently emit all-None fields; core consumers above accept that.
- Windows `EnrichmentCache::prime_process_metadata`,
  `enrich_event_with_cache` (including module fallback), KV/JSON parsers.
- macOS `enrich_event_with_cache`, module fallback, KV/unstructured parsers.
- macOS `esf/mod.rs` ES noise payload/path checks.

`telemetry.rs` serialization and `ebpf_smoke` printing are legacy passthroughs,
not decision parsers. Command/control-plane JSON is outside this inventory.

## Semantic boundaries
- Linux/replay typed values are binary-decoded, never percent escaped.
- `None` is distinct from `Some("")`; short numeric layouts remain absent.
- Typed fields do not authenticate user-controlled parent_comm or environment
  markers. Suppression still requires trusted PID ancestry/live identity.
- Enrichment retains existing live-process/cache precedence over event hints.
- Typed storage still duplicates legacy text; no memory reduction is claimed.
