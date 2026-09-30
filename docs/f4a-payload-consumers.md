# RawEvent payload consumer inventory (F4c)

F4b migrates Linux enrichment and agent-core decision consumers to typed
`RawEventFields`. Each present field, including empty strings and zero, wins
without decoding or consulting its shadow payload key. Missing fields retain
legacy parsing for partial records, decoder fallbacks and old replay.
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
  decoding remain fallback-only outside macOS. Partial typed endpoints or rename
  pairs use the payload for the entire composite key. macOS transactions always
  use the base payload parsers (typed enrichment hints have different
  percent/quote semantics).
- `coalesce_file_event_key`: uses the shared typed-first file-open access helper.
- Rename/field/percent/endpoint parsers: **fallback-only outside macOS**.

## agent-core/src/lifecycle/detection_event.rs — migrated
- Module fallback: typed module/path before legacy unstructured decoding.
- `fallback_file_path_from_payload`: typed path before legacy path/file/src.
- Field/percent/quote helpers: **fallback-only**.

## Windows and macOS decoder boundaries (F4c)
- Windows typed-hint promotion has one schema allowlist (`platform-windows/src/lib.rs::decoded_fields`):
  Kernel-Process start versions 0–5, stop versions 0–2, and Security 4688 opcode 0
  versions 0–2. Both Security collectors carry version/opcode to that boundary;
  missing/unknown metadata stays payload-only. All Windows nonprocess events
  (File, Network, DNS, General, Image-Load), at every version and guessed offset,
  keep default fields. Payloads and generation fields are unchanged.
- **Follow-up:** Windows nonprocess events remain payload-only until explicit
  provider/opcode/version schemas and offsets are validated natively. Synthetic
  v0 fixtures are not evidence of native schema support.
- Allowlisted Windows process events and macOS eslogger derive typed hints from
  their generated payload using the platform base parser. This is a boundary
  parse, not direct binary population; direct population is optional future work.
- Empty values retain each base parser's `None` handling. Windows typed paths
  retain the decoded, unnormalized payload spelling for raw coalescing/detection;
  `raw_event_metadata` applies Windows normalization only when enriching. Kernel
  prefixes (`\\??\\`, `\\\\?\\`, device-volume paths) and control characters are covered.
  Binary fallback events, Windows text replay, macOS raw-event JSON replay, and
  macOS JSON fallback payloads keep default fields. Malformed macOS replay records
  carrying `payload` are rejected rather than retried as native eslogger JSON;
  all offline JSON inputs keep default typed fields, irrespective of key spelling
  or nesting. Only the live eslogger stream may derive typed hints.
- Windows `raw_event_metadata`, used by `prime_process_metadata` and enrichment,
  prefers typed path/command/parent/destination/domain/size hints. ETW rename's
  ambiguous `path` is intentionally not promoted to a typed source (legacy raw
  transactions recognize only src/old); rename enrichment keeps its path fallback.
  macOS enrichment
  similarly prefers typed path/rename/command/destination/domain/size hints.
- **Still unconditional**: Windows base metadata parsing supplies file-object
  correlation and write classification; macOS base metadata parsing supplies write
  classification. Therefore their KV parsers are NOT globally fallback-only yet.
  Values already represented by present typed hints no longer decide enrichment.
- macOS module unstructured decoding is fallback-only. Windows image-load
  enrichment still unconditionally decodes the module payload.
- macOS `esf/mod.rs` ES noise payload/path checks remain legacy consumers.
- All agent-core decision call sites listed above remain typed-first/fallback-only
  except macOS raw transactions as described above; diagnostic trace and payload
  serialization remain unchanged.

## F4c regression provenance
`tests/fixtures/f4c-platforms.json` was generated at `i4-start-f4c` (67748db)
with only the test harness/feature exposure transplanted into a detached scratch
worktree under `/home/dimas/eguard-lab-soak/bench/`, removed after verification.
The real decoder → platform enrichment → DetectionEvent → envelope path is used;
no derived detection/envelope fields are masked. Full enriched-event serde round
trips reject extra or missing fields before conversion into the Linux-shaped
agent-core test adapter. Separate differentials clear only raw typed hints and
compare raw EventTxn (including coalescing key), full enrichment and DetectionEvent.
The expanded matrix includes distinct/empty/mixed strings, Windows numeric file
layouts with distinct object/key/size values, SID-dependent process image offsets,
unknown-version legacy and modern layouts (v6/v7/v255), normalization-sensitive
ETW/4688 paths, bracketed/unbracketed IPv6 endpoints, percent literals, quoted and
unquoted rename paths, replay fields/Fields/FIELDS at multiple nesting levels,
and distinct macOS command/target/rename/domain/subject values. Empty Security 4688
image names are explicitly checked as rejected rather than silently omitted.
Separate (non-golden) Windows regressions assert default hints for v0/v255
nonprocess records, all supported File opcodes, guessed File/Image offsets and
quoted buffers; Security 4688 version 255 is checked through both collector
builders. Supported process/4688 versions retain hints. DNS, Image-Load and
General quoted-subject raw transaction keys match the tagged payload-only parser.
The golden corpus remains unchanged at 1,299 records (SHA256
`5c5cb6628635d45c15e90a370e93fb897b3c65ad66264e55d9b2d1c81bf39add`).
These tests validate Windows/macOS codec and enrichment logic compiled on Linux,
not native collection/runtime behavior (covered separately by F20).
Existing workspace platforms are test-only dependencies; the production Linux
`cargo tree -e normal` is byte-identical before and after F4c.

`telemetry.rs` serialization and `ebpf_smoke` printing are legacy passthroughs,
not decision parsers. Command/control-plane JSON is outside this inventory.

## Semantic boundaries
- Linux/replay typed values are binary-decoded, never percent escaped.
- `None` is distinct from `Some("")`; short numeric layouts remain absent.
- Typed fields do not authenticate user-controlled parent_comm or environment
  markers. Suppression still requires trusted PID ancestry/live identity.
- Enrichment retains existing live-process/cache precedence over event hints.
- Typed storage still duplicates legacy text; no memory reduction is claimed.
