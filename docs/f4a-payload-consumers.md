# F4b handoff: remaining RawEvent payload consumers

F4a intentionally migrates **no consumers**. Locations below are production
call sites at the F4a commit (test fixtures and emitters excluded).

## platform-linux/src/lib.rs
- `EnrichmentCache::prime_process_metadata` (235): `parse_payload_metadata`.
- `enrich_event_with_cache` (451): `parse_payload_metadata`.
- Parser implementation (621–794): KV metadata, write flags, endpoints,
  percent decoding and unstructured fallbacks.

## platform-windows/src/lib.rs
- `EnrichmentCache::prime_process_metadata` (227): `parse_payload_metadata`.
- `enrich_event_with_cache` (660): `parse_payload_metadata`.
- Parser implementation (825 onward): KV/JSON metadata and fallback parsing.

## platform-macos/src/lib.rs
- `enrich_event_with_cache` (378): `parse_payload_metadata`.
- Parser implementation (480 onward): KV metadata and fallback parsing.

## agent-core/src/lifecycle/telemetry_pipeline.rs
- `should_drop_low_value_linux_raw_event` (557–565): path, comm,
  parent_comm, cmdline/command_line.
- `should_suppress_internal_process_event` (666): duplicate security keys.
- `should_track_internal_process_event` (687–692): JSON-container rejection,
  duplicate security keys, ppid/parent_pid.
- `raw_event_ingest_secondary_key` (1100): path.
- `raw_event_priority` (1184): path.
- `raw_file_open_access_intent` (1250–1251): flags and mode.
- `is_high_value_linux_file_open_event` (1264): path.
- `debug_trace_matching_raw_event` (1728–1729): path and decoded raw text.
- Shared helpers (1758–1832, 1914–1952): field parsing, integer conversion,
  duplicate-key validation, parent PID and legacy decoding.

## agent-core/src/lifecycle/event_txn.rs
- `EventTxn::from_raw`:
  - 79: rename src/old/old_path and dst/new/new_path.
  - 84–90: TCP dst/endpoint or dst_ip/ip plus dst_port/port.
  - 97–99: DNS dst_domain/qname/domain.
  - 103–108: process path/exe or decoded unstructured fallback.
  - 113–118: module/path or decoded unstructured fallback.
  - 123–126: file path or decoded unstructured fallback.
- `coalesce_file_event_key` (164): FileOpen flags/mode access intent.
- Helpers (241–301): field/percent decoding, rename paths and file-open intent.

## agent-core/src/lifecycle/detection_event.rs
- `to_detection_event` (35–43): ModuleLoad unstructured payload decoding.
- `fallback_file_path_from_payload` (154–156): path/file/src.
- Helpers (162 onward): field parsing, percent decoding, quote trimming.

`telemetry.rs` also serializes legacy payload text; `ebpf_smoke` prints it.
Those are passthroughs, not parsing consumers. Command/control-plane JSON
payloads are unrelated to RawEvent and are outside this inventory.

## Semantics for subsequent migration

- Linux fields come directly from binary values; they are not percent escaped.
- Legacy process-exec has no parent_comm field (`None`), unlike a present empty
  parent_comm (`Some("")`). Too-short numeric layouts leave typed fields absent.
- Replay encodes the existing binary layouts and then uses the same decoder.
- Windows/macOS producers and pre-existing synthetic literals use all-None
  fields. Keep legacy fallback paths when migrating their consumers.
- Strings retain existing lossy UTF-8 and cmdline normalization behavior.
- RawEvent serialization now includes fields; legacy telemetry envelope bytes
  are separately pinned by the baseline fixture.
- Typed strings temporarily duplicate payload information; F4a does not claim
  a memory/throughput improvement.
