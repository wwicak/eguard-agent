# F13/F14 review and validation

## Design and scope decisions

Linux/Windows sensor strings are percent-escaped before entering the internal `k=v;k=v` transport. A dependency-free source module, `crates/payload_codec.rs`, shared by both platform crates, escapes `%`, `;`, `,`, `=`, and control characters. Existing field parsers already percent-decode after splitting; they are retained. Escaping `%` intentionally fixes pre-existing corruption of literal `%3B` and similar OS strings. No server/Go change is required.

Raw-string consumers now decode before forwarding/matching. In particular, the ModuleLoad raw fallback retains its `module=` prefix: `module=evil%3Bppid%3D1` becomes `module=evil;ppid=1`. Normal enriched module paths remain parsed values as before. `telemetry.rs` sends typed detection/event-transaction fields, not `RawEvent.payload`; the detection crate has no RawEvent payload consumers. Enrichment fallback paths decode without reparsing as k=v.

Suppression rejects duplicate security fields (`ppid`/`parent_pid`, `pid`, `uid`, `cgroup_id`), case-insensitively, including events whose PID was already tracked. JSON-object/array fallbacks cannot establish suppression ancestry; independently validated cached PID identity still applies. This closes the macOS JSON fallback's possibility of semicolons inside string values being interpreted as ancestry.

The Linux positive cache stores `(expiry_ns, starttime_ticks)` per PID. Tracking reads `/proc/PID/stat` field 22; parsing uses the last `)` so unusual comm strings cannot shift fields. Lookup reads proc only for present entries and requires equal generation; mismatches and unreadable proc remove the entry. Both event-PID and parent-PID lookups use this path, including ProcessExit cleanup. TTL, pruning and size bounds remain. Non-Linux retains PID/TTL identity (generation zero), explicitly documented. The test-only reader is per runtime, not global.

Supervisor decisions: continue after discovering raw ModuleLoad telemetry forwarding, with compatibility decoding; leave macOS producers/sanitation unchanged; later add a narrow JSON ancestry guard without changing macOS telemetry. No macOS decoder semantics were changed: the new raw-consumer helper is identity on macOS.

## Every production payload producer audited

| Producer | Fields / handling |
|---|---|
| Linux `ebpf/codec.rs::parse_process_exec_payload` | comm, parent_comm, path, cmdline escaped (existing partial escaper replaced); ppid/cgroup numeric |
| Linux `parse_file_open_payload`, both layouts | path escaped; new-layout comm/parent_comm escaped; flags/mode/ppid/cgroup numeric |
| Linux `parse_file_write_payload` | path escaped; fd/size numeric |
| Linux `parse_file_rename_payload` | src and dst escaped |
| Linux `parse_file_unlink_payload` | path escaped |
| Linux `parse_dns_query_payload` | qname escaped; qtype/qclass numeric |
| Linux `parse_module_load_payload` | module escaped |
| Linux `parse_lsm_block_payload` | subject escaped; reason numeric |
| Linux `parse_tcp_connect_payload` | numeric protocol/family/ports; IP strings rendered from binary address octets, cannot contain delimiters |
| Linux ProcessExit / every short/empty binary fallback | complete naked text escaped; decoded only at raw-text consumers, never reparsed for ancestry |
| Linux `ebpf/replay_codec.rs` | writes binary records, not k=v text; real codec above escapes. File-open replay now carries ppid/cgroup/comm/parent_comm in the production layout |
| Windows `etw/codec.rs::decode_kernel_process` | start/stop path escaped by UTF-16 transport reader; PID/session/exit fields numeric |
| Windows `decode_kernel_file` | every name/create/legacy create/rename/unlink path escaped by same reader (opcodes 0/32/35/36/64/12/14/26); other fields numeric |
| Windows `decode_dns_client`, `decode_image_load` | qname/module escaped by same reader |
| Windows `decode_kernel_network` | numeric ports and IP addresses rendered from bytes; no arbitrary strings |
| Windows `fallback_event` | naked text escaped |
| Windows `etw/security_auditing.rs::build_process_create_event` | path, parent_process, cmdline escaped; PID/audit ID numeric |
| Windows `decode_etw_event` text replay and consumer NDJSON replay | preformatted serialized RawEvent payload, deliberately pass-through, not a userspace-field interpolator; fixtures must supply transport-escaped fields |
| macOS `esf/mod.rs::process_exec_payload`, snapshot ProcessExit | unchanged sanitation for path/cmdline |
| macOS `decode_payload` / `push_payload_kv` | unchanged sanitation for path/cmdline/src/dst/dst_ip/domain/subject and numeric fields; delimiters/CR/LF replaced with spaces |
| macOS empty-parts JSON fallback and serialized replay | unchanged raw JSON/RawEvent; new suppression guard rejects JSON ancestry |
| agent-core `platform.rs` engine adapters/fallbacks | no new payload-string interpolation; adapters forward platform RawEvent or return no events |
| agent-core throughput benchmark and test fixtures | synthetic/static payload strings, not production OS-string producers; unchanged |

## Agent-core / detection payload consumer inventory

Audit command: `rg -n '\.payload' crates/agent-core/src crates/detection/src` plus searches for payload splitting/formatting and platform enrichment consumers.

- `event_txn.rs`: rename paths, endpoint/IP/port/domain/process/module/path/access-intent fields — **parsed-only**, existing percent decoders. ProcessExec/ModuleLoad/default naked-text fallbacks — **decoded** (macOS identity).
- `detection_event.rs`: path/file/src fallbacks — **parsed-only**. Raw ModuleLoad text fallback — **decoded** (macOS identity, preserves prefix).
- `telemetry_pipeline.rs`: coalescing path/comm/parent_comm/cmdline, hash-related path lookups, file access intent, priority, parent PID — **parsed-only**. Duplicate-key and JSON guards inspect only transport structure — **internal-only**. Debug trace payload substring matching and payload log field — **decoded** (macOS identity).
- `command_pipeline.rs`: `.payload_json` command dispatch, command logging, rule-push JSON parsing — **internal-only / separate server-command JSON**, not RawEvent transport; unchanged.
- tests (`tests_ebpf_policy.rs`, observability and command tests), test payload assignments and benchmark strings — **internal-only**, assertions/fixtures, not production forwarding.
- `telemetry.rs::telemetry_payload_json`: **parsed-only**, sends typed `TelemetryEvent` and `EventTxn` fields; does not include the raw transport.
- detection crate: no `.payload` access to this transport; typed `TelemetryEvent` fields feed detection engines.
- Platform Linux/Windows enrichment `parse_kv_fields`: **parsed-only**, existing percent decoding; naked fallback and Windows raw path normalization now **decoded**. macOS enrichment unchanged.

## Tests and results

All cargo invocations used `CARGO_TARGET_DIR=/home/dimas/eguard-agent-wt-f13/target` and `timeout 1500`; each shell invocation stayed below 20 minutes.

- New agent regression suite: **6 passed** — real Linux binary codec via replay and real ingest/suppression with `/tmp/x;ppid=<agent>`; exact decoded filename and unrelated PPID; ordinary live direct child remains suppressed; duplicate security fields; injectable same/mismatched generation and reused parent; last-parenthesis stat parser; ModuleLoad raw fallback compatibility; JSON ancestry injection. The direct-child assertion is part of the injection regression, not a standalone claim of a new failure on baseline.
- Linux per-field round trips: every escaped structured string field with `; , = %`, embedded newline, and literal `%3B`; naked fallback injection test.
- Windows codec per-field round trips: process start/stop paths, each file payload family, qname/module; audit path/parent_process/cmdline.
- `cargo test --offline -p platform-linux`: **96 passed**, doc/integration targets pass.
- Additional `cargo test --offline -p platform-windows` on Linux host: **116 passed** (includes binary-codec tests; not live ETW).
- `cargo test --offline -p agent-core tests_ebpf_policy -- --test-threads=4`: **111 passed**.
- Agent filters, each with `--test-threads=4`: `internal_process` **7**, `suppress` **10**, `negative` **2**, `priority` **9**, `codec` **1**, `payload` **33**, `tests_reviewfix` **13**, all passed. These runs precede the final JSON guard; the final 6-test new suite includes and validates that guard.
- `cargo check -p platform-windows --target x86_64-pc-windows-gnu`: **passed**, installed target.
- `cargo fmt --check -p agent-core -p platform-linux`: **passed**. Combined check including platform-windows reports only **pre-existing `platform-windows/src/compliance/screen_lock.rs:34`**; verified against `git show 8a5751b:...`. All touched Windows files and shared module pass direct `rustfmt --check --config skip_children=true`.
- `git diff --check`: **passed**.
- Initial failures resolved: old codec assertion expected literal `=`; three old synthetic-PID tests needed an explicit stable starttime reader rather than nonexistent host `/proc` entries; new Windows legacy rename/unlink fixtures initially used wrong binary offsets. Full corresponding suites were rerun successfully.
- Baseline-failure assessment by source inspection, not a second checkout/build: old Linux/Windows unescaped codecs fail round trips and allow the file-open injection; old first-match ancestry accepts duplicate/JSON PPID; old positive cache ignores generation and keeps reused entries; old raw ModuleLoad fallback forwards encoded text. The stat-parser and real-direct-child checks are positive coverage within the new security suite.

## Residual risks / unverified behavior

- No live privileged eBPF load or real Windows ETW/macOS sensor test. Linux tests log expected libbpf EPERM and use real userspace codecs/replay ingestion. Windows cross-compiles and its platform-independent unit tests pass; native Windows runtime remains unverified. macOS is unchanged and not built/tested here.
- macOS extracted values remain lossy; pre-existing percent-sequence interpretation in agent field parsers remains. JSON fallback is now barred from ancestry trust without changing its telemetry.
- Linux identity observation is not atomic with the kernel event: delayed events spanning exit/reuse, proc races, and coarse starttime tick collisions remain limitations of the requested proc-based approach. Failed reads fail toward visibility; an already-exited legitimate child may produce self-noise. Non-Linux PID reuse protection remains unchanged by contract.
- Existing producer truncation/NUL handling/cmdline trimming and parser quote/whitespace normalization are not redesigned. Local serialized replay is a trusted input, not a format from which true field boundaries can be reconstructed after historical corruption.
- Existing selected-event comm-based noise filters and agent host PID/proc namespace assumptions remain outside this change.
