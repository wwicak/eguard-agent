# F4a baseline provenance

`f4a-legacy.json` was generated at tag `i2-start-f4a-fields`
(commit `0333176`) in a detached worktree under
`/home/dimas/eguard-lab-soak/bench/f4a-baseline`.
The test harness `lifecycle/tests_f4a_golden.rs` was copied into that baseline
and temporarily changed to write `actual` before the comparison. No production
code was changed in the baseline. Command (from scratch worktree):

```
CARGO_TARGET_DIR=$PWD/target timeout 1500 cargo test --offline -p agent-core f4a_legacy_envelope_and_detection_golden -- --test-threads=1
```

Result: 1 passed. The fixture was then copied unchanged into this checkout.
The committed test has no regeneration switch: it only compares exact bytes.

Corpus: all ten Linux event types, each with ordinary text, `; , = %` injection
text, and a string whose UTF-8 sequence is truncated by the real replay encoder
at byte 31 in `comm`. Thus real binary decoding sees invalid UTF-8, not a
pre-decoded replacement character. Replay files have unique temporary names and
are removed after polling. Process metadata is constructed deterministically,
without process/filesystem enrichment. The real `to_detection_event`, EventTxn,
and telemetry envelope serializer are used. `DetectionEvent` in the task maps
to the repository's `detection::TelemetryEvent`.

Regression red proof: the baseline-compatible
`typed_fields_cover_every_replay_event_type` test was copied into the same
baseline and run with `cargo test --offline -p platform-linux
 typed_fields_cover_every_replay_event_type -- --test-threads=1` (same target/
timeout wrapper). It compiled, then failed at runtime: every baseline serialized
RawEvent lacked `fields` (null), versus the ten expected typed field maps.
