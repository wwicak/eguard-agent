# Bug Report: v15.0.3 macOS Agent — Heartbeat Never Starts After Enrollment

## Summary
macOS agent v15.0.3 enrolls successfully but the gRPC heartbeat/telemetry loop never starts, leaving the agent unable to send events to the server.

## Affected Version
- v15.0.3 (tag `v15.0.3`, GH Actions run `25446842919`, May 6 2026)

## Fixed In
- v15.0.4 (tag `v15.0.4`, GH Actions run `25653728109`, May 11 2026)

## Root Cause
v15.0.3 was released from commit `8c7ac5b` which does NOT contain:
- `747f72e fix(macos): bound agent scan and inventory stalls`

Without this fix, macOS `system_profiler`, `softwareupdate`, and `profiles` CLI calls
during inventory collection block indefinitely (especially in KVM VMs). Since these
collectors run synchronously on the agent's tick path, the entire runtime loop stalls,
preventing gRPC heartbeat from ever firing.

## Symptoms
1. Agent starts normally, logs show `core started` with correct `server=192.168.122.25:50053`
2. Enrollment succeeds (bootstrap.conf consumed, agent.conf created)
3. After enrollment, no further log output (stdout fully buffered)
4. Zero network connections to server (`lsof -i` / `netstat` show nothing on port 50053)
5. Server DB: `lifecycle_state=active` (set during enrollment) but no new `endpoint_event` rows
6. Process runs at 5-8% CPU indefinitely (stuck in subprocess wait)

## Reproduction
1. Install `eguard-agent-15.0.3.pkg` on macOS Ventura (13.x) KVM VM
2. Write correct `[server]` INI bootstrap config at `/Library/Application Support/eGuard/bootstrap.conf`
3. Start via `launchctl bootstrap system /Library/LaunchDaemons/com.eguard.agent.plist`
4. Observe: enrollment succeeds, then no heartbeat/telemetry for 15+ minutes
5. Upgrade to v15.0.4 → immediately works (346 events within 45s)

## Fix Details (commit `747f72e`)
- Added `output_with_timeout()` helper for all macOS subprocess calls
- Applied wall-clock timeouts to `system_profiler`, `softwareupdate`, `profiles`, and `mdmclient`
- Deferred bundle bootstrap on macOS until after first successful heartbeat
- Moved inventory collectors to bounded async workers

## Affected Platforms
- **macOS only** (system_profiler/softwareupdate are macOS-specific)
- Especially impacts KVM/QEMU VMs where Apple CLIs hang longer
- Windows and Linux agents from v15.0.3 are unaffected

## Note
Despite zero source code diff between v15.0.1 and v15.0.3 tags (only CI YAML changes),
the v15.0.3 PKG binary is different (9,801,827 bytes vs 9,813,188 bytes for the working
build). The v15.0.4 tag includes the actual code fix from `release/v15.0.0-clean` branch.
