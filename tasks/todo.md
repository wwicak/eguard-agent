- [x] Review existing control-plane pipeline responsibilities and boundaries.
- [x] Split control-plane pipeline into focused submodules (scheduler, executor, policy, baseline, IOC/campaign, outbound sends, rollout helpers).
- [x] Keep behavior and public runtime method signatures unchanged while refactoring.
- [x] Run agent-core tests that cover control-plane and related flows.
- [x] Document outcome and verification notes.

## Windows release flake fix + v0.2.11
- [x] Make ETW session startup resilient to Windows `ERROR_ALREADY_EXISTS` races.
- [x] Remove shared session-name collision in ETW engine unit tests.
- [x] Run platform-windows and agent-core test suites locally.
- [ ] Commit fix, tag `v0.2.11`, and push.
- [ ] Trigger/verify release workflow and confirm published release assets.

---

## Live deploy + benchmark re-test (Linux + Windows VMs, 2026-03-02)

### Plan
- [x] Build updated Linux + Windows agent binaries from current source.
- [x] Deploy binaries to Linux and Windows endpoint VMs with service restart.
- [x] Re-run ransomware-churn ON/OFF benchmark on both VMs.
- [x] Summarize results and evaluate provisional gate.

### Review
- Build outputs:
  - `target/release/agent-core`
  - `target/x86_64-pc-windows-gnu/release/agent-core.exe`
- Deployed endpoints:
  - Linux (`agent@103.183.74.3`): `/usr/bin/eguard-agent`
  - Windows (`administrator@103.31.39.30`): `C:\Program Files\eGuard\eguard-agent.exe`
- Hash parity (local == deployed):
  - Linux: `dd1b2cfb1ddb86e11b1aa216365d7f190e25866c7400b5035d531ee3a13e22d7`
  - Windows: `ca110804d433b33698b008f79953da84ee50f184135ed524efd9ab4f51c7489d`
- Benchmark run tag: `retest-20260302T043407Z`
  - `artifacts/perf/retest-20260302T043407Z/linux/ransomware/raw.json`
  - `artifacts/perf/retest-20260302T043407Z/windows/ransomware/raw.json`
  - `artifacts/perf/retest-20260302T043407Z/summary.json`
  - `artifacts/perf/retest-20260302T043407Z/report.md`

### Result summary (ransomware scenario)
- Linux (6 ON + 6 OFF, 1 warmup):
  - median overhead: `-23.70%`
  - p95 overhead: `-51.36%`
  - agent CPU avg: `0.172s`
- Windows (6 ON + 6 OFF, 1 warmup):
  - median overhead: `+32.98%`
  - p95 overhead: `+19.40%`
  - agent CPU avg: `0.318s`
- Provisional gate verdict: **FAIL** (Windows thresholds exceeded).

### Verification
- `cargo build -p agent-core --release --features platform-linux/ebpf-libbpf` ✅
- `cargo build -p agent-core --release --target x86_64-pc-windows-gnu` ✅
- `python3 scripts/perf/summarize.py --input-root artifacts/perf/retest-20260302T043407Z` ✅
- `python3 scripts/perf/gate.py --summary artifacts/perf/retest-20260302T043407Z/summary.json --profile provisional` ❌ (expected fail)
