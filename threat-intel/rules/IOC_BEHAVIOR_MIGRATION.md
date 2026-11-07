# Behavioral IOC tombstone migration

`ioc_behavior_rules.json` deliberately retains the same 32 names and matching
content with `enabled: false`. Do not delete or empty this file: older servers
return early when the file or its rules are absent, leaving existing rows active.

Keep these tombstones for **at least two published bundle cycles with verified
server synchronization**. This change does not publish a bundle or attest any
completed synchronization cycle.

Before the first tombstone bundle is released, the corrected server builtins
(S2) and builtin-wins duplicate guard (S4) must be shipped together or already
present. Otherwise attacks previously caught only by a bundle copy can be missed.
Admin-owned records are intentionally not overwritten by the existing sync.

The reviewed server sync converts the optional enabled pointer directly to the
stored `Enabled` value and upserts bundle-owned matches by name. Its SQL update
explicitly binds `enabled`, including false (0). See
`go/agent/server/threat_intel_bundle_ioc_behavior_sync.go` and
`go/agent/server/persistence_threat_intel_rules.go` in fe_eguard.

Only retire this migration file after all supported servers implement absent-rule
retirement while preserving administrator enable/disable choices, and after the
two verified cycles. Update the collector/build quality-count gates in the same
reviewed removal; disabled tombstones currently count toward those gates.
