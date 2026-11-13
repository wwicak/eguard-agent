# Adapter filter: NAC (Go) + EDR (Rust)

## Scope / acceptance

Only the contents of existing adapter fields change. No server policy/evaluation,
wire schema, agent_id, or persisted identity migration changes. No push and no
real-device validation performed. Rust tooling was installed under ~/.cargo and
~/.rustup only; no system packages installed.

## Rules implemented

- Parse six-octet MACs; reject zero and multicast (including broadcast). Locally
  administered **unicast** MACs remain legal, rather than rejecting legitimate
  randomized Wi-Fi MACs. Reject Apple iBridge `ac:de:48:00:11:22` and iBridge names.
- Case-insensitive OS-specific prefix lists: macOS lo/awdl/llw/utun/bridge/p2p/
  anpi/ap/stf/gif/vmenet/feth/ipsec/ppp; Linux lo/veth/docker/br-/virbr/vnet/tun/
  tap/tailscale/wg/zt/flannel/cni/cali/kube/vxlan/genev/dummy/ifb/sit/ip6tnl/gre.
- Windows description **and** friendly name checked against Hyper-V/vEthernet,
  VMware/VirtualBox/WSL, Tailscale/WireGuard/TAP/Wintun/OpenVPN, Npcap loopback,
  Bluetooth PAN/personal area network, Microsoft Wi-Fi Direct Virtual, Kernel
  Debug, WAN Miniport, Teredo, ISATAP, Loopback. Existing vbox/tunnel exclusion
  retained. Prefix lists are OS-specific: Apple USB Ethernet on Windows must not
  be mistaken for macOS ap*.
- Linux requires sysfs device evidence, or bond/team/VLAN with recursively
  verified physical lower interface (bounded recursion). Bond slaves allowed.
  Unknown stacked devices without supported logical type are rejected.
- Require non-loopback/non-unspecified/non-multicast/non-link-local IPv4/IPv6,
  except default-route adapters. A virtual adapter never gets a route exception.
- Deduplicate normalized MACs, preferring the default-route record. NAC keeps
  existing address-cleaning behavior and marks only one retained route primary.
- EDR Linux inventory and enrollment use the same snapshot/filter. Default
  routes from IPv4/IPv6 proc tables sort first; remaining interfaces deterministic.
  Windows enrollment reuses filtered inventory with default gateways sorted first.
  macOS inventory does not emit network adapter lists; enrollment now shares
  name/MAC exclusions, rejects P2P flags, prefers default route then en0 scoring.

## Wiring

- NAC `Collect`: raw enumeration -> physical/flag evidence -> default route ->
  `RelevantAdapters`. Unix providers retain raw snapshot until route enrichment
  and filter before returning. Native Windows preserves description-based virtual
  classification even if later PnP evidence would override it.
- EDR new dependency-light `adapter-filter` crate (no circular dependencies).
  Linux inventory, Windows network parser and hardware-detail `hw.net.adapters`,
  and agent-core enrollment consume it. Windows hardware keeps Name/LinkSpeed
  wire fields, acquires description/IP/default-gateway evidence internally.

## TDD RED -> GREEN

1. Added Go real BSSB fixture (nine MACs/interfaces), invalid MAC/address cases,
   default-route duplicate preference, virtual-name tests **before** Go changes.
   `go test ./collector -run 'TestBSSBAdapters|TestAdapterValidationAndRouteDedup|TestVirtualAdapterNames'`
   failed with old implementation (iBridge/AP/feth/Windows virtual names accepted,
   route exception/dedup missing). After implementation these pass.
2. Added Rust `inventory::network::tests::rejects_virtual_inventory` before parser
   implementation. Test failed: two records returned instead of one (Intel + WSL).
   After shared filtering it passes.
3. Additional GREEN regression fixtures cover shared Rust nine-interface BSSB,
   Linux/Windows names, multicast/zero/random-unicast MACs, IP rejection,
   default-route dedup, Windows hardware-description filtering and duplicate
   gateway preference, OS-specific Apple name, and real temporary sysfs topology
   (physical/bond/VLAN versus docker/veth/unknown) in Go and Rust.

## Actual verification

Commands below run from repository root unless Go (nac-agent). Rust builds use
`nice -n 10`, `-j 4`, and `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc`:
repo default Zig linker was unavailable. Rust crypto acceleration warned that
Zig was missing and used its existing fallback.

- PASS: `go test -race -count=1 -p 1 ./...` (final uncached run, all packages).
  One repeat exceeded 120s harness timeout; rerun with 240s completed exit 0.
- PASS: `gofmt -l .` empty; `GOOS=windows go vet ./...` and
  `GOOS=darwin go vet ./...`, both exit 0 with no diagnostics.
- PASS: `cargo test -p adapter-filter -p platform-windows --lib`: 4 + 134 tests.
- PASS: `cargo test -p platform-linux --lib inventory`: 7 tests.
- Full `cargo test -p platform-linux --lib`: 103 passed, 1 failed:
  `strict_budget_mode_keeps_hash_for_high_value_tmp_file_open` (None vs hash).
  Reproduced the same failure after temporarily restoring inventory.rs from HEAD;
  restored modified file immediately afterwards. Hashing test/code not changed.
- PASS: `cargo check -p adapter-filter -p platform-linux -p platform-windows`.
- PASS: `cargo check -p platform-windows --target x86_64-pc-windows-gnu`;
  target installed in user rustup. This is compilation only, not Windows execution.
- `cargo test -p agent-core --lib`: unavailable (binary-only crate).
  `cargo check -p agent-core` and corrected binary test command
  `cargo test -p agent-core --bin agent-core config::defaults` blocked by
  libbpf-sys missing system libelf.h/gelf.h. No system software installed.
- PASS: `rustfmt --edition 2021 --check` on all six changed/new Rust source files
  (including both new crate source files), and `git diff --check`.

## Remaining verification

Agent-core full compile/tests require existing libelf development headers/build
infrastructure. Existing Linux hashing failure needs a separate investigation.
Native macOS/Windows execution and BSSB device/server observations are still
needed; no claim of testing on those devices or changing existing server assets.
