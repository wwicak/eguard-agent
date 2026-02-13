# Building the eGuard Agent

This document covers how to build the eGuard endpoint agent from source,
produce distributable packages, and how the automated release pipeline works.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Zig](https://ziglang.org/download/) | 0.14.x | eBPF probes and ASM acceleration libraries |
| [Rust](https://rustup.rs/) | stable (1.82+) | Agent binary (13-crate workspace) |
| [nfpm](https://nfpm.goreleaser.com/) | 2.x | `.deb` and `.rpm` packaging |

Optional: `protoc` (vendored via `protoc-bin-vendored` crate — no system install needed).

## Repository Layout

```
eguard-agent/
├── crates/                   # Rust workspace (13 crates)
│   ├── agent-core/           # Main binary entry point
│   ├── detection/            # Sigma/YARA/IOC detection engine
│   ├── response/             # Kill/quarantine/forensics response
│   ├── compliance/           # Posture assessment
│   ├── baseline/             # Process/network/file baseline
│   ├── grpc-client/          # gRPC transport (tonic)
│   ├── nac/                  # NAC bridge integration
│   ├── platform-linux/       # Linux-specific implementations
│   ├── platform-windows/     # Windows stubs
│   ├── platform-macos/       # macOS stubs
│   ├── crypto-accel/         # Hardware-accelerated crypto (links Zig ASM)
│   ├── self-protect/         # Tamper protection
│   └── acceptance/           # End-to-end acceptance tests
├── zig/                      # Zig source
│   ├── asm/                  # SHA-256 NI, AES-NI, integrity check
│   └── ebpf/                 # eBPF probes (process, file, network, DNS, LSM)
├── build.zig                 # Zig build script
├── Cargo.toml                # Workspace manifest
├── nfpm.yaml                 # Package manifest (deb/rpm)
├── conf/                     # Config files and systemd unit
│   ├── agent.conf.example
│   ├── bootstrap.conf.example
│   └── eguard-agent.service
├── packaging/                # Package scripts
│   ├── debian/control
│   ├── rpm/eguard-agent.spec
│   ├── postinstall.sh
│   └── preremove.sh
├── proto/                    # Protobuf definitions
├── rules/                    # Detection rule sources
├── threat-intel/             # Threat intelligence tooling
└── .github/workflows/        # CI/CD
    ├── release-agent.yml     # Release pipeline (this doc)
    ├── build-bundle.yml      # Daily threat-intel bundle
    └── collect-*.yml         # Rule collectors (sigma, yara, ioc, cve)
```

## Local Development Build

### Step 1: Build Zig Artifacts

The Zig build produces two categories of artifacts:

**eBPF probes** (BPF ELF objects loaded at runtime):
- `process_exec_bpf.o` — process execution monitoring
- `file_open_bpf.o` — file access monitoring
- `tcp_connect_bpf.o` — outbound connection tracking
- `dns_query_bpf.o` — DNS query interception
- `module_load_bpf.o` — kernel module load events
- `lsm_block_bpf.o` — LSM-based blocking hooks

**ASM acceleration libraries** (static `.a` linked into Rust binary):
- `libeguard_sha256_ni.a` — SHA-256 using Intel SHA extensions
- `libeguard_aes_ni.a` — AES using Intel AES-NI
- `libeguard_integrity.a` — binary integrity verification

```bash
# Build all artifacts (eBPF + ASM)
zig build agent-artifacts

# Build only ASM libraries
zig build asm-artifacts

# Build only eBPF probes
zig build ebpf-artifacts
```

Output locations:
- `zig-out/lib/libeguard_*.a`
- `zig-out/ebpf/*_bpf.o`

### Step 2: Build the Rust Binary

```bash
# Debug build (faster compilation, includes debug symbols)
cargo build -p agent-core

# Release build (optimized, stripped)
cargo build --release -p agent-core
```

The binary is at `target/release/agent-core` (renamed to `eguard-agent` for packaging).

### Step 3: Run Tests

```bash
# Unit tests for all crates
cargo test --workspace

# Tests for a specific crate
cargo test -p detection
cargo test -p response

# Acceptance tests (requires running agent + server)
cargo test -p acceptance
```

## Package Build

### Using nfpm (Recommended)

After building the binary, use [nfpm](https://nfpm.goreleaser.com/) to produce
`.deb` and `.rpm` packages from the `nfpm.yaml` manifest.

```bash
# Rename binary to package name
mv target/release/agent-core target/release/eguard-agent

# Build .deb
VERSION=0.1.0 nfpm package --packager deb --target eguard-agent_0.1.0_amd64.deb

# Build .rpm
VERSION=0.1.0 nfpm package --packager rpm --target eguard-agent-0.1.0-1.x86_64.rpm
```

Package contents:

| File | Path |
|------|------|
| Agent binary | `/usr/local/eg/sbin/eguard-agent` |
| Systemd unit | `/lib/systemd/system/eguard-agent.service` |

The postinstall script runs `systemctl daemon-reload && systemctl enable --now eguard-agent`.

### Package Install

```bash
# Debian/Ubuntu
sudo dpkg -i eguard-agent_0.1.0_amd64.deb

# RHEL/Rocky/AlmaLinux
sudo rpm -i eguard-agent-0.1.0-1.x86_64.rpm
```

After installation, configure the agent:
```bash
sudo mkdir -p /etc/eguard-agent
sudo cp /usr/local/eg/share/doc/agent.conf.example /etc/eguard-agent/agent.conf
# Edit agent.conf — set server_addr at minimum
sudo systemctl restart eguard-agent
```

## CI/CD Release Pipeline

### Workflow: `release-agent.yml`

Triggered by pushing a `v*` tag to `main`, or manually via `workflow_dispatch`.

```
v* tag push ──► Checkout
              ├─► Install Zig 0.14.x
              ├─► zig build agent-artifacts
              ├─► Install Rust stable
              ├─► cargo build --release -p agent-core
              ├─► Rename agent-core → eguard-agent
              ├─► Install nfpm
              ├─► nfpm package --packager deb
              ├─► nfpm package --packager rpm
              └─► Create GitHub Release with .deb + .rpm assets
```

### Creating a Release

```bash
# Tag and push
git tag v0.1.0
git push origin v0.1.0
```

Or trigger manually from the Actions tab with a version string.

### Manual Trigger (workflow_dispatch)

```bash
gh workflow run release-agent.yml -f version=v0.1.0
```

## Server-Side Package Sync

The eGuard server automatically fetches agent packages from GitHub releases.

### How It Works

1. **egcron task** `agent_package_sync` runs every hour (configurable)
2. Queries `GET /repos/{repo}/releases?per_page=20`
3. Finds the first release with `.deb`/`.rpm` assets (skips `rules-*` tags)
4. Compares version against `.agent-package-version` marker file
5. Downloads new packages to `/usr/local/eg/var/agent-packages/{deb,rpm}/`
6. Prunes old versions (keeps last 3 by default)
7. The Go agent server (`agent_install.go`) serves packages from this directory

### Server Configuration

In `eg.conf` (`[agent_packages]` section):

| Key | Default | Description |
|-----|---------|-------------|
| `github_repo` | `wwicak/eguard-agent` | GitHub repository |
| `github_token` | (empty) | Token for private repo access |
| `poll_interval` | `3600` | Seconds between polls |
| `package_dir` | `/usr/local/eg/var/agent-packages` | Download directory |
| `max_versions_keep` | `3` | Versions retained per format |

Environment variable overrides: `EG_AGENT_PACKAGE_GITHUB_REPO`,
`EG_AGENT_PACKAGE_GITHUB_TOKEN`, `EG_AGENT_PACKAGE_POLL_INTERVAL`,
`EGUARD_AGENT_PACKAGE_DIR`, `EG_AGENT_PACKAGE_MAX_VERSIONS`.

### Build-Time Fetch

To pre-populate agent packages during eGuard server build:

```bash
# Standalone
./packaging/fetch-agent-packages.sh /usr/local/eg/var/agent-packages

# During build-debs.sh
FETCH_AGENT_PACKAGES=yes ./build-debs.sh
```

## Troubleshooting

### Zig build fails with "error: FileNotFound"

Ensure Zig 0.14.x is installed. Older versions may not support the `createModule` API.

```bash
zig version   # should show 0.14.x
```

### Cargo build fails linking ASM libraries

Run `zig build asm-artifacts` first. The Rust `crypto-accel` crate expects
`zig-out/lib/libeguard_*.a` to exist.

### nfpm "VERSION not set" error

Export the `VERSION` env var before running nfpm:

```bash
export VERSION=0.1.0
nfpm package --packager deb
```

### Agent package not served by eGuard server

Check that packages exist in the expected directory:

```bash
ls -la /usr/local/eg/var/agent-packages/deb/
ls -la /usr/local/eg/var/agent-packages/rpm/
cat /usr/local/eg/var/agent-packages/.agent-package-version
```

Verify the egcron task is running:

```bash
journalctl -u eguard-egcron --grep agent_package_sync
```

### GitHub API rate limiting

For private repos or high-frequency polling, set a GitHub token:

```bash
# In eg.conf [agent_packages] section
github_token=ghp_...

# Or via environment variable
export EG_AGENT_PACKAGE_GITHUB_TOKEN=ghp_...
```
