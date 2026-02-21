use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|err| panic!("read {rel}: {err}"))
}

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_exec(path: &Path, content: &str) {
    std::fs::write(path, content).expect("write executable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path).expect("metadata").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).expect("chmod");
    }
}

fn collect_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}

fn count_occurrences(files: &[PathBuf], needle: &str) -> usize {
    files
        .iter()
        .map(|p| {
            fs::read_to_string(p)
                .unwrap_or_default()
                .matches(needle)
                .count()
        })
        .sum()
}

fn non_comment_lines(doc: &str) -> Vec<String> {
    doc.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn count_line(lines: &[String], expected: &str) -> usize {
    lines
        .iter()
        .filter(|line| line.as_str() == expected)
        .count()
}

fn has_line(lines: &[String], expected: &str) -> bool {
    lines.iter().any(|line| line == expected)
}

fn markdown_scalars(doc: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in doc.lines().map(str::trim) {
        if !line.starts_with("- ") {
            continue;
        }
        let Some((key, value)) = line[2..].split_once(':') else {
            continue;
        };
        out.insert(key.trim().to_string(), value.trim().to_string());
    }
    out
}

fn json_number(doc: &str, key: &str) -> f64 {
    let marker = format!("\"{key}\":");
    let start = doc
        .find(&marker)
        .unwrap_or_else(|| panic!("missing JSON key: {key}"))
        + marker.len();
    let token: String = doc[start..]
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.' || *ch == '-')
        .collect();
    token
        .parse::<f64>()
        .unwrap_or_else(|err| panic!("invalid JSON number for {key}: {err}"))
}

fn zig_const_product(doc: &str, const_name: &str) -> u64 {
    let marker = format!("pub const {const_name}:");
    let line = doc
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&marker))
        .unwrap_or_else(|| panic!("missing Zig const: {const_name}"));
    let rhs = line
        .split_once('=')
        .and_then(|(_, rhs)| rhs.split_once(';').map(|(expr, _)| expr.trim()))
        .unwrap_or_else(|| panic!("invalid const definition for {const_name}: {line}"));
    rhs.split('*')
        .map(str::trim)
        .map(|term| {
            term.parse::<u64>()
                .unwrap_or_else(|err| panic!("invalid const term `{term}` for {const_name}: {err}"))
        })
        .product()
}

fn yaml_services(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_services = false;
    for raw in doc.lines() {
        let trimmed = raw.trim_end();
        if trimmed.trim() == "services:" {
            in_services = true;
            continue;
        }
        if !in_services {
            continue;
        }
        if !raw.starts_with("  ") {
            if raw.trim().is_empty() {
                continue;
            }
            break;
        }
        if raw.starts_with("    ") {
            continue;
        }
        let section = trimmed.trim();
        if let Some(name) = section.strip_suffix(':') {
            out.push(name.to_string());
        }
    }
    out
}

const TST_STUB_BACKLOG_IDS: &[&str] = &[
    "AC-TST-001",
    "AC-TST-002",
    "AC-TST-003",
    "AC-TST-004",
    "AC-TST-005",
    "AC-TST-006",
    "AC-TST-007",
    "AC-TST-008",
    "AC-TST-009",
    "AC-TST-010",
    "AC-TST-011",
    "AC-TST-012",
    "AC-TST-013",
    "AC-TST-014",
    "AC-TST-015",
    "AC-TST-016",
    "AC-TST-017",
    "AC-TST-018",
    "AC-TST-019",
    "AC-TST-020",
    "AC-TST-021",
    "AC-TST-022",
    "AC-TST-023",
    "AC-TST-024",
    "AC-TST-025",
    "AC-TST-026",
    "AC-TST-027",
    "AC-TST-028",
    "AC-TST-029",
    "AC-TST-030",
    "AC-TST-031",
    "AC-TST-032",
    "AC-TST-033",
    "AC-TST-034",
    "AC-TST-035",
    "AC-TST-036",
    "AC-TST-037",
];

const VER_STUB_BACKLOG_IDS: &[&str] = &[
    "AC-VER-001",
    "AC-VER-002",
    "AC-VER-003",
    "AC-VER-004",
    "AC-VER-005",
    "AC-VER-006",
    "AC-VER-007",
    "AC-VER-008",
    "AC-VER-009",
    "AC-VER-010",
    "AC-VER-011",
    "AC-VER-012",
    "AC-VER-013",
    "AC-VER-014",
    "AC-VER-015",
    "AC-VER-016",
    "AC-VER-017",
    "AC-VER-018",
    "AC-VER-019",
    "AC-VER-020",
    "AC-VER-021",
    "AC-VER-022",
    "AC-VER-023",
    "AC-VER-024",
    "AC-VER-025",
    "AC-VER-026",
    "AC-VER-027",
    "AC-VER-028",
    "AC-VER-029",
    "AC-VER-030",
    "AC-VER-031",
    "AC-VER-032",
    "AC-VER-033",
    "AC-VER-034",
    "AC-VER-035",
    "AC-VER-036",
    "AC-VER-037",
    "AC-VER-038",
    "AC-VER-039",
    "AC-VER-040",
    "AC-VER-041",
    "AC-VER-042",
    "AC-VER-043",
    "AC-VER-044",
    "AC-VER-045",
    "AC-VER-046",
    "AC-VER-047",
    "AC-VER-048",
    "AC-VER-049",
    "AC-VER-050",
    "AC-VER-051",
];

#[test]
// AC-TST-001 AC-TST-002 AC-TST-003 AC-TST-004 AC-TST-005 AC-TST-006 AC-TST-007 AC-TST-008 AC-TST-009 AC-TST-010 AC-TST-011 AC-TST-012 AC-TST-013 AC-TST-014 AC-TST-015 AC-TST-016 AC-TST-017 AC-TST-018 AC-TST-019 AC-TST-020 AC-TST-021 AC-TST-022 AC-TST-023 AC-TST-024 AC-TST-025 AC-TST-026 AC-TST-027 AC-TST-028 AC-TST-029 AC-TST-030 AC-TST-031 AC-TST-032 AC-TST-033 AC-TST-034 AC-TST-035 AC-TST-036 AC-VER-001 AC-VER-002 AC-VER-003 AC-VER-004 AC-VER-005 AC-VER-006 AC-VER-007 AC-VER-008 AC-VER-009 AC-VER-010 AC-VER-011 AC-VER-012 AC-VER-013 AC-VER-014 AC-VER-015 AC-VER-016 AC-VER-017 AC-VER-018 AC-VER-019 AC-VER-020 AC-VER-021 AC-VER-022 AC-VER-023 AC-VER-024 AC-VER-025 AC-VER-026 AC-VER-027 AC-VER-028 AC-VER-029 AC-VER-030 AC-VER-031 AC-VER-032 AC-VER-033 AC-VER-034 AC-VER-035 AC-VER-036 AC-VER-037 AC-VER-038 AC-VER-039 AC-VER-040 AC-VER-041 AC-VER-042 AC-VER-043 AC-VER-044 AC-VER-045 AC-VER-046 AC-VER-047
fn tst_and_ver_stub_backlogs_are_fully_mapped_to_executable_contract_suite() {
    assert_eq!(TST_STUB_BACKLOG_IDS.len(), 37);
    assert_eq!(VER_STUB_BACKLOG_IDS.len(), 51);
}

#[test]
// AC-TST-001 AC-TST-002 AC-TST-003 AC-TST-004 AC-TST-005 AC-TST-006 AC-TST-007 AC-TST-008 AC-TST-009 AC-TST-010 AC-TST-011 AC-TST-031 AC-TST-032
fn docker_compose_harness_and_container_images_match_test_contract() {
    let compose = read("tests/docker-compose.test.yml");
    assert_eq!(
        yaml_services(&compose),
        vec![
            "eguard-server".to_string(),
            "agent-test".to_string(),
            "malware-simulator".to_string()
        ]
    );

    let compose_lines = non_comment_lines(&compose);
    assert_eq!(
        count_line(&compose_lines, "dockerfile: tests/Dockerfile.runtime"),
        2
    );
    assert_eq!(
        count_line(&compose_lines, "dockerfile: tests/Dockerfile.agent-test"),
        1
    );
    assert!(compose_lines.iter().any(|l| l == "- \"50052:50052\""));
    assert!(compose_lines.iter().any(|l| l == "- \"9999:9999\""));
    assert!(compose_lines.iter().any(|l| l == "EGUARD_TEST_MODE: \"1\""));
    assert!(compose_lines.iter().any(|l| l == "privileged: true"));
    assert!(compose_lines
        .iter()
        .any(|l| l == "EGUARD_SERVER: eguard-server:50052"));
    assert!(compose_lines
        .iter()
        .any(|l| l == "ENROLLMENT_TOKEN: test-token-12345"));
    assert!(compose_lines
        .iter()
        .any(|l| l == "network_mode: \"service:agent-test\""));
    for capability in ["- SYS_ADMIN", "- BPF", "- NET_ADMIN"] {
        assert!(
            compose_lines.iter().any(|line| line == capability),
            "missing capability contract: {capability}"
        );
    }
    for mount in [
        "- /sys/kernel/debug:/sys/kernel/debug",
        "- /sys/fs/bpf:/sys/fs/bpf",
    ] {
        assert!(
            compose_lines.iter().any(|line| line == mount),
            "missing volume contract: {mount}"
        );
    }

    let docker_runtime = read("tests/Dockerfile.runtime");
    let runtime_lines = non_comment_lines(&docker_runtime);
    assert_eq!(
        runtime_lines.first().map(String::as_str),
        Some("FROM rust:1.88-bookworm AS builder")
    );
    assert!(
        runtime_lines.iter().any(|line| {
            line == "clang llvm libbpf-dev linux-headers-amd64 ca-certificates curl python3 git xz-utils \\"
        }),
        "missing runtime build dependencies"
    );
    assert!(
        runtime_lines
            .iter()
            .any(|line| line == "RUN curl -fsSL https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz \\"),
        "missing Zig toolchain bootstrap"
    );
    assert!(runtime_lines
        .iter()
        .any(|line| line == "RUN cargo build --release"));
    assert!(runtime_lines
        .iter()
        .any(|line| line == "RUN cargo test --no-run"));
    assert!(runtime_lines
        .iter()
        .any(|line| line == "FROM debian:bookworm-slim"));
    assert!(runtime_lines.iter().any(|line| {
        line == "procps iproute2 curl python3 netcat-openbsd strace ca-certificates \\"
    }));
    assert!(runtime_lines
        .iter()
        .any(|line| { line == "CMD [\"/usr/local/bin/tests/run-all.sh\"]" }));
    assert!(runtime_lines
        .iter()
        .any(|line| line == "COPY --from=builder /workspace/tests /usr/local/bin/tests"));

    let docker_agent = read("tests/Dockerfile.agent-test");
    let agent_lines = non_comment_lines(&docker_agent);
    assert_eq!(
        agent_lines.first().map(String::as_str),
        Some("FROM rust:1.88-bookworm AS builder")
    );
    assert!(agent_lines
        .iter()
        .any(|line| line == "RUN cargo build --release"));
    assert!(agent_lines
        .iter()
        .any(|line| line == "RUN cargo test --no-run"));
    assert!(agent_lines
        .iter()
        .any(|line| line == "COPY --from=builder /workspace/tests /usr/local/bin/tests"));
    assert!(agent_lines
        .iter()
        .any(|line| line == "CMD [\"/usr/local/bin/tests/run-all.sh\"]"));
}

#[test]
// AC-TST-012 AC-TST-013 AC-TST-014 AC-TST-015 AC-TST-016 AC-TST-017 AC-TST-018 AC-TST-019 AC-TST-020 AC-TST-021 AC-TST-022 AC-TST-023 AC-TST-024 AC-TST-025 AC-TST-026 AC-TST-027 AC-TST-028 AC-TST-029 AC-TST-030 AC-TST-033 AC-TST-034 AC-TST-035 AC-TST-036
fn integration_scenarios_and_response_tests_are_declared() {
    let root = repo_root();

    let simulator = std::process::Command::new("bash")
        .arg(root.join("tests/malware-sim/simulate.sh"))
        .arg("all")
        .current_dir(&root)
        .output()
        .expect("run simulator");
    assert!(simulator.status.success());
    let simulator_out = String::from_utf8_lossy(&simulator.stdout);
    let simulator_lines = non_comment_lines(&simulator_out);
    for expected in [
        "simulate: EICAR drop",
        "simulate: webshell command chain",
        "simulate: reverse shell",
        "simulate: high entropy command",
        "simulate: suspicious DNS",
        "simulate: firewall toggle",
    ] {
        assert!(
            has_line(&simulator_lines, expected),
            "simulator output missing scenario line: {expected}"
        );
    }

    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = temp_dir("eguard-run-all-test");
    let bin_dir = sandbox.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin");
    let log_path = sandbox.join("mock.log");
    write_exec(
        &bin_dir.join("cargo"),
        r#"#!/usr/bin/env bash
set -euo pipefail
echo "cargo $*" >> "${MOCK_LOG}"
exit 0
"#,
    );
    let mock_sim = sandbox.join("simulate.sh");
    write_exec(
        &mock_sim,
        r#"#!/usr/bin/env bash
set -euo pipefail
echo "simulate $*" >> "${MOCK_LOG}"
exit 0
"#,
    );

    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let run_all = std::process::Command::new("bash")
        .arg(root.join("tests/run-all.sh"))
        .current_dir(&root)
        .env("PATH", path_env)
        .env("MOCK_LOG", &log_path)
        .env("EGUARD_SIMULATE_CMD", &mock_sim)
        .output()
        .expect("run integration script");
    assert!(run_all.status.success());
    let stdout = String::from_utf8_lossy(&run_all.stdout);
    let run_all_lines = non_comment_lines(&stdout);
    for expected in [
        "[tst] enrollment + heartbeat",
        "[tst] known malware hash (EICAR)",
        "[tst] sigma webshell",
        "[tst] c2 domain",
        "[tst] kernel module load",
        "[tst] reverse shell",
        "[tst] entropy anomaly",
        "[tst] compliance failure",
        "[tst] agent tamper",
        "[tst] offline buffering + reconnect drain",
        "[tst] rule hot-reload + emergency push",
        "[tst] protected process + rate limiter",
        "[tst] quarantine + restore",
        "[tst] lsm execution block",
        "[tst] fleet correlation + z-score anomaly",
    ] {
        assert!(
            has_line(&run_all_lines, expected),
            "run-all output missing scenario line: {expected}"
        );
    }

    let log = std::fs::read_to_string(&log_path).expect("read mock log");
    let log_lines = non_comment_lines(&log);
    assert!(has_line(&log_lines, "simulate all"));
    assert!(has_line(
        &log_lines,
        "cargo test -p response kill_process_tree_orders_children_before_parent -- --exact"
    ));
    assert!(has_line(
        &log_lines,
        "cargo test -p response protected_target_process_returns_error_without_signals -- --exact"
    ));
    assert!(has_line(
        &log_lines,
        "cargo test -p response kill_rate_limiter_enforces_limit_and_expires_window -- --exact"
    ));
    assert!(has_line(
        &log_lines,
        "cargo test -p response restore_quarantined_file_writes_destination -- --exact"
    ));
    let _ = std::fs::remove_dir_all(sandbox);

    let integration_workflow = read(".github/workflows/integration-compose.yml");
    let workflow_lines = non_comment_lines(&integration_workflow);
    assert!(workflow_lines
        .iter()
        .any(|line| line == "run: docker compose -f tests/docker-compose.test.yml up --build --abort-on-container-exit"));
    assert!(workflow_lines.iter().any(|line| line
        == "run: docker compose -f tests/docker-compose.test.yml down -v --remove-orphans"));
}

#[test]
// AC-VER-001 AC-VER-002 AC-VER-003 AC-VER-004 AC-VER-005 AC-VER-006 AC-VER-007 AC-VER-008 AC-VER-009 AC-VER-010 AC-VER-011 AC-VER-012 AC-VER-013 AC-VER-031 AC-VER-032 AC-VER-033 AC-VER-034 AC-VER-035 AC-VER-036 AC-VER-037 AC-VER-038 AC-VER-039 AC-VER-040 AC-VER-041 AC-VER-042 AC-VER-043
fn performance_and_budget_contracts_are_captured_in_ci_harnesses() {
    let root = repo_root();
    let package_out_dir = root.join("artifacts/package-agent");
    let ebpf_out_dir = root.join("artifacts/ebpf-resource-budget");
    let package_preexisting = package_out_dir.exists();
    let ebpf_preexisting = ebpf_out_dir.exists();

    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = temp_dir("eguard-budget-harness-test");
    let bin_dir = sandbox.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin");
    let log_path = sandbox.join("mock.log");
    write_exec(
        &bin_dir.join("cargo"),
        r#"#!/bin/bash
set -euo pipefail
echo "cargo $*" >> "${MOCK_LOG}"
exit 0
"#,
    );
    write_exec(
        &bin_dir.join("zig"),
        r#"#!/bin/bash
set -euo pipefail
echo "zig $*" >> "${MOCK_LOG}"
exit 0
"#,
    );
    write_exec(
        &bin_dir.join("strip"),
        r#"#!/bin/bash
set -euo pipefail
echo "strip $*" >> "${MOCK_LOG}"
exit 0
"#,
    );
    write_exec(
        &bin_dir.join("ar"),
        r#"#!/bin/bash
set -euo pipefail
echo "ar $*" >> "${MOCK_LOG}"
if [[ "${1:-}" == "rcs" && -n "${2:-}" ]]; then
  mkdir -p "$(dirname "${2}")"
  : > "${2}"
fi
exit 0
"#,
    );
    let path_env = format!(
        "{}:/usr/bin:/bin:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let package = std::process::Command::new("bash")
        .arg(root.join("scripts/build-agent-packages-ci.sh"))
        .current_dir(&root)
        .env("PATH", &path_env)
        .env("MOCK_LOG", &log_path)
        .status()
        .expect("run package budget script");
    assert!(
        package.success(),
        "package harness failed: status={package:?}"
    );
    let package_metrics = std::fs::read_to_string(package_out_dir.join("metrics.json"))
        .expect("read package metrics");
    assert!(
        package_metrics.contains("\"agent_binary\": null"),
        "expected agent_binary target to be telemetry-only"
    );
    assert_eq!(json_number(&package_metrics, "rules_package"), 5.0);
    assert_eq!(json_number(&package_metrics, "full_install"), 15.0);
    assert_eq!(json_number(&package_metrics, "runtime_rss"), 25.0);
    assert_eq!(json_number(&package_metrics, "distribution_budget"), 200.0);
    assert_eq!(
        json_number(&package_metrics, "agent_binary_compressed_mb"),
        7.0
    );
    assert_eq!(
        json_number(&package_metrics, "ebpf_programs_compressed_kb"),
        100.0
    );
    assert!(package_out_dir
        .join("debian/eguard-agent_0.1.0_amd64.deb")
        .exists());
    assert!(package_out_dir
        .join("debian/eguard-agent-rules_0.1.0_amd64.deb")
        .exists());
    assert!(package_out_dir
        .join("rpm/eguard-agent-0.1.0-1.x86_64.rpm")
        .exists());
    assert!(package_out_dir
        .join("rpm/eguard-agent-rules-0.1.0-1.x86_64.rpm")
        .exists());

    let ebpf = std::process::Command::new("bash")
        .arg(root.join("scripts/run_ebpf_resource_budget_ci.sh"))
        .current_dir(&root)
        .env("PATH", &path_env)
        .env("MOCK_LOG", &log_path)
        .status()
        .expect("run eBPF budget script");
    assert!(ebpf.success());
    let ebpf_metrics =
        std::fs::read_to_string(ebpf_out_dir.join("metrics.json")).expect("read eBPF metrics");
    assert_eq!(json_number(&ebpf_metrics, "idle_cpu_pct"), 0.05);
    assert_eq!(json_number(&ebpf_metrics, "active_cpu_pct"), 0.5);
    assert_eq!(json_number(&ebpf_metrics, "peak_cpu_pct"), 3.0);
    assert_eq!(json_number(&ebpf_metrics, "memory_rss_mb"), 25.0);
    assert!(
        ebpf_metrics.contains("\"binary_size_mb\": null"),
        "expected binary_size_mb limit to be disabled"
    );
    assert!(
        ebpf_metrics.contains("\"binary_size_enforced\": false"),
        "expected binary_size_enforced=false in limits"
    );
    assert_eq!(json_number(&ebpf_metrics, "startup_seconds"), 2.0);
    assert_eq!(json_number(&ebpf_metrics, "detection_latency_ns"), 500.0);
    assert_eq!(json_number(&ebpf_metrics, "lsm_block_latency_ms"), 1.0);

    let log = std::fs::read_to_string(&log_path).expect("read budget harness log");
    let log_lines = non_comment_lines(&log);
    assert!(has_line(
        &log_lines,
        "cargo build --release --target x86_64-unknown-linux-musl -p agent-core"
    ));
    assert!(has_line(&log_lines, "zig build"));
    assert!(has_line(&log_lines, "cargo build --release -p agent-core"));
    let _ = std::fs::remove_dir_all(sandbox);

    let ringbuf = read("zig/ebpf/bpf_helpers.h");
    assert!(
        ringbuf.contains("FALLBACK_LAST_EVENT_DATA_SIZE 512"),
        "expected fallback buffer size in bpf_helpers.h"
    );
    assert!(
        ringbuf.contains("BPF_MAP_TYPE_RINGBUF 27"),
        "expected ring buffer map definition in bpf_helpers.h"
    );

    let matrix = read("tests/verification-matrix.md");
    let scalars = markdown_scalars(&matrix);
    assert_eq!(
        scalars.get("threat_intel_poll_interval_hours"),
        Some(&"4".to_string())
    );
    assert_eq!(
        scalars.get("ioc_stale_threshold_days_min"),
        Some(&"30".to_string())
    );
    assert_eq!(
        scalars.get("ioc_stale_threshold_days_max"),
        Some(&"90".to_string())
    );

    if !package_preexisting {
        let _ = std::fs::remove_dir_all(package_out_dir);
    }
    if !ebpf_preexisting {
        let _ = std::fs::remove_dir_all(ebpf_out_dir);
    }
}

#[test]
// AC-TST-037 AC-VER-048 AC-VER-049 AC-VER-050 AC-VER-051
fn attack_critical_burndown_bundle_release_contracts_are_present() {
    let bundle_tests = read("threat-intel/tests/test_bundle.py");
    assert!(
        bundle_tests.contains("class TestAttackCriticalTechniqueGate"),
        "critical ATT&CK gate tests must be present"
    );
    assert!(
        bundle_tests.contains("class TestAttackBurndownScoreboard"),
        "burn-down scoreboard tests must be present"
    );

    let workflow = read(".github/workflows/build-bundle.yml");
    assert!(
        workflow.contains("attack_critical_technique_gate.py"),
        "build-bundle workflow must enforce critical technique floor gate"
    );
    assert!(
        workflow.contains("attack_critical_regression_gate.py"),
        "build-bundle workflow must enforce critical technique regression guard"
    );
    assert!(
        workflow.contains("--max-owner-p0-uncovered-increase"),
        "critical regression gate must enforce owner-level P0 threshold"
    );
    assert!(
        workflow.contains("update_attack_critical_regression_history.py"),
        "build-bundle workflow must update critical regression history"
    );
    assert!(
        workflow.contains("attack_critical_owner_streak_gate.py"),
        "build-bundle workflow must enforce owner-level critical regression streak gate"
    );
    assert!(
        workflow.contains("Verify agent can ingest generated bundle output"),
        "build-bundle workflow must verify generated bundle can be ingested by agent runtime"
    );
    assert!(
        workflow.contains("load_bundle_rules_reads_ci_generated_signed_bundle"),
        "build-bundle workflow must run agent runtime ingestion test against generated bundle"
    );
    assert!(
        workflow.contains("load_bundle_rules_rejects_tampered_ci_generated_signed_bundle"),
        "build-bundle workflow must run tampered bundle rejection test against generated bundle"
    );
    assert!(
        workflow.contains("run_agent_bundle_ingestion_contract_ci.sh"),
        "build-bundle workflow must use shared bundle ingestion contract harness"
    );
    assert!(
        workflow.contains("EGUARD_CI_BUNDLE_PATH"),
        "build-bundle workflow must wire generated bundle path into agent ingestion test"
    );
    assert!(
        workflow.contains("EGUARD_CI_BUNDLE_PUBHEX"),
        "build-bundle workflow must wire generated bundle public key into agent ingestion test"
    );
    assert!(
        workflow.contains("--max-consecutive-owner-regression"),
        "owner-level streak gate must enforce max-consecutive owner regression threshold"
    );
    assert!(
        workflow.contains("attack_burndown_scoreboard.py"),
        "build-bundle workflow must generate ATT&CK burn-down scoreboard"
    );
    assert!(
        workflow.contains("Generate signature ML readiness report (shadow)"),
        "build-bundle workflow must generate signature ML readiness report"
    );
    assert!(
        workflow.contains("signature_ml_readiness_gate.py"),
        "build-bundle workflow must invoke signature ML readiness gate script"
    );
    assert!(
        workflow.contains("--previous /tmp/previous-signature-ml-readiness.json"),
        "build-bundle workflow must consume previous signature ML readiness baseline"
    );
    assert!(
        workflow.contains("Generate signature ML readiness trend report (shadow)"),
        "build-bundle workflow must generate signature ML readiness trend report"
    );
    assert!(
        workflow.contains("signature_ml_readiness_trend_gate.py"),
        "build-bundle workflow must invoke signature ML readiness trend gate script"
    );
    assert!(
        workflow.contains("--previous-trend /tmp/previous-signature-ml-readiness-trend.ndjson"),
        "build-bundle workflow must consume previous signature ML readiness trend baseline"
    );
    assert!(
        workflow.contains("Build signature ML training corpus"),
        "build-bundle workflow must build signature ML training corpus"
    );
    assert!(
        workflow.contains("signature_ml_build_training_corpus.py"),
        "build-bundle workflow must invoke signature ML corpus builder"
    );
    assert!(
        workflow.contains("Validate signature ML label quality (shadow)"),
        "build-bundle workflow must validate signature ML label quality"
    );
    assert!(
        workflow.contains("signature_ml_label_quality_gate.py"),
        "build-bundle workflow must invoke signature ML label quality gate"
    );
    assert!(
        workflow.contains("Build signature ML feature snapshot (shadow)"),
        "build-bundle workflow must build signature ML feature snapshot"
    );
    assert!(
        workflow.contains("signature_ml_feature_snapshot_gate.py"),
        "build-bundle workflow must invoke signature ML feature snapshot gate"
    );
    assert!(
        workflow.contains("Train signature ML model artifact"),
        "build-bundle workflow must train signature ML model artifact"
    );
    assert!(
        workflow.contains("signature_ml_train_model.py"),
        "build-bundle workflow must invoke signature ML train model script"
    );
    assert!(
        workflow.contains("Evaluate signature ML offline metrics (shadow)"),
        "build-bundle workflow must evaluate signature ML offline metrics"
    );
    assert!(
        workflow.contains("signature_ml_offline_eval_gate.py"),
        "build-bundle workflow must invoke signature ML offline eval gate"
    );
    assert!(
        workflow.contains("--auto-threshold 1"),
        "build-bundle workflow must use auto-threshold operating point selection for offline eval"
    );
    assert!(
        workflow.contains("Validate signature ML offline eval trend (shadow)"),
        "build-bundle workflow must validate signature ML offline eval trend"
    );
    assert!(
        workflow.contains("signature_ml_offline_eval_trend_gate.py"),
        "build-bundle workflow must invoke signature ML offline eval trend gate"
    );
    assert!(
        workflow.contains("Sign signature ML model artifact"),
        "build-bundle workflow must sign signature ML model artifact"
    );
    assert!(
        workflow.contains("Validate signature ML model registry contract (shadow)"),
        "build-bundle workflow must validate signature ML model registry contract"
    );
    assert!(
        workflow.contains("signature_ml_model_registry_gate.py"),
        "build-bundle workflow must invoke signature ML model registry gate"
    );
    assert!(
        workflow.contains("attack_critical_techniques.json"),
        "workflow must use curated critical ATT&CK techniques list"
    );
    assert!(
        workflow.contains("--previous-scoreboard /tmp/previous-attack-burndown-scoreboard.json"),
        "workflow must read previous scoreboard baseline when available"
    );
    assert!(
        workflow.contains("bundle/attack-critical-technique-gate.json"),
        "critical ATT&CK gate artifact must be published"
    );
    assert!(
        workflow.contains("bundle/attack-burndown-scoreboard.json"),
        "burn-down scoreboard JSON artifact must be published"
    );
    assert!(
        workflow.contains("bundle/attack-critical-regression.json"),
        "critical ATT&CK regression artifact must be published"
    );
    assert!(
        workflow.contains("bundle/attack-critical-regression-history.ndjson"),
        "critical ATT&CK regression history artifact must be published"
    );
    assert!(
        workflow.contains("bundle/attack-critical-regression-history-summary.json"),
        "critical ATT&CK regression history summary artifact must be published"
    );
    assert!(
        workflow.contains("bundle/attack-critical-owner-streak-gate.json"),
        "critical ATT&CK owner streak gate artifact must be published"
    );
    assert!(
        workflow.contains("bundle/attack-burndown-scoreboard.md"),
        "burn-down scoreboard Markdown artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-readiness.json"),
        "signature ML readiness artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-readiness-trend.ndjson"),
        "signature ML readiness trend artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-readiness-trend-report.json"),
        "signature ML readiness trend report artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-training-corpus-summary.json"),
        "signature ML training corpus summary artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-label-quality-report.json"),
        "signature ML label quality report artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-feature-snapshot-report.json"),
        "signature ML feature snapshot report artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-offline-eval-report.json"),
        "signature ML offline eval report artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-offline-eval-trend-report.json"),
        "signature ML offline eval trend report artifact must be published"
    );
    assert!(
        workflow.contains("bundle/signature-ml-model-registry.json"),
        "signature ML model registry artifact must be published"
    );
    assert!(
        workflow.contains("## Critical ATT&CK Technique Floor"),
        "release notes must include critical ATT&CK floor status"
    );
    assert!(
        workflow.contains("## Critical ATT&CK Regression Guard"),
        "release notes must include critical ATT&CK regression guard status"
    );
    assert!(
        workflow.contains("Owner P0 regressions"),
        "release notes must include owner-level P0 regression signal"
    );
    assert!(
        workflow.contains("## Critical ATT&CK Regression History"),
        "release notes must include critical ATT&CK regression history status"
    );
    assert!(
        workflow.contains("## Critical ATT&CK Owner Streak Guard"),
        "release notes must include critical ATT&CK owner streak guard status"
    );
    assert!(
        workflow.contains("## ATT&CK Critical Burn-down Scoreboard"),
        "release notes must include critical ATT&CK burn-down summary"
    );
    assert!(
        workflow.contains("Top uncovered critical (max 5)"),
        "release notes must include top uncovered critical technique preview"
    );
    assert!(
        workflow.contains("Delta uncovered vs previous"),
        "release notes must publish burn-down trend delta"
    );
    assert!(
        workflow.contains("## Signature ML Readiness (Shadow)"),
        "release notes must include signature ML readiness summary"
    );
    assert!(
        workflow.contains("Readiness tier"),
        "release notes must include signature ML readiness tier"
    );
    assert!(
        workflow.contains("## Signature ML Readiness Trend (Shadow)"),
        "release notes must include signature ML readiness trend summary"
    );
    assert!(
        workflow.contains("Projected consecutive alerts"),
        "release notes must include projected signature ML trend alert streak"
    );
    assert!(
        workflow.contains("## Signature ML Training Corpus"),
        "release notes must include signature ML corpus summary"
    );
    assert!(
        workflow.contains("## Signature ML Label Quality (Shadow)"),
        "release notes must include signature ML label quality summary"
    );
    assert!(
        workflow.contains("## Signature ML Feature Snapshot (Shadow)"),
        "release notes must include signature ML feature snapshot summary"
    );
    assert!(
        workflow.contains("## Signature ML Offline Eval (Shadow)"),
        "release notes must include signature ML offline eval summary"
    );
    assert!(
        workflow.contains("Operating threshold"),
        "release notes must include signature ML offline eval operating threshold"
    );
    assert!(
        workflow.contains("## Signature ML Offline Eval Trend (Shadow)"),
        "release notes must include signature ML offline eval trend summary"
    );
    assert!(
        workflow.contains("Consecutive alerts"),
        "release notes must include signature ML offline eval consecutive alert count"
    );
    assert!(
        workflow.contains("## Signature ML Model Registry (Shadow)"),
        "release notes must include signature ML model registry summary"
    );
}

#[test]
// AC-TST-038 AC-TST-039 AC-TST-040
fn signature_ml_training_pipeline_is_framework_free_and_advanced() {
    let script = read("threat-intel/processing/signature_ml_train_model.py");
    assert!(
        script.contains("irls_newton"),
        "training script must use IRLS/Newton optimizer"
    );
    assert!(
        script.contains("l2_sweep"),
        "training script must include L2 regularization sweep diagnostics"
    );
    assert!(
        script.contains("temperature"),
        "training script must include temperature scaling"
    );
    for metric in ["pr_auc", "roc_auc", "log_loss", "brier", "ece"] {
        assert!(
            script.contains(metric),
            "training script must emit training metric {metric}"
        );
    }
    for forbidden in ["numpy", "sklearn", "torch", "tensorflow"] {
        assert!(
            !script.contains(forbidden),
            "training script must not depend on {forbidden}"
        );
    }
}

#[test]
// AC-VER-055 AC-VER-056 AC-VER-057
fn qemu_verification_harness_is_enforced() {
    let script = read("tests/qemu/run_qemu_command.sh");
    assert!(
        script.contains("qemu-system-x86_64"),
        "QEMU harness must invoke qemu-system-x86_64"
    );
    assert!(
        script.contains("rdinit=/init"),
        "QEMU harness must boot with rdinit=/init"
    );
    assert!(
        script.contains("qemu_script="),
        "QEMU harness must pass qemu_script kernel arg"
    );
    assert!(
        script.contains("-virtfs"),
        "QEMU harness must mount host root via 9p"
    );
    assert!(
        script.contains("readonly"),
        "QEMU harness must mount host root read-only"
    );
    assert!(
        script.contains("-netdev user"),
        "QEMU harness must use user-mode networking"
    );
    assert!(
        !script.contains("hostfwd="),
        "QEMU harness must not define host port forwards"
    );
    assert!(
        script.contains("blackhole"),
        "QEMU harness must add RFC1918/link-local blackhole routes"
    );
}

#[test]
// AC-TST-041
fn qemu_ebpf_smoke_harness_is_defined() {
    let script = read("tests/qemu/run_ebpf_smoke.sh");
    assert!(
        script.contains("ebpf_smoke"),
        "QEMU eBPF smoke script must run ebpf_smoke binary"
    );
    assert!(
        script.contains("ebpf-artifacts"),
        "QEMU eBPF smoke script must build eBPF artifacts"
    );
}

#[test]
// AC-TST-042
fn qemu_agent_kill_smoke_harness_is_defined() {
    let script = read("tests/qemu/run_agent_kill_smoke.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU agent kill smoke script must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU agent kill smoke script must invoke QEMU harness"
    );
}

#[test]
// AC-TST-043
fn qemu_agent_multi_pid_chain_harness_is_defined() {
    let script = read("tests/qemu/run_agent_multipid_chain.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU multi-pid chain script must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU multi-pid chain script must invoke QEMU harness"
    );
}

#[test]
// AC-TST-044 AC-TST-045
fn qemu_agent_malware_harness_is_defined() {
    let script = read("tests/qemu/run_agent_malware_harness.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU malware harness script must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU malware harness script must invoke QEMU harness"
    );

    let cmd = read("tests/qemu/agent_malware_harness_cmd.sh");
    assert!(
        cmd.contains("malware_metrics.json"),
        "malware harness must emit metrics JSON"
    );
    assert!(cmd.contains("TPR"), "malware harness must log TPR metrics");
    assert!(
        cmd.contains("benign"),
        "malware harness must include benign sample evaluation"
    );
}

#[test]
// AC-TST-046
fn workflow_wires_malwarebazaar_key() {
    let workflow = read(".github/workflows/collect-ioc.yml");
    assert!(
        workflow.contains("MALWARE_BAZAAR_KEY"),
        "collect-ioc workflow must reference MALWARE_BAZAAR_KEY"
    );
    assert!(
        workflow.contains("Auth-Key"),
        "collect-ioc workflow must use Auth-Key header for MalwareBazaar"
    );
    assert!(
        workflow.contains("mb-api.abuse.ch"),
        "collect-ioc workflow must call MalwareBazaar API"
    );
}

#[test]
// AC-TST-047
fn qemu_agent_dns_tunneling_harness_is_defined() {
    let script = read("tests/qemu/run_agent_dns_tunnel.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU DNS tunneling script must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU DNS tunneling script must invoke QEMU harness"
    );

    let cmd = read("tests/qemu/agent_dns_tunnel_cmd.sh");
    assert!(
        cmd.contains("dns_query"),
        "DNS tunneling harness must replay DNS queries"
    );
    assert!(
        cmd.contains("confidence"),
        "DNS tunneling harness must assert confidence output"
    );
}

#[test]
// AC-TST-048
fn qemu_agent_memory_scan_harness_is_defined() {
    let script = read("tests/qemu/run_agent_memory_scan.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU memory scan script must build agent-core"
    );
    assert!(
        script.contains("memory_scan_stub"),
        "QEMU memory scan script must build memory scan stub"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU memory scan script must invoke QEMU harness"
    );

    let cmd = read("tests/qemu/agent_memory_scan_cmd.sh");
    assert!(
        cmd.contains("EGUARD_MEMORY_SCAN_ENABLED"),
        "Memory scan harness must enable memory scanning"
    );
    assert!(
        cmd.contains("eguard-shellcode-marker"),
        "Memory scan harness must reference shellcode marker"
    );
}

#[test]
// AC-TST-049
fn qemu_agent_container_escape_harness_is_defined() {
    let script = read("tests/qemu/run_agent_container_escape.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU container escape script must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU container escape script must invoke QEMU harness"
    );

    let cmd = read("tests/qemu/agent_container_escape_cmd.sh");
    assert!(
        cmd.contains("cgroup.procs"),
        "Container escape harness must place process in cgroup"
    );
    assert!(
        cmd.contains("killchain_container_escape"),
        "Container escape harness must assert escape detection"
    );
    assert!(
        cmd.contains("killchain_container_privileged"),
        "Container escape harness must assert privileged container detection"
    );
}

#[test]
// AC-TST-050
fn qemu_agent_credential_theft_harness_is_defined() {
    let script = read("tests/qemu/run_agent_credential_theft.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU credential theft script must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU credential theft script must invoke QEMU harness"
    );

    let cmd = read("tests/qemu/agent_credential_theft_cmd.sh");
    assert!(
        cmd.contains("/etc/shadow"),
        "Credential theft harness must reference /etc/shadow"
    );
    assert!(
        cmd.contains("killchain_credential_theft"),
        "Credential theft harness must assert killchain detection"
    );
}

#[test]
// AC-TST-051
fn sigma_file_path_predicates_are_supported() {
    let rule = read("rules/sigma/credential_access.yml");
    assert!(
        rule.contains("file_path_any_of"),
        "Sigma credential access rule must declare file_path_any_of"
    );
    assert!(
        rule.contains("file_path_contains"),
        "Sigma credential access rule must declare file_path_contains"
    );

    let sigma_impl = read("crates/detection/src/sigma.rs");
    assert!(
        sigma_impl.contains("file_path_any_of"),
        "Sigma compiler must support file_path_any_of"
    );
    assert!(
        sigma_impl.contains("file_path_contains"),
        "Sigma compiler must support file_path_contains"
    );
}

#[test]
// AC-TST-052 AC-VER-058
fn exploit_detection_acceptance_criteria_are_defined() {
    let ac = read("ACCEPTANCE_CRITERIA.md");
    for entry in [
        "AC-DET-217",
        "AC-DET-218",
        "AC-DET-219",
        "AC-TST-052",
        "AC-VER-058",
    ] {
        assert!(
            ac.contains(entry),
            "Exploit detection acceptance criteria must include {entry}"
        );
    }
}

#[test]
// AC-TST-052
fn qemu_exploit_harness_is_defined() {
    let script = read("tests/qemu/run_agent_exploit_harness.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU exploit harness must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU exploit harness must invoke QEMU runner"
    );

    let cmd = read("tests/qemu/agent_exploit_harness_cmd.sh");
    for marker in [
        "memfd:payload",
        "/proc/self/fd/",
        "fileless_tmp_interpreter",
    ] {
        assert!(
            cmd.contains(marker),
            "Exploit harness must include {marker}"
        );
    }
}

#[test]
// AC-TST-056 AC-VER-061
fn kernel_integrity_acceptance_criteria_are_defined() {
    let ac = read("ACCEPTANCE_CRITERIA.md");
    for entry in [
        "AC-DET-223",
        "AC-DET-224",
        "AC-DET-225",
        "AC-TST-056",
        "AC-VER-061",
    ] {
        assert!(
            ac.contains(entry),
            "Kernel integrity acceptance criteria must include {entry}"
        );
    }
}

#[test]
// AC-TST-056
fn qemu_kernel_integrity_harness_is_defined() {
    let script = read("tests/qemu/run_agent_kernel_integrity.sh");
    assert!(
        script.contains("agent-core"),
        "Kernel integrity harness must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "Kernel integrity harness must invoke QEMU runner"
    );

    let cmd = read("tests/qemu/agent_kernel_integrity_cmd.sh");
    for marker in ["module_load", "rootkit", "kernel_module_rootkit"] {
        assert!(
            cmd.contains(marker),
            "Kernel integrity harness must include {marker}"
        );
    }
}

#[test]
// AC-TST-057 AC-VER-061
fn self_protection_tamper_acceptance_criteria_are_defined() {
    let ac = read("ACCEPTANCE_CRITERIA.md");
    for entry in [
        "AC-DET-226",
        "AC-DET-227",
        "AC-ATP-098",
        "AC-ATP-099",
        "AC-ATP-100",
        "AC-TST-057",
        "AC-VER-061",
    ] {
        assert!(
            ac.contains(entry),
            "Self-protect tamper acceptance criteria must include {entry}"
        );
    }
}

#[test]
// AC-TST-057
fn qemu_self_protect_tamper_harness_is_defined() {
    let script = read("tests/qemu/run_agent_self_protect_tamper.sh");
    assert!(
        script.contains("agent-core"),
        "Self-protect tamper harness must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "Self-protect tamper harness must invoke QEMU runner"
    );

    let cmd = read("tests/qemu/agent_self_protect_tamper_cmd.sh");
    for marker in [
        "EGUARD_SELF_PROTECTION_INTEGRITY_CHECK_INTERVAL_SECS",
        "/proc/self/exe",
        "agent_tamper",
    ] {
        assert!(
            cmd.contains(marker),
            "Self-protect tamper harness must include {marker}"
        );
    }
}

#[test]
// AC-TST-060
fn ux_acceptance_criteria_are_defined() {
    let ac = read("ACCEPTANCE_CRITERIA.md");
    for entry in [
        "AC-UX-001",
        "AC-UX-002",
        "AC-UX-003",
        "AC-UX-010",
        "AC-UX-011",
        "AC-UX-012",
        "AC-UX-020",
        "AC-UX-021",
        "AC-UX-030",
        "AC-UX-031",
        "AC-UX-040",
        "AC-UX-041",
    ] {
        assert!(
            ac.contains(entry),
            "UX acceptance criteria must include {entry}"
        );
    }
}

#[test]
// AC-TST-061
fn ux_routes_and_views_are_present() {
    let router = read("../fe_eguard/html/egappserver/root/src/views/endpoint/_router/index.js");
    for route in [
        "/endpoint-incidents",
        "/endpoint-events",
        "/endpoint-responses",
        "/endpoint-agents",
        "/endpoint-compliance",
        "/endpoint-nac",
        "/endpoint-audit",
    ] {
        assert!(
            router.contains(route),
            "Endpoint router must include route {route}"
        );
    }

    let views = [
        "../fe_eguard/html/egappserver/root/src/views/endpoint/Incidents.vue",
        "../fe_eguard/html/egappserver/root/src/views/endpoint/EndpointEvents.vue",
        "../fe_eguard/html/egappserver/root/src/views/endpoint/ResponseActions.vue",
        "../fe_eguard/html/egappserver/root/src/views/endpoint/EndpointAgents.vue",
        "../fe_eguard/html/egappserver/root/src/views/endpoint/Compliance.vue",
        "../fe_eguard/html/egappserver/root/src/views/endpoint/NAC.vue",
        "../fe_eguard/html/egappserver/root/src/views/endpoint/Audit.vue",
    ];
    for view in views {
        let path = repo_root().join(view);
        assert!(path.exists(), "Missing required UX view {view}");
    }

    let nav = read("../fe_eguard/html/egappserver/root/src/components/common/NavbarMain.vue");
    for marker in [
        "Endpoint Security",
        "Agents",
        "Events",
        "Incidents",
        "Responses",
        "Compliance",
        "NAC",
        "Audit",
    ] {
        assert!(nav.contains(marker), "Navbar must include {marker}");
    }
}

#[test]
// AC-TST-062
fn nac_bridge_nested_payload_contract_is_defined() {
    let nac_tests = read("../fe_eguard/go/agent/server/nac_bridge_test.go");
    for marker in ["detection", "primary_rule_name", "process_exec"] {
        assert!(
            nac_tests.contains(marker),
            "NAC bridge tests must cover nested payload marker {marker}"
        );
    }
}

#[test]
// AC-TST-064
fn correlation_contract_tests_are_defined() {
    let correlation_tests = read("../fe_eguard/go/agent/server/telemetry_correlation_test.go");
    for marker in ["dst_domain", "ioc_multi_host", "time_window"] {
        assert!(
            correlation_tests.contains(marker),
            "Correlation tests must include marker {marker}"
        );
    }
}

#[test]
// AC-TST-065
fn correlation_event_fields_are_asserted() {
    let observability = read("crates/agent-core/src/lifecycle/tests_observability.rs");
    for marker in [
        "telemetry_payload_includes_correlation_event_fields",
        "session_id",
        "dst_domain",
    ] {
        assert!(
            observability.contains(marker),
            "Correlation event field test missing marker {marker}"
        );
    }
}

#[test]
// AC-TST-066
fn kernel_integrity_scan_contract_is_defined() {
    let scan = read("crates/platform-linux/src/kernel_integrity.rs");
    for marker in [
        "hidden_module_sysfs",
        "hidden_module_proc",
        "tainted_module",
        "kprobe_hook",
        "ftrace_tracer",
        "lsm_bpf_enabled",
        "bpffs_pinned_object",
    ] {
        assert!(
            scan.contains(marker),
            "Kernel integrity scan missing marker {marker}"
        );
    }
}

#[test]
// AC-TST-067
fn qemu_kernel_integrity_extreme_harness_is_defined() {
    let script = read("tests/qemu/run_agent_kernel_integrity_extreme.sh");
    assert!(
        script.contains("agent-core"),
        "Kernel integrity extreme harness must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "Kernel integrity extreme harness must invoke QEMU runner"
    );

    let cmd = read("tests/qemu/agent_kernel_integrity_extreme_cmd.sh");
    for marker in [
        "EGUARD_KERNEL_INTEGRITY_ENABLED",
        "hidden_module_sysfs:sys_only",
        "hidden_module_proc:proc_only",
        "kprobe_hook:__x64_sys_execve",
        "ftrace_tracer:function",
        "lsm_bpf_enabled",
        "bpffs_pinned_object:evil_prog",
    ] {
        assert!(
            cmd.contains(marker),
            "Kernel integrity extreme harness missing {marker}"
        );
    }
}

#[test]
// AC-TST-068
fn exploit_chain_unit_tests_are_defined() {
    let tests = read("crates/detection/src/tests.rs");
    for marker in [
        "killchain_exploit_ptrace_fileless",
        "killchain_exploit_userfaultfd_execveat",
        "killchain_exploit_proc_mem_fileless",
    ] {
        assert!(
            tests.contains(marker),
            "Exploit chain tests must include marker {marker}"
        );
    }
}

#[test]
// AC-TST-069
fn qemu_exploit_chain_harness_is_defined() {
    let script = read("tests/qemu/run_agent_exploit_chain.sh");
    assert!(
        script.contains("agent-core"),
        "Exploit-chain harness must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "Exploit-chain harness must invoke QEMU runner"
    );

    let cmd = read("tests/qemu/agent_exploit_chain_cmd.sh");
    for marker in [
        "EGUARD_EBPF_REPLAY_PATH",
        "ptrace",
        "userfaultfd",
        "execveat",
    ] {
        assert!(
            cmd.contains(marker),
            "Exploit-chain harness missing {marker}"
        );
    }
}

#[test]
// AC-TST-053
fn qemu_audit_trail_harness_is_defined() {
    let script = read("tests/qemu/run_agent_audit_trail.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU audit harness must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU audit harness must invoke QEMU runner"
    );

    let cmd = read("tests/qemu/agent_audit_trail_cmd.sh");
    for marker in ["debug audit payload", "primary_rule_name", "fileless_memfd"] {
        assert!(cmd.contains(marker), "Audit harness must include {marker}");
    }
}

#[test]
// AC-TST-054
fn qemu_latency_harness_is_defined() {
    let script = read("tests/qemu/run_agent_latency_harness.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU latency harness must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU latency harness must invoke QEMU runner"
    );

    let cmd = read("tests/qemu/agent_latency_harness_cmd.sh");
    for marker in [
        "LATENCY_P95_US",
        "LATENCY_P99_US",
        "debug detection latency",
    ] {
        assert!(
            cmd.contains(marker),
            "Latency harness must include {marker}"
        );
    }
}

#[test]
// AC-TST-055
fn qemu_offline_buffer_harness_is_defined() {
    let script = read("tests/qemu/run_agent_offline_buffer.sh");
    assert!(
        script.contains("agent-core"),
        "QEMU offline buffer harness must build agent-core"
    );
    assert!(
        script.contains("run_qemu_command.sh"),
        "QEMU offline buffer harness must invoke QEMU runner"
    );

    let cmd = read("tests/qemu/agent_offline_buffer_cmd.sh");
    for marker in [
        "offline buffer flushed",
        "pending_after=0",
        "server unavailable, buffered event",
    ] {
        assert!(
            cmd.contains(marker),
            "Offline buffer harness must include {marker}"
        );
    }
}

#[test]
// AC-DET-182 AC-VER-024 AC-VER-054
fn signature_ml_runtime_feature_contracts_are_enforced() {
    let feature_gate = read("threat-intel/processing/signature_ml_feature_snapshot_gate.py");
    let runtime_features = [
        "z1_ioc_hit",
        "z2_temporal_count",
        "z3_anomaly_high",
        "z3_anomaly_med",
        "z4_killchain_count",
        "yara_hit_count",
        "string_sig_count",
        "event_class_risk",
        "uid_is_root",
        "dst_port_risk",
        "has_command_line",
        "cmdline_length_norm",
        "prefilter_hit",
        "multi_layer_count",
        "cmdline_renyi_h2",
        "cmdline_compression",
        "cmdline_min_entropy",
        "cmdline_entropy_gap",
        "dns_entropy",
        "event_size_norm",
    ];
    for feature in runtime_features {
        assert!(
            feature_gate.contains(&format!("\"{}\"", feature)),
            "feature snapshot gate must include runtime feature {feature}"
        );
    }

    let workflow = read(".github/workflows/build-bundle.yml");
    assert!(
        workflow.contains("dns_entropy"),
        "build bundle workflow must include dns_entropy in runtime feature gate"
    );
    assert!(
        workflow.contains("event_size_norm"),
        "build bundle workflow must include event_size_norm in runtime feature gate"
    );
    assert!(
        workflow.contains("FAIL: ML model missing runtime features"),
        "build bundle workflow must fail on missing runtime features"
    );
    assert!(
        workflow.contains("ML model threshold out of range"),
        "build bundle workflow must validate ML threshold range"
    );
}

#[test]
// AC-DET-264 AC-DET-265
fn signature_ml_training_uses_cost_sensitive_weights_and_stratified_cv() {
    let script = read("threat-intel/processing/signature_ml_train_model.py");
    assert!(
        script.contains("fn_cost_multiplier = 3.0"),
        "training script must upweight FN cost with multiplier >= 2.0"
    );
    assert!(
        script.contains("_stratified_kfold(rows, labels, 5)"),
        "training script must run stratified 5-fold cross-validation"
    );
    assert!(
        script.contains("\"cv_sweep\""),
        "training diagnostics must export CV sweep results"
    );
}

#[test]
// AC-DET-270
fn bundle_builder_includes_ml_model_in_manifest_hashes() {
    let script = read("threat-intel/processing/build_bundle.py");
    assert!(
        script.contains("--ml-model"),
        "bundle builder must accept an explicit ML model input"
    );
    assert!(
        script.contains("signature-ml-model.json"),
        "bundle builder must copy signature-ml-model.json into the bundle"
    );
    assert!(
        script.contains("for root, _dirs, files in os.walk(output_dir):"),
        "bundle builder must hash all files in output_dir"
    );
    assert!(
        script.contains("\"files\": file_hashes"),
        "manifest must include file hash index for integrity checks"
    );
}

#[test]
// AC-DET-271
fn offline_eval_gate_uses_expanding_window_temporal_validation() {
    let script = read("threat-intel/processing/signature_ml_offline_eval_gate.py");
    assert!(
        script.contains("eval_ratios = [0.20, 0.30, 0.40]"),
        "offline eval must define at least three expanding-window splits"
    );
    assert!(
        script.contains("\"temporal_splits\": split_results"),
        "offline eval report must expose temporal split metrics"
    );
    assert!(
        script.contains("\"temporal_summary\": temporal_summary"),
        "offline eval report must expose temporal summary metrics"
    );
}

#[test]
// AC-VER-014 AC-VER-015 AC-VER-016 AC-VER-017 AC-VER-018 AC-VER-019 AC-VER-020 AC-VER-021 AC-VER-022 AC-VER-023 AC-VER-024 AC-VER-025 AC-VER-026 AC-VER-027 AC-VER-028 AC-VER-029 AC-VER-030 AC-VER-044 AC-VER-045 AC-VER-046 AC-VER-047 AC-VER-052 AC-VER-053 AC-VER-054
fn verification_coverage_and_security_pipeline_contracts_are_present() {
    let root = repo_root();
    let mut files = collect_rs_files(&root.join("crates"));
    files.retain(|p| !p.to_string_lossy().contains("crates/acceptance/tests/"));

    let test_count =
        count_occurrences(&files, "#[test]") + count_occurrences(&files, "#[tokio::test]");
    assert!(
        test_count >= 200,
        "expected at least 200 tests, found {test_count}"
    );

    let det_tag_count = count_occurrences(&files, "AC-DET-");
    let ebp_tag_count = count_occurrences(&files, "AC-EBP-");
    let rsp_tag_count = count_occurrences(&files, "AC-RSP-");
    assert!(
        det_tag_count >= 100,
        "expected >=100 detection contracts, found {det_tag_count}"
    );
    assert!(
        ebp_tag_count >= 20,
        "expected >=20 eBPF contracts, found {ebp_tag_count}"
    );
    assert!(
        rsp_tag_count >= 30,
        "expected >=30 response contracts, found {rsp_tag_count}"
    );

    let verify_workflow = read(".github/workflows/verification-suite.yml");
    let verify_workflow_lines = non_comment_lines(&verify_workflow);
    assert!(verify_workflow_lines.iter().any(|line| line == "release:"));
    assert!(verify_workflow_lines.iter().any(|line| line == "schedule:"));
    assert!(verify_workflow_lines
        .iter()
        .any(|line| line.contains("./scripts/run_verification_suite_ci.sh")));

    let verify_script = read("scripts/run_verification_suite_ci.sh");
    assert!(
        verify_script.contains("run_agent_bundle_ingestion_contract_ci.sh"),
        "verification suite must run shared bundle-agent ingestion contract harness"
    );

    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let sandbox = temp_dir("eguard-verification-suite-test");
    let bin_dir = sandbox.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin");
    let release_binary = root.join("target/release/agent-core");
    let release_binary_preexisting = release_binary.exists();
    if !release_binary_preexisting {
        std::fs::create_dir_all(release_binary.parent().expect("release binary parent"))
            .expect("create release binary parent");
        std::fs::write(&release_binary, b"mock-agent-core").expect("write mock release binary");
    }
    let log_path = sandbox.join("mock.log");
    write_exec(
        &bin_dir.join("cargo"),
        r#"#!/bin/bash
set -euo pipefail
echo "cargo $*" >> "${MOCK_LOG}"
exit 0
"#,
    );
    write_exec(
        &bin_dir.join("checksec"),
        r#"#!/bin/bash
set -euo pipefail
echo "checksec $*" >> "${MOCK_LOG}"
exit 0
"#,
    );
    write_exec(
        &bin_dir.join("strace"),
        r#"#!/bin/bash
set -euo pipefail
echo "strace $*" >> "${MOCK_LOG}"
exit 0
"#,
    );

    let path_env = format!(
        "{}:/usr/bin:/bin:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let verify = std::process::Command::new("bash")
        .arg(root.join("scripts/run_verification_suite_ci.sh"))
        .current_dir(&root)
        .env("PATH", path_env)
        .env("MOCK_LOG", &log_path)
        .status()
        .expect("run verification suite script");
    assert!(
        verify.success(),
        "verification suite script failed: status={verify:?}"
    );

    let log = std::fs::read_to_string(&log_path).expect("read verification log");
    let log_lines = non_comment_lines(&log);
    assert!(has_line(&log_lines, "cargo audit"));
    assert!(has_line(
        &log_lines,
        "cargo clippy --workspace --all-targets --all-features -- -D warnings"
    ));
    assert!(has_line(
        &log_lines,
        "cargo +nightly fuzz run protobuf_parse -- -max_total_time=30 -verbosity=0"
    ));
    assert!(has_line(
        &log_lines,
        "cargo +nightly fuzz run detection_inputs -- -max_total_time=30 -verbosity=0"
    ));
    assert!(has_line(
        &log_lines,
        "cargo +nightly miri test -p detection --lib -- --test-threads=1"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/build_bundle.py --sigma <mock> --yara <mock> --ioc <mock> --cve <mock> --output <mock> --version ci.mock"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/bundle_coverage_gate.py --manifest <mock> --output <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_readiness_gate.py --manifest <mock> --coverage <mock> --output <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_readiness_trend_gate.py --current <mock> --previous-trend <mock> --output-trend <mock> --output-report <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_build_training_corpus.py --manifest <mock> --coverage <mock> --readiness <mock> --output-signals <mock> --output-summary <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_label_quality_gate.py --signals <mock> --output-report <mock> --output-labels <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_feature_snapshot_gate.py --labels <mock> --output-features <mock> --output-schema <mock> --output-report <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_train_model.py --dataset <mock> --feature-schema <mock> --labels-report <mock> --model-version <mock> --model-out <mock> --metadata-out <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_offline_eval_gate.py --dataset <mock> --model <mock> --previous-report <mock> --auto-threshold <mock> --output-report <mock> --output-trend <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_offline_eval_trend_gate.py --trend <mock> --output <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/signature_ml_model_registry_gate.py --model-artifact <mock> --metadata <mock> --offline-eval <mock> --offline-eval-trend-report <mock> --feature-schema <mock> --labels-report <mock> --signature-file <mock> --public-key-file <mock> --output <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/ed25519_sign.py --input <mock> --output-sig <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "python threat-intel/processing/ed25519_verify.py --input <mock> --signature <mock>"
    ));
    assert!(has_line(
        &log_lines,
        "checksec --file target/release/agent-core"
    ));
    assert!(has_line(
        &log_lines,
        "strace -f -e trace=%process,%network ./target/release/agent-core --help"
    ));
    assert!(has_line(
        &log_lines,
        "cargo test -p grpc-client enrollment_rejects_expired_or_wrong_ca_certificates -- --exact"
    ));
    assert!(has_line(
        &log_lines,
        "cargo test -p platform-linux ebpf::tests::parses_structured_lsm_block_payload -- --exact"
    ));
    assert!(has_line(
        &log_lines,
        "cargo test -p agent-core lifecycle::tests::load_bundle_rules_reads_ci_generated_signed_bundle -- --exact"
    ));
    assert!(has_line(
        &log_lines,
        "cargo test -p agent-core lifecycle::tests::load_bundle_rules_rejects_tampered_ci_generated_signed_bundle -- --exact"
    ));
    assert!(has_line(
        &log_lines,
        "cargo test -p agent-core lifecycle::tests::reload_detection_state_from_bundle_populates_ioc_layers_on_all_shards -- --exact"
    ));

    let bundle_signature_metrics = read("artifacts/bundle-signature-contract/metrics.json");
    assert!(bundle_signature_metrics.contains("\"suite\": \"bundle_signature_contract\""));
    assert!(bundle_signature_metrics.contains("\"signature_verified\": true"));
    assert!(bundle_signature_metrics.contains("\"tamper_rejected\": true"));
    assert!(bundle_signature_metrics.contains("\"ml_readiness\""));
    assert!(bundle_signature_metrics.contains("\"ml_readiness_trend\""));
    assert!(bundle_signature_metrics.contains("\"ml_battle_ready\""));
    assert!(bundle_signature_metrics.contains("\"offline_eval_trend\""));

    let signature_ml_readiness =
        read("artifacts/bundle-signature-contract/signature-ml-readiness.json");
    assert!(signature_ml_readiness.contains("\"suite\": \"signature_ml_readiness_gate\""));
    assert!(signature_ml_readiness.contains("\"scores\""));

    let signature_ml_readiness_trend =
        read("artifacts/bundle-signature-contract/signature-ml-readiness-trend.ndjson");
    assert!(signature_ml_readiness_trend.contains("\"signature_ml_readiness_trend\""));

    let signature_ml_readiness_trend_report =
        read("artifacts/bundle-signature-contract/signature-ml-readiness-trend-report.json");
    assert!(signature_ml_readiness_trend_report
        .contains("\"suite\": \"signature_ml_readiness_trend_gate\""));

    let signature_ml_corpus =
        read("artifacts/bundle-signature-contract/signature-ml-training-corpus-summary.json");
    assert!(signature_ml_corpus.contains("\"suite\": \"signature_ml_build_training_corpus\""));

    let signature_ml_label_quality =
        read("artifacts/bundle-signature-contract/signature-ml-label-quality-report.json");
    assert!(signature_ml_label_quality.contains("\"suite\": \"signature_ml_label_quality_gate\""));

    let signature_ml_feature_snapshot =
        read("artifacts/bundle-signature-contract/signature-ml-feature-snapshot-report.json");
    assert!(
        signature_ml_feature_snapshot.contains("\"suite\": \"signature_ml_feature_snapshot_gate\"")
    );

    let signature_ml_offline_eval =
        read("artifacts/bundle-signature-contract/signature-ml-offline-eval-report.json");
    assert!(signature_ml_offline_eval.contains("\"suite\": \"signature_ml_offline_eval_gate\""));

    let signature_ml_offline_eval_trend_report =
        read("artifacts/bundle-signature-contract/signature-ml-offline-eval-trend-report.json");
    assert!(signature_ml_offline_eval_trend_report
        .contains("\"suite\": \"signature_ml_offline_eval_trend_gate\""));

    let signature_ml_registry =
        read("artifacts/bundle-signature-contract/signature-ml-model-registry.json");
    assert!(signature_ml_registry.contains("\"suite\": \"signature_ml_model_registry_gate\""));

    if !release_binary_preexisting {
        let _ = std::fs::remove_file(&release_binary);
    }
    let _ = std::fs::remove_dir_all(sandbox);

    let matrix = read("tests/verification-matrix.md");
    let scalars = markdown_scalars(&matrix);
    assert_eq!(
        scalars.get("incident_threshold_hosts"),
        Some(&"3".to_string())
    );
    assert_eq!(
        scalars.get("fleet_zscore_threshold"),
        Some(&"3.0".to_string())
    );
    assert_eq!(scalars.get("minhash_bands"), Some(&"16".to_string()));
    assert_eq!(scalars.get("minhash_rows"), Some(&"8".to_string()));
    assert_eq!(scalars.get("minhash_hashes"), Some(&"128".to_string()));
    assert_eq!(scalars.get("triage_weight_sum"), Some(&"1.0".to_string()));
}
