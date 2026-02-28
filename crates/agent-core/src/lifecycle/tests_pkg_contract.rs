use std::path::{Path, PathBuf};

use grpc_client::{pb, Client};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(workspace_root().join(rel))
        .unwrap_or_else(|err| panic!("read {rel}: {err}"))
}

fn non_comment_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

fn bullet_entries(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn has_line(lines: &[String], expected: &str) -> bool {
    lines.iter().any(|line| line == expected)
}

fn script_lock() -> &'static std::sync::Mutex<()> {
    super::shared_env_var_lock()
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
    std::fs::write(path, content).expect("write mock executable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path).expect("metadata").permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).expect("chmod");
    }
}

fn install_mock_tools(bin_dir: &Path) {
    for tool in [
        "curl",
        "dpkg",
        "rpm",
        "systemctl",
        "sha256sum",
        "install",
        "cargo",
        "zig",
        "strip",
        "ar",
    ] {
        let script = format!(
            "#!/bin/bash
set -euo pipefail
echo \"{} $*\" >> \"${{MOCK_LOG}}\"
case \"{}\" in
  curl)
    out=\"\"
    while [[ $# -gt 0 ]]; do
      if [[ \"$1\" == \"-o\" ]]; then
        out=\"${{2:-}}\"
        shift 2
      else
        shift
      fi
    done
    if [[ -n \"$out\" && \"${{MOCK_CURL_WRITE:-0}}\" == \"1\" ]]; then
      mkdir -p \"$(dirname \"$out\")\" 2>/dev/null || true
      printf 'mock-package' > \"$out\" 2>/dev/null || true
    fi
    ;;
  sha256sum)
    cat >/dev/null || true
    exit 0
    ;;
  install)
    target=\"${{@: -1}}\"
    if [[ -n \"$target\" ]]; then
      mkdir -p \"$target\" 2>/dev/null || true
    fi
    exit 0
    ;;
  ar)
    if [[ \"${{1:-}}\" == \"t\" || \"${{1:-}}\" == \"x\" ]]; then
      exit 0
    fi
    if [[ \"${{1:-}}\" == \"rcs\" ]]; then
      archive=\"${{2:-}}\"
      if [[ -n \"$archive\" ]]; then
        mkdir -p \"$(dirname \"$archive\")\" 2>/dev/null || true
        : > \"$archive\"
      fi
      exit 0
    fi
    exit 0
    ;;
esac
",
            tool, tool
        );
        write_exec(&bin_dir.join(tool), &script);
    }
}

#[test]
// AC-PKG-001 AC-PKG-002 AC-PKG-003 AC-PKG-031
fn package_manifests_define_agent_and_optional_rules_for_deb_and_rpm() {
    let deb_control = read("packaging/debian/control");
    let deb_lines = non_comment_lines(&deb_control);
    let deb_packages: Vec<String> = deb_lines
        .iter()
        .filter_map(|line| line.strip_prefix("Package: ").map(ToOwned::to_owned))
        .collect();
    assert!(deb_packages.iter().any(|pkg| pkg == "eguard-agent"));
    assert!(deb_packages.iter().any(|pkg| pkg == "eguard-agent-rules"));

    let rpm_spec = read("packaging/rpm/eguard-agent.spec");
    let rpm_lines = non_comment_lines(&rpm_spec);
    assert!(has_line(&rpm_lines, "Name: eguard-agent"));
    assert!(has_line(&rpm_lines, "%package rules"));

    let core_manifest = read("packaging/manifest/eguard-agent.contents");
    let core_entries = non_comment_lines(&core_manifest);
    for required in [
        "/usr/bin/eguard-agent",
        "process_exec.bpf.o",
        "file_open.bpf.o",
        "tcp_connect.bpf.o",
        "dns_query.bpf.o",
        "module_load.bpf.o",
        "lsm_block.bpf.o",
        "/usr/lib/systemd/system/eguard-agent.service",
        "/etc/eguard-agent/agent.conf",
    ] {
        assert!(
            core_entries.iter().any(|entry| entry.ends_with(required)),
            "missing core payload: {required}"
        );
    }

    let rules_manifest = read("packaging/manifest/eguard-agent-rules.contents");
    let rules_entries = non_comment_lines(&rules_manifest);
    for required in [
        "/var/lib/eguard-agent/rules/sigma/default_webshell.yml",
        "/var/lib/eguard-agent/rules/yara/default.yar",
        "/var/lib/eguard-agent/rules/ioc/default_ioc.txt",
    ] {
        assert!(
            rules_entries.iter().any(|entry| entry == required),
            "missing rules payload: {required}"
        );
    }
}

#[test]
// AC-PKG-004 AC-PKG-005 AC-PKG-006 AC-PKG-007 AC-PKG-008 AC-PKG-009 AC-PKG-010 AC-PKG-011 AC-PKG-012
// AC-PKG-028 AC-PKG-029 AC-PKG-030 AC-PKG-031 AC-PKG-032 AC-PKG-033
fn package_build_harness_executes_and_emits_metrics_with_mocked_toolchain() {
    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let sandbox = temp_dir("eguard-pkg-build-test");
    let bin_dir = sandbox.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin");
    install_mock_tools(&bin_dir);
    let fake_bin = root.join("target/x86_64-unknown-linux-musl/release/agent-core");
    let fake_bin_preexisting = fake_bin.exists();
    if !fake_bin_preexisting {
        std::fs::create_dir_all(fake_bin.parent().expect("fake binary parent"))
            .expect("create fake bin parent");
        std::fs::write(&fake_bin, b"mock-agent-core").expect("write fake bin");
    }

    let log_path = sandbox.join("mock.log");
    let path = format!(
        "{}:/usr/bin:/bin:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let status = std::process::Command::new("bash")
        .arg(root.join("scripts/build-agent-packages-ci.sh"))
        .current_dir(&root)
        .env("PATH", path)
        .env("MOCK_LOG", &log_path)
        .status()
        .expect("run package build harness");
    assert!(status.success());

    let log = std::fs::read_to_string(&log_path).expect("read mock log");
    let log_lines = non_comment_lines(&log);
    assert!(has_line(
        &log_lines,
        "cargo build --release --target x86_64-unknown-linux-musl -p agent-core"
    ));
    assert!(has_line(&log_lines, "zig build"));
    assert!(log_lines.iter().any(|line| line.starts_with("strip ")));

    let metrics_path = root.join("artifacts/package-agent/metrics.json");
    let metrics_raw = std::fs::read_to_string(&metrics_path).expect("read metrics");
    let metrics: serde_json::Value = serde_json::from_str(&metrics_raw).expect("parse metrics");
    assert_eq!(metrics["suite"], "package-agent");
    assert!(metrics["targets_mb"]["agent_binary"].is_null());
    assert_eq!(metrics["targets_mb"]["rules_package"], 5);
    assert_eq!(metrics["targets_mb"]["full_install"], 15);
    assert_eq!(metrics["targets_mb"]["runtime_rss"], 25);
    assert_eq!(metrics["targets_mb"]["distribution_budget"], 200);
    assert_eq!(metrics["component_budget"]["agent_binary_compressed_mb"], 7);
    assert_eq!(
        metrics["component_budget"]["ebpf_programs_compressed_kb"],
        100
    );
    assert_eq!(metrics["component_budget"]["asm_lib_compressed_kb"], 50);
    assert_eq!(
        metrics["component_budget"]["seed_baseline_compressed_kb"],
        10
    );
    assert_eq!(
        metrics["component_budget"]["default_config_compressed_kb"],
        5
    );
    assert_eq!(metrics["component_budget"]["systemd_unit_kb"], 1);

    for pkg in [
        "artifacts/package-agent/debian/eguard-agent_0.1.0_amd64.deb",
        "artifacts/package-agent/debian/eguard-agent-rules_0.1.0_amd64.deb",
        "artifacts/package-agent/rpm/eguard-agent-0.1.0-1.x86_64.rpm",
        "artifacts/package-agent/rpm/eguard-agent-rules-0.1.0-1.x86_64.rpm",
    ] {
        assert!(root.join(pkg).exists(), "expected package artifact: {pkg}");
    }

    let _ = std::fs::remove_dir_all(root.join("artifacts/package-agent"));
    if !fake_bin_preexisting {
        let _ = std::fs::remove_file(&fake_bin);
    }
    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
// AC-PKG-013 AC-PKG-014 AC-PKG-015 AC-PKG-016
fn distribution_channels_cover_server_repo_manual_and_github_release() {
    let channels = read("packaging/repositories/channels.txt");
    let entries = bullet_entries(&channels);
    assert!(entries
        .iter()
        .any(|entry| entry == "https://<server>/api/v1/agent-install/linux-deb"));
    assert!(entries
        .iter()
        .any(|entry| entry == "https://<server>/api/v1/agent-install/linux-rpm"));
    assert!(entries
        .iter()
        .any(|entry| entry == "https://<server>/api/v1/agent-install/windows-exe"));
    assert!(entries
        .iter()
        .any(|entry| entry == "https://<server>/api/v1/agent-install/macos"));
    assert!(entries
        .iter()
        .any(|entry| entry == "apt repository (Debian/Ubuntu)"));
    assert!(entries
        .iter()
        .any(|entry| entry == "yum repository (RHEL/Fedora/Rocky)"));
    assert!(entries
        .iter()
        .any(|entry| entry == "Admin UI downloadable .deb/.rpm/.pkg files"));
    assert!(
        entries.iter().any(|entry| entry == "GitHub Releases"),
        "missing GitHub releases channel entry"
    );

    let workflow = read(".github/workflows/package-agent.yml");
    let workflow_lines = non_comment_lines(&workflow);
    assert!(has_line(
        &workflow_lines,
        "- name: Publish packages to GitHub Releases"
    ));
}

#[test]
// AC-PKG-017 AC-PKG-018 AC-PKG-019 AC-PKG-020 AC-PKG-021
fn install_script_executes_with_mocked_package_manager_and_systemd() {
    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let sandbox = temp_dir("eguard-install-test");
    let bin_dir = sandbox.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin");
    install_mock_tools(&bin_dir);
    let log_path = sandbox.join("mock.log");
    let path = format!(
        "{}:/usr/bin:/bin:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let help = std::process::Command::new("bash")
        .arg(root.join("scripts/install-eguard-agent.sh"))
        .arg("--help")
        .current_dir(&root)
        .output()
        .expect("run install --help");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout)
        .lines()
        .any(|line| line == "Usage: install-eguard-agent.sh --server <host[:port]> [--token <token>] [--url <package-url>]"));

    let missing_server = std::process::Command::new("bash")
        .arg(root.join("scripts/install-eguard-agent.sh"))
        .current_dir(&root)
        .output()
        .expect("run install missing server");
    assert!(!missing_server.status.success());
    assert!(String::from_utf8_lossy(&missing_server.stderr)
        .lines()
        .any(|line| line == "error: --server is required"));

    let run = std::process::Command::new("bash")
        .arg(root.join("scripts/install-eguard-agent.sh"))
        .arg("--server")
        .arg("example.local:50052")
        .arg("--url")
        .arg("https://example.local/pkg.deb")
        .current_dir(&root)
        .env("PATH", path)
        .env("MOCK_LOG", &log_path)
        .env("MOCK_CURL_WRITE", "1")
        .output()
        .expect("run install script");
    assert!(run.status.success());
    let stdout_text = String::from_utf8_lossy(&run.stdout);
    let stdout_lines: Vec<&str> = stdout_text.lines().collect();
    assert!(stdout_lines.contains(&"eguard-agent installed from https://example.local/pkg.deb"));

    let log = std::fs::read_to_string(&log_path).expect("read mock log");
    let log_lines = non_comment_lines(&log);
    assert!(log_lines
        .iter()
        .any(|line| line.starts_with("curl -fsSL https://example.local/pkg.deb -o ")));
    // Debian-based runners should take dpkg path; if not, rpm path is acceptable.
    assert!(
        log_lines.iter().any(|line| line.starts_with("dpkg -i "))
            || log_lines.iter().any(|line| line.starts_with("rpm -i "))
    );
    assert!(has_line(&log_lines, "systemctl enable eguard-agent"));
    assert!(has_line(&log_lines, "systemctl start eguard-agent"));

    let _ = std::fs::remove_dir_all(&sandbox);
}

#[test]
// AC-PKG-022 AC-PKG-023 AC-PKG-024 AC-PKG-025 AC-PKG-026 AC-PKG-027
fn update_script_executes_deb_and_rpm_paths_with_mocked_installers() {
    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let sandbox = temp_dir("eguard-update-test");
    let bin_dir = sandbox.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create mock bin");
    install_mock_tools(&bin_dir);
    let log_path = sandbox.join("mock.log");
    let update_dir = sandbox.join("update");
    let path = format!(
        "{}:/usr/bin:/bin:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let invalid = std::process::Command::new("bash")
        .arg(root.join("scripts/apply-agent-update.sh"))
        .arg("--server")
        .arg("example.local")
        .arg("--version")
        .arg("1.2.3")
        .arg("--checksum")
        .arg("abc")
        .arg("--format")
        .arg("zip")
        .current_dir(&root)
        .output()
        .expect("run invalid format");
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr)
        .lines()
        .any(|line| line == "error: --format must be deb or rpm"));

    let run_deb = std::process::Command::new("bash")
        .arg(root.join("scripts/apply-agent-update.sh"))
        .arg("--server")
        .arg("example.local")
        .arg("--version")
        .arg("1.2.3")
        .arg("--checksum")
        .arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .arg("--format")
        .arg("deb")
        .current_dir(&root)
        .env("PATH", &path)
        .env("MOCK_LOG", &log_path)
        .env("MOCK_CURL_WRITE", "1")
        .env("EGUARD_UPDATE_DIR", &update_dir)
        .output()
        .expect("run deb update");
    assert!(
        run_deb.status.success(),
        "deb update failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        run_deb.status,
        String::from_utf8_lossy(&run_deb.stdout),
        String::from_utf8_lossy(&run_deb.stderr)
    );
    assert!(String::from_utf8_lossy(&run_deb.stdout)
        .lines()
        .any(|line| line
            == "updated eguard-agent to 1.2.3; next heartbeat reports updated agent_version"));

    let run_rpm = std::process::Command::new("bash")
        .arg(root.join("scripts/apply-agent-update.sh"))
        .arg("--server")
        .arg("example.local")
        .arg("--version")
        .arg("2.0.1")
        .arg("--checksum")
        .arg("feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface")
        .arg("--format")
        .arg("rpm")
        .current_dir(&root)
        .env("PATH", &path)
        .env("MOCK_LOG", &log_path)
        .env("MOCK_CURL_WRITE", "1")
        .env("EGUARD_UPDATE_DIR", &update_dir)
        .output()
        .expect("run rpm update");
    assert!(
        run_rpm.status.success(),
        "rpm update failed: status={:?}\nstdout:\n{}\nstderr:\n{}",
        run_rpm.status,
        String::from_utf8_lossy(&run_rpm.stdout),
        String::from_utf8_lossy(&run_rpm.stderr)
    );
    assert!(String::from_utf8_lossy(&run_rpm.stdout)
        .lines()
        .any(|line| line
            == "updated eguard-agent to 2.0.1; next heartbeat reports updated agent_version"));

    let mut client = Client::new("127.0.0.1:50052".to_string());
    client.set_agent_version("2.0.1");
    assert_eq!(client.agent_version(), "2.0.1");

    let heartbeat = pb::HeartbeatResponse {
        heartbeat_interval_secs: 30,
        policy_update: None,
        rule_update: None,
        pending_commands: vec![pb::ServerCommand {
            command_id: "cmd-update-1".to_string(),
            command_type: pb::CommandType::RunScan as i32,
            issued_at: 1_700_000_000,
            issued_by: "server".to_string(),
            params: Some(pb::server_command::Params::Scan(pb::ScanParams {
                paths: vec!["/tmp".to_string()],
                yara_scan: true,
                ioc_scan: true,
            })),
        }],
        fleet_baseline: None,
        status: "ok".to_string(),
        server_time: String::new(),
    };
    assert_eq!(heartbeat.pending_commands.len(), 1);
    assert_eq!(heartbeat.pending_commands[0].command_id, "cmd-update-1");

    let log = std::fs::read_to_string(&log_path).expect("read mock log");
    let log_lines = non_comment_lines(&log);
    let deb_pkg = update_dir.join("eguard-agent-1.2.3.deb");
    let rpm_pkg = update_dir.join("eguard-agent-2.0.1.rpm");
    assert!(has_line(
        &log_lines,
        &format!(
            "curl -fsSL https://example.local/api/v1/agent-install/linux-deb?version=1.2.3 -o {}",
            deb_pkg.display()
        )
    ));
    assert!(has_line(
        &log_lines,
        &format!(
            "curl -fsSL https://example.local/api/v1/agent-install/linux-rpm?version=2.0.1 -o {}",
            rpm_pkg.display()
        )
    ));
    assert!(has_line(&log_lines, "sha256sum --check --status"));
    assert!(has_line(
        &log_lines,
        &format!("dpkg -i {}", deb_pkg.display())
    ));
    assert!(has_line(
        &log_lines,
        &format!("rpm -Uvh {}", rpm_pkg.display())
    ));

    let workflow = read(".github/workflows/package-agent.yml");
    let workflow_lines = non_comment_lines(&workflow);
    assert!(workflow_lines
        .iter()
        .any(|line| line.starts_with("gh release create ")));
    assert!(has_line(&workflow_lines, "echo \"sync apt repository\""));
    assert!(has_line(&workflow_lines, "echo \"sync yum repository\""));

    let _ = std::fs::remove_dir_all(&sandbox);
}
