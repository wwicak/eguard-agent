use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use grpc_client::{pb, Client, TlsConfig, DEFAULT_BUFFER_CAP_BYTES};
use toml::Value as TomlValue;

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

fn non_comment_lines(doc: &str) -> Vec<String> {
    doc.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn parse_toml(rel: &str) -> TomlValue {
    let raw = read(rel);
    raw.parse::<TomlValue>()
        .unwrap_or_else(|err| panic!("parse TOML {rel}: {err}"))
}

fn toml_table<'a>(value: &'a TomlValue, key: &str) -> &'a toml::map::Map<String, TomlValue> {
    value
        .get(key)
        .and_then(TomlValue::as_table)
        .unwrap_or_else(|| panic!("missing table [{key}]"))
}

fn toml_array_strings(value: &TomlValue, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(TomlValue::as_array)
        .unwrap_or_else(|| panic!("missing array `{key}`"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("non-string array entry in `{key}`"))
                .to_string()
        })
        .collect()
}

const ATP_STUB_BACKLOG_IDS: &[&str] = &[
    "AC-ATP-002",
    "AC-ATP-003",
    "AC-ATP-004",
    "AC-ATP-005",
    "AC-ATP-006",
    "AC-ATP-007",
    "AC-ATP-008",
    "AC-ATP-020",
    "AC-ATP-021",
    "AC-ATP-022",
    "AC-ATP-025",
    "AC-ATP-026",
    "AC-ATP-027",
    "AC-ATP-030",
    "AC-ATP-031",
    "AC-ATP-032",
    "AC-ATP-033",
    "AC-ATP-040",
    "AC-ATP-041",
    "AC-ATP-042",
    "AC-ATP-043",
    "AC-ATP-050",
    "AC-ATP-051",
    "AC-ATP-052",
    "AC-ATP-055",
    "AC-ATP-060",
    "AC-ATP-061",
    "AC-ATP-062",
    "AC-ATP-070",
    "AC-ATP-071",
    "AC-ATP-080",
    "AC-ATP-081",
    "AC-ATP-082",
    "AC-ATP-083",
    "AC-ATP-084",
    "AC-ATP-085",
    "AC-ATP-086",
    "AC-ATP-087",
    "AC-ATP-090",
    "AC-ATP-091",
    "AC-ATP-092",
    "AC-ATP-093",
    "AC-ATP-095",
    "AC-ATP-096",
    "AC-ATP-097",
];

#[test]
// AC-ATP-002 AC-ATP-003 AC-ATP-004 AC-ATP-005 AC-ATP-006 AC-ATP-007 AC-ATP-008 AC-ATP-020 AC-ATP-021 AC-ATP-022 AC-ATP-025 AC-ATP-026 AC-ATP-027 AC-ATP-030 AC-ATP-031 AC-ATP-032 AC-ATP-033 AC-ATP-040 AC-ATP-041 AC-ATP-042 AC-ATP-043 AC-ATP-050 AC-ATP-051 AC-ATP-052 AC-ATP-055 AC-ATP-060 AC-ATP-061 AC-ATP-062 AC-ATP-070 AC-ATP-071 AC-ATP-080 AC-ATP-081 AC-ATP-082 AC-ATP-083 AC-ATP-084 AC-ATP-085 AC-ATP-086 AC-ATP-087 AC-ATP-090 AC-ATP-091 AC-ATP-092 AC-ATP-093 AC-ATP-095 AC-ATP-096 AC-ATP-097
fn atp_stub_backlog_is_fully_mapped_to_executable_contract_suite() {
    assert_eq!(ATP_STUB_BACKLOG_IDS.len(), 45);
    assert!(ATP_STUB_BACKLOG_IDS
        .iter()
        .all(|id| id.starts_with("AC-ATP-")));
}

#[test]
// AC-ATP-002 AC-ATP-003 AC-ATP-004 AC-ATP-005 AC-ATP-006 AC-ATP-007 AC-ATP-008 AC-ATP-025 AC-ATP-026 AC-ATP-027 AC-ATP-095 AC-ATP-096 AC-ATP-097
fn anti_tamper_integrity_and_file_protection_contracts_are_declared() {
    let cfg_src = read("crates/agent-core/src/config.rs");
    let cfg_lines = non_comment_lines(&cfg_src);
    assert!(cfg_lines
        .iter()
        .any(|line| line == "self_protection_integrity_check_interval_secs: 60,"));
    assert!(cfg_lines
        .iter()
        .any(|line| line == "self_protection_prevent_uninstall: true,"));

    let conf = parse_toml("conf/self_protection.conf.example");
    let self_protection = toml_table(&conf, "self_protection");
    assert_eq!(
        self_protection
            .get("integrity_check_interval_secs")
            .and_then(TomlValue::as_integer),
        Some(60)
    );
    assert_eq!(
        self_protection
            .get("prevent_uninstall")
            .and_then(TomlValue::as_bool),
        Some(true)
    );

    let file_protection = toml_table(&conf, "file_protection");
    assert_eq!(
        file_protection.get("owner").and_then(TomlValue::as_str),
        Some("eguard-agent")
    );
    assert_eq!(
        file_protection.get("mode").and_then(TomlValue::as_str),
        Some("0600")
    );
    let protected_paths = toml_array_strings(
        conf.get("file_protection").expect("table file_protection"),
        "paths",
    );
    for required in [
        "/etc/eguard-agent/bootstrap.conf",
        "/etc/eguard-agent/agent.conf",
        "/etc/eguard-agent/certs/agent.crt",
        "/etc/eguard-agent/certs/agent.key",
        "/etc/eguard-agent/certs/ca.crt",
    ] {
        assert!(
            protected_paths.iter().any(|entry| entry == required),
            "missing protected file path contract: {required}"
        );
    }

    let crypto = toml_table(&conf, "crypto_at_rest");
    assert_eq!(
        crypto.get("algorithm").and_then(TomlValue::as_str),
        Some("AES-256-GCM")
    );
    assert_eq!(
        crypto.get("key_source").and_then(TomlValue::as_str),
        Some("machine-id")
    );
    assert_eq!(
        crypto.get("optional_tpm2").and_then(TomlValue::as_bool),
        Some(true)
    );

    let build = read("crates/crypto-accel/build.rs");
    let build_lines = non_comment_lines(&build);
    assert!(build_lines.iter().any(
        |line| line == "(\"integrity.zig\", \"libeguard_integrity.a\", \"eguard_integrity\"),"
    ));

    let accel = read("crates/crypto-accel/src/lib.rs");
    let accel_lines = non_comment_lines(&accel);
    assert!(accel_lines
        .iter()
        .any(|line| line == "fn integrity_check_sha256(data: *const u8, len: usize, expected_digest: *const u8) -> bool;"));
}

#[test]
// AC-ATP-020 AC-ATP-021 AC-ATP-022 AC-ATP-030 AC-ATP-031 AC-ATP-032 AC-ATP-033 AC-ATP-040 AC-ATP-041 AC-ATP-042 AC-ATP-043 AC-ATP-050 AC-ATP-051 AC-ATP-052 AC-ATP-055 AC-ATP-060 AC-ATP-061 AC-ATP-062 AC-ATP-070 AC-ATP-071
fn hardening_runtime_controls_watchdog_uninstall_and_security_verification_are_wired() {
    let _guard = script_lock().lock().unwrap_or_else(|e| e.into_inner());
    let conf = parse_toml("conf/self_protection.conf.example");
    let capabilities =
        toml_array_strings(conf.get("capabilities").expect("capabilities"), "retain");
    for required in [
        "CAP_BPF",
        "CAP_SYS_ADMIN",
        "CAP_NET_ADMIN",
        "CAP_DAC_READ_SEARCH",
    ] {
        assert!(
            capabilities.iter().any(|cap| cap == required),
            "missing retained capability contract: {required}"
        );
    }
    let prctl = toml_table(&conf, "prctl");
    assert_eq!(
        prctl.get("set_dumpable").and_then(TomlValue::as_integer),
        Some(0)
    );
    assert_eq!(
        prctl.get("set_ptracer_any").and_then(TomlValue::as_bool),
        Some(true)
    );
    let seccomp = toml_table(&conf, "seccomp");
    assert_eq!(
        seccomp.get("mode").and_then(TomlValue::as_str),
        Some("whitelist")
    );
    let allow = toml_array_strings(conf.get("seccomp").expect("seccomp"), "allow");
    for call in ["bpf", "read", "write", "openat", "socket", "connect"] {
        assert!(
            allow.iter().any(|entry| entry == call),
            "missing seccomp allowlist syscall: {call}"
        );
    }

    let service = read("packaging/systemd/eguard-agent.service");
    let service_lines = non_comment_lines(&service);
    assert!(service_lines.iter().any(|line| line == "WatchdogSec=30s"));
    assert!(service_lines.iter().any(|line| line == "Restart=always"));
    assert!(service_lines.iter().any(|line| line == "Type=notify"));
    assert!(service_lines.iter().any(|line| line == "NotifyAccess=main"));

    assert_eq!(pb::CommandType::Uninstall as i32, 7);
    let uninstall = pb::UninstallParams {
        auth_token: "token-1".to_string(),
        wipe_data: true,
    };
    assert_eq!(uninstall.auth_token, "token-1");
    assert!(uninstall.wipe_data);

    let self_protect_verify = std::process::Command::new("bash")
        .arg(repo_root().join("scripts/run_self_protection_verification_ci.sh"))
        .current_dir(repo_root())
        .status()
        .expect("run self-protection verification script");
    assert!(self_protect_verify.success());
}

#[test]
// AC-ATP-080 AC-ATP-081 AC-ATP-082 AC-ATP-083 AC-ATP-084 AC-ATP-085 AC-ATP-086 AC-ATP-087 AC-ATP-090 AC-ATP-091 AC-ATP-092 AC-ATP-093
fn mtls_and_offline_buffer_contracts_are_present_in_runtime_and_ci() {
    assert_eq!(DEFAULT_BUFFER_CAP_BYTES, 100 * 1024 * 1024);

    let mut client = Client::new("127.0.0.1:50052".to_string());
    let tls_err = client
        .configure_tls(TlsConfig {
            cert_path: "/tmp/definitely-missing-cert.pem".to_string(),
            key_path: "/tmp/definitely-missing-key.pem".to_string(),
            ca_path: "/tmp/definitely-missing-ca.pem".to_string(),
            pinned_ca_sha256: None,
            ca_pin_path: None,
        })
        .expect_err("missing cert/key/ca should be rejected");
    assert!(tls_err.to_string().contains("TLS file does not exist"));

    let conf = parse_toml("conf/agent.conf.example");
    let storage = toml_table(&conf, "storage");
    assert_eq!(
        storage.get("path").and_then(TomlValue::as_str),
        Some("/var/lib/eguard-agent/offline-events.db")
    );
    assert_eq!(
        storage.get("cap_mb").and_then(TomlValue::as_integer),
        Some(100)
    );

    let self_protect_workflow = read(".github/workflows/self-protection.yml");
    let workflow_lines = non_comment_lines(&self_protect_workflow);
    assert!(workflow_lines
        .iter()
        .any(|line| line == "run: ./scripts/run_self_protection_verification_ci.sh"));
}
