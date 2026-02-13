use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
// AC-RES-008
fn runtime_dependency_set_excludes_ml_frameworks_and_keeps_zig_build_path() {
    let root = workspace_root();
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("read Cargo.lock");
    let lower = lock.to_ascii_lowercase();

    for banned in [
        "tensorflow",
        "pytorch",
        "onnxruntime",
        "xgboost",
        "lightgbm",
        "scikit",
        "numpy",
    ] {
        assert!(
            !lower.contains(banned),
            "unexpected external ML dependency in lockfile: {banned}"
        );
    }

    assert!(
        root.join("build.zig").exists(),
        "expected zig build entrypoint"
    );
}

#[test]
// AC-RES-009
fn runtime_loop_is_event_driven_without_busy_wait_contracts() {
    let root = workspace_root();
    let main_src =
        std::fs::read_to_string(root.join("crates/agent-core/src/main.rs")).expect("main.rs");
    let ebpf_src =
        std::fs::read_to_string(root.join("crates/platform-linux/src/ebpf.rs")).expect("ebpf.rs");
    let lifecycle_src = std::fs::read_to_string(root.join("crates/agent-core/src/lifecycle.rs"))
        .expect("lifecycle.rs");

    assert!(main_src.contains("time::interval("));
    assert!(main_src.contains("tokio::select!"));
    assert!(ebpf_src.contains(".poll(timeout)"));

    assert!(!main_src.contains("while true"));
    assert!(!lifecycle_src.contains("while true"));
    assert!(!lifecycle_src.contains("std::thread::sleep("));
}
