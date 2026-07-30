#![cfg(target_os = "windows")]

use std::fs;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use response::{kill_process_tree, ProtectedList};

const TEST_NAME: &str = "windows_real_process_tree_is_terminated_children_first";
const ROLE_ENV: &str = "EGUARD_WINDOWS_TREE_TEST_ROLE";
const PID_FILE_ENV: &str = "EGUARD_WINDOWS_TREE_TEST_PID_FILE";

fn spawn(role: &str, pid_file: &std::path::Path) -> Child {
    Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(ROLE_ENV, role)
        .env(PID_FILE_ENV, pid_file)
        .spawn()
        .expect("spawn disposable Windows test process")
}

#[test]
fn windows_real_process_tree_is_terminated_children_first() {
    let pid_file = std::env::var_os(PID_FILE_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("eguard-windows-tree-{}.pid", std::process::id()))
        });

    match std::env::var(ROLE_ENV).as_deref() {
        Ok("leaf") => {
            thread::sleep(Duration::from_secs(30));
            return;
        }
        Ok("parent") => {
            let leaf = spawn("leaf", &pid_file);
            fs::write(&pid_file, leaf.id().to_string()).expect("publish disposable child pid");
            thread::sleep(Duration::from_secs(30));
            return;
        }
        _ => {}
    }

    let mut parent = spawn("parent", &pid_file);
    let parent_pid = parent.id();
    let deadline = Instant::now() + Duration::from_secs(10);
    let leaf_pid = loop {
        if let Ok(raw) = fs::read_to_string(&pid_file) {
            break raw.trim().parse::<u32>().expect("published child pid");
        }
        assert!(Instant::now() < deadline, "disposable child did not start");
        thread::sleep(Duration::from_millis(50));
    };

    let result = kill_process_tree(parent_pid, &ProtectedList::default_windows());
    if result.is_err() {
        let _ = parent.kill();
        let _ = kill_process_tree(leaf_pid, &ProtectedList::default_windows());
    }
    let report = result.expect("terminate disposable process tree");

    assert_eq!(report.killed_pids.last(), Some(&parent_pid));
    assert!(report.killed_pids.contains(&leaf_pid));
    assert!(!parent.wait().expect("wait for terminated parent").success());
    let _ = fs::remove_file(pid_file);
}
