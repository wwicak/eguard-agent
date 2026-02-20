//! Forensic collection: system state snapshots.
//!
//! Collects ps, netstat, and launchctl list output for incident response.

#[cfg(target_os = "macos")]
use std::process::Command;

/// Forensics data collector.
pub struct ForensicsCollector;

impl ForensicsCollector {
    pub fn new() -> Self {
        Self
    }

    /// Collect a snapshot of running processes via `ps aux`.
    pub fn snapshot_processes(&self) -> String {
        #[cfg(target_os = "macos")]
        {
            run_command_output("ps", &["aux"])
        }
        #[cfg(not(target_os = "macos"))]
        {
            String::new()
        }
    }

    /// Collect a snapshot of network connections via `netstat`.
    pub fn snapshot_network(&self) -> String {
        #[cfg(target_os = "macos")]
        {
            run_command_output("netstat", &["-an"])
        }
        #[cfg(not(target_os = "macos"))]
        {
            String::new()
        }
    }

    /// Collect a snapshot of launchd services via `launchctl list`.
    pub fn snapshot_launchctl(&self) -> String {
        #[cfg(target_os = "macos")]
        {
            run_command_output("launchctl", &["list"])
        }
        #[cfg(not(target_os = "macos"))]
        {
            String::new()
        }
    }

    /// Collect a full forensic snapshot combining all data sources.
    pub fn collect_full_snapshot(&self) -> ForensicSnapshot {
        ForensicSnapshot {
            processes: self.snapshot_processes(),
            network: self.snapshot_network(),
            launchctl: self.snapshot_launchctl(),
        }
    }
}

impl Default for ForensicsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete forensic snapshot.
#[derive(Debug, Clone)]
pub struct ForensicSnapshot {
    pub processes: String,
    pub network: String,
    pub launchctl: String,
}

#[cfg(target_os = "macos")]
fn run_command_output(binary: &str, args: &[&str]) -> String {
    match Command::new(binary).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if stdout.is_empty() {
                stderr
            } else {
                stdout
            }
        }
        Err(err) => {
            tracing::warn!(binary, ?err, "forensic command failed");
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ForensicsCollector;

    #[test]
    fn forensics_collector_creates_snapshot() {
        let collector = ForensicsCollector::new();
        let snapshot = collector.collect_full_snapshot();
        // On non-macOS, all fields are empty strings.
        #[cfg(not(target_os = "macos"))]
        {
            assert!(snapshot.processes.is_empty());
            assert!(snapshot.network.is_empty());
            assert!(snapshot.launchctl.is_empty());
        }
        let _ = snapshot;
    }
}
