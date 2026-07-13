use response::{CommandExecution, CommandOutcome};

use super::host_isolation_allowlist::resolve_host_isolation_allowlist;
use super::host_isolation_linux::{apply_linux_host_isolation, remove_linux_host_isolation};
use super::payloads::RestoreQuarantinePayload;
use super::AgentRuntime;
use crate::lifecycle::circuit_breaker::{BreakerDecision, DestructiveKind};
use crate::lifecycle::now_unix;

impl AgentRuntime {
    pub(super) fn apply_host_isolate(&mut self, payload_json: &str, exec: &mut CommandExecution) {
        #[derive(Debug, serde::Deserialize, Default)]
        struct IsolatePayload {
            #[serde(default)]
            allow_server_connection: bool,
            #[serde(default)]
            allow_server_ips: Vec<String>,
        }

        let payload: IsolatePayload = serde_json::from_str(payload_json).unwrap_or_default();
        let allowed = resolve_host_isolation_allowlist(
            &self.config.server_addr,
            payload.allow_server_connection,
            &payload.allow_server_ips,
        );

        #[cfg(any(target_os = "windows", target_os = "macos"))]
        if allowed.is_empty() {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = "isolation rejected: no routable server IPs provided".to_string();
            return;
        }

        if matches!(
            self.breaker.check_and_charge(
                DestructiveKind::IsolationApply,
                8,
                now_unix().max(0) as u64,
            ),
            BreakerDecision::Deny { .. }
        ) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = "isolation_skipped:circuit_open".to_string();
            return;
        }

        #[cfg(target_os = "windows")]
        {
            if let Err(err) = super::isolation_state::save_isolation_state(&allowed) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!(
                    "host isolation aborted: cannot persist recovery state: {}",
                    err
                );
                return;
            }
            let refs: Vec<&str> = allowed.iter().map(|value| value.as_str()).collect();
            match platform_windows::response::isolate_host(&refs) {
                Ok(()) => {
                    exec.detail = format!(
                        "host isolation enforced via Windows Firewall (allowing: {})",
                        allowed.join(",")
                    );
                }
                Err(err) => {
                    // Apply failed: tear down anything partially applied and only
                    // drop the durable recovery record if teardown is verified.
                    // Otherwise retain it so the failsafe can retry — never delete
                    // the only recovery record while isolation might be active.
                    if super::isolation_state::force_remove_isolation() {
                        super::isolation_state::clear_isolation_state();
                    }
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("host isolation failed: {}", err);
                }
            }
            return;
        }

        #[cfg(target_os = "macos")]
        {
            if let Err(err) = super::isolation_state::save_isolation_state(&allowed) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!(
                    "host isolation aborted: cannot persist recovery state: {}",
                    err
                );
                return;
            }
            let refs: Vec<&str> = allowed.iter().map(|value| value.as_str()).collect();
            match platform_macos::response::isolate_host(&refs) {
                Ok(()) => {
                    exec.detail = format!(
                        "host isolation enforced via pf (allowing: {})",
                        allowed.join(",")
                    );
                }
                Err(err) => {
                    // Apply failed: tear down anything partially applied and only
                    // drop the durable recovery record if teardown is verified.
                    // Otherwise retain it so the failsafe can retry — never delete
                    // the only recovery record while isolation might be active.
                    if super::isolation_state::force_remove_isolation() {
                        super::isolation_state::clear_isolation_state();
                    }
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("host isolation failed: {}", err);
                }
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            if let Err(err) = super::isolation_state::save_isolation_state(&allowed) {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!(
                    "host isolation aborted: cannot persist recovery state: {}",
                    err
                );
                return;
            }
            match apply_linux_host_isolation(&allowed) {
                Ok(()) => {
                    exec.detail = format!(
                        "host isolation enforced via iptables/nftables (allowing: {})",
                        allowed.join(",")
                    );
                }
                Err(err) => {
                    // Apply failed: tear down anything partially applied and only
                    // drop the durable recovery record if teardown is verified.
                    // Otherwise retain it so the failsafe can retry — never delete
                    // the only recovery record while isolation might be active.
                    if super::isolation_state::force_remove_isolation() {
                        super::isolation_state::clear_isolation_state();
                    }
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("host isolation failed: {}", err);
                }
            }
        }
    }

    pub(super) fn apply_host_unisolate(&self, exec: &mut CommandExecution) {
        let _ = self.breaker.allow_recovery();
        #[cfg(target_os = "windows")]
        {
            match platform_windows::response::remove_isolation() {
                Ok(()) => {
                    super::isolation_state::clear_isolation_state();
                    exec.detail = "host isolation removed via Windows Firewall".to_string();
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("failed removing host isolation: {}", err);
                }
            }
            return;
        }

        #[cfg(target_os = "macos")]
        {
            match platform_macos::response::remove_isolation() {
                Ok(()) => {
                    super::isolation_state::clear_isolation_state();
                    exec.detail = "host isolation removed via pf".to_string();
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("failed removing host isolation: {}", err);
                }
            }
            return;
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            match remove_linux_host_isolation() {
                Ok(()) => {
                    super::isolation_state::clear_isolation_state();
                    exec.detail = "host isolation removed via iptables".to_string();
                }
                Err(err) => {
                    exec.outcome = CommandOutcome::Ignored;
                    exec.status = "failed";
                    exec.detail = format!("failed removing host isolation: {}", err);
                }
            }
        }
    }

    pub(super) fn apply_quarantine_restore(&self, payload_json: &str, exec: &mut CommandExecution) {
        let _ = self.breaker.allow_recovery();
        let payload: RestoreQuarantinePayload = match serde_json::from_str(payload_json) {
            Ok(payload) => payload,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid restore_quarantine payload: {}", err);
                return;
            }
        };

        if payload.sha256.trim().is_empty() {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = "restore_quarantine failed: legacy_quarantine_requires_manual_restore: sha256 is required".to_string();
            return;
        }

        let quarantine_path = (!payload.quarantine_path.trim().is_empty())
            .then(|| std::path::Path::new(payload.quarantine_path.trim()));
        let original_path = (!payload.original_path.trim().is_empty())
            .then(|| std::path::Path::new(payload.original_path.trim()));

        match response::restore_quarantined(payload.sha256.trim(), quarantine_path, original_path) {
            Ok(report) => {
                exec.detail = format!("quarantine restored: {}", report.restored_path.display());
            }
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("restore_quarantine failed: {}", err);
            }
        }
    }
}
