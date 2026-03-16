use anyhow::Result;
use serde_json::json;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use grpc_client::EventEnvelope;
use self_protect::SelfProtectReport;

use super::{AgentRuntime, DegradedCause};

/// Interval between config file permission enforcement checks (seconds).
const CONFIG_PERMISSION_CHECK_INTERVAL_SECS: i64 = 300;

impl AgentRuntime {
    pub(crate) async fn run_self_protection_if_due(&mut self, now_unix: i64) -> Result<()> {
        if self.tamper_forced_degraded {
            return Ok(());
        }

        let interval = self.config.self_protection_integrity_check_interval_secs;
        if std::env::var("EGUARD_DEBUG_SELF_PROTECT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            tracing::info!(
                interval_secs = interval,
                last_check = self.last_self_protect_check_unix,
                now_unix,
                integrity_paths = ?self.self_protect_engine.config().runtime_integrity_paths,
                config_paths = ?self.self_protect_engine.config().runtime_config_paths,
                "debug self-protect tick"
            );
        }
        if interval == 0 {
            return Ok(());
        }

        if let Some(last) = self.last_self_protect_check_unix {
            if now_unix.saturating_sub(last) < interval as i64 {
                return Ok(());
            }
        }
        self.last_self_protect_check_unix = Some(now_unix);

        let report = self.self_protect_engine.evaluate();
        if std::env::var("EGUARD_DEBUG_SELF_PROTECT_LOG")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
        {
            tracing::info!(
                clean = report.is_clean(),
                violations = ?report.violation_codes(),
                tampered_paths = ?report.tampered_paths(),
                "debug self-protect report"
            );
        }
        if report.is_clean() {
            return Ok(());
        }

        self.handle_self_protection_violation(now_unix, &report)
            .await
    }

    pub(super) async fn handle_self_protection_violation(
        &mut self,
        now_unix: i64,
        report: &SelfProtectReport,
    ) -> Result<()> {
        if self.tamper_forced_degraded {
            return Ok(());
        }

        let alert = EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "alert".to_string(),
            severity: "critical".to_string(),
            rule_name: "agent_tamper".to_string(),
            payload_json: self.self_protect_alert_payload(report, now_unix),
            created_at_unix: now_unix,
        };

        if self.client.is_online() {
            if let Err(err) = self.client.send_events(std::slice::from_ref(&alert)).await {
                warn!(
                    error = %err,
                    pending = self.buffer.pending_count(),
                    "failed sending self-protect alert; buffering locally"
                );
                self.buffer.enqueue(alert)?;
            }
        } else {
            self.buffer.enqueue(alert)?;
        }

        self.tamper_forced_degraded = true;
        self.transition_to_degraded(DegradedCause::SelfProtection);
        warn!(
            violations = ?report.violation_codes(),
            summary = %report.summary(),
            "self-protection violation detected; forcing degraded mode"
        );

        Ok(())
    }

    pub(crate) async fn report_shutdown_tamper(
        &mut self,
        now_unix: i64,
        signal_name: &str,
    ) -> Result<()> {
        let payload = json!({
            "rule_name": "agent_stop_tamper",
            "severity": "critical",
            "timestamp": now_unix,
            "signal": signal_name,
            "detail": "agent received termination signal; restart is expected under self-protection",
        })
        .to_string();

        let alert = EventEnvelope {
            agent_id: self.config.agent_id.clone(),
            event_type: "alert".to_string(),
            severity: "critical".to_string(),
            rule_name: "agent_stop_tamper".to_string(),
            payload_json: payload,
            created_at_unix: now_unix,
        };

        if self.client.is_online() {
            match timeout(
                Duration::from_secs(2),
                self.client.send_events(std::slice::from_ref(&alert)),
            )
            .await
            {
                Ok(Ok(())) => {
                    warn!(
                        signal = signal_name,
                        "sent shutdown tamper alert before termination"
                    );
                    return Ok(());
                }
                Ok(Err(err)) => {
                    warn!(
                        signal = signal_name,
                        error = %err,
                        "failed immediate shutdown tamper send; buffering for post-restart delivery"
                    );
                }
                Err(_) => {
                    warn!(
                        signal = signal_name,
                        "timed out sending shutdown tamper alert; buffering for post-restart delivery"
                    );
                }
            }
        }

        self.buffer.enqueue(alert)?;
        warn!(
            signal = signal_name,
            pending = self.buffer.pending_count(),
            "recorded shutdown tamper alert into local buffer for post-restart delivery"
        );

        Ok(())
    }

    /// Enforce restrictive permissions on sensitive config files.
    /// Runs every 5 minutes to prevent permission drift.
    #[cfg(unix)]
    pub(super) fn enforce_config_permissions_if_due(&mut self, now_unix: i64) {
        if let Some(last) = self.last_config_permission_check_unix {
            if now_unix.saturating_sub(last) < CONFIG_PERMISSION_CHECK_INTERVAL_SECS {
                return;
            }
        }
        self.last_config_permission_check_unix = Some(now_unix);

        use std::os::unix::fs::PermissionsExt;

        let sensitive_paths = [
            "/etc/eguard-agent/agent.conf",
            "/etc/eguard-agent/bootstrap.conf",
            "/etc/eguard-agent/certs/agent.crt",
            "/etc/eguard-agent/certs/agent.key",
            "/etc/eguard-agent/certs/ca.crt",
        ];

        for path in &sensitive_paths {
            let p = std::path::Path::new(path);
            if !p.exists() {
                continue;
            }
            match std::fs::metadata(p) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode != 0o600 && mode != 0o400 {
                        if let Err(err) = std::fs::set_permissions(
                            p,
                            std::fs::Permissions::from_mode(0o600),
                        ) {
                            warn!(
                                path = path,
                                error = %err,
                                "failed enforcing 0600 permissions on config file"
                            );
                        } else {
                            info!(
                                path = path,
                                old_mode = format!("{:o}", mode),
                                "enforced 0600 permissions on config file"
                            );
                        }
                    }
                }
                Err(err) => {
                    warn!(path = path, error = %err, "failed reading config file metadata");
                }
            }
        }
    }

    #[cfg(not(unix))]
    pub(super) fn enforce_config_permissions_if_due(&mut self, _now_unix: i64) {
        // Windows ACLs are set by the installer (install.ps1).
    }

    pub(super) fn self_protect_alert_payload(
        &self,
        report: &SelfProtectReport,
        now_unix: i64,
    ) -> String {
        let tampered_paths = report.tampered_paths();
        let tamper_indicators: Vec<String> = tampered_paths
            .iter()
            .map(|path| format!("self_protect:{}", path))
            .collect();
        json!({
            "rule_name": "agent_tamper",
            "severity": "critical",
            "timestamp": now_unix,
            "violations": report.violation_codes(),
            "tampered_paths": tampered_paths,
            "tamper_indicators": tamper_indicators,
            "detail": report.summary(),
        })
        .to_string()
    }
}
