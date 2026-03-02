use anyhow::Result;
use baseline::BaselineStatus;
use compliance::parse_policy_json;
use grpc_client::{PolicyEnvelope, TlsConfig};
use tracing::{info, warn};

use crate::config::AgentMode;

use super::super::{update_tls_policy_from_server, AgentRuntime};

impl AgentRuntime {
    pub(super) async fn refresh_policy_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !self.policy_refresh_due(now_unix) {
            return Ok(());
        }
        self.last_policy_fetch_unix = Some(now_unix);
        match self.client.fetch_policy(&self.config.agent_id).await {
            Ok(Some(policy)) => {
                self.apply_policy_from_server(policy);
            }
            Ok(None) => {}
            Err(err) => {
                warn!(error = %err, "failed to refresh policy from server");
            }
        }
        Ok(())
    }

    fn apply_policy_from_server(&mut self, policy: PolicyEnvelope) {
        let mut policy_changed = self.apply_policy_metadata_fields(&policy);
        self.apply_compliance_policy_document(&policy, &mut policy_changed);
        self.apply_policy_json_runtime_overrides(&policy.policy_json);

        if policy_changed {
            self.last_compliance_checked_unix = None;
            self.last_compliance_result = None;
        }

        if update_tls_policy_from_server(&mut self.config, &policy)
            && self.client.is_tls_configured()
        {
            if let (Some(cert), Some(key), Some(ca)) = (
                self.config.tls_cert_path.clone(),
                self.config.tls_key_path.clone(),
                self.config.tls_ca_path.clone(),
            ) {
                if let Err(err) = self.client.configure_tls(TlsConfig {
                    cert_path: cert,
                    key_path: key,
                    ca_path: ca,
                    pinned_ca_sha256: self.config.tls_pinned_ca_sha256.clone(),
                    ca_pin_path: self.config.tls_ca_pin_path.clone(),
                }) {
                    warn!(error = %err, "failed to apply updated TLS policy");
                }
            }
        }
    }

    fn apply_policy_metadata_fields(&mut self, policy: &PolicyEnvelope) -> bool {
        let mut policy_changed = false;

        if !policy.policy_id.trim().is_empty() && self.compliance_policy_id != policy.policy_id {
            self.compliance_policy_id = policy.policy_id.clone();
            policy_changed = true;
        }
        if !policy.policy_version.trim().is_empty()
            && self.compliance_policy_version != policy.policy_version
        {
            self.compliance_policy_version = policy.policy_version.clone();
            policy_changed = true;
        } else if !policy.config_version.trim().is_empty()
            && self.compliance_policy_version != policy.config_version
        {
            self.compliance_policy_version = policy.config_version.clone();
            policy_changed = true;
        }

        if !policy.policy_hash.trim().is_empty()
            && self.compliance_policy_hash != policy.policy_hash
        {
            self.compliance_policy_hash = policy.policy_hash.clone();
            policy_changed = true;
        }
        if !policy.policy_signature.trim().is_empty()
            && self.compliance_policy_signature != policy.policy_signature
        {
            self.compliance_policy_signature = policy.policy_signature.clone();
            policy_changed = true;
        }
        if !policy.schema_version.trim().is_empty()
            && self.compliance_policy_schema_version != policy.schema_version
        {
            self.compliance_policy_schema_version = policy.schema_version.clone();
            policy_changed = true;
        }

        policy_changed
    }

    fn apply_compliance_policy_document(
        &mut self,
        policy: &PolicyEnvelope,
        policy_changed: &mut bool,
    ) {
        if policy.policy_json.trim().is_empty() {
            return;
        }

        if !super::super::policy::verify_policy_envelope(policy) {
            warn!("policy verification failed; keeping current policy");
            return;
        }

        match parse_policy_json(&policy.policy_json) {
            Ok(parsed) => {
                info!(
                    firewall = parsed.firewall_required,
                    kernel_prefix = ?parsed.min_kernel_prefix,
                    disk_enc = parsed.disk_encryption_required,
                    ssh_root = parsed.require_ssh_root_login_disabled,
                    password_policy = parsed.password_policy_required,
                    screen_lock = parsed.screen_lock_required,
                    auto_updates = parsed.auto_updates_required,
                    antivirus = parsed.antivirus_required,
                    "compliance policy updated from server"
                );
                self.compliance_policy = parsed;
                *policy_changed = true;
            }
            Err(err) => {
                warn!(error = %err, "invalid compliance policy JSON from server; keeping current");
            }
        }
    }

    fn apply_policy_json_runtime_overrides(&mut self, policy_json: &str) {
        if policy_json.trim().is_empty() {
            return;
        }

        let Ok(raw) = serde_json::from_str::<serde_json::Value>(policy_json) else {
            return;
        };

        self.apply_detection_allowlist_override(&raw);
        self.apply_baseline_policy_overrides(&raw);
        self.apply_runtime_tuning_overrides(&raw);
        self.apply_bundle_key_override(&raw);
        self.apply_feature_policy_overrides(&raw);
    }

    fn apply_detection_allowlist_override(&mut self, raw: &serde_json::Value) {
        let Some(allowlist_obj) = raw.get("detection_allowlist") else {
            return;
        };

        let processes: Vec<String> = allowlist_obj
            .get("processes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let path_prefixes: Vec<String> = allowlist_obj
            .get("path_prefixes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        info!(
            processes_count = processes.len(),
            path_prefixes_count = path_prefixes.len(),
            "applying detection allowlist from policy"
        );
        if let Err(err) = self
            .detection_state
            .update_allowlist(processes, path_prefixes)
        {
            warn!(error = %err, "failed to update detection allowlist");
        }
    }

    fn apply_baseline_policy_overrides(&mut self, raw: &serde_json::Value) {
        // Baseline mode — server can force-skip the learning window.
        if let Some(mode) = raw.get("baseline_mode").and_then(|v| v.as_str()) {
            match mode {
                "force_active" | "skip_learning" => {
                    if matches!(self.baseline_store.status, BaselineStatus::Learning) {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        self.baseline_store.force_active(now);
                        if !matches!(self.runtime_mode, AgentMode::Degraded) {
                            self.runtime_mode = AgentMode::Active;
                        }
                        info!(
                            baseline_mode = mode,
                            "baseline forced to Active via server policy"
                        );
                        if let Err(err) = self.baseline_store.save() {
                            warn!(error = %err, "failed to persist baseline after force_active");
                        }
                    }
                }
                "default" | "" => {} // natural progression
                other => warn!(baseline_mode = other, "unknown baseline_mode in policy"),
            }
        }

        if let Some(upload_enabled) = raw.get("baseline_upload_enabled").and_then(|v| v.as_bool()) {
            self.baseline_upload_enabled = upload_enabled;
            info!(
                baseline_upload_enabled = upload_enabled,
                "updated baseline upload flag from policy"
            );
        }

        if let Some(seed_enabled) = raw.get("fleet_seed_enabled").and_then(|v| v.as_bool()) {
            self.fleet_seed_enabled = seed_enabled;
            info!(
                fleet_seed_enabled = seed_enabled,
                "updated fleet-seed flag from policy"
            );
        }

        if let Some(upload_canary) = raw
            .get("baseline_upload_canary_percent")
            .and_then(|v| v.as_u64())
        {
            self.baseline_upload_canary_percent = upload_canary.min(100) as u8;
            info!(
                baseline_upload_canary_percent = self.baseline_upload_canary_percent,
                "updated baseline upload canary percent from policy"
            );
        }

        if let Some(seed_canary) = raw
            .get("fleet_seed_canary_percent")
            .and_then(|v| v.as_u64())
        {
            self.fleet_seed_canary_percent = seed_canary.min(100) as u8;
            info!(
                fleet_seed_canary_percent = self.fleet_seed_canary_percent,
                "updated fleet-seed canary percent from policy"
            );
        }
    }

    fn apply_runtime_tuning_overrides(&mut self, raw: &serde_json::Value) {
        if let Some(arr) = raw
            .get("detection_expensive_check_excluded_paths")
            .or_else(|| raw.get("detection_hot_path_exclusions"))
        {
            if let Some(paths) = parse_string_vec_or_csv(arr) {
                self.expensive_check_excluded_paths = paths;
            }
            self.enrichment_cache.set_expensive_check_exclusions(
                self.expensive_check_excluded_paths.clone(),
                self.expensive_check_excluded_processes.clone(),
            );
            info!(
                count = self.expensive_check_excluded_paths.len(),
                "updated expensive-check path exclusions from policy"
            );
        }

        if let Some(arr) = raw
            .get("detection_expensive_check_excluded_processes")
            .or_else(|| raw.get("detection_hot_process_exclusions"))
        {
            if let Some(processes) = parse_string_vec_or_csv(arr) {
                self.expensive_check_excluded_processes = processes;
            }
            self.enrichment_cache.set_expensive_check_exclusions(
                self.expensive_check_excluded_paths.clone(),
                self.expensive_check_excluded_processes.clone(),
            );
            info!(
                count = self.expensive_check_excluded_processes.len(),
                "updated expensive-check process exclusions from policy"
            );
        }

        if let Some(ms) = raw
            .get("file_event_coalesce_window_ms")
            .and_then(|v| v.as_u64())
        {
            self.file_event_coalesce_window_ns = ms.max(50).saturating_mul(1_000_000);
            info!(
                file_event_coalesce_window_ms = ms.max(50),
                "updated file-event coalesce window from policy"
            );
        }

        if let Some(value) = raw
            .get("strict_budget_pending_threshold")
            .and_then(|v| v.as_u64())
        {
            self.strict_budget_pending_threshold = (value as usize).max(64);
            info!(
                strict_budget_pending_threshold = self.strict_budget_pending_threshold,
                "updated strict-budget pending threshold from policy"
            );
        }

        if let Some(value) = raw
            .get("strict_budget_raw_backlog_threshold")
            .and_then(|v| v.as_u64())
        {
            self.strict_budget_raw_backlog_threshold = (value as usize).max(32);
            info!(
                strict_budget_raw_backlog_threshold = self.strict_budget_raw_backlog_threshold,
                "updated strict-budget raw backlog threshold from policy"
            );
        }

        if let Some(value) = raw
            .get("raw_event_backlog_cap")
            .or_else(|| raw.get("detection_raw_event_backlog_cap"))
            .and_then(|v| v.as_u64())
        {
            self.raw_event_backlog_cap = (value as usize).max(256);
            info!(
                raw_event_backlog_cap = self.raw_event_backlog_cap,
                "updated raw-event backlog cap from policy"
            );
        }
    }

    fn apply_bundle_key_override(&mut self, raw: &serde_json::Value) {
        // Bundle public key — server distributes Ed25519 key via policy.
        if let Some(key_hex) = raw.get("bundle_public_key").and_then(|v| v.as_str()) {
            let key_hex = key_hex.trim();
            if !key_hex.is_empty() && key_hex.len() == 64 {
                // SAFETY: set_var is acceptable here because this runs on the single
                // runtime tick thread and the key is validated by the bundle verifier.
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::set_var("EGUARD_RULE_BUNDLE_PUBKEY", key_hex);
                }
                info!("bundle public key updated from server policy");
            }
        }
    }

    fn apply_feature_policy_overrides(&mut self, raw: &serde_json::Value) {
        // --- Feature policy: FIM ---
        if let Some(v) = raw.get("fim_enabled").and_then(|v| v.as_bool()) {
            self.fim_policy.enabled = v;
            info!(fim_enabled = v, "updated FIM enabled from policy");
        }
        if let Some(arr) = raw.get("fim_watched_paths") {
            if let Some(paths) = parse_string_vec_or_csv(arr) {
                self.fim_policy.watched_paths = paths;
            }
            info!(
                count = self.fim_policy.watched_paths.len(),
                "updated FIM watched paths from policy"
            );
        }
        if let Some(arr) = raw.get("fim_excluded_paths") {
            if let Some(paths) = parse_string_vec_or_csv(arr) {
                self.fim_policy.excluded_paths = paths;
            }
            info!(
                count = self.fim_policy.excluded_paths.len(),
                "updated FIM excluded paths from policy"
            );
        }
        if let Some(v) = raw.get("fim_scan_interval_secs").and_then(|v| v.as_u64()) {
            self.fim_policy.scan_interval_secs = v.max(60);
            info!(
                fim_scan_interval_secs = self.fim_policy.scan_interval_secs,
                "updated FIM scan interval from policy"
            );
        }

        // --- Feature policy: USB Control ---
        if let Some(v) = raw.get("usb_storage_blocked").and_then(|v| v.as_bool()) {
            self.usb_policy.storage_blocked = v;
            info!(
                usb_storage_blocked = v,
                "updated USB storage blocked from policy"
            );
        }
        if let Some(v) = raw.get("usb_network_blocked").and_then(|v| v.as_bool()) {
            self.usb_policy.network_blocked = v;
            info!(
                usb_network_blocked = v,
                "updated USB network blocked from policy"
            );
        }
        if let Some(v) = raw.get("usb_log_all").and_then(|v| v.as_bool()) {
            self.usb_policy.log_all = v;
            info!(usb_log_all = v, "updated USB log all from policy");
        }
        if let Some(arr) = raw.get("usb_allowed_vendor_ids") {
            if let Some(ids) = parse_string_vec_or_csv(arr) {
                self.usb_policy.allowed_vendor_ids = ids;
            }
            info!(
                count = self.usb_policy.allowed_vendor_ids.len(),
                "updated USB allowed vendor IDs from policy"
            );
        }

        // --- Feature policy: Deception ---
        if let Some(v) = raw.get("deception_enabled").and_then(|v| v.as_bool()) {
            self.deception_policy.enabled = v;
            info!(
                deception_enabled = v,
                "updated deception enabled from policy"
            );
        }
        if let Some(arr) = raw.get("deception_custom_paths") {
            if let Some(paths) = parse_string_vec_or_csv(arr) {
                self.deception_policy.custom_paths = paths;
            }
            info!(
                count = self.deception_policy.custom_paths.len(),
                "updated deception custom paths from policy"
            );
        }

        // --- Feature policy: Threat Hunting ---
        if let Some(v) = raw.get("hunting_enabled").and_then(|v| v.as_bool()) {
            self.hunting_policy.enabled = v;
            info!(hunting_enabled = v, "updated hunting enabled from policy");
        }
        if let Some(v) = raw.get("hunting_interval_secs").and_then(|v| v.as_u64()) {
            self.hunting_policy.interval_secs = v.max(300);
            info!(
                hunting_interval_secs = self.hunting_policy.interval_secs,
                "updated hunting interval from policy"
            );
        }

        // --- Feature policy: Zero Trust ---
        if let Some(v) = raw.get("zero_trust_enabled").and_then(|v| v.as_bool()) {
            self.zero_trust_policy.enabled = v;
            info!(
                zero_trust_enabled = v,
                "updated zero trust enabled from policy"
            );
        }
        if let Some(v) = raw
            .get("zero_trust_quarantine_threshold")
            .and_then(|v| v.as_u64())
        {
            self.zero_trust_policy.quarantine_threshold = v.min(100) as u8;
            info!(
                zero_trust_quarantine_threshold = self.zero_trust_policy.quarantine_threshold,
                "updated zero trust quarantine threshold from policy"
            );
        }
        if let Some(v) = raw
            .get("zero_trust_restrict_threshold")
            .and_then(|v| v.as_u64())
        {
            self.zero_trust_policy.restrict_threshold = v.min(100) as u8;
            info!(
                zero_trust_restrict_threshold = self.zero_trust_policy.restrict_threshold,
                "updated zero trust restrict threshold from policy"
            );
        }
    }
}

fn parse_string_vec_or_csv(value: &serde_json::Value) -> Option<Vec<String>> {
    if let Ok(values) = serde_json::from_value::<Vec<String>>(value.clone()) {
        return Some(values);
    }

    value.as_str().map(|csv| {
        csv.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}
