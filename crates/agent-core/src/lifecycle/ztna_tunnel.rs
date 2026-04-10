use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use tracing::{info, warn};
use ztna::{resolve_or_create_wireguard_identity, LocalForwardManager, TunnelRequest};

use super::{interval_due, AgentRuntime};

impl AgentRuntime {
    pub(super) async fn release_ztna_session(&mut self, detail: &str) {
        let session_id = self.ztna_last_session_id.clone();
        if let (Some(client), Some(session_id)) = (self.ztna_client.as_ref(), session_id.as_ref()) {
            if let Err(err) = client.release_tunnel(session_id).await {
                warn!(session_id = %session_id, error = %err, "failed to release ztna session");
            }
        }
        self.ztna_last_outcome = Some(detail.to_string());
    }

    pub(super) async fn teardown_idle_ztna_session_if_needed(&mut self, now_unix: i64) {
        let Some(forward) = self.ztna_forward.as_ref() else {
            return;
        };
        if self.config.ztna_idle_timeout_secs == 0 {
            return;
        }
        if forward.active_connections() > 0 {
            return;
        }
        let last_activity_unix = forward.last_activity_unix();
        if last_activity_unix <= 0 {
            return;
        }
        if now_unix.saturating_sub(last_activity_unix) < self.config.ztna_idle_timeout_secs as i64 {
            return;
        }

        self.stop_ztna_session(Some("idle timeout reached")).await;
    }

    pub(super) fn ensure_ztna_wireguard_identity(&mut self) -> Result<()> {
        if !self.config.ztna_enabled {
            return Ok(());
        }
        if self
            .config
            .ztna_agent_wg_public_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_some()
        {
            return Ok(());
        }

        let data_dir = resolve_agent_data_dir();
        let identity = resolve_or_create_wireguard_identity(&self.config.agent_id, &data_dir)?;
        info!(
            backend = %identity.storage_backend,
            path = ?identity.storage_path,
            "ztna wireguard identity resolved"
        );
        self.config.ztna_agent_wg_public_key = Some(identity.public_key_b64);
        Ok(())
    }

    pub(super) async fn ensure_ztna_tunnel_if_due(&mut self, now_unix: i64) -> Result<()> {
        if !self.config.ztna_enabled {
            return Ok(());
        }
        if self.ztna_client.is_none() {
            return Ok(());
        }
        if self.ztna_forward.is_some() {
            return Ok(());
        }
        if !interval_due(
            self.ztna_last_request_unix,
            now_unix,
            self.config.ztna_request_interval_secs as i64,
        ) {
            return Ok(());
        }

        let Some(app_id) = self
            .config
            .ztna_app_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            return Ok(());
        };
        let Some(agent_wg_public_key) = self
            .config
            .ztna_agent_wg_public_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            return Ok(());
        };

        self.ztna_last_request_unix = Some(now_unix);
        let req = TunnelRequest {
            agent_id: self.config.agent_id.clone(),
            app_id: app_id.to_string(),
            agent_wg_public_key: agent_wg_public_key.to_string(),
            forward_host: self.config.ztna_forward_host.clone(),
            forward_port: self.config.ztna_forward_port,
            preferred_transport: "wireguard".to_string(),
        };

        let decision = match self
            .ztna_client
            .as_ref()
            .expect("checked is_some")
            .request_tunnel(&req)
            .await
        {
            Ok(decision) => decision,
            Err(err) => {
                warn!(error = %err, "ztna tunnel request failed");
                return Ok(());
            }
        };

        let Some(grant) = decision.grant else {
            return Ok(());
        };

        let Some(forward_host) = self
            .config
            .ztna_forward_host
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            info!(session_id = %grant.session_id, "ztna tunnel granted without local forward target");
            self.ztna_last_session_id = Some(grant.session_id);
            return Ok(());
        };
        let Some(forward_port) = self.config.ztna_forward_port else {
            info!(session_id = %grant.session_id, "ztna tunnel granted without forward port");
            self.ztna_last_session_id = Some(grant.session_id);
            return Ok(());
        };

        let listen_addr: SocketAddr = self
            .config
            .ztna_local_bind_addr
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));
        let upstream = format!("{}:{}", forward_host, forward_port);
        let manager = LocalForwardManager;
        match manager.start(listen_addr, upstream.clone()).await {
            Ok(handle) => {
                info!(
                    session_id = %grant.session_id,
                    listen = %handle.listen_addr,
                    upstream = %upstream,
                    "ztna local forward started"
                );
                self.ztna_forward = Some(handle);
                self.ztna_last_session_id = Some(grant.session_id);
                self.ztna_last_outcome = Some(format!("connected via {}", grant.transport));
            }
            Err(err) => {
                warn!(error = %err, upstream = %upstream, "failed to start ztna local forward");
                self.ztna_last_outcome = Some(format!("local forward failed: {err}"));
            }
        }

        Ok(())
    }
}

fn resolve_agent_data_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("EGUARD_AGENT_DATA_DIR") {
        if !raw.trim().is_empty() {
            return PathBuf::from(raw.trim());
        }
    }

    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\ProgramData\eGuard");
    }

    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/eGuard");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/var/lib/eguard-agent")
    }
}
