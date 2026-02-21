mod config;
mod detection_state;
mod lifecycle;
mod platform;
#[cfg(test)]
mod test_support;

use anyhow::Result;
use tokio::signal;
use tokio::time::{self, Duration, MissedTickBehavior};
use tracing::{info, warn};

use config::AgentConfig;
use lifecycle::AgentRuntime;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let config = AgentConfig::load()?;
    let mut runtime = AgentRuntime::new(config.clone())?;

    info!(
        agent_id = %config.agent_id,
        mac = %config.mac,
        server = %config.server_addr,
        transport = %config.transport_mode,
        tls_configured = config.tls_cert_path.is_some() && config.tls_key_path.is_some() && config.tls_ca_path.is_some(),
        "eguard-agent core started"
    );

    if env_flag_enabled("EGUARD_SELF_PROTECT_RUN_ONCE") {
        if let Some(delay_secs) = env_u64("EGUARD_SELF_PROTECT_RUN_ONCE_DELAY_SECS") {
            time::sleep(Duration::from_secs(delay_secs)).await;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        runtime.run_self_protection_if_due(now).await?;
        info!("self-protect run-once completed");
        return Ok(());
    }

    let mut tick = time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            _ = tick.tick() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or_default();
                if let Err(err) = runtime.tick(now).await {
                    warn!(error = %err, "runtime tick failed; continuing");
                }
            }
        }
    }

    info!("eguard-agent stopped");
    Ok(())
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("register SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("shutdown signal received (SIGINT)");
            }
            _ = sigterm.recv() => {
                info!("shutdown signal received (SIGTERM)");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
        info!("shutdown signal received");
    }
}
