mod config;
mod detection_state;
mod lifecycle;

use anyhow::Result;
use tokio::signal;
use tokio::time::{self, Duration};
use tracing::info;

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

    let mut tick = time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or_default();
                runtime.tick(now).await?;
            }
            _ = signal::ctrl_c() => {
                info!("shutdown signal received");
                break;
            }
        }
    }

    info!("eguard-agent stopped");
    Ok(())
}
