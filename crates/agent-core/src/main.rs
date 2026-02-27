mod config;
mod detection_state;
mod lifecycle;
mod platform;
#[cfg(test)]
mod test_support;

use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::Once;
use tokio::signal;
use tokio::time::{self, Duration, MissedTickBehavior};
use tracing::{info, warn};

use config::AgentConfig;
use lifecycle::AgentRuntime;

type ShutdownFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        return windows_service_entry::run().await;
    }

    #[cfg(not(target_os = "windows"))]
    {
        run_console().await
    }
}

async fn run_console() -> Result<()> {
    run_console_with_shutdown(Box::pin(wait_for_shutdown_signal())).await
}

async fn run_console_with_shutdown(shutdown: ShutdownFuture) -> Result<()> {
    init_tracing();

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

    run_tick_loop(&mut runtime, shutdown).await;

    info!("eguard-agent stopped");
    Ok(())
}

async fn run_tick_loop(runtime: &mut AgentRuntime, shutdown: ShutdownFuture) {
    let mut tick = time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut shutdown = shutdown;

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
}

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(tracing_subscriber::fmt::init);
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

#[cfg(target_os = "windows")]
mod windows_service_entry {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;

    use anyhow::Result;
    use tokio::runtime::Builder;
    use tracing::{error, info, warn};
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::service_dispatcher;

    const SERVICE_NAME: &str = "eGuardAgent";

    define_windows_service!(ffi_service_main, service_main);

    pub async fn run() -> Result<()> {
        if super::env_flag_enabled("EGUARD_WINDOWS_CONSOLE") {
            info!("running eGuard in console mode (EGUARD_WINDOWS_CONSOLE enabled)");
            return super::run_console().await;
        }

        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to attach to Windows service dispatcher; falling back to console mode"
                );
                super::run_console().await
            }
        }
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(err) = run_service_main() {
            error!(error = %err, "Windows service main failed");
        }
    }

    fn run_service_main() -> Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        set_service_status(
            &status_handle,
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            1,
            15_000,
            0,
        )?;

        let runtime = Builder::new_multi_thread().enable_all().build()?;

        set_service_status(
            &status_handle,
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            0,
            0,
        )?;

        let run_result = runtime.block_on(async {
            super::run_console_with_shutdown(Box::pin(wait_for_service_shutdown(shutdown_rx))).await
        });

        let exit_code = if run_result.is_ok() { 0 } else { 1 };
        set_service_status(
            &status_handle,
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            1,
            10_000,
            exit_code,
        )?;
        set_service_status(
            &status_handle,
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            0,
            0,
            exit_code,
        )?;

        run_result
    }

    async fn wait_for_service_shutdown(rx: mpsc::Receiver<()>) {
        let _ = tokio::task::spawn_blocking(move || rx.recv()).await;
        info!("shutdown signal received (Windows service control)");
    }

    fn set_service_status(
        status_handle: &ServiceStatusHandle,
        current_state: ServiceState,
        controls_accepted: ServiceControlAccept,
        checkpoint: u32,
        wait_hint_ms: u32,
        win32_exit_code: u32,
    ) -> windows_service::Result<()> {
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted,
            exit_code: ServiceExitCode::Win32(win32_exit_code),
            checkpoint,
            wait_hint: Duration::from_millis(wait_hint_ms as u64),
            process_id: None,
        })
    }
}
