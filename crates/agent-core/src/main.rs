mod config;
mod detection_state;
mod lifecycle;
mod platform;
#[cfg(test)]
mod test_support;

use anyhow::Result;
use std::fs::OpenOptions;
use std::future::Future;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Once;
#[cfg(not(unix))]
use tokio::signal;
use tokio::time::{self, Duration, MissedTickBehavior};
use tracing::{info, warn};

use config::AgentConfig;
use lifecycle::AgentRuntime;

type ShutdownFuture = Pin<Box<dyn Future<Output = ShutdownReason> + Send>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownReason {
    SigInt,
    SigTerm,
    ServiceStop,
    CtrlC,
}

// NOTE: We intentionally do NOT use #[tokio::main] here.
//
// On Windows, service_dispatcher::start() is a blocking Win32 call
// (StartServiceCtrlDispatcherW) that must run on the main thread outside
// any async runtime context. It spawns the service entry point on a
// background thread, where we create the tokio runtime. Using
// #[tokio::main] would create a competing tokio runtime on the main
// thread, causing the second runtime's I/O driver (IOCP) to conflict
// and preventing SetServiceStatus(SERVICE_RUNNING) from being called
// within the 30-second SCM timeout.
fn main() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        return windows_service_entry::run();
    }

    #[cfg(not(target_os = "windows"))]
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(run_console())
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

    #[cfg(target_os = "linux")]
    let mut systemd_notifier = SystemdNotifier::from_env();
    #[cfg(target_os = "linux")]
    systemd_notifier.notify_ready();

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

    #[cfg(target_os = "linux")]
    let shutdown_reason = run_tick_loop(&mut runtime, shutdown, &mut systemd_notifier).await;
    #[cfg(not(target_os = "linux"))]
    let shutdown_reason = run_tick_loop(&mut runtime, shutdown).await;

    if matches!(shutdown_reason, ShutdownReason::SigTerm) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        if let Err(err) = runtime.report_shutdown_tamper(now, "sigterm").await {
            warn!(error = %err, "failed to emit shutdown tamper alert");
        }
    }

    #[cfg(target_os = "linux")]
    systemd_notifier.notify_stopping();

    info!(reason = ?shutdown_reason, "eguard-agent stopped");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_tick_loop(
    runtime: &mut AgentRuntime,
    shutdown: ShutdownFuture,
    systemd_notifier: &mut SystemdNotifier,
) -> ShutdownReason {
    let mut tick = time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            reason = &mut shutdown => {
                return reason;
            }
            _ = tick.tick() => {
                systemd_notifier.notify_watchdog_if_due();
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

#[cfg(not(target_os = "linux"))]
async fn run_tick_loop(runtime: &mut AgentRuntime, shutdown: ShutdownFuture) -> ShutdownReason {
    let mut tick = time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            reason = &mut shutdown => {
                return reason;
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

/// Shared initialization guard: ensures tracing is only set up once, regardless
/// of whether the first call is `init_tracing()` (stderr) or
/// `init_tracing_to_file()` (log file for Windows service mode).
static TRACING_INIT: Once = Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
            .expect("default tracing filter should be valid");

        if let Some(log_path) = configured_log_path() {
            if let Some(parent) = log_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            match OpenOptions::new().create(true).append(true).open(&log_path) {
                Ok(file) => {
                    let writer = std::sync::Mutex::new(file);
                    tracing_subscriber::fmt()
                        .with_env_filter(env_filter)
                        .with_ansi(false)
                        .with_writer(writer)
                        .init();
                    return;
                }
                Err(_) => {
                    // Fall back to stderr if the log file can't be opened.
                }
            }
        }

        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .init();
    });
}

fn configured_log_path() -> Option<PathBuf> {
    if let Some(path) = env_path("EGUARD_LOG_PATH") {
        return Some(path);
    }

    #[cfg(target_os = "windows")]
    {
        return Some(PathBuf::from(r"C:\ProgramData\eGuard\logs\agent.log"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        return Some(PathBuf::from("/var/log/eguard-agent.log"));
    }

    #[allow(unreachable_code)]
    None
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
}

/// Initialize tracing with output directed to a log file. Used by the Windows
/// service path where stderr is not captured by SCM. Must be called before
/// `init_tracing()` so the file subscriber wins the `Once` guard.
#[cfg(target_os = "windows")]
fn init_tracing_to_file(log_path: &Path) {
    TRACING_INIT.call_once(|| {
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match OpenOptions::new().create(true).append(true).open(log_path) {
            Ok(file) => {
                let writer = std::sync::Mutex::new(file);
                let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
                    .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
                    .expect("default tracing filter should be valid");
                tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .with_writer(writer)
                    .with_ansi(false)
                    .init();
            }
            Err(_) => {
                // Fall back to stderr if the log file can't be opened.
                let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
                    .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
                    .expect("default tracing filter should be valid");
                tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .with_ansi(false)
                    .init();
            }
        }
    });
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

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct SystemdNotifier {
    notify_socket: Option<String>,
    watchdog_interval: Option<std::time::Duration>,
    next_watchdog_ping: Option<std::time::Instant>,
}

#[cfg(target_os = "linux")]
impl SystemdNotifier {
    fn from_env() -> Self {
        let mut notify_socket = std::env::var("NOTIFY_SOCKET")
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty());

        if notify_socket
            .as_deref()
            .map(|raw| raw.starts_with('@'))
            .unwrap_or(false)
        {
            if let Some(path) = notify_socket.as_deref() {
                warn!(
                    notify_socket = path,
                    "abstract NOTIFY_SOCKET is unsupported by built-in notifier"
                );
            }
            notify_socket = None;
        }

        let watchdog_interval = std::env::var("WATCHDOG_USEC")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|usec| *usec > 0)
            .map(|usec| {
                let half_usec = (usec / 2).max(1_000_000);
                std::time::Duration::from_micros(half_usec)
            });

        let next_watchdog_ping =
            watchdog_interval.map(|interval| std::time::Instant::now() + interval);

        Self {
            notify_socket,
            watchdog_interval,
            next_watchdog_ping,
        }
    }

    fn notify_ready(&mut self) {
        let _ = self.send("READY=1\nSTATUS=eGuard agent runtime online");
        if let Some(interval) = self.watchdog_interval {
            self.next_watchdog_ping = Some(std::time::Instant::now() + interval);
        }
    }

    fn notify_watchdog_if_due(&mut self) {
        let Some(interval) = self.watchdog_interval else {
            return;
        };

        let now = std::time::Instant::now();
        let Some(next) = self.next_watchdog_ping else {
            self.next_watchdog_ping = Some(now + interval);
            return;
        };

        if now < next {
            return;
        }

        if self.send("WATCHDOG=1").is_ok() {
            self.next_watchdog_ping = Some(now + interval);
        } else {
            self.next_watchdog_ping = Some(now + std::time::Duration::from_secs(1));
        }
    }

    fn notify_stopping(&self) {
        let _ = self.send("STOPPING=1\nSTATUS=eGuard agent shutting down");
    }

    fn send(&self, message: &str) -> std::io::Result<()> {
        let Some(socket_path) = self.notify_socket.as_deref() else {
            return Ok(());
        };

        use std::os::unix::net::UnixDatagram;
        let socket = UnixDatagram::unbound()?;
        let _ = socket.send_to(message.as_bytes(), socket_path)?;
        Ok(())
    }
}

async fn wait_for_shutdown_signal() -> ShutdownReason {
    #[cfg(unix)]
    {
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("register SIGINT handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("register SIGTERM handler");
        tokio::select! {
            _ = sigint.recv() => {
                info!("shutdown signal received (SIGINT)");
                ShutdownReason::SigInt
            }
            _ = sigterm.recv() => {
                info!("shutdown signal received (SIGTERM)");
                ShutdownReason::SigTerm
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
        info!("shutdown signal received");
        ShutdownReason::CtrlC
    }
}

#[cfg(target_os = "windows")]
mod windows_service_entry {
    use std::ffi::OsString;
    use std::sync::{mpsc, Arc, Mutex};
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

    pub fn run() -> Result<()> {
        // Console mode: run directly with a tokio runtime (no SCM).
        if super::env_flag_enabled("EGUARD_WINDOWS_CONSOLE") {
            let runtime = Builder::new_multi_thread().enable_all().build()?;
            return runtime.block_on(super::run_console());
        }

        // Service mode: service_dispatcher::start() is a blocking Win32 call
        // (StartServiceCtrlDispatcherW) that must run on the main thread
        // outside any async runtime. It spawns service_main on a background
        // thread, which creates its own tokio runtime.
        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(()),
            Err(err) => {
                super::init_tracing();
                warn!(
                    error = %err,
                    "failed to attach to Windows service dispatcher; falling back to console mode"
                );
                let runtime = Builder::new_multi_thread().enable_all().build()?;
                runtime.block_on(super::run_console())
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
        let allow_stop_control = resolve_windows_service_stop_control_policy_fast();

        // Share the status handle with the event handler closure so it can
        // immediately transition to StopPending when SCM sends Stop/Shutdown.
        // Without this, SCM times out waiting for the status change and
        // Restart-Service / Stop-Service fails.
        let shared_status_handle: Arc<Mutex<Option<ServiceStatusHandle>>> =
            Arc::new(Mutex::new(None));
        let handler_status_handle = Arc::clone(&shared_status_handle);

        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => {
                    if !allow_stop_control {
                        warn!(
                            "ignoring Windows service stop control due to self-protection policy"
                        );
                        return ServiceControlHandlerResult::NotImplemented;
                    }

                    // Immediately tell SCM we are stopping. This must happen
                    // inside the handler callback for SCM to accept the stop.
                    if let Ok(guard) = handler_status_handle.lock() {
                        if let Some(handle) = guard.as_ref() {
                            let _ = handle.set_service_status(ServiceStatus {
                                service_type: ServiceType::OWN_PROCESS,
                                current_state: ServiceState::StopPending,
                                controls_accepted: ServiceControlAccept::empty(),
                                exit_code: ServiceExitCode::Win32(0),
                                checkpoint: 1,
                                wait_hint: Duration::from_secs(15),
                                process_id: None,
                            });
                        }
                    }
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Shutdown => {
                    if let Ok(guard) = handler_status_handle.lock() {
                        if let Some(handle) = guard.as_ref() {
                            let _ = handle.set_service_status(ServiceStatus {
                                service_type: ServiceType::OWN_PROCESS,
                                current_state: ServiceState::StopPending,
                                controls_accepted: ServiceControlAccept::empty(),
                                exit_code: ServiceExitCode::Win32(0),
                                checkpoint: 1,
                                wait_hint: Duration::from_secs(15),
                                process_id: None,
                            });
                        }
                    }
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        // Store handle so the event handler closure can use it.
        if let Ok(mut guard) = shared_status_handle.lock() {
            *guard = Some(status_handle.clone());
        }

        // Initialize file-based tracing before anything else logs. Windows SCM
        // does not capture stderr, so service mode must write to a log file.
        let log_path = crate::lifecycle::resolve_logs_dir().join("agent.log");
        crate::lifecycle::prepare_managed_log_file(&log_path);
        super::init_tracing_to_file(&log_path);

        set_service_status(
            &status_handle,
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            1,
            15_000,
            0,
        )?;

        let runtime = Builder::new_multi_thread().enable_all().build()?;

        let controls_accepted = if allow_stop_control {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::SHUTDOWN
        };

        set_service_status(
            &status_handle,
            ServiceState::Running,
            controls_accepted,
            0,
            0,
            0,
        )?;

        let run_result = runtime.block_on(async {
            super::run_console_with_shutdown(Box::pin(wait_for_service_shutdown(shutdown_rx))).await
        });

        let exit_code = if run_result.is_ok() { 0 } else { 1 };
        // Checkpoint 2: the handler already set StopPending(checkpoint=1).
        set_service_status(
            &status_handle,
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            2,
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

    fn resolve_windows_service_stop_control_policy_fast() -> bool {
        if std::env::var_os("EGUARD_WINDOWS_ALLOW_STOP").is_some() {
            return super::env_flag_enabled("EGUARD_WINDOWS_ALLOW_STOP");
        }

        // Do not load AgentConfig here. Windows SCM requires the service process
        // to connect and report status promptly; first-enrollment bootstrap and
        // config recovery can perform filesystem/network work and previously
        // caused service start timeouts before SERVICE_RUNNING was reported.
        // Once the runtime is online, self-protection still handles tamper and
        // stop reporting through the normal tick loop.
        true
    }

    async fn wait_for_service_shutdown(rx: mpsc::Receiver<()>) -> super::ShutdownReason {
        let _ = tokio::task::spawn_blocking(move || rx.recv()).await;
        info!("shutdown signal received (Windows service control)");
        super::ShutdownReason::ServiceStop
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
