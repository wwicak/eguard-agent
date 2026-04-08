mod app;

#[cfg(target_os = "macos")]
mod macos;

use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))?,
        )
        .with_ansi(false)
        .init();

    let args = std::env::args().skip(1).collect::<Vec<_>>();

    if let Some(first) = args.first() {
        if first.starts_with("eguard-ztna://") {
            return app::run_cli(args);
        }
        return app::run_cli(args);
    }

    #[cfg(target_os = "macos")]
    {
        return macos::run_menu_bar();
    }

    #[cfg(not(target_os = "macos"))]
    {
        app::run_cli(Vec::new())
    }
}
