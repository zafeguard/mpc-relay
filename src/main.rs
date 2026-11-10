use std::process::ExitCode;

use mpc_relay::config::{Config, KeySource, LogFormat};
use tracing_subscriber::EnvFilter;

fn init_tracing(format: &LogFormat) {
    // pinky_swear (lapin's promises) warns whenever a publisher confirm
    // arrives after its waiter has gone, which is routine under load.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,pinky_swear=error"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Json => builder.json().flatten_event(true).init(),
        LogFormat::Text => builder.init(),
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Some(arg) = std::env::args().nth(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("mpc-relay {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!(
                    "mpc-relay {}\n\nConfigured entirely by MPC_RELAY_* environment variables; see the README.\nUsage: mpc-relay [--version]",
                    env!("CARGO_PKG_VERSION")
                );
                return ExitCode::from(if arg == "--help" || arg == "-h" { 0 } else { 2 });
            }
        }
    }
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mpc-relay: configuration error: {e}");
            return ExitCode::from(2);
        }
    };
    init_tracing(&config.log_format);
    if let KeySource::Disabled = config.auth.source {
        tracing::warn!("**************************************************************");
        tracing::warn!("MPC_RELAY_AUTH=none: AUTHENTICATION IS DISABLED.");
        tracing::warn!("Any client can claim any node id. Development use only.");
        tracing::warn!("**************************************************************");
    }
    let relay = match mpc_relay::server::start(config).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to start");
            return ExitCode::FAILURE;
        }
    };
    wait_for_signal().await;
    tracing::info!("signal received; shutting down");
    relay.shutdown().await;
    ExitCode::SUCCESS
}
