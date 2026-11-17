use std::io::{self, IsTerminal};
use tracing_subscriber::EnvFilter;

/// Configure structured diagnostics on stderr, using `IKANATA_LOG` when set.
pub fn init(default: &str, verbose: bool) -> anyhow::Result<()> {
    let fallback = if verbose { "trace" } else { default };
    let filter =
        EnvFilter::try_from_env("IKANATA_LOG").unwrap_or_else(|_| EnvFilter::new(fallback));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .with_target(verbose)
        .with_thread_ids(verbose)
        .try_init()
        .map_err(|error| anyhow::anyhow!("Cannot initialize diagnostic logging: {error}"))
}

/// Print an actionable error without a backtrace unless verbose output is enabled.
pub fn report(error: &anyhow::Error, hint: Option<&str>, verbose: bool) {
    let message = if verbose {
        format!("{error:?}")
    } else {
        format!("{error}")
    };
    if cliclack::log::error(message).is_err() {
        eprintln!("error: {error}");
    }
    if let Some(hint) = hint {
        if cliclack::log::remark(hint).is_err() {
            eprintln!("{hint}");
        }
    }
}
