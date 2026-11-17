use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "ikanata", version, about = "Manage iKanata keyboard remapping")]
pub(super) struct Cli {
    /// Show trace diagnostics.
    #[arg(long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub(super) enum Commands {
    /// Validate configuration and register approved services.
    Setup {
        /// Install the bundled driver through the approved root service.
        #[arg(long)]
        install_driver: bool,
        /// Enable the background app at login.
        #[arg(long)]
        enable_startup: bool,
    },
    /// Show setup and runtime state.
    Status,
    /// Start remapping for the enrolled user.
    Start,
    /// Stop until an explicit start.
    Stop,
    /// Validate and reload without restarting.
    Reload,
    /// Show sanitized lifecycle events.
    Logs,
    /// Remove iKanata and its owned driver, preserving keymaps by default.
    Uninstall {
        /// Leave the app bundle for the package manager to remove.
        #[arg(long)]
        keep_app: bool,
        /// Also remove `VirtualHID` when it was installed before iKanata.
        #[arg(long)]
        remove_driver: bool,
        /// Delete config.kbd and its directory only if empty, preserving other files.
        #[arg(long)]
        remove_config: bool,
    },
}
