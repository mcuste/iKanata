//! Command-line interface for iKanata.

mod args;
mod commands;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = args::Cli::parse();
    let verbose = cli.verbose;
    match ikanata_diagnostics::init("warn", verbose)
        .and_then(|()| commands::run(cli.command, verbose))
    {
        Ok(code) => code,
        Err(error) => {
            tracing::debug!(?error, "command failed");
            ikanata_diagnostics::report(
                &error,
                Some("Use ikanata --help for commands. Set IKANATA_LOG=trace for diagnostics."),
                verbose,
            );
            ExitCode::FAILURE
        }
    }
}
