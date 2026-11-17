use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, ensure};
use clap::CommandFactory;
use ikanata_native::Operation;

use crate::args::{Cli, Commands};

pub(super) fn run(command: Option<Commands>, verbose: bool) -> Result<ExitCode> {
    let Some(command) = command else {
        Cli::command().print_help()?;
        println!();
        return Ok(ExitCode::SUCCESS);
    };
    tracing::debug!(?command, "executing CLI command");
    let operation = match command {
        Commands::Setup {
            install_driver,
            enable_startup,
        } => {
            let arguments = [
                Some("setup"),
                install_driver.then_some("--install-driver"),
                enable_startup.then_some("--enable-startup"),
            ];
            return app_command(arguments.into_iter().flatten(), verbose);
        }
        Commands::Uninstall {
            keep_app,
            remove_driver,
            remove_config,
        } => {
            let arguments = [
                Some("uninstall"),
                keep_app.then_some("--keep-app"),
                remove_driver.then_some("--remove-driver"),
                remove_config.then_some("--remove-config"),
            ];
            return app_command(arguments.into_iter().flatten(), verbose);
        }
        Commands::Status => Operation::Status,
        Commands::Start => Operation::Start,
        Commands::Stop => Operation::Stop,
        Commands::Reload => Operation::Reload,
        Commands::Logs => Operation::Logs,
    };
    service_command(operation)?;
    Ok(ExitCode::SUCCESS)
}

fn app_command(
    arguments: impl IntoIterator<Item = &'static str>,
    verbose: bool,
) -> Result<ExitCode> {
    let executable = Path::new("/Applications/iKanata.app/Contents/MacOS/ikanata-app");
    ensure!(
        executable.is_file(),
        "iKanata is not installed. Install the local package before running setup"
    );
    let mut command = Command::new(executable);
    command.args(arguments);
    if verbose {
        command.arg("--verbose");
    }
    let status = command
        .status()
        .context("Cannot open the installed iKanata application")?;
    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn service_command(operation: Operation) -> Result<()> {
    if matches!(operation, Operation::Reload | Operation::Start) {
        let engine =
            ikanata_native::bundle_resource("kanata").context("The installed engine is missing")?;
        ikanata_native::verify_executable(&engine, "io.github.mcuste.ikanata.engine")
            .context("The installed engine signature is invalid")?;
        let home = ikanata_native::home_for_uid(ikanata_native::effective_uid())?;
        ikanata_config::validate(&engine, &ikanata_config::default_path(&home))
            .context("Cannot load your configuration. The active keymap remains unchanged")?;
    }
    tracing::debug!(?operation, "requesting native service operation");
    let reply = ikanata_native::request(operation)
        .context("Cannot contact the approved iKanata service. Run ikanata setup and check Login Items & Extensions")?;
    let mut lines = reply.lines().skip(1);
    let state = lines
        .next()
        .unwrap_or("state=unknown")
        .trim_start_matches("state=")
        .replace('_', " ");
    let detail = lines
        .map(|line| {
            if operation != Operation::Status {
                return line;
            }
            match line {
                "accessibility=granted" => "Accessibility: approved",
                "accessibility=missing" => "Accessibility: approval needed",
                "input_monitoring=granted" => "Input Monitoring: approved",
                "input_monitoring=missing" => "Input Monitoring: approval needed",
                _ => line,
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    ensure!(ikanata_core::succeeded(&reply), "{state}: {detail}");
    if operation == Operation::Logs {
        println!("{detail}");
    } else {
        let message = format!("iKanata: {state}\n{detail}");
        if operation != Operation::Status || state == "running" {
            cliclack::log::success(message)?;
        } else if matches!(state.as_str(), "stopped" | "paused") {
            cliclack::log::info(message)?;
        } else {
            cliclack::log::warning(message)?;
        }
    }
    Ok(())
}
