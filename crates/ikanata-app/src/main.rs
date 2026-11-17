//! Native background application and first-run guidance.

mod removal;
mod setup;
mod watch;

use std::env;
use std::process::ExitCode;

use anyhow::{Result, ensure};

fn run(arguments: &[String]) -> Result<()> {
    ensure!(
        ikanata_native::effective_uid() != 0
            || (arguments.len() == 1 && arguments.first().is_some_and(|value| value == "service")),
        "Root may run only the privileged service"
    );
    match arguments.first().map(String::as_str) {
        Some("service") if arguments.len() == 1 => ikanata_service::run(),
        Some("setup") => {
            ensure!(
                arguments
                    .iter()
                    .skip(1)
                    .all(|value| matches!(value.as_str(), "--install-driver" | "--enable-startup")),
                "Unsupported setup option"
            );
            setup::run(
                arguments.iter().any(|value| value == "--install-driver"),
                arguments.iter().any(|value| value == "--enable-startup"),
            )?;
            Ok(())
        }
        Some("refresh-service") if arguments.len() == 1 => setup::refresh_service_registration(),
        Some("uninstall") => {
            ensure!(
                arguments.iter().skip(1).all(|value| matches!(
                    value.as_str(),
                    "--keep-app" | "--remove-driver" | "--remove-config"
                )),
                "Unsupported uninstall option"
            );
            removal::run(
                arguments.iter().any(|value| value == "--keep-app"),
                arguments.iter().any(|value| value == "--remove-driver"),
                arguments.iter().any(|value| value == "--remove-config"),
            )
        }
        Some("watch") if arguments.len() == 1 => watch::run(false, false),
        Some("onboard") if arguments.len() == 1 => watch::run(false, true),
        Some("permissions-fallback") if arguments.len() == 1 => setup::manual_permissions(),
        None => watch::run(true, false),
        _ => anyhow::bail!("Unsupported app operation"),
    }
}

fn main() -> ExitCode {
    let mut arguments: Vec<String> = env::args().skip(1).collect();
    let verbose = arguments.iter().any(|argument| argument == "--verbose");
    arguments.retain(|argument| argument != "--verbose");
    let service_mode = arguments
        .first()
        .is_some_and(|argument| argument == "service");
    let root = ikanata_native::effective_uid() == 0;
    let level = if service_mode { "info" } else { "warn" };
    if let Err(error) = ikanata_diagnostics::init(level, verbose).and_then(|()| run(&arguments)) {
        if service_mode || root {
            ikanata_diagnostics::report(&error, None, verbose);
            return ExitCode::FAILURE;
        }
        ikanata_diagnostics::report(
            &error,
            Some("Use ikanata status to inspect setup and runtime state."),
            verbose,
        );
        if let Err(notification_error) =
            ikanata_native::notify("iKanata needs attention", &format!("{error:#}"))
        {
            tracing::debug!(%notification_error, "cannot display failure notification");
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
