//! Root service for the fixed bundled Kanata runtime.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::{runtime::Runtime, storage};
use anyhow::{Context, Result, ensure};
use ikanata_core::{State, response};
use ikanata_native::{Caller, Operation};

static RUNTIME: OnceLock<Mutex<Runtime>> = OnceLock::new();

fn handle(operation: Operation, caller: Caller) -> String {
    let Some(runtime) = RUNTIME.get() else {
        return response(false, State::SetupRequired, "service is initializing");
    };
    match runtime.lock() {
        Ok(mut runtime) => runtime.operation(operation, caller),
        Err(_) => response(
            false,
            State::Stopped,
            "service state is unavailable; reinstall the signed application",
        ),
    }
}

/// Run the authenticated root service on the process's main thread.
///
/// The caller must initialize diagnostics before starting the service.
pub fn run() -> Result<()> {
    ensure!(
        ikanata_native::effective_uid() == 0,
        "The service must run through its approved launch daemon"
    );
    tracing::info!("privileged service initializing");
    storage::check_directory().context("The protected runtime installation is invalid")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(0x100)
        .open(format!("{}/service.lock", storage::DIRECTORY))
        .context("Cannot open the service lock")?;
    ikanata_native::lock_file(&lock).context("Another service instance is active")?;
    let runtime = Runtime::new().context("Cannot restore service enrollment")?;
    RUNTIME
        .set(Mutex::new(runtime))
        .map_err(|_| anyhow::anyhow!("Service initialized twice"))?;
    std::thread::Builder::new()
        .name("session-observer".into())
        .spawn(|| {
            loop {
                std::thread::sleep(Duration::from_millis(250));
                let Some(runtime) = RUNTIME.get() else { return };
                let Ok(mut runtime) = runtime.lock() else {
                    return;
                };
                if let Err(error) = runtime.tick() {
                    tracing::warn!(%error, "runtime observation failed");
                }
            }
        })
        .context("Cannot start session observation")?;
    tracing::info!("privileged service started");
    ikanata_native::serve(handle, |accepted| {
        tracing::trace!(accepted, "native peer authentication result");
    })
    .context("Native service listener failed")
}
