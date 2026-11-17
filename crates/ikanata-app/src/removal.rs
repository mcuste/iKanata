use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use ikanata_native::Operation;

use crate::setup;

const MANAGER: &str = "/Applications/.Karabiner-VirtualHIDDevice-Manager.app/Contents/MacOS/Karabiner-VirtualHIDDevice-Manager";
const EXTENSION: &str = "org.pqrs.Karabiner-DriverKit-VirtualHIDDevice";

pub(super) fn run(keep_app: bool, remove_driver: bool, remove_config: bool) -> Result<()> {
    let uid = ikanata_native::effective_uid();
    ensure!(uid != 0, "Run uninstall as your normal login user");
    let home = ikanata_native::home_for_uid(uid)?;
    let cache = home.join("Library/Caches/io.github.mcuste.ikanata");
    let _observer_lock = stop_observer(&cache, uid)?;
    ikanata_native::set_login_enabled(false).context("Cannot remove login registration")?;
    let status = ikanata_native::service_status().context("Cannot inspect service registration")?;
    if status != "enabled" {
        ikanata_native::register_service()
            .context("Approve the service to remove its protected runtime files")?;
    }
    request(Operation::Stop).context("Cannot stop remapping before uninstall")?;
    let runtime = request(Operation::Status).context("Cannot inspect runtime enrollment")?;
    if runtime.lines().nth(1) == Some("state=setup_required") {
        request(Operation::Setup).context("Cannot enroll the login user for protected cleanup")?;
    }
    let ownership =
        request(Operation::DriverOwnership).context("Cannot inspect driver ownership")?;
    let owned = match ownership.lines().nth(2) {
        Some("driver_owned=true") => true,
        Some("driver_owned=false") => false,
        _ => bail!("The service returned an invalid driver ownership response"),
    };
    let removing_driver = remove_driver || owned;
    if removing_driver {
        request(Operation::PrepareDriverRemoval)
            .context("Cannot stop driver consumers before deactivation")?;
        deactivate_driver(uid)?;
        request(Operation::RemoveDriver).context(
            "Driver cleanup did not finish. iKanata remains installed; resolve the reported problem and run uninstall again with the same options",
        )?;
    }
    reset_privacy_permissions()?;
    if !keep_app {
        request(Operation::RemoveAppReceipt)
            .context("Cannot remove iKanata's installer receipt; the app remains installed")?;
    }
    request(Operation::Uninstall).context("Cannot stop and remove the owned runtime")?;
    if remove_config {
        remove_configuration(&home)?;
    }
    if cache.try_exists()? {
        fs::remove_dir_all(&cache).context("Cannot remove the application cache")?;
    }
    ikanata_native::unregister_service().context("Cannot unregister the privileged service")?;
    if !keep_app {
        ikanata_native::trash_app()
            .context("Runtime, registrations, and installer receipt removed, but macOS could not move iKanata to Trash. Run uninstall again to retry app removal")?;
    }
    let app = if keep_app {
        "iKanata services removed. The app remains for the package manager to remove."
    } else {
        "iKanata services removed and the app moved to Trash."
    };
    let driver = if removing_driver {
        "VirtualHID driver removed."
    } else {
        "The pre-existing shared VirtualHID driver remains unchanged."
    };
    let config = if remove_config {
        "config.kbd removed; other configuration files remain unchanged."
    } else {
        "Your keymaps remain unchanged."
    };
    cliclack::log::success(format!("{app} {driver} {config}"))?;
    Ok(())
}

fn request(operation: Operation) -> Result<String> {
    let reply = ikanata_native::request(operation)
        .context("Cannot contact the approved iKanata service")?;
    ensure!(
        ikanata_core::succeeded(&reply),
        "{}",
        setup::service_detail(&reply)
    );
    Ok(reply)
}

fn stop_observer(cache: &Path, uid: u32) -> Result<Option<File>> {
    if !cache.try_exists()? {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(cache)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o7777 == 0o700,
        "Cannot remove an unsafe application cache"
    );
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(0x100)
        .open(cache.join("observer.stop"))?;
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(0x100)
        .open(cache.join("app.lock"))?;
    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        match ikanata_native::lock_file(&lock) {
            Ok(()) => return Ok(Some(lock)),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error).context("Cannot stop background observation"),
        }
    }
}

fn deactivate_driver(uid: u32) -> Result<()> {
    let Some(state) = extension_state()? else {
        return Ok(());
    };
    if state.contains("waiting for uninstall on reboot") {
        bail!(
            "VirtualHID removal requires a restart. Restart macOS, then run uninstall again with the same options. iKanata and the driver manager remain installed"
        );
    }
    ensure!(
        ikanata_native::console_uid()? == uid && ikanata_native::session_active(uid)?,
        "Remove VirtualHID from your active, unlocked login session"
    );
    ikanata_native::verify_driver_manager().context("The driver manager signature is invalid")?;
    cliclack::log::info(
        "Requesting VirtualHID deactivation. Approve the macOS removal prompt. Waiting for the signed driver manager to finish; iKanata and the manager remain installed until deactivation completes.",
    )?;
    let status = Command::new(MANAGER)
        .arg("deactivate")
        .env_clear()
        .stdin(Stdio::null())
        .status()
        .context("Cannot run the signed driver manager; no driver files were removed")?;
    let remaining = extension_state()?;
    if let Some(state) = remaining {
        if state.contains("waiting for uninstall on reboot") {
            bail!(
                "VirtualHID deactivation requires a restart. Restart macOS, then run uninstall again with the same options. iKanata and the driver manager remain installed"
            );
        }
        bail!(
            "VirtualHID deactivation has not completed ({state}). Complete the macOS approval prompt, then run uninstall again with the same options. iKanata and the driver manager remain installed"
        );
    }
    ensure!(
        status.success(),
        "The driver manager failed ({status}). No driver files were removed. Run uninstall again with the same options"
    );
    Ok(())
}

fn extension_state() -> Result<Option<String>> {
    let output = Command::new("/usr/bin/systemextensionsctl")
        .arg("list")
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .context("Cannot inspect VirtualHID deactivation state")?;
    ensure!(
        output.status.success(),
        "Cannot inspect system extensions; no driver files were removed"
    );
    let listing = std::str::from_utf8(&output.stdout)
        .context("macOS returned an invalid system extension listing")?;
    let mut states = Vec::new();
    for line in listing.lines() {
        if line.split_whitespace().any(|field| field == EXTENSION) {
            ensure!(
                line.split_whitespace().any(|field| field == "G43BCU2T37"),
                "VirtualHID has an unexpected signing team; no driver files were removed"
            );
            states.push(line.trim());
        }
    }
    Ok((!states.is_empty()).then(|| states.join("; ")))
}

fn remove_configuration(home: &Path) -> Result<()> {
    let path = ikanata_config::default_path(home);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("Cannot remove config.kbd"),
    }
    if let Some(directory) = path.parent() {
        match fs::symlink_metadata(directory) {
            Ok(metadata) if !metadata.is_dir() => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).context("Cannot inspect the configuration directory");
            }
        }
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => {
                return Err(error).context("Cannot remove the empty configuration directory");
            }
        }
    }
    Ok(())
}

fn reset_privacy_permissions() -> Result<()> {
    for service in ["Accessibility", "ListenEvent"] {
        let status = Command::new("/usr/bin/tccutil")
            .args(["reset", service, "io.github.mcuste.ikanata"])
            .env_clear()
            .stdin(Stdio::null())
            .status()
            .with_context(|| format!("Cannot reset iKanata's {service} permission"))?;
        ensure!(
            status.success(),
            "macOS could not reset iKanata's {service} permission ({status}). iKanata remains installed; review its privacy permissions in System Settings before retrying uninstall"
        );
    }
    Ok(())
}
