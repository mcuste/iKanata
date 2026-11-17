//! Standalone driver compatibility, ownership, and verified removal.

use crate::storage;
use ikanata_core::State;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const DAEMON: &str = "/Library/Application Support/org.pqrs/Karabiner-DriverKit-VirtualHIDDevice/Applications/Karabiner-VirtualHIDDevice-Daemon.app/Contents/MacOS/Karabiner-VirtualHIDDevice-Daemon";
const DIRECTORY: &str =
    "/Library/Application Support/org.pqrs/Karabiner-DriverKit-VirtualHIDDevice";
const MANAGER: &str = "/Applications/.Karabiner-VirtualHIDDevice-Manager.app/Contents/MacOS/Karabiner-VirtualHIDDevice-Manager";
const RECEIPT: &str = "org.pqrs.Karabiner-DriverKit-VirtualHIDDevice";
const SIGNING_REQUIREMENT: &str = "=anchor apple generic and certificate leaf[subject.OU] = \"G43BCU2T37\" and identifier \"org.pqrs.Karabiner-VirtualHIDDevice-Daemon\"";
const MANAGER_REQUIREMENT: &str = "=anchor apple generic and certificate leaf[subject.OU] = \"G43BCU2T37\" and identifier \"org.pqrs.Karabiner-VirtualHIDDevice-Manager\"";
const MANAGER_APP: &str = "/Applications/.Karabiner-VirtualHIDDevice-Manager.app";
const ROOTONLY: &str = "/Library/Application Support/org.pqrs/tmp/rootonly";
const DRIVER_SOCKET: &str =
    "/Library/Application Support/org.pqrs/tmp/rootonly/karabiner_virtual_hid_device_service.sock";
const LOG_DIRECTORY: &str = "/private/var/log/karabiner";
const DRIVER_LOGS: [&str; 4] = [
    "virtual_hid_device_service.log",
    "virtual_hid_device_service.1.log",
    "virtual_hid_device_service.2.log",
    "virtual_hid_device_service.3.log",
];

fn output(program: &str, args: &[&str]) -> io::Result<std::process::Output> {
    Command::new(program)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .output()
}

fn installation() -> Result<bool, State> {
    let receipts =
        output("/usr/sbin/pkgutil", &["--pkgs"]).map_err(|_| State::DriverIncompatible)?;
    if !receipts.status.success() {
        return Err(State::DriverIncompatible);
    }
    if !String::from_utf8_lossy(&receipts.stdout)
        .lines()
        .any(|line| line == RECEIPT)
    {
        if String::from_utf8_lossy(&receipts.stdout)
            .lines()
            .any(|line| line.starts_with(RECEIPT))
        {
            return Err(State::DriverIncompatible);
        }
        for path in [
            DIRECTORY,
            "/Applications/.Karabiner-VirtualHIDDevice-Manager.app",
            "/Library/LaunchDaemons/org.pqrs.Karabiner-DriverKit-VirtualHIDDeviceClient.plist",
        ] {
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(State::DriverIncompatible),
            }
        }
        match std::fs::read_dir("/Library/Application Support/org.pqrs/tmp/rootonly") {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.map_err(|_| State::DriverIncompatible)?;
                    let name = entry.file_name();
                    if name == "karabiner_virtual_hid_device_service.sock"
                        || name == "vhidd_server"
                        || name
                            .as_encoded_bytes()
                            .starts_with(b"virtual_hid_device_service_server.")
                    {
                        return Err(State::DriverIncompatible);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(State::DriverIncompatible),
        }
        let extensions = output("/usr/bin/systemextensionsctl", &["list"])
            .map_err(|_| State::DriverIncompatible)?;
        if !extensions.status.success()
            || String::from_utf8_lossy(&extensions.stdout).contains(RECEIPT)
        {
            return Err(State::DriverIncompatible);
        }
        return Ok(false);
    }
    let receipt = output("/usr/sbin/pkgutil", &["--pkg-info", RECEIPT])
        .map_err(|_| State::DriverIncompatible)?;
    if !receipt.status.success()
        || !String::from_utf8_lossy(&receipt.stdout)
            .lines()
            .any(|line| line == "version: 8.0.0")
    {
        return Err(State::DriverIncompatible);
    }
    for (path, requirement) in [
        (DAEMON, SIGNING_REQUIREMENT),
        (MANAGER, MANAGER_REQUIREMENT),
    ] {
        let signature = output(
            "/usr/bin/codesign",
            &["--verify", "--strict", "-R", requirement, path],
        )
        .map_err(|_| State::DriverIncompatible)?;
        if !signature.status.success() {
            return Err(State::DriverIncompatible);
        }
    }
    Ok(true)
}

pub(super) fn readiness() -> Result<(), State> {
    if !installation()? {
        return Err(State::DriverMissing);
    }
    let extensions =
        output("/usr/bin/systemextensionsctl", &["list"]).map_err(|_| State::ApprovalPending)?;
    if !extensions.status.success()
        || !String::from_utf8_lossy(&extensions.stdout)
            .lines()
            .any(|line| {
                line.contains(RECEIPT)
                    && line.contains("G43BCU2T37")
                    && line.contains("[activated enabled]")
            })
    {
        return Err(State::ApprovalPending);
    }
    Ok(())
}

pub(super) fn install() -> io::Result<()> {
    match installation() {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(_) => {
            return Err(io::Error::other(
                "the shared VirtualHID installation is incompatible or unverified; it was not changed",
            ));
        }
    }
    if conflicting_remapper()? {
        return Err(io::Error::other(
            "stop other remappers before installing the shared VirtualHID driver",
        ));
    }
    tracing::info!("preparing bundled driver installation");
    ikanata_native::with_driver_package(|snapshot| {
        let package = snapshot
            .to_str()
            .ok_or_else(|| io::Error::other("invalid private driver package path"))?;
        let signature = output("/usr/sbin/pkgutil", &["--check-signature", package])?;
        if !signature.status.success()
            || !String::from_utf8_lossy(&signature.stdout)
                .lines()
                .filter_map(|line| line.trim().strip_prefix("1. "))
                .any(|leaf| {
                    leaf.starts_with("Developer ID Installer: ") && leaf.ends_with(" (G43BCU2T37)")
                })
        {
            return Err(io::Error::other(
                "the bundled driver package vendor signature was rejected",
            ));
        }
        let assessment = output(
            "/usr/sbin/spctl",
            &["--assess", "--type", "install", package],
        )?;
        if !assessment.status.success() {
            return Err(io::Error::other(
                "macOS rejected the bundled driver package assessment",
            ));
        }
        match installation() {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(_) => {
                return Err(io::Error::other(
                    "the shared VirtualHID installation changed; it was not replaced",
                ));
            }
        }
        if conflicting_remapper()? {
            return Err(io::Error::other(
                "stop other remappers before installing the shared VirtualHID driver",
            ));
        }
        let daemon = output(
            "/usr/bin/pgrep",
            &[
                "-x",
                "Karabiner-VirtualHIDDevice-Daemon|Karabiner-DriverKit-VirtualHIDDeviceClient",
            ],
        )?;
        if daemon.status.code() != Some(1) {
            return Err(io::Error::other(
                "the shared VirtualHID daemon must not be active during installation",
            ));
        }
        tracing::info!("installing verified bundled driver package");
        let status = Command::new("/usr/sbin/installer")
            .args(["-pkg", package, "-target", "/"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(io::Error::other("the driver package installation failed"));
        }
        if !matches!(installation(), Ok(true)) {
            return Err(io::Error::other(
                "the installed driver receipt or vendor signature could not be verified",
            ));
        }
        let identity =
            receipt_identity()?.ok_or_else(|| io::Error::other("driver receipt disappeared"))?;
        storage::save_driver_owner(&identity)?;
        tracing::info!("driver package installed; extension approval remains separate");
        Ok(())
    })
}

fn parse_receipt(contents: &str) -> io::Result<String> {
    let mut version = None;
    let mut installed = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("version: ") {
            if version.replace(value).is_some() {
                return Err(io::Error::other("duplicate driver receipt version"));
            }
        }
        if let Some(value) = line.strip_prefix("install-time: ") {
            if installed.replace(value).is_some() {
                return Err(io::Error::other("duplicate driver receipt install time"));
            }
        }
    }
    let installed = installed
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| io::Error::other("driver receipt has no valid install time"))?;
    let version = version
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'.')
        })
        .ok_or_else(|| io::Error::other("driver receipt has no valid version"))?;
    Ok(format!("{version}\n{installed}\n"))
}

fn receipt_identity() -> io::Result<Option<String>> {
    let receipts = output("/usr/sbin/pkgutil", &["--pkgs"])?;
    if !receipts.status.success() {
        return Err(io::Error::other("could not inspect driver receipts"));
    }
    if !String::from_utf8_lossy(&receipts.stdout)
        .lines()
        .any(|line| line == RECEIPT)
    {
        return Ok(None);
    }
    let receipt = output("/usr/sbin/pkgutil", &["--pkg-info", RECEIPT])?;
    if !receipt.status.success() {
        return Err(io::Error::other("could not inspect driver receipt"));
    }
    parse_receipt(&String::from_utf8_lossy(&receipt.stdout)).map(Some)
}

pub(super) fn owned() -> io::Result<bool> {
    let Some(marker) = storage::driver_owner()? else {
        return Ok(false);
    };
    Ok(receipt_identity()?.as_deref() == Some(marker.as_str()))
}

fn extension_absent() -> io::Result<()> {
    let extensions = output("/usr/bin/systemextensionsctl", &["list"])?;
    if !extensions.status.success() {
        return Err(io::Error::other(
            "could not inspect system extensions; no driver files were removed",
        ));
    }
    if extensions_registered(&String::from_utf8_lossy(&extensions.stdout)) {
        return Err(io::Error::other(
            "VirtualHID is still registered; deactivate it as the console user, approve removal in macOS, and restart if requested before retrying",
        ));
    }
    Ok(())
}

fn extensions_registered(contents: &str) -> bool {
    contents
        .lines()
        .any(|line| line.split_whitespace().any(|field| field == RECEIPT))
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn receipt_files() -> io::Result<HashSet<PathBuf>> {
    let files = output("/usr/sbin/pkgutil", &["--files", RECEIPT])?;
    if !files.status.success() {
        return Err(io::Error::other(
            "could not inspect vendor-managed driver files",
        ));
    }
    let mut result = HashSet::new();
    for line in String::from_utf8_lossy(&files.stdout).lines() {
        let relative = Path::new(line);
        if relative.is_absolute()
            || relative.components().any(|component| {
                !matches!(
                    component,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            })
        {
            return Err(io::Error::other("invalid path in the driver receipt"));
        }
        result.insert(Path::new("/").join(relative));
    }
    Ok(result)
}

fn verify_managed_tree(path: &Path, files: &HashSet<PathBuf>) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !files.contains(path)
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || !(metadata.is_dir() || metadata.is_file())
        || (metadata.is_file() && metadata.nlink() != 1)
    {
        return Err(io::Error::other(
            "driver files contain an unverified path; nothing was removed",
        ));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            verify_managed_tree(&entry?.path(), files)?;
        }
    }
    Ok(())
}

fn verify_auxiliary_files() -> io::Result<()> {
    match fs::symlink_metadata(DRIVER_SOCKET) {
        Ok(metadata) if metadata.uid() == 0 && metadata.file_type().is_socket() => {}
        Ok(_) => {
            return Err(io::Error::other(
                "the driver socket path is not a root-owned socket",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    for name in DRIVER_LOGS {
        match fs::symlink_metadata(Path::new(LOG_DIRECTORY).join(name)) {
            Ok(metadata) if metadata.uid() == 0 && metadata.is_file() && metadata.nlink() == 1 => {}
            Ok(_) => {
                return Err(io::Error::other(
                    "a driver log path is not a root-owned regular file",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn removal_preflight() -> io::Result<Option<String>> {
    if conflicting_remapper()? {
        return Err(io::Error::other(
            "stop other remappers before removing the shared VirtualHID driver",
        ));
    }
    ikanata_native::verify_driver_removal_paths()?;
    for path in [
        "/Library/LaunchDaemons/org.pqrs.Karabiner-DriverKit-VirtualHIDDeviceClient.plist",
        "/Library/Application Support/org.pqrs/tmp/rootonly/vhidd_server",
    ] {
        if exists(Path::new(path))? {
            return Err(io::Error::other(
                "legacy VirtualHID components remain; their vendor uninstaller must remove them first",
            ));
        }
    }
    let identity = receipt_identity()?;
    let pending = storage::driver_removal()?;
    if identity.is_none() {
        if pending.is_some() {
            if exists(Path::new(DIRECTORY))? || exists(Path::new(MANAGER_APP))? {
                return Err(io::Error::other(
                    "driver files remain without the verified removal receipt",
                ));
            }
        } else if !matches!(installation(), Ok(false)) {
            return Err(io::Error::other(
                "the shared driver installation is incompatible or unverified",
            ));
        }
        verify_auxiliary_files()?;
        return Ok(None);
    }
    if pending.is_some() && pending != identity {
        return Err(io::Error::other(
            "the driver was replaced during removal; its files were not changed",
        ));
    }
    if pending.is_none() && !matches!(installation(), Ok(true)) {
        return Err(io::Error::other(
            "the shared driver installation is incompatible or unverified",
        ));
    }
    let files = receipt_files()?;
    for path in [DIRECTORY, MANAGER_APP] {
        verify_managed_tree(Path::new(path), &files)?;
    }
    for (path, requirement) in [
        (DAEMON, SIGNING_REQUIREMENT),
        (MANAGER, MANAGER_REQUIREMENT),
    ] {
        if exists(Path::new(path))? {
            let signature = output(
                "/usr/bin/codesign",
                &["--verify", "--deep", "--strict", "-R", requirement, path],
            )?;
            if !signature.status.success() {
                return Err(io::Error::other("a driver vendor signature was rejected"));
            }
        }
    }
    verify_auxiliary_files()?;
    Ok(identity)
}

pub(super) fn prepare_removal() -> io::Result<()> {
    removal_preflight()?;
    ikanata_native::stop_standalone_driver_daemons()
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_empty_directory(path: &Path) -> io::Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn remove() -> io::Result<()> {
    let identity = removal_preflight()?;
    extension_absent()?;
    ikanata_native::stop_standalone_driver_daemons()?;
    if let Some(identity) = &identity {
        storage::save_driver_removal(identity)?;
    }
    extension_absent()?;
    for path in [MANAGER_APP, DIRECTORY] {
        if exists(Path::new(path))? {
            fs::remove_dir_all(path)?;
        }
    }
    remove_file_if_present(Path::new(DRIVER_SOCKET))?;
    for name in DRIVER_LOGS {
        remove_file_if_present(&Path::new(LOG_DIRECTORY).join(name))?;
    }
    for path in [
        ROOTONLY,
        "/Library/Application Support/org.pqrs/tmp",
        "/Library/Application Support/org.pqrs",
        LOG_DIRECTORY,
    ] {
        remove_empty_directory(Path::new(path))?;
    }
    if identity.is_some() {
        let forgotten = output("/usr/sbin/pkgutil", &["--forget", RECEIPT])?;
        if !forgotten.status.success() {
            return Err(io::Error::other(
                "driver files were removed but its receipt remains; retry removal",
            ));
        }
    }
    if receipt_identity()?.is_some() {
        return Err(io::Error::other(
            "the driver receipt remains; retry removal",
        ));
    }
    extension_absent()?;
    storage::clear_driver_records()?;
    tracing::info!("verified shared driver files and receipt removed");
    Ok(())
}

pub(super) fn conflicting_remapper() -> io::Result<bool> {
    let result = output(
        "/usr/bin/pgrep",
        &[
            "-i",
            "-x",
            "kanata|karabiner_grabber|karabiner_observer|karabiner_console_user_server|Karabiner-Elements|keypath|Goku|KMonad",
        ],
    )?;
    match result.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(io::Error::other("could not inspect active remappers")),
    }
}

pub(super) fn ensure_daemon() -> io::Result<Option<Child>> {
    let result = output("/usr/bin/pgrep", &["-f", DAEMON])?;
    match result.status.code() {
        Some(0) => Ok(None),
        Some(1) => Command::new(DAEMON)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(Some),
        _ => Err(io::Error::other("could not inspect driver daemon")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MANAGER_REQUIREMENT, SIGNING_REQUIREMENT, extensions_registered, output, parse_receipt,
    };
    use std::io;

    #[test]
    fn ownership_changes_when_the_same_version_is_reinstalled() {
        let original = parse_receipt("version: 8.0.0\ninstall-time: 1794771679\n").unwrap();
        let replacement = parse_receipt("version: 8.0.0\ninstall-time: 1794771680\n").unwrap();
        assert_ne!(original, replacement);
        assert!(parse_receipt("version: 8.0.0\ninstall-time: 0\n").is_err());
        assert!(parse_receipt("version: 8.0.0\ninstall-time: 1\ninstall-time: 2\n").is_err());
        assert_ne!(
            original,
            parse_receipt("version: 9.0.0\ninstall-time: 1794771679\n").unwrap()
        );
        assert!(parse_receipt("version: invalid\ninstall-time: 1\n").is_err());
    }

    #[test]
    fn pending_extension_removal_does_not_allow_file_deletion() {
        for state in [
            "[activated enabled]",
            "[terminated waiting to uninstall on reboot]",
        ] {
            assert!(extensions_registered(&format!(
                "G43BCU2T37 org.pqrs.Karabiner-DriverKit-VirtualHIDDevice (8.0.0/8.0.0) {state}"
            )));
        }
        assert!(!extensions_registered(
            "G43BCU2T37 org.pqrs.unrelated [activated enabled]"
        ));
    }

    #[test]
    fn vendor_requirement_compiles_with_the_system_signature_parser() -> io::Result<()> {
        for requirement in [SIGNING_REQUIREMENT, MANAGER_REQUIREMENT] {
            let result = output("/usr/bin/csreq", &["-r", requirement, "-t"])?;
            if !result.status.success() {
                return Err(io::Error::other(
                    "The driver signing requirement must compile as a requirement, not a filename",
                ));
            }
        }
        Ok(())
    }
}
