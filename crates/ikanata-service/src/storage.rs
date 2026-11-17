//! Root-owned enrollment and startup intent.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) const DIRECTORY: &str = "/Library/Application Support/iKanata";
const EXECUTABLE_DIRECTORY: &str = "/Library/PrivilegedHelperTools/iKanata";
pub(super) const ENGINE: &str = "/Library/PrivilegedHelperTools/iKanata/kanata";
pub(super) const READER: &str = "/Library/PrivilegedHelperTools/iKanata/ikanata-config-reader";
pub(super) const SOCKET: &str = "/Library/Application Support/iKanata/control.sock";
const ENROLLMENT: &str = "/Library/Application Support/iKanata/owner";

pub(super) fn check_directory() -> io::Result<()> {
    let metadata = fs::symlink_metadata(DIRECTORY)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        return Err(io::Error::other(
            "runtime directory must be root-owned mode 0700",
        ));
    }
    Ok(())
}

pub(super) fn load() -> io::Result<Option<(u32, bool)>> {
    let metadata = match fs::symlink_metadata(ENROLLMENT) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o600 {
        return Err(io::Error::other("unsafe enrollment file"));
    }
    let contents = fs::read_to_string(ENROLLMENT)?;
    let mut lines = contents.lines();
    let uid: u32 = lines
        .next()
        .and_then(|line| line.parse().ok())
        .filter(|uid| *uid > 0)
        .ok_or_else(|| io::Error::other("invalid enrolled identity"))?;
    let enabled = match lines.next() {
        Some("enabled") => true,
        Some("stopped") => false,
        _ => return Err(io::Error::other("invalid saved intent")),
    };
    if lines.next().is_some() {
        return Err(io::Error::other("invalid enrollment data"));
    }
    Ok(Some((uid, enabled)))
}

pub(super) fn save(uid: u32, enabled: bool) -> io::Result<()> {
    let temporary = Path::new(DIRECTORY).join(format!("owner.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        writeln!(
            file,
            "{uid}\n{}",
            if enabled { "enabled" } else { "stopped" }
        )?;
        file.sync_all()?;
        fs::rename(&temporary, ENROLLMENT)?;
        fs::File::open(DIRECTORY)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn driver_record(name: &str) -> io::Result<Option<String>> {
    check_directory()?;
    let path = Path::new(DIRECTORY).join(name);
    let file = match OpenOptions::new().read(true).custom_flags(0x100).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 128
    {
        return Err(io::Error::other("unsafe driver ownership record"));
    }
    let mut contents = String::new();
    file.take(129).read_to_string(&mut contents)?;
    if contents.len() > 128 {
        return Err(io::Error::other("invalid driver ownership record"));
    }
    Ok(Some(contents))
}

fn save_driver_record(name: &str, identity: &str) -> io::Result<()> {
    check_directory()?;
    let temporary = Path::new(DIRECTORY).join(format!("{name}.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(identity.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, Path::new(DIRECTORY).join(name))?;
        fs::File::open(DIRECTORY)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub(super) fn driver_owner() -> io::Result<Option<String>> {
    driver_record("driver-owner")
}

pub(super) fn save_driver_owner(identity: &str) -> io::Result<()> {
    save_driver_record("driver-owner", identity)
}

pub(super) fn driver_removal() -> io::Result<Option<String>> {
    driver_record("driver-removal")
}

pub(super) fn save_driver_removal(identity: &str) -> io::Result<()> {
    save_driver_record("driver-removal", identity)
}

pub(super) fn clear_driver_records() -> io::Result<()> {
    check_directory()?;
    for name in ["driver-owner", "driver-removal"] {
        match fs::remove_file(Path::new(DIRECTORY).join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::File::open(DIRECTORY)?.sync_all()
}

pub(super) fn remove_app_receipt() -> io::Result<()> {
    const RECEIPT: &str = "io.github.mcuste.ikanata.installer";
    let receipts = std::process::Command::new("/usr/sbin/pkgutil")
        .arg("--pkgs")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()?;
    if !receipts.status.success() {
        return Err(io::Error::other(
            "could not inspect the app installer receipt",
        ));
    }
    if !String::from_utf8_lossy(&receipts.stdout)
        .lines()
        .any(|line| line == RECEIPT)
    {
        return Ok(());
    }
    let removed = std::process::Command::new("/usr/sbin/pkgutil")
        .args(["--forget", RECEIPT])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()?;
    if !removed.status.success() {
        return Err(io::Error::other(
            "could not remove the app installer receipt",
        ));
    }
    Ok(())
}

pub(super) fn remove_owned_resources() -> io::Result<()> {
    check_directory()?;
    match fs::symlink_metadata(EXECUTABLE_DIRECTORY) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != 0o755
            {
                return Err(io::Error::other(
                    "executable directory must be root:wheel mode 0755",
                ));
            }
            fs::remove_dir_all(EXECUTABLE_DIRECTORY)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let runtime = Path::new(DIRECTORY).join("Runtime");
    if runtime.try_exists()? {
        fs::remove_dir_all(runtime)?;
    }
    for name in [
        "owner",
        "driver-owner",
        "control.sock",
        "service.log",
        "service.lock",
    ] {
        match fs::remove_file(Path::new(DIRECTORY).join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::remove_dir(DIRECTORY)
}

pub(super) fn logs() -> io::Result<String> {
    check_directory()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(0x100)
        .open(Path::new(DIRECTORY).join("service.log"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o600 {
        return Err(io::Error::other("Unsafe service log permissions"));
    }
    if metadata.len() > 32768 {
        file.seek(SeekFrom::End(-32768))?;
    }
    let mut buffer = Vec::new();
    file.take(32768).read_to_end(&mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}
