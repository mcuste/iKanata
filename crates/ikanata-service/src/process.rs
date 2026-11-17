//! Fixed executable launch and bounded completion.

use std::io;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::storage;

pub(super) fn engine(uid: u32, home: &Path) -> Command {
    let uid = uid.to_string();
    let mut command = Command::new("/bin/launchctl");
    command
        // Match the enrolled user's privacy session while retaining root privileges.
        .args(["asuser", &uid, storage::ENGINE])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", home)
        .env("IKANATA_OWNER_UID", &uid)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}

pub(super) fn completes(mut command: Command, timeout: Duration) -> io::Result<bool> {
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "engine operation timed out",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn stop(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    // SIGTERM lets Kanata release its virtual keys before the shutdown deadline.
    let status = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() && child.try_wait()?.is_none() {
        return Err(io::Error::other("could not stop owned child"));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}
