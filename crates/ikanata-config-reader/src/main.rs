//! Read engine configuration only with the enrolled user's file permissions.

use std::env;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

fn read() -> io::Result<()> {
    let mut arguments = env::args_os().skip(1);
    let uid = arguments
        .next()
        .and_then(|value| value.to_str().and_then(|value| value.parse::<u32>().ok()))
        .filter(|uid| *uid > 0)
        .ok_or_else(|| io::Error::other("invalid user identity"))?;
    let path = arguments
        .next()
        .ok_or_else(|| io::Error::other("missing configuration path"))?;
    if arguments.next().is_some() {
        return Err(io::Error::other("unexpected argument"));
    }
    ikanata_native::drop_privileges(uid)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0x0004)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("configuration is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(io::Error::other("configuration exceeds 16 MiB"));
    }
    io::stdout().lock().write_all(&bytes)
}

fn main() -> ExitCode {
    if let Ok(()) = read() {
        ExitCode::SUCCESS
    } else {
        eprintln!("configuration is not readable by the enrolled user");
        ExitCode::FAILURE
    }
}
