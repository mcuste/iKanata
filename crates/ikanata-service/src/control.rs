//! Private engine control with explicit reload acceptance.

use serde_json::Value;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::storage;

pub(super) fn ready() -> io::Result<bool> {
    let reply = request(b"{\"Hello\":{}}\n", "HelloOk", Duration::from_millis(500))?;
    Ok(reply
        .get("capabilities")
        .and_then(Value::as_array)
        .is_some_and(|capabilities| {
            capabilities
                .iter()
                .any(|value| value.as_str() == Some("ikanata-ready"))
        }))
}

pub(super) fn reload() -> io::Result<()> {
    let reply = request(
        b"{\"Reload\":{\"wait\":true,\"timeout_ms\":5000}}\n",
        "ReloadResult",
        Duration::from_secs(7),
    )?;
    if reply.get("ok").and_then(Value::as_bool) == Some(true) && reply.get("timeout_ms").is_none() {
        Ok(())
    } else {
        Err(io::Error::other(
            "Engine did not accept the reload before the deadline",
        ))
    }
}

fn request(command: &[u8], field: &str, timeout: Duration) -> io::Result<Value> {
    storage::check_directory()?;
    let mut stream = UnixStream::connect(storage::SOCKET)?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(command)?;
    let mut reader = BufReader::new(stream);
    let deadline = Instant::now() + timeout;
    let mut line = Vec::new();
    let mut received = 0;
    while Instant::now() < deadline {
        reader.get_ref().set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ))?;
        line.clear();
        let size = reader.by_ref().take(65537).read_until(b'\n', &mut line)?;
        received += size;
        if size == 0 {
            return Err(io::Error::other("Engine closed the control connection"));
        }
        if received > 65536 {
            return Err(io::Error::other("Engine control response is too large"));
        }
        let mut value: Value = serde_json::from_slice(&line)
            .map_err(|_| io::Error::other("Invalid engine control response"))?;
        if value.get("status").and_then(Value::as_str) == Some("Error") {
            return Err(io::Error::other("Engine rejected the operation"));
        }
        if let Some(result) = value.get_mut(field) {
            return Ok(result.take());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Engine acknowledgement timed out",
    ))
}
