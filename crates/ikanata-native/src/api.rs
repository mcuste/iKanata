//! Native macOS integration with authenticated, bounded XPC operations.
//!
//! Service Management calls require the signed app at `/Applications/iKanata.app`.
//! XPC accepts valid ad-hoc signatures only when their code hashes match the
//! protected installed build. A successful notification call means macOS accepted
//! the submission, not that the user saw it.

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("ikanata-native supports Apple Silicon macOS 15 or later only");

use std::{io, path::Path};

pub use ffi::{
    bundle_resource, console_uid, effective_uid, home_for_uid, lock_file, notify, request_app_exit,
    run_app, session_active,
};

/// Fixed privileged service operations. No operation carries a path or command.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Read service and runtime state.
    Status = 0,
    /// Explicitly enable and start remapping.
    Start = 1,
    /// Stop remapping and preserve the stopped intent.
    Stop = 2,
    /// Validate and reload the enrolled user's configuration.
    Reload = 3,
    /// Read bounded service diagnostics.
    Logs = 4,
    /// Remove only this app's privileged resources.
    Uninstall = 5,
    /// Enroll the authenticated user and prepare configuration.
    Setup = 6,
    /// Resume only when saved user intent permits remapping.
    Resume = 7,
    /// Install only the bundled, pinned `VirtualHID` package.
    InstallDriver = 8,
    /// Remove the verified shared driver after user-session deactivation.
    RemoveDriver = 9,
    /// Report whether this app installed the current shared driver.
    DriverOwnership = 10,
    /// Stop driver consumers before user-session deactivation.
    PrepareDriverRemoval = 11,
    /// Forget only this app's package receipt during full removal.
    RemoveAppReceipt = 12,
}

impl Operation {
    const fn code(self) -> u32 {
        match self {
            Self::Status => 0,
            Self::Start => 1,
            Self::Stop => 2,
            Self::Reload => 3,
            Self::Logs => 4,
            Self::Uninstall => 5,
            Self::Setup => 6,
            Self::Resume => 7,
            Self::InstallDriver => 8,
            Self::RemoveDriver => 9,
            Self::DriverOwnership => 10,
            Self::PrepareDriverRemoval => 11,
            Self::RemoveAppReceipt => 12,
        }
    }

    const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Status),
            1 => Some(Self::Start),
            2 => Some(Self::Stop),
            3 => Some(Self::Reload),
            4 => Some(Self::Logs),
            5 => Some(Self::Uninstall),
            6 => Some(Self::Setup),
            7 => Some(Self::Resume),
            8 => Some(Self::InstallDriver),
            9 => Some(Self::RemoveDriver),
            10 => Some(Self::DriverOwnership),
            11 => Some(Self::PrepareDriverRemoval),
            12 => Some(Self::RemoveAppReceipt),
            _ => None,
        }
    }
}

/// The authenticated peer's kernel-provided effective credentials.
#[derive(Clone, Copy, Debug)]
pub struct Caller {
    /// Effective user ID. Root clients never reach the handler.
    pub uid: u32,
    /// Effective group ID from the XPC peer's audit credentials.
    pub gid: u32,
}

/// Send one operation to the fixed system Mach service.
///
/// The reply is limited to 64 KiB. The client waits up to 10 minutes for driver
/// installation or removal and 60 seconds for other requests. The root peer must
/// match this app's signed `Contents/MacOS/ikanata-app` exactly.
/// The service accepts only the exact signed CLI and app builds copied into its
/// root-protected `Runtime/Clients` directory. Root clients cannot connect.
pub fn request(op: Operation) -> io::Result<String> {
    ffi::request(op.code())
}

/// Serve authenticated operations serially on a native dispatch queue.
///
/// Call once, from the root service's main thread. This function does not return
/// after a successful start. Responses must not exceed 64 KiB. The handler must
/// not panic or wait for work on the main dispatch queue.
/// The running service must execute from the installed app's main executable
/// and match its private `Runtime/Clients/ikanata-app` reference exactly.
/// The private runtime directories must be root-owned with mode 0700. Client
/// signatures must match the trusted `Clients/ikanata` or `Clients/ikanata-app`.
pub fn serve(
    handler: fn(Operation, Caller) -> String,
    record_authentication: fn(bool),
) -> io::Result<()> {
    ffi::serve(handler, record_authentication)
}

/// Register the bundled daemon through `SMAppService` from the installed app.
pub fn register_service() -> io::Result<()> {
    ffi::service_action(0)
}

/// Unregister the bundled daemon through `SMAppService` from the installed app.
pub fn unregister_service() -> io::Result<()> {
    ffi::service_action(1)
}

/// Replace the stopped daemon's registration after updating its app bundle.
pub fn refresh_service_registration() -> io::Result<()> {
    ffi::service_action(5)
}

/// Enable or disable the installed background app's main login item.
pub fn set_login_enabled(enabled: bool) -> io::Result<()> {
    ffi::service_action(if enabled { 2 } else { 3 })
}

/// Return `enabled`, `requires-approval`, `not-registered`, or `not-found`.
///
/// This call requires the installed app's actual main bundle context.
pub fn service_status() -> io::Result<String> {
    ffi::service_status()
}

/// Request Accessibility and Input Monitoring consent for the installed app.
///
/// Only the signed, non-root main executable at `/Applications/iKanata.app`
/// may call this. It uses `AXIsProcessTrustedWithOptions` with prompting enabled
/// and `IOHIDRequestAccess` for event listening. It does not open input devices.
/// Success means the requests ran, not that macOS granted access. The root
/// service's permission probe remains the authority for runtime readiness.
pub fn request_input_permissions() -> io::Result<()> {
    ffi::request_input_permissions()
}

/// Permanently drop a single-threaded root reader to a non-root user.
///
/// This sets supplementary groups, real and effective group IDs, and real and
/// effective user IDs. Call before creating threads. Any error is fatal for the
/// reader because the process may already have changed some credentials.
pub fn drop_privileges(uid: u32) -> io::Result<()> {
    ffi::drop_privileges(uid)
}

/// Verify an executable's valid signature, exact identifier, and protected path.
///
/// Valid ad-hoc signatures do not require a signing identity or team. The
/// executable and its ancestors must be root-owned and free of symlinks,
/// group writes, other writes, and ACL write grants. Root may verify only the
/// fixed engine and reader in `/Library/PrivilegedHelperTools/iKanata`.
/// That directory and both executables must use root:wheel mode 0755.
/// Non-root callers may verify only their own app's resources, with a
/// group-writable `/Applications` parent.
pub fn verify_executable(path: &Path, identifier: &str) -> io::Result<()> {
    ffi::verify_executable(path, identifier)
}

/// Run an installation against a checksum-verified, immutable private package.
///
/// Root may use only the fixed bundled package. The snapshot remains immutable
/// until the callback returns, then this function removes it.
pub fn with_driver_package<T>(install: impl FnOnce(&Path) -> io::Result<T>) -> io::Result<T> {
    ffi::with_driver_package(install)
}

/// Verify the fixed vendor removal paths without changing the installation.
pub fn verify_driver_removal_paths() -> io::Result<()> {
    ffi::driver_cleanup(0)
}

/// Stop only root-owned, signed vendor daemons with no supervising app.
pub fn stop_standalone_driver_daemons() -> io::Result<()> {
    ffi::driver_cleanup(1)
}

/// Verify the fixed vendor manager before running it in the user's session.
pub fn verify_driver_manager() -> io::Result<()> {
    ffi::verify_driver_manager()
}

/// Move this process's own installed app bundle to the current user's Trash.
///
/// Only the actual main app at `/Applications/iKanata.app` can call this. macOS
/// permission failures propagate to the caller.
pub fn trash_app() -> io::Result<()> {
    ffi::service_action(4)
}

#[expect(
    unsafe_code,
    reason = "The audited native ABI is isolated to this module"
)]
mod ffi {
    use super::{Caller, Operation};
    use std::{
        ffi::{CString, OsString, c_char, c_int},
        fs::File,
        io,
        os::{
            fd::AsRawFd,
            unix::ffi::{OsStrExt, OsStringExt},
        },
        panic::catch_unwind,
        path::{Path, PathBuf},
        ptr,
        sync::OnceLock,
    };

    const MAX_REPLY: usize = 65_536;
    const MAX_PATH: usize = 16_384;
    #[derive(Debug)]
    struct Handlers {
        operation: fn(Operation, Caller) -> String,
        authentication: fn(bool),
    }

    static HANDLERS: OnceLock<Handlers> = OnceLock::new();
    static OPEN_HANDLER: OnceLock<fn()> = OnceLock::new();
    type Callback = extern "C" fn(u32, u32, u32, *mut u8, usize) -> usize;
    type AuthenticationLog = extern "C" fn(u32);
    type ApplicationOpen = extern "C" fn() -> c_int;

    unsafe extern "C" {
        fn ikanata_request(
            op: u32,
            output: *mut u8,
            capacity: usize,
            written: *mut usize,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_serve(
            handler: Callback,
            authentication_log: AuthenticationLog,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_service_action(action: u32, error: *mut u8, error_capacity: usize) -> c_int;
        fn ikanata_service_status(
            output: *mut u8,
            capacity: usize,
            written: *mut usize,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_request_input_permissions(error: *mut u8, error_capacity: usize) -> c_int;
        fn ikanata_console_uid(uid: *mut u32, error: *mut u8, error_capacity: usize) -> c_int;
        fn ikanata_session_active(
            uid: u32,
            active: *mut c_int,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_home_for_uid(
            uid: u32,
            output: *mut u8,
            capacity: usize,
            written: *mut usize,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_notify(
            title: *const c_char,
            message: *const c_char,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_bundle_resource(
            name: *const c_char,
            output: *mut u8,
            capacity: usize,
            written: *mut usize,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_effective_uid() -> u32;
        fn ikanata_drop_privileges(uid: u32, error: *mut u8, error_capacity: usize) -> c_int;
        fn ikanata_verify_executable(
            path: *const c_char,
            identifier: *const c_char,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_driver_package(action: u32, error: *mut u8, error_capacity: usize) -> c_int;
        fn ikanata_driver_cleanup(action: u32, error: *mut u8, error_capacity: usize) -> c_int;
        fn ikanata_verify_driver_manager(error: *mut u8, error_capacity: usize) -> c_int;
        fn ikanata_lock_file(fd: c_int, error: *mut u8, error_capacity: usize) -> c_int;
        fn ikanata_run_app(
            on_open: ApplicationOpen,
            show_on_launch: c_int,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
        fn ikanata_request_app_exit(error: *mut u8, error_capacity: usize) -> c_int;
        #[cfg(test)]
        fn ikanata_protected_acl(
            path: *const c_char,
            error: *mut u8,
            error_capacity: usize,
        ) -> c_int;
    }

    fn checked(invoke: impl FnOnce(*mut u8, usize) -> c_int) -> io::Result<()> {
        let mut error = [0_u8; 1024];
        let code = invoke(error.as_mut_ptr(), error.len());
        if code == 0 {
            return Ok(());
        }
        let end = error
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(error.len());
        let message = String::from_utf8_lossy(error.get(..end).unwrap_or_default());
        if message.is_empty() {
            Err(io::Error::from_raw_os_error(code))
        } else {
            Err(io::Error::new(
                io::Error::from_raw_os_error(code).kind(),
                message.into_owned(),
            ))
        }
    }

    fn output(
        capacity: usize,
        invoke: impl FnOnce(*mut u8, usize, *mut usize, *mut u8, usize) -> c_int,
    ) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0_u8; capacity];
        let mut written = 0;
        checked(|error, error_capacity| {
            invoke(
                bytes.as_mut_ptr(),
                bytes.len(),
                &raw mut written,
                error,
                error_capacity,
            )
        })?;
        if written > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native output exceeds capacity",
            ));
        }
        bytes.truncate(written);
        Ok(bytes)
    }

    fn text(bytes: Vec<u8>) -> io::Result<String> {
        String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn cstring(bytes: impl Into<Vec<u8>>) -> io::Result<CString> {
        CString::new(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    pub(super) fn request(op: u32) -> io::Result<String> {
        text(output(MAX_REPLY, |out, cap, len, err, err_cap| {
            // SAFETY: All output pointers reference live, writable buffers of the stated sizes.
            unsafe { ikanata_request(op, out, cap, len, err, err_cap) }
        })?)
    }

    extern "C" fn authentication_log(outcome: u32) {
        if let Some(handlers) = HANDLERS.get() {
            (handlers.authentication)(outcome != 0);
        }
    }

    extern "C" fn handle(op: u32, uid: u32, gid: u32, out: *mut u8, cap: usize) -> usize {
        let (Some(operation), Some(handlers)) = (Operation::from_code(op), HANDLERS.get()) else {
            return usize::MAX;
        };
        let Ok(response) = catch_unwind(|| (handlers.operation)(operation, Caller { uid, gid }))
        else {
            return usize::MAX;
        };
        if response.len() > cap || out.is_null() {
            return usize::MAX;
        }
        // SAFETY: The bridge provides cap writable bytes. response owns separate live bytes.
        unsafe {
            ptr::copy_nonoverlapping(response.as_ptr(), out, response.len());
        }
        response.len()
    }

    pub(super) fn serve(
        handler: fn(Operation, Caller) -> String,
        record_authentication: fn(bool),
    ) -> io::Result<()> {
        HANDLERS
            .set(Handlers {
                operation: handler,
                authentication: record_authentication,
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "native service handler is already installed",
                )
            })?;
        checked(|err, cap| {
            // SAFETY: The callback remains valid for the process lifetime and buffers are live.
            unsafe { ikanata_serve(handle, authentication_log, err, cap) }
        })
    }

    pub(super) fn service_action(action: u32) -> io::Result<()> {
        checked(|err, cap| {
            // SAFETY: The bridge receives a fixed action and a live error buffer.
            unsafe { ikanata_service_action(action, err, cap) }
        })
    }

    pub(super) fn service_status() -> io::Result<String> {
        text(output(128, |out, cap, len, err, err_cap| {
            // SAFETY: All pointers reference writable output buffers with matching capacities.
            unsafe { ikanata_service_status(out, cap, len, err, err_cap) }
        })?)
    }

    pub(super) fn request_input_permissions() -> io::Result<()> {
        checked(|err, cap| {
            // SAFETY: The error buffer remains writable for the native request.
            unsafe { ikanata_request_input_permissions(err, cap) }
        })
    }

    /// Return the non-root user who owns the global graphical console session.
    pub fn console_uid() -> io::Result<u32> {
        let mut uid = 0;
        checked(|err, cap| {
            // SAFETY: uid and the error buffer remain writable for the call.
            unsafe { ikanata_console_uid(&raw mut uid, err, cap) }
        })?;
        Ok(uid)
    }

    /// Check the global console registry for an unlocked login session.
    pub fn session_active(uid: u32) -> io::Result<bool> {
        let mut active = 0;
        checked(|err, cap| {
            // SAFETY: active and the error buffer remain writable for the call.
            unsafe { ikanata_session_active(uid, &raw mut active, err, cap) }
        })?;
        Ok(active != 0)
    }

    /// Resolve the user's absolute home directory with `getpwuid_r`, not `HOME`.
    pub fn home_for_uid(uid: u32) -> io::Result<PathBuf> {
        let bytes = output(MAX_PATH, |out, cap, len, err, err_cap| {
            // SAFETY: All output pointers reference live buffers with matching capacities.
            unsafe { ikanata_home_for_uid(uid, out, cap, len, err, err_cap) }
        })?;
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }

    /// Submit a bounded native notification in the current user session.
    pub fn notify(title: &str, message: &str) -> io::Result<()> {
        let title = cstring(title)?;
        let message = cstring(message)?;
        checked(|err, cap| {
            // SAFETY: Both strings are terminated and live; the error buffer is writable.
            unsafe { ikanata_notify(title.as_ptr(), message.as_ptr(), err, cap) }
        })
    }

    /// Resolve one existing filename in this executable's app resources.
    pub fn bundle_resource(name: &str) -> io::Result<PathBuf> {
        let name = cstring(name)?;
        let bytes = output(MAX_PATH, |out, cap, len, err, err_cap| {
            // SAFETY: name is terminated and live; output buffers have matching capacities.
            unsafe { ikanata_bundle_resource(name.as_ptr(), out, cap, len, err, err_cap) }
        })?;
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }

    /// Return the process's effective user ID.
    pub fn effective_uid() -> u32 {
        // SAFETY: This native getter has no preconditions and returns the process effective UID.
        unsafe { ikanata_effective_uid() }
    }

    pub(super) fn drop_privileges(uid: u32) -> io::Result<()> {
        checked(|err, cap| {
            // SAFETY: Credential changes use the checked UID and a live writable error buffer.
            unsafe { ikanata_drop_privileges(uid, err, cap) }
        })
    }

    pub(super) fn verify_executable(path: &Path, identifier: &str) -> io::Result<()> {
        let path = cstring(path.as_os_str().as_bytes())?;
        let identifier = cstring(identifier)?;
        checked(|err, cap| {
            // SAFETY: The path and identifier are terminated and live; error is writable.
            unsafe { ikanata_verify_executable(path.as_ptr(), identifier.as_ptr(), err, cap) }
        })
    }

    pub(super) fn with_driver_package<T>(
        install: impl FnOnce(&Path) -> io::Result<T>,
    ) -> io::Result<T> {
        struct Snapshot;
        impl Drop for Snapshot {
            fn drop(&mut self) {
                let _ = checked(|error, capacity| {
                    // SAFETY: The error buffer remains writable for this fixed-path cleanup.
                    unsafe { ikanata_driver_package(1, error, capacity) }
                });
            }
        }
        checked(|error, capacity| {
            // SAFETY: The error buffer remains writable for this fixed-path snapshot.
            unsafe { ikanata_driver_package(0, error, capacity) }
        })?;
        let snapshot = Snapshot;
        let result = install(Path::new(
            "/Library/Application Support/iKanata/Runtime/DriverPackage.pkg",
        ));
        let cleanup = checked(|error, capacity| {
            // SAFETY: The error buffer remains writable for this fixed-path cleanup.
            unsafe { ikanata_driver_package(1, error, capacity) }
        });
        std::mem::forget(snapshot);
        match (result, cleanup) {
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    pub(super) fn driver_cleanup(action: u32) -> io::Result<()> {
        checked(|error, capacity| {
            // SAFETY: The fixed action uses a live writable error buffer.
            unsafe { ikanata_driver_cleanup(action, error, capacity) }
        })
    }

    pub(super) fn verify_driver_manager() -> io::Result<()> {
        checked(|error, capacity| {
            // SAFETY: The fixed-path verification uses a live writable error buffer.
            unsafe { ikanata_verify_driver_manager(error, capacity) }
        })
    }

    /// Hold an exclusive, nonblocking lock on a private mode-0600 file.
    pub fn lock_file(file: &File) -> io::Result<()> {
        checked(|err, cap| {
            // SAFETY: The borrowed File keeps its descriptor open throughout the call.
            unsafe { ikanata_lock_file(file.as_raw_fd(), err, cap) }
        })
    }

    extern "C" fn application_open() -> c_int {
        let Some(callback) = OPEN_HANDLER.get() else {
            return -1;
        };
        catch_unwind(*callback).map_or(-1, |()| 0)
    }

    /// Run the windowless app's native event loop on its main thread.
    ///
    /// The callback handles launch and reopen requests. It must not panic.
    pub fn run_app(on_open: fn(), show_on_launch: bool) -> io::Result<()> {
        OPEN_HANDLER
            .set(on_open)
            .map_err(|_| io::Error::other("Application event loop already initialized"))?;
        checked(|error, capacity| {
            // SAFETY: The callback and error buffer remain valid for this blocking call.
            unsafe {
                ikanata_run_app(
                    application_open,
                    c_int::from(show_on_launch),
                    error,
                    capacity,
                )
            }
        })
    }

    /// Request termination on the app's main queue.
    pub fn request_app_exit() -> io::Result<()> {
        checked(|error, capacity| {
            // SAFETY: The error buffer remains writable for the call.
            unsafe { ikanata_request_app_exit(error, capacity) }
        })
    }

    #[cfg(test)]
    mod acl_tests {
        use super::{CString, checked, ikanata_protected_acl};
        use std::{
            fs::{self, OpenOptions},
            io,
            os::unix::fs::OpenOptionsExt,
            path::{Path, PathBuf},
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };

        struct Fixture(PathBuf);

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn protected_acl_accepts_absent_or_read_only_acl_but_rejects_writes() -> io::Result<()> {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
            fs::create_dir_all(&root)?;
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let directory = root.join(format!("native-acl-{}-{nonce}", std::process::id()));
            fs::create_dir(&directory)?;
            let fixture = Fixture(directory);
            let path = fixture.0.join("protected");
            drop(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?,
            );
            let terminated = CString::new(path.as_os_str().as_encoded_bytes())?;
            for (arguments, expected) in [
                (&["-N"][..], 0),
                (&["+a", "everyone allow read"][..], 0),
                (&["+a", "everyone allow write"][..], 13),
            ] {
                let status = Command::new("/bin/chmod")
                    .args(arguments)
                    .arg(&path)
                    .status()?;
                if !status.success() {
                    return Err(io::Error::other(format!("Cannot set test ACL: {status}")));
                }
                let mut actual = 0;
                let result = checked(|error, capacity| {
                    // SAFETY: The path is terminated and the error buffer remains writable.
                    actual = unsafe { ikanata_protected_acl(terminated.as_ptr(), error, capacity) };
                    actual
                });
                if actual != expected {
                    return Err(io::Error::other(format!(
                        "Expected ACL result {expected}, got {actual}: {result:?}"
                    )));
                }
            }
            fs::remove_file(&path)?;
            let result = checked(|error, capacity| {
                // SAFETY: The path is terminated and the error buffer remains writable.
                unsafe { ikanata_protected_acl(terminated.as_ptr(), error, capacity) }
            });
            if !matches!(result, Err(error) if error.kind() == io::ErrorKind::NotFound) {
                return Err(io::Error::other("Missing files must fail ACL inspection"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Operation, bundle_resource, request, verify_executable};
    use std::{io::ErrorKind, path::Path};

    #[test]
    fn executable_verification_rejects_requirement_injection() {
        for identifier in ["", "app\" or true", "app/name", "app name"] {
            assert!(matches!(
                verify_executable(Path::new("/not-inspected"), identifier),
                Err(error) if error.kind() == ErrorKind::InvalidInput
            ));
        }
    }

    #[test]
    fn resource_names_cannot_select_paths() {
        for name in ["", ".", "..", "nested/config", "/absolute", "name\0suffix"] {
            assert!(matches!(
                bundle_resource(name),
                Err(error) if error.kind() == ErrorKind::InvalidInput
            ));
        }
    }

    #[test]
    fn an_uninstalled_binary_cannot_install_the_driver() {
        let error = request(Operation::InstallDriver)
            .expect_err("unauthorized test binary must not install a driver");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn driver_cleanup_operations_preserve_authentication() {
        for operation in [
            Operation::RemoveDriver,
            Operation::DriverOwnership,
            Operation::PrepareDriverRemoval,
            Operation::RemoveAppReceipt,
        ] {
            let error = request(operation)
                .expect_err("unauthorized test binary must not control the driver");
            assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        }
    }

    #[test]
    fn driver_cleanup_operations_round_trip_without_accepting_unknown_codes() {
        for operation in [
            Operation::RemoveDriver,
            Operation::DriverOwnership,
            Operation::PrepareDriverRemoval,
            Operation::RemoveAppReceipt,
        ] {
            assert_eq!(Operation::from_code(operation.code()), Some(operation));
        }
        assert_eq!(Operation::from_code(13), None);
        assert_eq!(Operation::from_code(u32::MAX), None);
    }

    #[test]
    fn an_uninstalled_binary_cannot_control_the_root_service() {
        let error =
            request(Operation::Status).expect_err("unauthorized test binary must not connect");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    }
}
