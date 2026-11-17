//! Shared runtime state and service response contracts.

use std::fmt;

/// Observed runtime or setup state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// No user has enrolled.
    SetupRequired,
    /// The standalone driver is absent.
    DriverMissing,
    /// The installed driver uses another protocol.
    DriverIncompatible,
    /// macOS has not enabled the driver extension.
    ApprovalPending,
    /// The engine lacks privacy permissions.
    PermissionsMissing,
    /// The user's configuration cannot load.
    ConfigurationInvalid,
    /// Another remapper owns keyboard input.
    Conflict,
    /// An explicit stop or engine exit disabled remapping.
    Stopped,
    /// Input capture waits for its console session or output backend.
    Paused,
    /// The engine runs for the enrolled user.
    Running,
}

impl fmt::Display for State {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SetupRequired => "setup_required",
            Self::DriverMissing => "driver_missing",
            Self::DriverIncompatible => "driver_incompatible",
            Self::ApprovalPending => "approval_pending",
            Self::PermissionsMissing => "permissions_missing",
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::Conflict => "remapper_conflict",
            Self::Stopped => "stopped",
            Self::Paused => "paused",
            Self::Running => "running",
        })
    }
}

/// Persisted user intent, separate from session eligibility.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Intent {
    enabled: bool,
}

impl Intent {
    /// Restore a previously saved intent.
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether an eligible session may run the engine.
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Record an explicit start.
    pub fn start(&mut self) {
        self.enabled = true;
    }

    /// Record an explicit stop or any unrequested engine exit.
    pub fn stop(&mut self) {
        self.enabled = false;
    }

    /// Session transitions do not change the user's saved intent.
    pub const fn should_run(self, eligible: bool) -> bool {
        self.enabled && eligible
    }
}

/// Encode a bounded, human-readable native IPC result.
pub fn response(success: bool, state: State, detail: &str) -> String {
    let outcome = if success { "ok" } else { "error" };
    let detail: String = detail
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .take(32768)
        .collect();
    format!("{outcome}\nstate={state}\n{detail}")
}

/// Return success only for the service's explicit success prefix.
pub fn succeeded(response: &str) -> bool {
    response.starts_with("ok\n")
}

#[cfg(test)]
mod tests {
    use super::Intent;

    #[test]
    fn emergency_exit_stays_stopped_after_session_changes() {
        let mut intent = Intent::new(true);
        intent.stop();
        assert!(!intent.should_run(false));
        assert!(!intent.should_run(true));
        intent.start();
        assert!(intent.should_run(true));
    }

    #[test]
    fn session_pause_preserves_startup_intent() {
        let intent = Intent::new(true);
        assert!(!intent.should_run(false));
        assert!(intent.should_run(true));
        assert!(Intent::new(intent.enabled()).should_run(true));
    }
}
