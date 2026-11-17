//! Authorized engine lifecycle and sanitized event history.

use std::io;
use std::path::PathBuf;
use std::process::Child;
use std::time::Duration;

use crate::{control, driver, process, storage};
use ikanata_core::{Intent, State, response};
use ikanata_native::{Caller, Operation};

#[derive(Debug)]
pub(super) struct Runtime {
    owner: Option<u32>,
    intent: Intent,
    engine: Option<Child>,
    daemon: Option<Child>,
    state: State,
    permission_status: Option<(bool, bool)>,
}

impl Runtime {
    pub(super) fn new() -> io::Result<Self> {
        storage::check_directory()?;
        ikanata_native::verify_executable(
            std::path::Path::new(storage::ENGINE),
            "io.github.mcuste.ikanata.engine",
        )?;
        ikanata_native::verify_executable(
            std::path::Path::new(storage::READER),
            "io.github.mcuste.ikanata.config-reader",
        )?;
        let enrollment = storage::load()?;
        Ok(Self {
            owner: enrollment.map(|(uid, _)| uid),
            intent: Intent::new(enrollment.is_some_and(|(_, enabled)| enabled)),
            engine: None,
            daemon: None,
            permission_status: None,
            state: if enrollment.is_some() {
                State::Stopped
            } else {
                State::SetupRequired
            },
        })
    }

    fn save(&self) -> io::Result<()> {
        let owner = self
            .owner
            .ok_or_else(|| io::Error::other("setup is required"))?;
        storage::save(owner, self.intent.enabled())
    }

    fn home(&self) -> io::Result<PathBuf> {
        ikanata_native::home_for_uid(
            self.owner
                .ok_or_else(|| io::Error::other("setup is required"))?,
        )
    }

    fn eligible(&self) -> io::Result<bool> {
        self.owner.map_or(Ok(false), ikanata_native::session_active)
    }

    pub(super) fn operation(&mut self, operation: Operation, caller: Caller) -> String {
        if caller.uid == 0 || self.owner.is_some_and(|owner| owner != caller.uid) {
            return response(false, self.state, "caller is not the enrolled user");
        }
        tracing::debug!(?operation, state = %self.state, "received authorized operation");
        let result = self.perform(operation, caller);
        match result {
            Ok(detail) => response(true, self.state, &detail),
            Err(error) => {
                tracing::warn!(?operation, %error, state = %self.state, "operation failed");
                response(false, self.state, &error.to_string())
            }
        }
    }

    fn perform(&mut self, operation: Operation, caller: Caller) -> io::Result<String> {
        match operation {
            Operation::Setup => {
                self.enroll(caller.uid)?;
                self.refresh_status()?;
            }
            Operation::Status => self.refresh_status()?,
            Operation::Start => {
                if !self.eligible()? {
                    self.state = State::Paused;
                    return Err(io::Error::other(
                        "the enrolled user's console session is not active",
                    ));
                }
                self.intent.start();
                self.save()?;
                self.start()?;
            }
            Operation::Resume => {
                if self.intent.should_run(self.eligible()?) {
                    self.start()?;
                }
            }
            Operation::Stop => {
                self.intent.stop();
                self.stop_engine()?;
                self.state = State::Stopped;
                if self.owner.is_some() {
                    self.save()?;
                }
                tracing::info!(state = %self.state, "remapping stopped explicitly");
            }
            Operation::Reload => self.reload()?,
            Operation::Logs => return storage::logs(),
            Operation::InstallDriver => self.install_driver(caller)?,
            Operation::DriverOwnership => {
                self.authorize_driver_caller(caller)?;
                return Ok(if driver::owned()? {
                    "driver_owned=true"
                } else {
                    "driver_owned=false"
                }
                .to_owned());
            }
            Operation::PrepareDriverRemoval => {
                self.authorize_driver_caller(caller)?;
                self.intent.stop();
                self.stop_engine()?;
                self.state = State::Stopped;
                self.save()?;
                driver::prepare_removal()?;
                if let Some(child) = &mut self.daemon {
                    process::stop(child)?;
                }
                self.daemon = None;
            }
            Operation::RemoveDriver => {
                self.authorize_driver_caller(caller)?;
                if self.engine.is_some() || self.intent.enabled() {
                    return Err(io::Error::other(
                        "stop remapping before removing the shared VirtualHID driver",
                    ));
                }
                driver::remove()?;
                if let Some(child) = &mut self.daemon {
                    process::stop(child)?;
                }
                self.daemon = None;
                self.refresh_status()?;
            }
            Operation::RemoveAppReceipt => {
                self.authorize_driver_caller(caller)?;
                storage::remove_app_receipt()?;
            }
            Operation::Uninstall => {
                if self.owner.is_none() {
                    self.enroll(caller.uid)?;
                }
                if storage::driver_removal()?.is_some() {
                    self.authorize_driver_caller(caller)?;
                    driver::remove()?;
                }
                self.uninstall()?;
            }
        }
        let mut detail = self.state_detail().to_owned();
        if let (Operation::Status, Some((accessibility, input_monitoring))) =
            (operation, self.permission_status)
        {
            detail.push_str(if accessibility {
                "\naccessibility=granted"
            } else {
                "\naccessibility=missing"
            });
            detail.push_str(if input_monitoring {
                "\ninput_monitoring=granted"
            } else {
                "\ninput_monitoring=missing"
            });
        }
        Ok(detail)
    }

    fn install_driver(&mut self, caller: Caller) -> io::Result<()> {
        if self.owner != Some(caller.uid)
            || ikanata_native::console_uid()? != caller.uid
            || !self.eligible()?
        {
            return Err(io::Error::other(
                "driver installation requires the enrolled active unlocked console user",
            ));
        }
        if self.engine.is_some() {
            return Err(io::Error::other(
                "stop remapping before installing the shared VirtualHID driver",
            ));
        }
        driver::install()?;
        self.refresh_status()
    }

    fn authorize_driver_caller(&self, caller: Caller) -> io::Result<()> {
        if self.owner != Some(caller.uid)
            || ikanata_native::console_uid()? != caller.uid
            || !self.eligible()?
        {
            return Err(io::Error::other(
                "driver operations require the enrolled active unlocked console user",
            ));
        }
        Ok(())
    }

    fn state_detail(&self) -> &'static str {
        match self.state {
            State::SetupRequired => "Run ikanata setup to enroll your configuration.",
            State::DriverMissing => {
                "Run ikanata setup --install-driver to install the standalone driver."
            }
            State::DriverIncompatible => {
                "iKanata requires VirtualHID 8.0.0 (protocol 7). Resolve compatibility with other consumers before changing it."
            }
            State::ApprovalPending => {
                "Approve the VirtualHID extension in Login Items & Extensions. Restart macOS if requested."
            }
            State::PermissionsMissing => "Approve iKanata in Accessibility and Input Monitoring.",
            State::ConfigurationInvalid => {
                "The configuration is invalid or unreadable. The active keymap remains unchanged."
            }
            State::Conflict => "Stop the other remapper explicitly before starting iKanata.",
            State::Stopped => "Run ikanata start to enable remapping.",
            State::Paused => {
                "Input capture is paused. Check the console session and VirtualHID daemon."
            }
            State::Running => "Remapping is active.",
        }
    }

    fn enroll(&mut self, uid: u32) -> io::Result<()> {
        if ikanata_native::console_uid()? != uid || !ikanata_native::session_active(uid)? {
            return Err(io::Error::other(
                "setup requires the active unlocked console user",
            ));
        }
        if self.owner.is_none() {
            self.owner = Some(uid);
            self.intent.stop();
            self.save()?;
            tracing::info!("configuration owner enrolled");
        }
        Ok(())
    }

    fn refresh_status(&mut self) -> io::Result<()> {
        if self.engine.is_some() {
            self.tick()?;
            if self.engine.is_some() && self.state != State::ConfigurationInvalid {
                self.state = if control::ready()? {
                    State::Running
                } else {
                    State::Paused
                };
            }
            return Ok(());
        }
        if self.owner.is_none() {
            self.state = State::SetupRequired;
            return Ok(());
        }
        if let Err(state) = driver::readiness() {
            self.state = state;
        } else if !self.permissions()? {
            self.state = State::PermissionsMissing;
        } else if !self.validate()? {
            self.state = State::ConfigurationInvalid;
        } else {
            self.state = if self.eligible()? {
                State::Stopped
            } else {
                State::Paused
            };
        }
        Ok(())
    }

    fn permissions(&mut self) -> io::Result<bool> {
        self.permission_status = None;
        let owner = self
            .owner
            .ok_or_else(|| io::Error::other("setup is required"))?;
        let mut child = process::engine(owner, &self.home()?)
            .arg("--ikanata-check-permissions")
            .spawn()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait()? {
                let permissions = match status.code() {
                    Some(0) => (true, true),
                    Some(10) => (false, true),
                    Some(11) => (true, false),
                    Some(12) => (false, false),
                    _ => {
                        return Err(io::Error::other(
                            "the installed engine could not check privacy permissions",
                        ));
                    }
                };
                self.permission_status = Some(permissions);
                return Ok(permissions.0 && permissions.1);
            }
            if std::time::Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "engine permission check timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn validate(&self) -> io::Result<bool> {
        let owner = self
            .owner
            .ok_or_else(|| io::Error::other("setup is required"))?;
        let home = self.home()?;
        let config = home.join(".config/kanata/config.kbd");
        let mut command = process::engine(owner, &home);
        command.args(["--check", "--no-wait", "-c"]).arg(config);
        process::completes(command, Duration::from_secs(10))
    }

    fn start(&mut self) -> io::Result<()> {
        if self.engine.is_some() {
            if !control::ready()? {
                self.state = State::Paused;
                return Err(io::Error::other(
                    "Input capture is not ready. Check the driver, then run ikanata stop and ikanata start",
                ));
            }
            if self.state != State::ConfigurationInvalid {
                self.state = State::Running;
            }
            return Ok(());
        }
        self.refresh_status()?;
        if self.state != State::Stopped {
            return Err(io::Error::other(self.state_detail()));
        }
        if driver::conflicting_remapper()? {
            self.state = State::Conflict;
            return Err(io::Error::other(
                "another remapper is active; stop it explicitly",
            ));
        }
        ikanata_native::verify_executable(
            std::path::Path::new(storage::ENGINE),
            "io.github.mcuste.ikanata.engine",
        )?;
        ikanata_native::verify_executable(
            std::path::Path::new(storage::READER),
            "io.github.mcuste.ikanata.config-reader",
        )?;
        if self.daemon.is_none() {
            self.daemon = driver::ensure_daemon()?;
        }
        match std::fs::remove_file(storage::SOCKET) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let owner = self
            .owner
            .ok_or_else(|| io::Error::other("setup is required"))?;
        let home = self.home()?;
        self.engine = Some(
            process::engine(owner, &home)
                .args(["--no-wait", "--port", "0", "-c"])
                .arg(home.join(".config/kanata/config.kbd"))
                .spawn()?,
        );
        self.state = State::Running;
        tracing::info!("engine process started; waiting for readiness");
        self.wait_ready()
    }

    fn wait_ready(&mut self) -> io::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            self.tick()?;
            if self.engine.is_none() {
                return Err(io::Error::other(
                    "engine exited before becoming ready; check macOS approvals",
                ));
            }
            if control::ready().unwrap_or(false) {
                tracing::info!("engine input and output are ready");
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.stop_engine()?;
        self.state = State::Stopped;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "engine readiness timed out",
        ))
    }

    fn reload(&mut self) -> io::Result<()> {
        if self.engine.is_none() || !self.eligible()? {
            return Err(io::Error::other(
                "remapping is not running in an eligible session",
            ));
        }
        if !self.validate()? {
            self.state = State::ConfigurationInvalid;
            tracing::warn!("configuration validation failed; active keymap preserved");
            return Err(io::Error::other(
                "configuration is invalid or unreadable; active keymap preserved",
            ));
        }
        control::reload()?;
        self.state = State::Running;
        tracing::info!("engine accepted configuration reload");
        Ok(())
    }

    fn stop_engine(&mut self) -> io::Result<()> {
        if let Some(child) = &mut self.engine {
            process::stop(child)?;
        }
        self.engine = None;
        Ok(())
    }

    pub(super) fn tick(&mut self) -> io::Result<()> {
        if let Some(child) = &mut self.daemon {
            if child.try_wait()?.is_some() {
                self.daemon = None;
            }
        }
        let exited = self
            .engine
            .as_mut()
            .map(Child::try_wait)
            .transpose()?
            .flatten()
            .is_some();
        if exited {
            self.engine = None;
            self.intent.stop();
            self.state = State::Stopped;
            self.save()?;
            tracing::info!("engine exited; explicit start required");
        }
        let eligible = match self.eligible() {
            Ok(eligible) => eligible,
            Err(error) => {
                tracing::warn!(%error, "session identity unavailable; pausing input capture");
                false
            }
        };
        if self.engine.is_some() && !eligible {
            self.stop_engine()?;
            self.state = State::Paused;
            tracing::info!("console session paused; input capture released");
        }
        Ok(())
    }

    fn uninstall(&mut self) -> io::Result<()> {
        if storage::driver_removal()?.is_some() || driver::owned()? {
            return Err(io::Error::other(
                "finish shared driver removal before removing the private runtime",
            ));
        }
        self.intent.stop();
        self.stop_engine()?;
        self.state = State::Stopped;
        self.save()?;
        if let Some(child) = &mut self.daemon {
            process::stop(child)?;
        }
        self.daemon = None;
        storage::remove_owned_resources()?;
        self.owner = None;
        self.state = State::SetupRequired;
        tracing::info!("owned runtime resources removed; keymaps preserved");
        Ok(())
    }
}
