use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use ikanata_core::succeeded;
use ikanata_native::Operation;

const LOGIN_SETTINGS: &str = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension";
const ACCESSIBILITY_SETTINGS: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";
const INPUT_SETTINGS: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent";

pub(super) fn refresh_service_registration() -> Result<()> {
    let engine = Command::new("/usr/bin/pgrep")
        .args(["-f", "^/Library/PrivilegedHelperTools/iKanata/kanata( |$)"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("Cannot check remapping before refreshing the service")?;
    match engine.code() {
        Some(1) => {}
        Some(0) => bail!("Stop remapping before refreshing the service registration"),
        _ => bail!("Cannot determine whether remapping has stopped"),
    }
    ikanata_native::refresh_service_registration().context("Cannot register the updated service")
}

struct OnboardingOptions {
    install_driver: bool,
    enable_startup: bool,
}

enum DriverRequest {
    NotRequested,
    ActivationRequested,
    Failed(String),
}

enum PermissionRequest {
    NotRequested,
    Pending(Instant),
    FallbackOffered,
}

pub(super) struct Onboarding {
    options: OnboardingOptions,
    start_pending: bool,
    prepared: bool,
    registration_requested: bool,
    driver_request: DriverRequest,
    permission_request: PermissionRequest,
    last_guidance: Option<&'static str>,
}

impl Onboarding {
    pub(super) fn new(install_driver: bool, enable_startup: bool, explicit_start: bool) -> Self {
        Self {
            options: OnboardingOptions {
                install_driver,
                enable_startup,
            },
            start_pending: explicit_start,
            prepared: false,
            registration_requested: false,
            driver_request: DriverRequest::NotRequested,
            permission_request: PermissionRequest::NotRequested,
            last_guidance: None,
        }
    }

    pub(super) fn poll(&mut self) -> Result<bool> {
        if !self.prepared {
            self.prepare_configuration()?;
        }
        let mut registration = ikanata_native::service_status()
            .context("Cannot inspect privileged service registration")?;
        if registration != "requires-approval" && !self.registration_requested {
            ikanata_native::register_service().context("Cannot register the privileged service")?;
            self.registration_requested = true;
            registration = ikanata_native::service_status()?;
        }
        if registration != "enabled" {
            self.guide(
                "service-approval",
                "Enable iKanata in Login Items & Extensions. Setup will continue after approval.",
                Some(LOGIN_SETTINGS),
            )?;
            return Ok(false);
        }
        if self.options.enable_startup {
            ikanata_native::set_login_enabled(true).context("Cannot enable login startup")?;
            self.options.enable_startup = false;
        }
        let mut reply = ikanata_native::request(Operation::Status)
            .context("Cannot check the installed runtime")?;
        ensure!(succeeded(&reply), "{}", service_detail(&reply));
        if state(&reply) == Some("setup_required") {
            reply = self.enroll()?;
        }
        if self.start_pending {
            // Save initial start intent before waiting for consent; later checks only resume it.
            self.start_pending = false;
            let start = ikanata_native::request(Operation::Start)
                .context("Cannot save the requested start intent")?;
            tracing::info!(
                accepted = succeeded(&start),
                "requested explicit or first onboarding start"
            );
            if !succeeded(&start) && matches!(state(&start), Some("paused" | "stopped")) {
                ikanata_native::notify("iKanata did not start", &service_detail(&start))?;
            }
            reply = ikanata_native::request(Operation::Status)
                .context("Cannot verify runtime prerequisites after requesting start")?;
            ensure!(succeeded(&reply), "{}", service_detail(&reply));
        }
        match state(&reply) {
            Some(step @ ("driver_missing" | "approval_pending")) => {
                self.guide_driver(step)?;
                Ok(false)
            }
            Some("permissions_missing") => {
                self.guide_permissions(&reply)?;
                Ok(false)
            }
            Some("stopped" | "paused" | "running") => {
                let resumed = ikanata_native::request(Operation::Resume)
                    .context("Cannot resume the saved remapping intent")?;
                ensure!(succeeded(&resumed), "{}", service_detail(&resumed));
                tracing::debug!(
                    state = state(&resumed),
                    "runtime prerequisites verified by the root service"
                );
                if self.last_guidance.take().is_some() {
                    ikanata_native::notify("iKanata", &service_detail(&resumed))?;
                }
                Ok(true)
            }
            _ => bail!("{}", service_detail(&reply)),
        }
    }

    fn prepare_configuration(&mut self) -> Result<()> {
        let uid = ikanata_native::effective_uid();
        ensure!(uid != 0, "Run iKanata as your normal login user");
        let engine = ikanata_native::bundle_resource("kanata")?;
        ikanata_native::verify_executable(&engine, "io.github.mcuste.ikanata.engine")
            .context("The bundled engine signature is invalid")?;
        let home = ikanata_native::home_for_uid(uid)?;
        let created = ikanata_config::setup(&ikanata_config::default_path(&home))
            .context("Cannot use the existing Kanata configuration")?;
        tracing::info!(
            created,
            "configuration selected without replacing an existing file"
        );
        self.prepared = true;
        Ok(())
    }

    fn enroll(&mut self) -> Result<String> {
        let uid = ikanata_native::effective_uid();
        let intent = ikanata_native::home_for_uid(uid)?
            .join("Library/Caches/io.github.mcuste.ikanata/upgrade-intent");
        let saved = match OpenOptions::new()
            .read(true)
            .custom_flags(0x104)
            .open(&intent)
        {
            Ok(mut file) => {
                let metadata = file.metadata()?;
                ensure!(
                    metadata.is_file()
                        && metadata.uid() == uid
                        && metadata.mode() & 0o777 == 0o600
                        && metadata.len() == 8,
                    "The saved upgrade intent is unsafe"
                );
                let mut bytes = [0; 8];
                file.read_exact(&mut bytes)?;
                Some(match &bytes {
                    b"running\n" => true,
                    b"stopped\n" => false,
                    _ => bail!("The saved upgrade intent is invalid"),
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("Cannot read the saved upgrade intent"),
        };
        let reply = ikanata_native::request(Operation::Setup)
            .context("Cannot enroll the configuration owner")?;
        ensure!(succeeded(&reply), "{}", service_detail(&reply));
        self.start_pending |= saved.unwrap_or(true);
        if saved.is_some() {
            fs::remove_file(intent).context("Cannot remove the restored upgrade intent")?;
        }
        tracing::info!(restored = ?saved, "enrolled the active login user");
        Ok(reply)
    }

    fn guide_permissions(&mut self, reply: &str) -> Result<()> {
        if matches!(self.permission_request, PermissionRequest::NotRequested) {
            ikanata_native::request_input_permissions()
                .context("Cannot request iKanata privacy approval from macOS")?;
            self.permission_request = PermissionRequest::Pending(Instant::now());
            tracing::info!("requested privacy consent through the iKanata app");
        }
        if reply.lines().any(|line| line == "accessibility=missing") {
            self.guide(
                "accessibility",
                "Enable iKanata in Accessibility. Setup will continue after the root service verifies approval.",
                Some(ACCESSIBILITY_SETTINGS),
            )?;
        } else if reply.lines().any(|line| line == "input_monitoring=missing") {
            self.guide(
                "input-monitoring",
                "Enable iKanata in Input Monitoring. Setup will continue after the root service verifies approval.",
                Some(INPUT_SETTINGS),
            )?;
        } else {
            bail!("The runtime did not identify the missing privacy approval");
        }
        if matches!(
            self.permission_request,
            PermissionRequest::Pending(since) if since.elapsed() >= Duration::from_secs(90)
        ) {
            ikanata_native::notify(
                "iKanata permission approval",
                "Open iKanata's entries in Accessibility and Input Monitoring and enable the missing approval. Keep iKanata open while the root service checks it.",
            )?;
            self.permission_request = PermissionRequest::FallbackOffered;
        }
        Ok(())
    }

    fn guide_driver(&mut self, state: &str) -> Result<()> {
        if matches!(self.driver_request, DriverRequest::NotRequested) {
            let result = (|| -> Result<()> {
                if state == "driver_missing" {
                    ensure!(
                        self.options.install_driver,
                        "The standalone driver is missing. Run ikanata setup --install-driver"
                    );
                    let reply = ikanata_native::request(Operation::InstallDriver)
                        .context("Cannot install the bundled VirtualHID driver")?;
                    ensure!(succeeded(&reply), "{}", service_detail(&reply));
                }
                activate_driver()
            })();
            self.driver_request = match result {
                Ok(()) => DriverRequest::ActivationRequested,
                Err(error) => DriverRequest::Failed(format!("{error:#}")),
            };
        }
        if let DriverRequest::Failed(detail) = &self.driver_request {
            bail!("{detail}");
        }
        self.guide(
            "driver-approval",
            "Approve VirtualHID in Login Items & Extensions. Restart macOS if requested. Setup will keep checking.",
            Some(LOGIN_SETTINGS),
        )
    }

    fn guide(&mut self, key: &'static str, message: &str, settings: Option<&str>) -> Result<()> {
        if self.last_guidance == Some(key) {
            return Ok(());
        }
        if let Some(settings) = settings {
            open(&[settings]).context("Cannot open the missing approval in System Settings")?;
        }
        ikanata_native::notify("iKanata setup", message)?;
        tracing::info!(step = key, "{message}");
        self.last_guidance = Some(key);
        Ok(())
    }
}

pub(super) fn run(install_driver: bool, enable_startup: bool) -> Result<()> {
    let mut onboarding = Onboarding::new(install_driver, enable_startup, true);
    while !onboarding.poll()? {
        std::thread::sleep(Duration::from_secs(2));
    }
    open(&[
        "-g",
        "-n",
        "-a",
        "/Applications/iKanata.app",
        "--args",
        "onboard",
    ])
    .context("Cannot start background configuration observation")?;
    let reply = ikanata_native::request(Operation::Status)?;
    ensure!(succeeded(&reply), "{}", service_detail(&reply));
    cliclack::log::success(service_detail(&reply))?;
    Ok(())
}

pub(super) fn manual_permissions() -> Result<()> {
    cliclack::log::warning(concat!(
        "Use this guidance if the automatic permission request needs attention.\n",
        "Enable iKanata in Accessibility and Input Monitoring in System Settings.\n",
        "Keep /Applications/iKanata.app open. Setup continues only after the root service verifies approval.\n",
        "Do not select the engine executable or another app."
    ))?;
    open(&[ACCESSIBILITY_SETTINGS, INPUT_SETTINGS])
}

fn state(reply: &str) -> Option<&str> {
    reply.lines().nth(1)?.strip_prefix("state=")
}

fn open(arguments: &[&str]) -> Result<()> {
    let status = Command::new("/usr/bin/open")
        .args(arguments)
        .status()
        .context("Cannot invoke LaunchServices")?;
    ensure!(
        status.success(),
        "macOS refused to open the requested application or setting"
    );
    Ok(())
}

pub(super) fn service_detail(reply: &str) -> String {
    let mut lines = reply.lines().skip(1);
    let state = lines
        .next()
        .unwrap_or("state=unknown")
        .trim_start_matches("state=");
    let detail = lines
        .filter(|line| {
            !line.starts_with("accessibility=") && !line.starts_with("input_monitoring=")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if detail.is_empty() {
        state.replace('_', " ")
    } else {
        format!("{}: {detail}", state.replace('_', " "))
    }
}

fn activate_driver() -> Result<()> {
    let manager = Path::new("/Applications/.Karabiner-VirtualHIDDevice-Manager.app");
    ensure!(
        manager.is_dir(),
        "The driver manager is missing; the root service must complete driver installation"
    );
    let status = Command::new("/usr/bin/open")
        .arg("-a")
        .arg(manager)
        .args(["--args", "forceActivate"])
        .env_clear()
        .status()
        .context("Cannot request driver activation")?;
    ensure!(status.success(), "Cannot open the driver manager");
    Ok(())
}
