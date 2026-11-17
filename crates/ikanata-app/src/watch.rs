use std::fs::{self, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use ikanata_native::Operation;

static STATUS_REQUESTS: OnceLock<SyncSender<()>> = OnceLock::new();

pub(super) fn run(show_on_launch: bool, replace_observer: bool) -> Result<()> {
    let uid = ikanata_native::effective_uid();
    ensure!(uid != 0, "Run iKanata as your normal login user");
    let home = ikanata_native::home_for_uid(uid)?;
    let directory = home.join("Library/Caches/io.github.mcuste.ikanata");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    let metadata = fs::symlink_metadata(&directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o7777 == 0o700,
        "The application cache directory has unsafe permissions"
    );
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(0x100)
        .open(directory.join("app.lock"))?;
    match ikanata_native::lock_file(&lock) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && replace_observer => {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(0x100)
                .open(directory.join("observer.stop"))?;
            let deadline = Instant::now() + Duration::from_secs(75);
            loop {
                match ikanata_native::lock_file(&lock) {
                    Ok(()) => break,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(error) => {
                        return Err(error).context("Cannot stop the previous background observer");
                    }
                }
            }
            tracing::info!("previous background observer stopped for onboarding");
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(0x100)
                .open(directory.join("observer.check"))?;
            tracing::debug!("requested onboarding check from the running background app");
            return Ok(());
        }
        Err(error) => return Err(error).context("Cannot lock the background app instance"),
    }
    match fs::remove_file(directory.join("observer.stop")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("Cannot resume background observation"),
    }
    let config = ikanata_config::default_path(&home);
    let engine = ikanata_native::bundle_resource("kanata")?;
    let (sender, requests) = sync_channel(1);
    STATUS_REQUESTS
        .set(sender)
        .map_err(|_| anyhow::anyhow!("Status observation already initialized"))?;
    std::thread::Builder::new()
        .name("config-observer".into())
        .spawn(move || {
            if let Err(error) = observe(&config, &engine, &directory, &requests) {
                tracing::error!(?error, "configuration observation stopped");
                if let Err(error) = ikanata_native::notify(
                    "iKanata needs attention",
                    "Configuration observation stopped. Open iKanata again or run ikanata status.",
                ) {
                    tracing::debug!(%error, "cannot display observer failure");
                }
            }
            if let Err(error) = ikanata_native::request_app_exit() {
                tracing::error!(%error, "cannot terminate background app");
                std::process::exit(1);
            }
        })
        .context("Cannot start configuration observation")?;
    ikanata_native::run_app(request_status, show_on_launch)
        .context("Native application event loop failed")
}

fn request_status() {
    let Some(requests) = STATUS_REQUESTS.get() else {
        tracing::error!("status observation is unavailable");
        return;
    };
    match requests.try_send(()) {
        Ok(()) | Err(TrySendError::Full(())) => {}
        Err(TrySendError::Disconnected(())) => tracing::error!("status observation stopped"),
    }
}

fn show_status() {
    let message = match ikanata_native::request(Operation::Status) {
        Ok(reply) => super::setup::service_detail(&reply),
        Err(_) => "iKanata is checking setup and waiting for any missing approvals.".into(),
    };
    if let Err(error) = ikanata_native::notify("iKanata", &message) {
        tracing::debug!(%error, "cannot display runtime status");
    }
}

fn observe(config: &Path, engine: &Path, directory: &Path, requests: &Receiver<()>) -> Result<()> {
    let mut watcher: Option<ikanata_config::Watcher> = None;
    let mut last_error = None;
    let mut onboarding = super::setup::Onboarding::new(true, false, false);
    let mut onboarding_error = None;
    let mut next_check = Instant::now();
    tracing::info!("background configuration observation started");
    loop {
        if directory.join("observer.stop").try_exists()? {
            tracing::info!("background observer stopped by an explicit stop marker");
            return Ok(());
        }
        let recheck = directory.join("observer.check");
        let requested = match fs::remove_file(recheck) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error).context("Cannot read onboarding check request"),
        };
        let show = requests.try_recv().is_ok();
        if show || requested {
            next_check = Instant::now();
        }
        if next_check <= Instant::now() {
            match onboarding.poll() {
                Ok(_) => onboarding_error = None,
                Err(error) => {
                    let detail = format!("{error:#}");
                    if onboarding_error.as_ref() != Some(&detail) {
                        tracing::warn!(error = %detail, "automatic onboarding needs attention");
                        if let Err(error) =
                            ikanata_native::notify("iKanata setup", &error.to_string())
                        {
                            tracing::debug!(%error, "cannot display onboarding failure");
                        }
                        onboarding_error = Some(detail);
                    }
                }
            }
            next_check = Instant::now() + Duration::from_secs(5);
        }
        if show {
            show_status();
        }
        if !config.try_exists()? {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }
        let change = match &mut watcher {
            Some(watcher) => watcher.changed(),
            None => ikanata_config::Watcher::new(config.to_path_buf()).map(|new| {
                watcher = Some(new);
                false
            }),
        };
        let result = match change {
            Ok(true) => {
                tracing::debug!("configuration dependency changed");
                ikanata_config::validate(engine, config).and_then(|()| {
                    let reply = ikanata_native::request(Operation::Reload)?;
                    if ikanata_core::succeeded(&reply) {
                        tracing::info!("automatic reload accepted");
                        Ok(())
                    } else {
                        Err(std::io::Error::other(super::setup::service_detail(&reply)))
                    }
                })
            }
            Ok(false) => Ok(()),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            let error = error.to_string();
            if last_error.as_ref() != Some(&error) {
                tracing::warn!(%error, "automatic reload unavailable; active keymap preserved");
                if let Err(error) = ikanata_native::notify(
                    "iKanata configuration",
                    "Cannot reload the configuration. The active keymap remains unchanged. Run ikanata reload for details.",
                ) {
                    tracing::debug!(%error, "cannot display status notification");
                }
                last_error = Some(error);
            }
        } else {
            last_error = None;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
