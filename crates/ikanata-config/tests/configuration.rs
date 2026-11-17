//! Isolated filesystem tests for the public configuration contract.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use anyhow::{Result, ensure};
use ikanata_config::{STARTER, Watcher, default_path, dependencies, setup, validate};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> io::Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/config-tests");
        fs::create_dir_all(&root)?;
        loop {
            let directory = root.join(format!(
                "{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&directory) {
                Ok(()) => return Ok(Self(directory)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, contents: &str) -> io::Result<PathBuf> {
        let path = self.path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, contents)?;
        Ok(path)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn setup_creates_starter_once_and_preserves_user_edits() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let path = default_path(&sandbox.0);
    ensure!(setup(&path)?, "setup did not create the missing starter");
    ensure!(
        fs::read_to_string(&path)? == STARTER,
        "starter contents differ"
    );
    fs::write(&path, "(defsrc a)\n(deflayer custom a)\n")?;
    ensure!(!setup(&path)?, "setup replaced an existing keymap");
    ensure!(
        fs::read_to_string(path)? == "(defsrc a)\n(deflayer custom a)\n",
        "setup changed the user keymap"
    );
    Ok(())
}

#[test]
fn setup_has_only_one_creator_under_contention() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let path = sandbox.path("new/config.kbd");
    let barrier = Arc::new(Barrier::new(16));
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                setup(&path)
            })
        })
        .collect();
    let mut created = 0;
    for thread in threads {
        let result = thread
            .join()
            .map_err(|_| io::Error::other("setup thread failed"))?;
        match result {
            Ok(true) => created += 1,
            Ok(false) => {}
            // The creator may not yet have written its exclusively opened file.
            Err(error) => ensure!(
                error.kind() == io::ErrorKind::InvalidData,
                "unexpected concurrent setup error"
            ),
        }
    }
    ensure!(
        created == 1,
        "concurrent setup must have exactly one creator"
    );
    ensure!(
        fs::read_to_string(path)? == STARTER,
        "concurrent setup changed the starter"
    );
    Ok(())
}

#[test]
fn setup_preserves_existing_empty_invalid_and_nonregular_files() -> Result<()> {
    let sandbox = Sandbox::new()?;
    for (name, contents) in [
        ("empty", b"".as_slice()),
        ("invalid-utf8", b"\xff".as_slice()),
    ] {
        let path = sandbox.path(name);
        fs::write(&path, contents)?;
        ensure!(
            setup(&path).is_err(),
            "invalid existing config was accepted"
        );
        ensure!(
            fs::read(path)? == contents,
            "setup overwrote an invalid config"
        );
    }
    let directory = sandbox.path("directory");
    fs::create_dir(&directory)?;
    ensure!(setup(&directory).is_err(), "setup accepted a directory");
    ensure!(directory.is_dir(), "setup replaced the directory");
    Ok(())
}

#[cfg(unix)]
#[test]
fn setup_preserves_valid_and_dangling_symlinks() -> Result<()> {
    use std::os::unix::fs::symlink;

    let sandbox = Sandbox::new()?;
    let target = sandbox.write("user.kbd", "(defsrc a)\n(deflayer user a)\n")?;
    let valid = sandbox.path("valid.kbd");
    symlink(&target, &valid)?;
    ensure!(!setup(&valid)?, "setup replaced a symlink");
    ensure!(
        fs::read_link(&valid)? == target,
        "setup retargeted a symlink"
    );
    ensure!(
        fs::read_to_string(valid)? == "(defsrc a)\n(deflayer user a)\n",
        "setup changed the symlink target"
    );
    let missing = sandbox.path("missing.kbd");
    let dangling = sandbox.path("dangling.kbd");
    symlink(&missing, &dangling)?;
    ensure!(
        setup(&dangling).is_err(),
        "setup accepted a dangling symlink"
    );
    ensure!(
        fs::read_link(dangling)? == missing,
        "setup replaced a dangling symlink"
    );
    ensure!(!missing.exists(), "setup created the missing target");
    Ok(())
}

#[cfg(unix)]
#[test]
fn setup_rejects_unreadable_files_and_sockets_without_replacing_them() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let sandbox = Sandbox::new()?;
    let unreadable = sandbox.write("unreadable.kbd", STARTER)?;
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))?;
    let result = setup(&unreadable);
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600))?;
    ensure!(
        result.err().map(|error| error.kind()) == Some(io::ErrorKind::PermissionDenied),
        "unreadable config was not rejected"
    );
    ensure!(
        fs::read_to_string(unreadable)? == STARTER,
        "setup modified an unreadable config"
    );
    let socket = sandbox.path("socket");
    let _listener = UnixListener::bind(&socket)?;
    ensure!(setup(&socket).is_err(), "setup accepted a socket");
    ensure!(
        !fs::metadata(socket)?.is_file(),
        "setup replaced the socket"
    );
    Ok(())
}

#[test]
fn dependencies_ignore_comments_strings_and_nested_noninclude_forms() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let config = sandbox.write(
        "config.kbd",
        concat!(
            "\u{feff};; (include missing-line.kbd)\n",
            "#| outer (include missing-block.kbd) #| nested |# still ignored |#\n",
            "(defvar text \"(include missing-string.kbd)\")\n",
            "(defvar raw r#\"multiline\n(include missing-raw.kbd)\"#)\n",
            "(defalias test (include missing-nested.kbd))\n",
            "(include #| before path |# \"with spaces.kbd\")\n",
            "(include unquoted.kbd)\n",
            "(include r#\"raw path.kbd\"#)\n",
        ),
    )?;
    let one = sandbox.write("with spaces.kbd", "(defalias first a)")?;
    let two = sandbox.write("unquoted.kbd", "(defalias second b)")?;
    let three = sandbox.write("raw path.kbd", "(defalias third c)")?;
    let mut expected = vec![
        fs::canonicalize(config.clone())?,
        fs::canonicalize(one)?,
        fs::canonicalize(two)?,
        fs::canonicalize(three)?,
    ];
    expected.sort();
    ensure!(
        dependencies(&config)? == expected,
        "include discovery read text outside include forms"
    );
    Ok(())
}

#[test]
fn dependencies_resolve_transitive_paths_against_main_directory() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let config = sandbox.write("config.kbd", "(include nested/first.kbd)")?;
    let first = sandbox.write("nested/first.kbd", "(include second.kbd)")?;
    let second = sandbox.write("second.kbd", "(defalias test a)")?;
    let mut expected = vec![
        fs::canonicalize(&config)?,
        fs::canonicalize(first)?,
        fs::canonicalize(second)?,
    ];
    expected.sort();
    ensure!(
        dependencies(&config)? == expected,
        "nested includes used the wrong base directory"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn stow_main_uses_selected_directory_and_allows_outside_targets() -> Result<()> {
    use std::os::unix::fs::symlink;

    let sandbox = Sandbox::new()?;
    let target = sandbox.write("dotfiles/deep/main.kbd", "(include ../outside.kbd)")?;
    let included = sandbox.write("outside.kbd", "(defalias test a)")?;
    let config = sandbox.path("selected/config.kbd");
    fs::create_dir_all(sandbox.path("selected"))?;
    symlink(&target, &config)?;
    let mut expected = vec![fs::canonicalize(target)?, fs::canonicalize(included)?];
    expected.sort();
    ensure!(
        dependencies(&config)? == expected,
        "Stow includes used the target's directory"
    );
    Ok(())
}

#[test]
fn dependencies_reject_malformed_forms_and_missing_targets() -> Result<()> {
    let sandbox = Sandbox::new()?;
    for contents in [
        "(include)",
        "(include a b)",
        "(include (nested))",
        "(include \"\")",
        "(include missing.kbd)",
        "(defsrc",
        ")",
        "top-level-atom",
        "(defvar text \"unterminated)",
        "(defvar text r#\"unterminated)",
        "#| unterminated #| nested |#",
    ] {
        let config = sandbox.write("config.kbd", contents)?;
        ensure!(dependencies(&config).is_err(), "accepted malformed input");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn dependencies_detect_cycles_through_symlinks_and_deduplicate_targets() -> Result<()> {
    use std::os::unix::fs::symlink;

    let sandbox = Sandbox::new()?;
    let config = sandbox.write("config.kbd", "(include first.kbd)\n(include alias.kbd)")?;
    let first = sandbox.write("first.kbd", "(defalias test a)")?;
    symlink(&first, sandbox.path("alias.kbd"))?;
    ensure!(
        dependencies(&config)?.len() == 2,
        "duplicate include targets were not deduplicated"
    );
    fs::write(first, "(include config.kbd)")?;
    ensure!(dependencies(&config).is_err(), "include cycle was accepted");
    Ok(())
}

#[test]
fn watcher_detects_contents_even_when_size_and_timestamp_are_unchanged() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let config = sandbox.write("config.kbd", "(defalias test a)")?;
    let modified = fs::metadata(&config)?.modified()?;
    let mut watcher = Watcher::new(config.clone())?;
    ensure!(
        !watcher.changed()?,
        "unchanged configuration reported a change"
    );
    fs::write(&config, "(defalias test b)")?;
    let file = OpenOptions::new().write(true).open(config)?;
    file.set_times(fs::FileTimes::new().set_modified(modified))?;
    ensure!(watcher.changed()?, "same-size edit was missed");
    ensure!(
        !watcher.changed()?,
        "unchanged configuration reported a change"
    );
    Ok(())
}

#[test]
fn watcher_detects_atomic_replacement_and_new_include_dependencies() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let config = sandbox.write("config.kbd", "(defalias test a)")?;
    let included = sandbox.write("included.kbd", "(defalias other b)")?;
    let mut watcher = Watcher::new(config.clone())?;
    let replacement = sandbox.write("replacement.kbd", "(include included.kbd)")?;
    fs::rename(replacement, &config)?;
    ensure!(watcher.changed()?, "atomic replacement was missed");
    fs::write(included, "(defalias other c)")?;
    ensure!(watcher.changed()?, "new include dependency edit was missed");
    ensure!(!watcher.changed()?, "unchanged include reported a change");
    Ok(())
}

#[cfg(unix)]
#[test]
fn watcher_observes_include_and_main_symlink_retargeting() -> Result<()> {
    use std::os::unix::fs::symlink;

    let sandbox = Sandbox::new()?;
    let first = sandbox.write("first.kbd", "(defalias test a)")?;
    let second = sandbox.write("second.kbd", "(defalias test b)")?;
    let config = sandbox.write("config.kbd", "(include selected.kbd)")?;
    let link = sandbox.path("selected.kbd");
    symlink(&first, &link)?;
    let mut watcher = Watcher::new(config.clone())?;
    fs::remove_file(&link)?;
    symlink(&second, &link)?;
    ensure!(watcher.changed()?, "include symlink retargeting was missed");
    let main_link = sandbox.path("main-link.kbd");
    symlink(config, &main_link)?;
    let mut watcher = Watcher::new(main_link.clone())?;
    fs::remove_file(&main_link)?;
    symlink(first, main_link)?;
    ensure!(watcher.changed()?, "main symlink retargeting was missed");
    Ok(())
}

#[test]
fn watcher_preserves_snapshot_across_parse_and_disappearance_errors() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let config = sandbox.write("config.kbd", "(include included.kbd)")?;
    let included = sandbox.write("included.kbd", "(defalias test a)")?;
    let mut watcher = Watcher::new(config.clone())?;
    fs::write(&config, "(include")?;
    ensure!(watcher.changed().is_err(), "incomplete config was accepted");
    fs::write(&included, "(defalias test b)")?;
    fs::write(&config, "(include included.kbd)")?;
    ensure!(
        watcher.changed()?,
        "include edit during parse failure was lost"
    );
    fs::remove_file(&included)?;
    ensure!(watcher.changed().is_err(), "missing include was accepted");
    ensure!(
        watcher.changed().is_err(),
        "missing include error was discarded"
    );
    fs::write(&included, "(defalias test c)")?;
    ensure!(watcher.changed()?, "restored include was missed");
    fs::remove_file(&config)?;
    ensure!(
        watcher.changed().is_err(),
        "missing main config was accepted"
    );
    ensure!(!config.exists(), "watcher regenerated a missing config");
    Ok(())
}

#[test]
fn watcher_debug_does_not_disclose_configuration_contents() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let config = sandbox.write("config.kbd", "(defvar private private-test-value)")?;
    let watcher = Watcher::new(config)?;
    ensure!(
        !format!("{watcher:?}").contains("private-test-value"),
        "debug output disclosed config contents"
    );
    Ok(())
}

#[cfg(unix)]
fn engine(sandbox: &Sandbox, script: &str) -> io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path = sandbox.write("engine", script)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

#[cfg(unix)]
#[test]
fn validation_errors_never_include_engine_diagnostics_or_input() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let config = sandbox.write("config.kbd", "private-test-value")?;
    let executable = engine(&sandbox, "#!/bin/sh\ncat \"$4\"\ncat \"$4\" >&2\nexit 1\n")?;
    let result = validate(&executable, &config);
    let error = result
        .err()
        .ok_or_else(|| io::Error::other("invalid configuration was accepted"))?;
    ensure!(
        !error.to_string().contains("private-test-value"),
        "validation disclosed configuration contents"
    );
    let missing = validate(&sandbox.path("missing-engine"), &config);
    let error = missing
        .err()
        .ok_or_else(|| io::Error::other("missing engine was accepted"))?;
    ensure!(
        !error.to_string().contains("private-test-value"),
        "spawn error disclosed configuration contents"
    );
    Ok(())
}
