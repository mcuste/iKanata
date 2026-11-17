//! Tests for the command-line interface.

use std::process::Command;

#[test]
fn help_and_version_describe_the_available_interface() {
    let help = Command::new(env!("CARGO_BIN_EXE_ikanata"))
        .arg("--help")
        .output()
        .expect("run ikanata --help");
    assert!(help.status.success());
    let help_text = String::from_utf8(help.stdout).expect("UTF-8 help output");
    assert!(help_text.contains("Usage: ikanata"));
    assert_eq!(help.stderr.as_slice(), b"");

    let version = Command::new(env!("CARGO_BIN_EXE_ikanata"))
        .arg("--version")
        .output()
        .expect("run ikanata --version");
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).expect("UTF-8 version output"),
        format!("ikanata {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(version.stderr.as_slice(), b"");
}

#[test]
fn unsupported_commands_and_extra_arguments_fail() {
    let cases: &[&[&str]] = &[&["unknown-command"], &["status", "extra"]];
    for args in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_ikanata"))
            .args(*args)
            .output()
            .expect("run ikanata with invalid arguments");
        assert!(!output.status.success());
        assert_eq!(output.stdout.as_slice(), b"");
        let error = String::from_utf8(output.stderr).expect("UTF-8 error output");
        assert!(error.contains("error:"));
    }
}
