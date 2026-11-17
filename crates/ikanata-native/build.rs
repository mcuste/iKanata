//! Compile the dependency-free Objective-C bridge with the selected Apple SDK.

use std::{env, error::Error, io, path::PathBuf, process::Command};

fn run(command: &mut Command) -> io::Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "native compiler failed with {status}"
        )))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=native/bridge.m");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    if env::var("CARGO_CFG_TARGET_OS")? != "macos" {
        return Ok(());
    }
    if env::var("CARGO_CFG_TARGET_ARCH")? != "aarch64" {
        return Err(io::Error::other("iKanata requires Apple Silicon").into());
    }
    let output = PathBuf::from(
        env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::other("Cargo did not provide an output directory"))?,
    );
    let object = output.join("bridge.o");
    let library = output.join("libikanata_native_bridge.a");
    run(Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "clang",
            "-arch",
            "arm64",
            "-mmacosx-version-min=15.0",
            "-fobjc-arc",
            "-fblocks",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fobjc-arc-exceptions",
            "-Wno-deprecated-declarations",
            "-c",
            "native/bridge.m",
            "-o",
        ])
        .arg(&object))?;
    run(Command::new("xcrun")
        .args(["ar", "crs"])
        .arg(&library)
        .arg(&object))?;
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=ikanata_native_bridge");
    println!("cargo:rustc-link-lib=proc");
    for framework in [
        "Foundation",
        "AppKit",
        "ApplicationServices",
        "ServiceManagement",
        "Security",
        "IOKit",
        "SystemConfiguration",
    ] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    Ok(())
}
