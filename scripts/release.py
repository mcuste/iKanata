#!/usr/bin/env python3
"""Build pinned sources and local ad-hoc signed macOS installer artifacts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "target" / "ikanata-release"
PINS = json.loads((ROOT / "release" / "upstream.json").read_text())
TARGET = PINS["target"]
BUNDLE_ID = PINS["bundle_identifier"]
SERVICE_ID = PINS["service_identifier"]
PRIVATE = Path("Library/Application Support/iKanata")
EXECUTABLES = Path("Library/PrivilegedHelperTools/iKanata")
DRIVER_ADAPTER = {
    "version": "0.3.1",
    "url": "https://static.crates.io/crates/karabiner-driverkit/karabiner-driverkit-0.3.1.crate",
    "sha256": "97e4fc764f78a4a5cbf705c9502a51a0ba4931dbee25f4fbc59654059f6ca9e9",
}


def run(*arguments, cwd=ROOT, capture=False, env=None):
    result = subprocess.run(
        [str(argument) for argument in arguments], cwd=cwd,
        env=env, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout if capture else None


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def build_environment():
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(BUILD / "cargo-home")
    environment["MACOSX_DEPLOYMENT_TARGET"] = PINS["minimum_macos"]
    environment.pop("CARGO_TARGET_DIR", None)
    return environment


def download(url, checksum, name):
    destination = BUILD / "downloads" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        temporary = destination.with_suffix(destination.suffix + ".part")
        run("curl", "--fail", "--location", "--proto", "=https", "--tlsv1.2",
            "--output", temporary, url)
        if digest(temporary) != checksum:
            temporary.unlink()
            raise ValueError("Downloaded checksum does not match: " + name)
        temporary.replace(destination)
    if digest(destination) != checksum:
        raise ValueError("Cached checksum does not match: " + name)
    return destination


def driver_source_archive():
    driver = PINS["driver"]
    return download(driver["source_url"], driver["source_sha256"],
                    "driver-" + driver["commit"] + "-source.tar.gz")


def prepare_driver_adapter(source):
    name = "karabiner-driverkit-" + DRIVER_ADAPTER["version"]
    archive = download(DRIVER_ADAPTER["url"], DRIVER_ADAPTER["sha256"], name + ".crate")
    run("tar", "-xzf", archive, "-C", source)
    vendor = source / name / "c_src" / "Karabiner-DriverKit-VirtualHIDDevice"
    shutil.rmtree(vendor)
    vendor.mkdir()
    driver_root = "Karabiner-DriverKit-VirtualHIDDevice-" + PINS["driver"]["commit"]
    run("tar", "-xzf", driver_source_archive(), "-C", vendor, "--strip-components=1",
        driver_root + "/include", driver_root + "/vendor", driver_root + "/LICENSE.md")


def prepare_engine():
    engine = PINS["engine"]
    source = BUILD / "engine-source" / ("kanata-" + engine["commit"])
    archive = download(engine["source_url"], engine["source_sha256"], "kanata-source.tar.gz")
    patch_hashes = {path: digest(ROOT / path) for path in engine["patches"]}
    fingerprint = {
        "commit": engine["commit"],
        "source_sha256": engine["source_sha256"],
        "patch_sha256": patch_hashes,
        "driver_commit": PINS["driver"]["commit"],
        "driver_source_sha256": PINS["driver"]["source_sha256"],
        "adapter_sha256": DRIVER_ADAPTER["sha256"],
        "release_script_sha256": digest(ROOT / "scripts" / "release.py"),
    }
    stamp = source.parent / "patches.json"
    if source.is_dir() and stamp.exists() and json.loads(stamp.read_text()) == fingerprint:
        return source
    if source.parent.exists():
        shutil.rmtree(source.parent)
    source.parent.mkdir(parents=True)
    run("tar", "-xzf", archive, "-C", source.parent)
    prepare_driver_adapter(source)
    for patch in engine["patches"]:
        directory = str(source.relative_to(ROOT))
        run("git", "apply", "--check", "--directory", directory, ROOT / patch)
        run("git", "apply", "--directory", directory, ROOT / patch)
    write_json(stamp, fingerprint)
    return source


def build_engine():
    source = prepare_engine()
    run("cargo", "build", "--manifest-path", source / "Cargo.toml", "--locked",
        "--release", "--target", TARGET, "--target-dir", BUILD / "engine-target",
        "--no-default-features", "--features", "tcp_server", "--bin", "kanata",
        env=build_environment())
    binary = BUILD / "engine-target" / TARGET / "release" / "kanata"
    validate_engine(binary)
    return binary

def validate_engine(binary):
    if os.geteuid() == 0:
        raise ValueError("Run release validation as an unprivileged user")
    run(binary, "--check", "--no-wait", "-c", ROOT / "crates" / "ikanata-config" / "starter.kbd")
    preflight = subprocess.run(
        [str(binary), "--ikanata-check-permissions"],
        cwd=ROOT, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if preflight.returncode not in (0, 10, 11, 12):
        raise ValueError("The engine permission preflight is unavailable")
    directory = BUILD / "validation"
    directory.mkdir(exist_ok=True)
    candidate = directory / "commands-disabled.kbd"
    candidate.write_text("(defcfg danger-enable-cmd yes)\n(defsrc a)\n(deflayer base (cmd /usr/bin/true))\n")
    try:
        result = subprocess.run(
            [str(binary), "--check", "--no-wait", "-c", str(candidate)],
            cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if result.returncode == 0 or "cmd is not enabled for this kanata executable" not in result.stdout:
            raise ValueError("The engine did not reject compiled-out commands:\n" + result.stdout)
    finally:
        candidate.unlink()


def workspace_metadata():
    return json.loads(run("cargo", "metadata", "--locked", "--no-deps",
                          "--format-version", "1", capture=True, env=build_environment()))


def build_workspace():
    run("cargo", "build", "--workspace", "--bins", "--locked", "--release",
        "--target", TARGET, "--target-dir", BUILD / "workspace-target",
        env=build_environment())
    return BUILD / "workspace-target" / TARGET / "release"


def vendor_sources(project, license_metadata):
    configuration = run("cargo", "vendor", "--locked", "--versioned-dirs",
                        "vendor-dependencies", cwd=project, capture=True,
                        env=build_environment())
    cargo_configuration = project / ".cargo" / "config.toml"
    cargo_configuration.parent.mkdir(exist_ok=True)
    with cargo_configuration.open("a") as output:
        output.write("\n" + configuration)
    metadata = json.loads(run("cargo", "metadata", "--offline", "--locked",
                              "--format-version", "1", cwd=project, capture=True,
                              env=build_environment()))
    write_json(license_metadata, [
        {"name": package["name"], "version": package["version"],
         "license": package["license"],
         "license_file": Path(package["license_file"]).name if package["license_file"] else None,
         "source": package["source"]}
        for package in metadata["packages"]
    ])


def corresponding_source(version):
    source = prepare_engine()
    staging = BUILD / "corresponding-source"
    if staging.exists():
        shutil.rmtree(staging)
    engine = staging / "source" / "kanata"
    shutil.copytree(source, engine)
    vendor_sources(engine, staging / "dependency-licenses.json")
    project = staging / "source" / "ikanata"
    project.mkdir(parents=True)
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "LICENSE"):
        shutil.copy2(ROOT / name, project / name)
    for name in ("crates", "scripts", "packaging", "release"):
        shutil.copytree(ROOT / name, project / name,
                        ignore=shutil.ignore_patterns("target", "__pycache__", ".env", ".env.*"))
    vendor_sources(project, staging / "ikanata-dependency-licenses.json")
    shutil.copy2(driver_source_archive(), staging / "source" / "driver-source.tar.gz")
    gpl = PINS["gpl_license"]
    shutil.copy2(download(gpl["url"], gpl["sha256"], "GPL-3.0.txt"), staging / "GPL-3.0.txt")
    shutil.copy2(ROOT / "packaging" / "NOTICE.txt", staging / "NOTICE.txt")
    destination = BUILD / ("iKanata-" + version + "-source.tar.gz")
    run("tar", "-czf", destination, "-C", staging, ".")
    return destination


def copy_file(source, destination, executable=False):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if executable else 0o644)


def sign(path, identifier):
    run("codesign", "--force", "--identifier", identifier, "--sign", "-", path)
    verify_code(path, identifier)


def verify_code(path, identifier):
    requirement = '=identifier "' + identifier + '"'
    run("codesign", "--verify", "--strict", "--test-requirement", requirement, path)


def bundle(version, engine, binaries, sources):
    payload = BUILD / "payload"
    if payload.exists():
        shutil.rmtree(payload)
    app = payload / "Applications" / "iKanata.app"
    contents = app / "Contents"
    resources = contents / "Resources"
    resources.mkdir(parents=True)
    runtime = payload / PRIVATE / "Runtime"
    clients = runtime / "Clients"
    clients.mkdir(parents=True)
    executables = payload / EXECUTABLES
    executables.mkdir(parents=True)
    with (contents / "Info.plist").open("wb") as output:
        plistlib.dump({
            "CFBundleIdentifier": BUNDLE_ID,
            "CFBundleName": "iKanata",
            "CFBundleDisplayName": "iKanata",
            "CFBundleExecutable": "ikanata-app",
            "CFBundlePackageType": "APPL",
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": version,
            "LSMinimumSystemVersion": PINS["minimum_macos"],
            "LSArchitecturePriority": ["arm64"],
            "LSUIElement": True,
            "NSHumanReadableCopyright": "iKanata contributors. MIT license.",
        }, output)
    app_main = contents / "MacOS" / "ikanata-app"
    copy_file(binaries / "ikanata-app", app_main, executable=True)
    bundled_engine = resources / "kanata"
    code = [
        (binaries / "ikanata", contents / "MacOS" / "ikanata", BUNDLE_ID + ".cli"),
        (engine, bundled_engine, BUNDLE_ID + ".engine"),
        (binaries / "ikanata-config-reader", executables / "ikanata-config-reader", BUNDLE_ID + ".config-reader"),
    ]
    for source, destination, identifier in code:
        copy_file(source, destination, executable=True)
        sign(destination, identifier)
    public_engine = executables / "kanata"
    copy_file(bundled_engine, public_engine, executable=True)
    verify_code(public_engine, BUNDLE_ID + ".engine")
    copy_file(ROOT / "packaging" / (SERVICE_ID + ".plist"),
              contents / "Library" / "LaunchDaemons" / (SERVICE_ID + ".plist"))
    driver = PINS["driver"]
    package = download(driver["url"], driver["sha256"], driver["package"])
    signature = run("pkgutil", "--check-signature", package, capture=True)
    if "Developer ID Installer:" not in signature or ("(" + driver["team_id"] + ")") not in signature:
        raise ValueError("The driver package does not have the expected upstream signer")
    copy_file(package, resources / driver["package"])
    copy_file(sources, resources / "CorrespondingSource.tar.gz")
    copy_file(ROOT / "packaging" / "NOTICE.txt", resources / "NOTICE.txt")
    licenses = resources / "Licenses"
    copy_file(prepare_engine() / "LICENSE", licenses / "Kanata-LGPL-3.0.txt")
    gpl = PINS["gpl_license"]
    copy_file(download(gpl["url"], gpl["sha256"], "GPL-3.0.txt"), licenses / "GPL-3.0.txt")
    copy_file(ROOT / "LICENSE", licenses / "iKanata-MIT.txt")
    with tarfile.open(driver_source_archive(), "r:gz") as archive:
        member = archive.getmember("Karabiner-DriverKit-VirtualHIDDevice-" + driver["commit"] + "/LICENSE.md")
        licenses.mkdir(exist_ok=True)
        with archive.extractfile(member) as source:
            (licenses / "Driver-Unlicense.txt").write_bytes(source.read())
    metadata = dict(PINS)
    metadata["version"] = version
    metadata["code_signature"] = "ad-hoc"
    metadata["installer_signature"] = "unsigned"
    metadata["patch_sha256"] = {name: digest(ROOT / name) for name in PINS["engine"]["patches"]}
    metadata["source_sha256"] = digest(sources)
    metadata["binary_sha256"] = {
        str(path.relative_to(payload)): digest(path)
        for _, path, _ in code
    }
    metadata["binary_sha256"][str(public_engine.relative_to(payload))] = digest(public_engine)
    metadata["rustc"] = run("rustc", "--version", capture=True).strip()
    metadata["cargo"] = run("cargo", "--version", capture=True).strip()
    write_json(resources / "release-metadata.json", metadata)
    for directory, _, files in os.walk(payload):
        Path(directory).chmod(0o755)
        for filename in files:
            path = Path(directory) / filename
            if not path.stat().st_mode & 0o111:
                path.chmod(0o644)
    for directory in (payload / PRIVATE, runtime, clients):
        directory.chmod(0o700)
    sign(app, BUNDLE_ID)
    run("codesign", "--verify", "--deep", "--strict", app)
    for path in (bundled_engine, public_engine):
        verify_code(path, BUNDLE_ID + ".engine")
    if digest(bundled_engine) != digest(public_engine):
        raise ValueError("The protected engine differs from its signed source")
    protected_copies = [
        (contents / "MacOS" / "ikanata", clients / "ikanata", BUNDLE_ID + ".cli"),
        (app_main, clients / "ikanata-app", BUNDLE_ID),
    ]
    for source, destination, identifier in protected_copies:
        copy_file(source, destination, executable=True)
        # The app signature requires its source bundle's Info.plist.
        if identifier != BUNDLE_ID:
            verify_code(destination, identifier)
        if digest(destination) != digest(source):
            raise ValueError("The protected executable copy differs from its signed source")
        metadata["binary_sha256"][str(destination.relative_to(payload))] = digest(destination)
    metadata["binary_sha256"][str(app_main.relative_to(payload))] = digest(app_main)
    return payload, metadata


def release(args):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("Local release builds require an Apple Silicon Mac")
    binaries = build_workspace()
    packages = workspace_metadata()["packages"]
    versions = {package["version"] for package in packages if package["name"].startswith("ikanata-")}
    if versions != {args.version}:
        raise ValueError("The release version must match every workspace package version")
    engine = build_engine()
    sources = corresponding_source(args.version)
    payload, metadata = bundle(args.version, engine, binaries, sources)
    component = BUILD / "component.pkg"
    package = BUILD / ("iKanata-" + args.version + "-arm64.pkg")
    scripts = BUILD / "installer-scripts"
    scripts.mkdir(exist_ok=True)
    for name in ("preinstall", "postinstall"):
        copy_file(ROOT / "packaging" / "installer" / name, scripts / name, executable=True)
    run("pkgbuild", "--root", payload, "--install-location", "/", "--ownership", "recommended",
        "--identifier", BUNDLE_ID + ".installer", "--version", args.version,
        "--component-plist", ROOT / "packaging" / "components.plist", "--scripts", scripts, component)
    run("productbuild", "--package", component, package)
    metadata["installer"] = {"name": package.name, "sha256": digest(package)}
    metadata["corresponding_source"] = {"name": sources.name, "sha256": digest(sources)}
    write_json(BUILD / "release-metadata.json", metadata)
    (BUILD / "SHA256SUMS").write_text(
        digest(package) + "  " + package.name + "\n" + digest(sources) + "  " + sources.name + "\n")
    cask(args.version, package, args.release_base_url)
    print("Release artifacts: " + str(BUILD))


def cask(version, package, base_url):
    parsed = urlparse(base_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or re.search(r'[\s"\\]', base_url)):
        raise ValueError("Use an HTTPS release directory URL without credentials, query, or fragment")
    if not package.is_file() or package.name != "iKanata-" + version + "-arm64.pkg":
        raise ValueError("Generate the cask from the actual versioned installer")
    checksum = digest(package)
    metadata = json.loads((package.parent / "release-metadata.json").read_text())
    if metadata["version"] != version or metadata["installer"] != {"name": package.name, "sha256": checksum}:
        raise ValueError("The installer does not match the completed release metadata")
    text = '''cask "ikanata" do
  version "VERSION"
  sha256 "CHECKSUM"

  url "ARTIFACT_URL"
  name "iKanata"
  desc "Background Kanata keyboard remapper"
  homepage "https://github.com/mcuste/iKanata"

  depends_on arch: :arm64
  depends_on macos: :sequoia

  pkg "iKanata-#{version}-arm64.pkg"
  binary "/Applications/iKanata.app/Contents/MacOS/ikanata"

  caveats <<~EOS
    This installer is unsigned and its ad-hoc signed app is not notarized.
    macOS may block installation or launch under Gatekeeper.
  EOS

  uninstall_preflight_steps do
    run "/bin/sh",
        args: ["-ec", 'state=enabled; if test -f "/Library/Application Support/iKanata/owner"; then state=$(/usr/bin/sed -n 2p "/Library/Application Support/iKanata/owner"); fi; case "$state" in enabled) state=running;; stopped) ;; *) exit 1;; esac; printf "%s\\n" "$state"'],
        sudo: true, stdout_path: "{{temp}}/intent"
  end

  preflight_steps do
    if_path_exists "{{temp}}/intent" do
      mkdir_p "Library/Caches/io.github.mcuste.ikanata", base: :home
      set_permissions "Library/Caches/io.github.mcuste.ikanata", "0700", base: :home
      copy "{{temp}}/intent", "Library/Caches/io.github.mcuste.ikanata/upgrade-intent", target_base: :home
      set_permissions "Library/Caches/io.github.mcuste.ikanata/upgrade-intent", "0600", base: :home
    end
  end

  uninstall script: {
              executable: "/Applications/iKanata.app/Contents/MacOS/ikanata",
              args: ["uninstall", "--keep-app"],
              sudo: false,
              must_succeed: true,
            },
            pkgutil: "io.github.mcuste.ikanata.installer",
            delete: [
              "/Applications/iKanata.app",
              "/Library/Application Support/iKanata/Runtime",
              "/Library/PrivilegedHelperTools/iKanata",
            ]
end
'''
    text = text.replace("VERSION", version).replace("CHECKSUM", checksum)
    text = text.replace("ARTIFACT_URL", base_url.rstrip("/") + "/" + package.name)
    (BUILD / "ikanata.rb").write_text(text)


def main():
    if Path.cwd().resolve() != ROOT:
        raise ValueError("Run this script from the repository root")
    if not BUILD.resolve().is_relative_to(ROOT):
        raise ValueError("The build directory must remain inside the repository")
    BUILD.mkdir(parents=True, exist_ok=True)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("engine", help="Build only the pinned, patched engine")
    source = commands.add_parser("source", help="Archive corresponding source and locked dependencies")
    source.add_argument("--version", required=True)
    publish = commands.add_parser("release", help="Build ad-hoc signed code, an unsigned installer, and a cask")
    publish.add_argument("--version", required=True)
    publish.add_argument("--release-base-url", required=True)
    generate = commands.add_parser("cask", help="Generate a cask from an existing installer")
    generate.add_argument("--version", required=True)
    generate.add_argument("--package", type=Path, required=True)
    generate.add_argument("--release-base-url", required=True)
    args = parser.parse_args()
    if hasattr(args, "version") and not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        raise ValueError("Use a three-part numeric release version")
    if args.command == "engine":
        print(build_engine())
    elif args.command == "source":
        print(corresponding_source(args.version))
    elif args.command == "release":
        release(args)
    else:
        package = args.package.resolve()
        if not package.is_relative_to(ROOT):
            raise ValueError("The installer must be inside the repository")
        cask(args.version, package, args.release_base_url)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("Release failed: " + str(error), file=sys.stderr)
        sys.exit(1)
