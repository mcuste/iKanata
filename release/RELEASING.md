# Release

Use an Apple Silicon Mac with macOS 15+, Python 3.9+, Rust stable, and Xcode tools.
No Apple developer account, signing identity, or credentials are required.

## Tagged releases

Use Python 3.11+ for release preparation. Start on `main` with a clean working tree.
Add release entries under `## [Unreleased]` in `CHANGELOG.md` and commit them first.

1. Prepare and verify the workspace release.

```sh
just release 0.1.0
```

The command updates the workspace version, local dependency versions, and lockfile.
It moves the unreleased changelog entries into a dated version section and keeps
an empty `[Unreleased]` section. It rejects empty notes and duplicate releases.
It runs `just verify`, commits release metadata and the changelog, and creates `v0.1.0`.
Verification failures restore the manifest, lockfile, and changelog. Other changes remain.
An existing tag or a lower version fails without changing files.

2. Push the branch and tag together.

```sh
git push --atomic origin main v0.1.0
```

Use `just release 0.1.0 --push` to prepare and push in one command.
If pushing fails, the local commit and tag remain. Retry the push command.

The Release workflow verifies the workspace on an Apple Silicon macOS runner.
It builds and publishes the installer, corresponding source, checksums, metadata,
and `ikanata.rb` as GitHub release assets. It does not install the package or run
interactive VM tests. Complete those checks before pushing a release tag.
The package remains unsigned and unnotarized.
The GitHub release body contains the actual entries from that version's changelog
section, not a link or automatically generated commit notes.

3. Copy the published `ikanata.rb` into `Casks/ikanata.rb` in the Homebrew tap.

Commit and push the tap change after Homebrew validation and VM lifecycle checks.
The workflow does not need credentials for the tap and does not modify it.

## Local packages

1. Build the local installer from the repository root.

```sh
python3 scripts/release.py release --version 0.1.0 \
  --release-base-url https://github.com/mcuste/iKanata/releases/download/v0.1.0
```

The command builds and validates pinned, patched Kanata with commands disabled.
It ad-hoc signs project executables, the plain Kanata engine, and iKanata with explicit identifiers.
It produces an unsigned `.pkg`, source archive, checksums, metadata, and a cask
under `target/ikanata-release`. It does not install or publish anything.
The cask uses the actual package SHA-256, never a placeholder.

2. Install the package in the dedicated Tart VM.
3. Complete onboarding in the VM's active console session.
Onboarding rechecks existing approvals and guides only missing steps. It preserves
configuration and saved startup intent. Without a console user, installation
defers onboarding until the user opens `/Applications/iKanata.app`.
The package bundles the CLI at `/Applications/iKanata.app/Contents/MacOS/ikanata`.
Homebrew adds it to `PATH`; direct package installs require the full path or a
session-only `export PATH="/Applications/iKanata.app/Contents/MacOS:$PATH"`.

Approve iKanata's root service in macOS Login Items & Extensions. After enrollment,
the app asks that service to install the original signed, pinned VirtualHID package
bundled with iKanata. No driver installer wizard opens. The root service checks
the package checksum, vendor signature, installed version, and existing receipts.
It preserves a compatible shared driver and rejects incompatible or unreceipted
installations. The user-session vendor manager requests extension activation.
Approve only macOS authorization, extension, Accessibility, and Input Monitoring
prompts. `ikanata setup --install-driver` uses the same integrated installation.
Run installation and runtime checks only inside the dedicated Tart VM. Do not
install the app or driver on the host or change host system settings.

The unsigned, unnotarized package or app may fail Gatekeeper checks.
Ad-hoc signatures do not establish a trusted publisher or guarantee acceptance.
Do not disable Gatekeeper, quarantine, SIP, or privacy protections.
The bundled daemon plist registers `Contents/MacOS/ikanata-app` with the internal
`service` argument through SMAppService. The GUI and root service share the
identifier `io.github.mcuste.ikanata`. The root service verifies its code hash
against `Runtime/Clients/ikanata-app` before accepting requests.
The installer keeps the app and installed executables root:wheel owned.
`/Library/PrivilegedHelperTools/iKanata` contains plain `kanata` and
`ikanata-config-reader` executables. The same signed engine also resides at
`iKanata.app/Contents/Resources/kanata`, with identifier
`io.github.mcuste.ikanata.engine`. The package checks engine signatures and byte
equality. The public directory and executables use mode 0755. Their ancestors
reject symlinks, non-root ownership, group or other writes, and ACL write grants.
The private base `/Library/Application Support/iKanata`, Runtime, and Clients
directories retain mode 0700. The app and CLI trust references remain there with
exactly the app executables' signatures. State, logs, and the control socket stay
private. Upgrades stop the owned root service before replacement and remove the
obsolete engine app wrappers, standalone service, and Runtime engine/reader copies.
They preserve user configuration, driver installation, and startup intent.
Uninstall removes the whole owned public directory. A failed upgrade may leave
the service stopped; no custom rollback exists.
Path checks accept absent ACLs but reject ACL write grants.
Homebrew runs `ikanata uninstall --keep-app` before deleting the protected app.
The CLI removes owned services; Homebrew removes the bundle. Keep the service
available until the CLI cleanup completes.
The nonroot iKanata app requests Accessibility and Input Monitoring approval
through public macOS APIs. Approve iKanata in System Settings, not a hidden
executable or a separate engine app. The root service checks the exact installed
engine using device-free `--ikanata-check-permissions`, which returns 0, 10, 11,
or 12. Only that root check permits setup to continue. Onboarding guides missing
approvals without file selection, TCC edits, or changes to saved startup intent.
New ad-hoc builds can require fresh macOS privacy approval.

4. Publish the package, source archive, `SHA256SUMS`, and `release-metadata.json` together.
5. Add the generated `ikanata.rb` to the existing Homebrew tap when distributing.

Keep free corresponding-source access beside every binary download. The app also
contains patched Kanata, locked dependency sources and licenses, driver source,
iKanata source, and build scripts. The distribution includes GPL/LGPL texts.
Rebuild the extracted engine from `source/kanata` with:

```sh
cargo build --offline --locked --release --target aarch64-apple-darwin \
  --no-default-features --features tcp_server --bin kanata
```
Require dedicated-VM install, SMAppService, privacy, reload/include, held-key stop,
session/sleep, upgrade, Homebrew, ownership/IPC, and config-preserving removal tests.

## Manual VM tests

Run these from an interactive host terminal.

1. Test a fresh installation.

```sh
just vm-manual-fresh target/ikanata-release/iKanata-0.1.0-arm64.pkg
```

2. Test installation over an existing system, using baseline and candidate packages.
Use the same package twice to test reinstallation.

```sh
just vm-manual-existing target/ikanata-release/iKanata-0.1.0-arm64.pkg target/ikanata-release/iKanata-0.1.0-arm64.pkg
```

Each command creates a uniquely named fresh VM and opens its window. Approve
iKanata's root service and the macOS extension and privacy prompts there. The root
service installs the bundled driver without a wizard. Type `CHECK` in the host
terminal after approval. The existing-system run checks the baseline before
installing the candidate without resetting the VM. These commands install nothing
on the host and do not change host system settings.

Both runs load `release/manual-test.kbd`, which maps Caps Lock to Escape. In the
VM's TextEdit, press Command-F, then Caps Lock. Find must close without toggling
capitalization. Type `PASS` only after physical testing. The scripts do not
simulate keys or record typed text.
For keyboard capture errors, inspect
`/Library/Application Support/iKanata/service.log` inside the VM.

Type `DELETE` to test removal. The CLI removes services; the script removes the
protected package bundle. The test removes the driver but preserves the keymap.
Repeat the typing check: Caps Lock must toggle capitalization again.
If macOS requires a restart to unload the extension, finish it and rerun cleanup
before marking the removal test as passed.

Normal uninstall removes an unchanged driver that iKanata installed. It preserves
pre-existing drivers unless you pass `--remove-driver`. Add `--remove-config` to
delete the main keymap; other configuration files remain.

Reports and Tart logs are under `target/manual-vm/<name>`. Human confirmations
are separate from automated checks. Aborting leaves an incomplete report and the
VM for inspection. Stop it with `just --set vm_name NAME vm-stop`.

Guest Agent uses password-free guest execution. Only `target/vm-artifacts` is
shared, read-only. The pinned CI image disables SIP and Gatekeeper; these runs do
not prove protected-Mac behavior. No host keyboard or security settings change.
