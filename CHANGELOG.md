# Changelog

## [Unreleased]

## [0.1.0] - 2026-11-17

### Added

- Add the iKanata app and CLI for Apple Silicon Macs running macOS 15 or later.
- Add onboarding for the root service, VirtualHID driver, and keyboard permissions.
- Build installer packages, corresponding source archives, checksums, and a Homebrew cask.
- Prepare tagged releases with `just release` and publish artifacts through GitHub Actions.

### Known issues

- Upgrade and uninstall verification currently fails.
- The installer is unsigned and the app is not notarized. Gatekeeper may block installation or launch.
