set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

vm_name := "ikanata-test"
vm_image := "ghcr.io/cirruslabs/macos-tahoe-base@sha256:65c3133a633fda8753cf1f71f2d55727792d534a2125b0032466563dcc8e58fd"
vm_cpu := "4"
vm_memory := "8192"
vm_artifacts := justfile_directory() / "target" / "vm-artifacts"

default:
    @just --list

setup:
    cargo install cargo-deny --version 0.20.2 --locked
    cargo install cargo-machete --version 0.10.1 --locked

format:
    cargo fmt --all

format-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

cargo-check:
    cargo check --workspace --all-targets --all-features --locked

build:
    cargo build --workspace --all-features --locked

build-release:
    cargo build --workspace --all-features --release --locked

test:
    cargo test --workspace --all-features --locked

test-integration:
    cargo test --workspace --all-features --locked --test '*'

deny:
    cargo deny --locked check

machete:
    cargo machete

lint: clippy deny machete

check: format-check clippy cargo-check build deny machete

verify: check test

run *args:
    cargo run --locked --bin ikanata -- "$@"

release version *args:
    python3 scripts/prepare_release.py "$@"

package version base_url:
    python3 scripts/release.py release --version "$1" --release-base-url "$2"

engine:
    python3 scripts/release.py engine

source:
    python3 scripts/release.py source --version "$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')"

vm-create:
    TART_NO_AUTO_PRUNE=1 tart clone "{{vm_image}}" "{{vm_name}}"
    tart set "{{vm_name}}" --cpu "{{vm_cpu}}" --memory "{{vm_memory}}"

vm-run:
    mkdir -p "{{vm_artifacts}}"
    tart run "{{vm_name}}" --no-clipboard --dir "ikanata:{{vm_artifacts}}:ro"

vm-exec +args:
    tart exec "{{vm_name}}" "$@"

vm-install package:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{vm_artifacts}}"
    checksum="$(shasum -a 256 "$1" | cut -d ' ' -f 1)"
    cp -- "$1" "{{vm_artifacts}}/$checksum.pkg"
    tart exec "{{vm_name}}" /bin/sh -ec 'package="/Volumes/My Shared Files/ikanata/$1.pkg"; actual=$(/usr/bin/shasum -a 256 "$package" | /usr/bin/cut -d " " -f 1); test "$actual" = "$1" || { echo "VM package checksum mismatch" >&2; exit 1; }; /usr/bin/sudo -n /usr/sbin/installer -pkg "$package" -target /' -- "$checksum"

vm-setup *args:
    tart exec "{{vm_name}}" /Applications/iKanata.app/Contents/MacOS/ikanata setup "$@"

vm-status:
    tart exec "{{vm_name}}" /Applications/iKanata.app/Contents/MacOS/ikanata status

vm-smoke:
    tart exec "{{vm_name}}" /usr/bin/codesign --verify --deep --strict /Applications/iKanata.app
    tart exec "{{vm_name}}" /Applications/iKanata.app/Contents/MacOS/ikanata --version
    tart exec "{{vm_name}}" /Applications/iKanata.app/Contents/MacOS/ikanata status

vm-security:
    tart exec "{{vm_name}}" /usr/bin/csrutil status
    tart exec "{{vm_name}}" /usr/sbin/spctl --status

vm-stop:
    tart stop "{{vm_name}}"

vm-delete:
    tart delete "{{vm_name}}"

vm-manual-fresh package:
    python3 scripts/manual_vm.py fresh "$1" --image "{{vm_image}}" --cpu "{{vm_cpu}}" --memory "{{vm_memory}}" --artifacts "{{vm_artifacts}}"

vm-manual-existing baseline package:
    python3 scripts/manual_vm.py existing "$2" --baseline "$1" --image "{{vm_image}}" --cpu "{{vm_cpu}}" --memory "{{vm_memory}}" --artifacts "{{vm_artifacts}}"
