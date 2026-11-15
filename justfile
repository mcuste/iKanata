set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

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
