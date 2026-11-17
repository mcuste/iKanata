//! Preserve and observe user-owned Kanata configuration.

mod config;

pub use config::{STARTER, Watcher, default_path, dependencies, setup, validate};
