//! Authenticated privileged runtime for the installed iKanata application.

mod control;
mod driver;
mod process;
mod runtime;
mod service;
mod storage;

pub use service::run;
