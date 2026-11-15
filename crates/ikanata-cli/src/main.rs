//! Command-line entry point for iKanata.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let argument = args.next();

    if args.next().is_some() {
        eprintln!("error: expected at most one option; use --help for usage");
        return ExitCode::FAILURE;
    }

    match argument.as_deref().and_then(|value| value.to_str()) {
        Some("--version" | "-V") => {
            println!("ikanata {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        None if argument.is_none() => {
            print_help();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("error: unsupported argument; use --help for usage");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "iKanata\n\n\
         Usage: ikanata [OPTIONS]\n\n\
         Options:\n  \
         -h, --help     Print help\n  \
         -V, --version  Print version\n\n\
         This scaffold does not install or control Kanata."
    );
}
