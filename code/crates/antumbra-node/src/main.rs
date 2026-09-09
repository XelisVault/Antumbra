//! The `antumbra-node` binary: the assembly entry point (ADR-025).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match antumbra_node::cli::run(&args) {
        Ok(code) => ExitCode::from(code as u8),
        Err(usage) => {
            eprintln!("{usage}");
            ExitCode::from(2)
        }
    }
}
