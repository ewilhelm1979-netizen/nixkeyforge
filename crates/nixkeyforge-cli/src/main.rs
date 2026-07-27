#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use nixkeyforge_cli::{Cli, EXIT_BLOCKER, execute};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(&cli) {
        Ok((output, code)) => {
            println!("{output}");
            ExitCode::from(code)
        }
        Err(error) => {
            eprintln!("nixkeyforge: {error}");
            ExitCode::from(EXIT_BLOCKER)
        }
    }
}
