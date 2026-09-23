#![forbid(unsafe_code)]

use std::{io::IsTerminal, process::ExitCode};

use banksy_c2pa::{cli::Cli, menu, run};
use clap::Parser;

fn main() -> ExitCode {
    if std::env::args_os().len() == 1
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
    {
        return match menu::run() {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("ERROR: {error}");
                ExitCode::from(error.exit_code())
            }
        };
    }

    let cli = Cli::parse();
    let json = cli.json;

    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if json {
                let body = serde_json::json!({
                    "status": "error",
                    "error": error.to_string(),
                    "exit_code": error.exit_code(),
                });
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string())
                );
            } else {
                eprintln!("ERROR: {error}");
            }
            ExitCode::from(error.exit_code())
        }
    }
}
