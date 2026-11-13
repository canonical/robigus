//! `tsp-analyzer` entry point. Diagnostics and tracing stay on stderr.

#![forbid(unsafe_code)]

mod cli;
mod commands;

use clap::Parser;
use cli::{Cli, CliError};
use std::io::Write;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let code = error.exit_code();
            eprintln!("{:?}", miette::Report::new(error));
            ExitCode::from(code)
        }
    }
}

async fn run(cli: Cli) -> Result<u8, CliError> {
    cli.validate()?;
    tracing_subscriber::fmt()
        .with_max_level(if cli.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| CliError::Analysis(format!("cannot initialize tracing: {error}")))?;

    let config = cli.load_config()?;
    config.describe_future_settings();
    let output = commands::run(&cli, &config).await?;
    std::io::stdout()
        .lock()
        .write_all(output.text.as_bytes())
        .map_err(|error| CliError::Analysis(format!("cannot write output: {error}")))?;
    Ok(output.exit_code)
}
