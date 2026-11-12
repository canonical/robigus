//! Dispatch for the independently implemented acquisition and graph renderers.

pub mod check;
pub mod fetch;
pub mod print;

use crate::cli::{Cli, CliError, Command, Config, OutputFormat};
use robigus::fetch::{Cache, FetchedSource};
use robigus::{Store, StoreError};
use std::path::Path;

#[derive(Debug)]
pub struct CommandOutput {
    pub text: String,
    pub exit_code: u8,
}

impl CommandOutput {
    fn success(text: String) -> Self {
        Self { text, exit_code: 0 }
    }
}

pub async fn run(cli: &Cli, config: &Config) -> Result<CommandOutput, CliError> {
    cli.validate()?;
    let json = cli.format == OutputFormat::Json;
    match &cli.command {
        Command::Fetch(args) => {
            let cache = Cache::new(cli.cache.clone().unwrap_or_else(Cache::default_dir));
            let options = config.fetch_options();
            let source = fetch::run(args, cli.offline, &cache, &options).await?;
            Ok(CommandOutput::success(render_fetch(&source, json)?))
        }
        Command::Check => {
            let store = open_reader(database_path(cli)?).await?;
            let report = store.check().await?;
            let text = check::render(&report, json).map_err(output_error)?;
            Ok(CommandOutput {
                text,
                exit_code: if report.is_ok() { 0 } else { 3 },
            })
        }
        Command::Print(args) => {
            let store = open_reader(database_path(cli)?).await?;
            let analysis = store.load().await?;
            let text = print::render(&analysis.graph, args, json).map_err(output_error)?;
            Ok(CommandOutput::success(text))
        }
        Command::Analyze { .. } => Err(CliError::NotImplemented("analyze")),
        Command::Export => Err(CliError::NotImplemented("export")),
        Command::Version => {
            let text = if json {
                format!(
                    "{}\n",
                    serde_json::to_string(&serde_json::json!({
                        "name": "tsp-analyzer",
                        "version": env!("CARGO_PKG_VERSION"),
                    }))
                    .map_err(output_error)?
                )
            } else {
                format!("tsp-analyzer {}\n", env!("CARGO_PKG_VERSION"))
            };
            Ok(CommandOutput::success(text))
        }
    }
}

fn database_path(cli: &Cli) -> Result<&Path, CliError> {
    cli.db
        .as_deref()
        .ok_or_else(|| CliError::Usage("--db <PATH> is required for this command".into()))
}

async fn open_reader(path: &Path) -> Result<Store, CliError> {
    // Store::open creates/migrates databases. Readers must reject a missing
    // path before calling it, rather than create an empty database by accident.
    let metadata = tokio::fs::metadata(path).await.map_err(|error| {
        StoreError::Sqlite(format!(
            "cannot read database '{}': {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(StoreError::Sqlite(format!(
            "database '{}' is not a regular file",
            path.display()
        ))
        .into());
    }
    Ok(Store::open(path).await?)
}

fn output_error(error: serde_json::Error) -> CliError {
    CliError::Analysis(format!("cannot serialize command output: {error}"))
}

#[derive(serde::Serialize)]
struct FetchOutput<'a> {
    path: &'a Path,
    digest: &'a str,
    provenance: robigus::fetch::Provenance,
}

fn render_fetch(source: &FetchedSource, json: bool) -> Result<String, CliError> {
    if json {
        Ok(format!(
            "{}\n",
            serde_json::to_string(&FetchOutput {
                path: &source.tree,
                digest: &source.digest,
                provenance: source.provenance,
            })
            .map_err(output_error)?
        ))
    } else {
        Ok(format!(
            "path: {}\ndigest: {}\n",
            source.tree.display(),
            source.digest
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use robigus::fetch::Provenance;
    use robigus::model::SourceKind;

    #[test]
    fn fetch_output_contract() {
        let source = FetchedSource {
            tree: "source-tree".into(),
            digest: "abc123".into(),
            provenance: Provenance::Verified,
            kind: SourceKind::Path {
                path: "source-tree".into(),
            },
        };
        assert_eq!(
            render_fetch(&source, false).unwrap(),
            "path: source-tree\ndigest: abc123\n"
        );
        let value: serde_json::Value =
            serde_json::from_str(&render_fetch(&source, true).unwrap()).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "path": "source-tree", "digest": "abc123", "provenance": "Verified",
            })
        );
    }

    #[tokio::test]
    async fn readers_do_not_create_missing_databases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.db");
        for command in ["check", "print"] {
            let cli =
                Cli::try_parse_from(["tsp-analyzer", "--db", path.to_str().unwrap(), command])
                    .unwrap();
            let error = run(&cli, &Config::default()).await.unwrap_err();
            assert_eq!(error.exit_code(), 3);
            assert!(!path.exists());
        }
    }

    #[tokio::test]
    async fn stubs_fail_without_opening_database_or_establishing_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.db");
        for command in ["analyze", "export"] {
            let mut args = vec![
                "tsp-analyzer",
                "--db",
                path.to_str().unwrap(),
                "--sandbox",
                "native",
                command,
            ];
            if command == "analyze" {
                args.push("https://example.invalid/source.tar.gz");
            }
            let cli = Cli::try_parse_from(args).unwrap();
            let error = run(&cli, &Config::default()).await.unwrap_err();
            assert!(matches!(error, CliError::NotImplemented(_)));
            assert_eq!(error.exit_code(), 1);
            assert!(!path.exists());
        }
    }

    #[tokio::test]
    async fn check_exit_status_comes_from_integrity_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.db");
        Store::open(&path).await.unwrap();
        let cli = Cli::try_parse_from([
            "tsp-analyzer",
            "check",
            "--db",
            path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .unwrap();
        let report = Store::open(&path).await.unwrap().check().await.unwrap();
        let output = run(&cli, &Config::default()).await.unwrap();
        assert_eq!(output.exit_code, if report.is_ok() { 0 } else { 3 });
        serde_json::from_str::<serde_json::Value>(&output.text).unwrap();
    }

    #[tokio::test]
    async fn version_succeeds_without_a_database() {
        let cli = Cli::try_parse_from(["tsp-analyzer", "version"]).unwrap();
        let output = run(&cli, &Config::default()).await.unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(
            output.text,
            format!("tsp-analyzer {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}
