//! Command-line parsing, validated acquisition configuration, and exit diagnostics.

use clap::{Parser, Subcommand, ValueEnum};
use robigus::fetch::{DownloadLimits, ExtractionLimits, FetchOptions, GitOptions};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::time::Duration;

use crate::commands::{fetch::FetchArgs, print::PrintArgs};

const CONFIG_HELP: &str = "TOML acquisition configuration (unknown fields are errors). Schema:
[network]
allowlist = [\"crates.io\"] # future analysis proxy only; NOT enforced by fetch
[limits.download]
max_bytes = 536870912
connect_timeout = 30 # seconds, positive integer
timeout = 600 # seconds, positive integer
[limits.extraction]
max_entries = 100000
max_total_size = 1073741824 # bytes
[limits.git]
timeout = 600 # seconds, positive integer
max_submodule_depth = 4 # zero disables submodule expansion
max_submodules = 64 # zero disables submodule fetching
submodule_schemes = [\"https\"]
[subagent]
enabled = false # future opt-in placeholder; no sub-agent is invoked
All fields are optional. Size/count limits must be positive except the two
submodule limits. Download limits apply to HTTP; extraction limits apply to
tarballs and git checkouts; git limits apply to git acquisition. Local sources
are hashed in place without acquisition limits. Graph readers do not acquire
sources. This file does not yet override recorded graph predicate configuration.";

#[derive(Debug, Parser)]
#[command(
    name = "tsp-analyzer",
    version,
    about = "Analyze upstream dependency graphs"
)]
pub struct Cli {
    /// Database path; required for analyze, check, print, and export.
    #[arg(long, global = true, value_name = "PATH")]
    pub db: Option<PathBuf>,
    /// Output representation; DOT is reserved for the unimplemented export command.
    #[arg(long, global = true, value_enum, default_value = "text")]
    pub format: OutputFormat,
    /// Forbid network acquisition (local sources and supported cache hits only).
    #[arg(long, global = true)]
    pub offline: bool,
    /// Future analysis sandbox preference; fetch and graph readers do not establish one.
    #[arg(long, global = true, value_enum, default_value = "auto")]
    pub sandbox: SandboxChoice,
    /// Positive analysis concurrency limit (future-only; fetch is a single acquisition).
    #[arg(long, global = true, default_value = "1")]
    pub jobs: NonZeroUsize,
    /// Enable debug tracing on stderr.
    #[arg(long, global = true)]
    pub verbose: bool,
    #[arg(long, global = true, value_name = "PATH", help = "TOML configuration (see --help for schema)", long_help = CONFIG_HELP)]
    pub config: Option<PathBuf>,
    /// Source cache root (default: XDG_CACHE_HOME/robigus or ~/.cache/robigus).
    #[arg(long, global = true, value_name = "PATH")]
    pub cache: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Dot,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SandboxChoice {
    Auto,
    Bwrap,
    Native,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Acquire a source and print its local path and digest.
    Fetch(FetchArgs),
    /// Not implemented yet: fetch, analyze, and persist/resume an analysis.
    Analyze {
        #[arg(value_name = "SOURCE")]
        source: String,
    },
    /// Validate an existing database's schema and graph integrity.
    Check,
    /// Print an existing graph; predicates are displayed, not evaluated.
    /// Predicate filters and --why are future work (WP-2.3).
    Print(PrintArgs),
    /// Not implemented yet: lossless JSON or lossy DOT graph export.
    Export,
    /// Print the tool version.
    Version,
}

impl Cli {
    pub fn validate(&self) -> Result<(), CliError> {
        if matches!(
            self.command,
            Command::Analyze { .. } | Command::Check | Command::Print(_) | Command::Export
        ) && self.db.is_none()
        {
            return Err(CliError::Usage(
                "--db <PATH> is required for analyze, check, print, and export".into(),
            ));
        }
        if self.format == OutputFormat::Dot && !matches!(self.command, Command::Export) {
            return Err(CliError::Usage(
                "--format dot is only supported by export (not implemented yet)".into(),
            ));
        }
        Ok(())
    }

    pub fn load_config(&self) -> Result<Config, CliError> {
        let config: Config = match &self.config {
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(|error| {
                    CliError::Usage(format!("cannot read config '{}': {error}", path.display()))
                })?;
                toml::from_str(&text).map_err(|error| {
                    CliError::Usage(format!("invalid config '{}': {error}", path.display()))
                })?
            }
            None => Config::default(),
        };
        config.validate()?;
        Ok(config)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub network: NetworkConfig,
    pub limits: LimitsConfig,
    pub subagent: SubagentConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub allowlist: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubagentConfig {
    pub enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub download: DownloadConfig,
    pub extraction: ExtractionConfig,
    pub git: GitConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DownloadConfig {
    pub max_bytes: Option<NonZeroU64>,
    /// Seconds, matching DownloadLimits::connect_timeout.
    pub connect_timeout: Option<NonZeroU64>,
    /// Seconds, matching DownloadLimits::timeout.
    pub timeout: Option<NonZeroU64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractionConfig {
    pub max_entries: Option<NonZeroU64>,
    pub max_total_size: Option<NonZeroU64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GitConfig {
    /// Seconds, matching GitOptions::timeout.
    pub timeout: Option<NonZeroU64>,
    pub max_submodule_depth: Option<usize>,
    pub max_submodules: Option<usize>,
    pub submodule_schemes: Option<BTreeSet<String>>,
}

impl Config {
    pub fn validate(&self) -> Result<(), CliError> {
        if let Some(hosts) = &self.network.allowlist {
            for host in hosts {
                // Future proxy policy uses literal DNS hosts, not URLs or wildcards.
                if host.len() > 253
                    || host.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    })
                {
                    return Err(CliError::Usage(format!(
                        "network.allowlist entry '{host}' must be a literal DNS hostname"
                    )));
                }
            }
        }
        if let Some(schemes) = &self.limits.git.submodule_schemes {
            for scheme in schemes {
                if !scheme.starts_with(|c: char| c.is_ascii_lowercase())
                    || !scheme.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.')
                    })
                {
                    return Err(CliError::Usage(format!(
                        "invalid URL scheme '{scheme}' in limits.git.submodule_schemes"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn fetch_options(&self) -> FetchOptions {
        let download = &self.limits.download;
        let extraction = &self.limits.extraction;
        let git = &self.limits.git;
        let defaults = FetchOptions::default();
        FetchOptions {
            download: DownloadLimits {
                max_bytes: download
                    .max_bytes
                    .map_or(defaults.download.max_bytes, NonZeroU64::get),
                connect_timeout: download
                    .connect_timeout
                    .map_or(defaults.download.connect_timeout, |seconds| {
                        Duration::from_secs(seconds.get())
                    }),
                timeout: download
                    .timeout
                    .map_or(defaults.download.timeout, |seconds| {
                        Duration::from_secs(seconds.get())
                    }),
            },
            extraction: ExtractionLimits {
                max_entries: extraction
                    .max_entries
                    .map_or(defaults.extraction.max_entries, NonZeroU64::get),
                max_total_size: extraction
                    .max_total_size
                    .map_or(defaults.extraction.max_total_size, NonZeroU64::get),
            },
            git: GitOptions {
                timeout: git.timeout.map_or(defaults.git.timeout, |seconds| {
                    Duration::from_secs(seconds.get())
                }),
                max_submodule_depth: git
                    .max_submodule_depth
                    .unwrap_or(defaults.git.max_submodule_depth),
                max_submodules: git.max_submodules.unwrap_or(defaults.git.max_submodules),
                submodule_schemes: git
                    .submodule_schemes
                    .clone()
                    .unwrap_or(defaults.git.submodule_schemes),
            },
        }
    }

    pub fn describe_future_settings(&self) {
        if self.network.allowlist.is_some() {
            eprintln!(
                "notice: network.allowlist is reserved for the future analysis proxy; fetch does NOT enforce this host allowlist"
            );
        }
        if self.subagent.enabled {
            eprintln!(
                "notice: subagent.enabled is a future opt-in placeholder; no sub-agent is implemented or invoked"
            );
        }
    }
}

/// These variants represent real failure classes, not simulated command outcomes.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum CliError {
    #[error("{0}")]
    #[diagnostic(code(tsp_analyzer::analysis))]
    Analysis(String),
    #[error("{0}")]
    #[diagnostic(code(tsp_analyzer::usage))]
    Usage(String),
    #[error(transparent)]
    #[diagnostic(code(tsp_analyzer::database))]
    Database(#[from] robigus::StoreError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Sandbox(#[from] robigus::SandboxUnavailable),
    // The expansion engine will produce this only after an analysis has finished.
    #[allow(dead_code)]
    #[error("analysis finished with an incomplete graph: {0}")]
    #[diagnostic(code(tsp_analyzer::incomplete))]
    Incomplete(String),
    #[error("{0} is not implemented yet; no analysis, export, or sandbox setup was performed")]
    #[diagnostic(code(tsp_analyzer::not_implemented))]
    NotImplemented(&'static str),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Analysis(_) | Self::NotImplemented(_) => 1,
            Self::Usage(_) => 2,
            Self::Database(_) => 3,
            Self::Sandbox(_) => 4,
            Self::Incomplete(_) => 5,
        }
    }
}

impl From<robigus::RobigusError> for CliError {
    fn from(error: robigus::RobigusError) -> Self {
        match error {
            robigus::RobigusError::Store(error) => Self::Database(error),
            robigus::RobigusError::Sandbox(error) => Self::Sandbox(error),
            robigus::RobigusError::Predicate(error) => Self::Usage(error.to_string()),
            robigus::RobigusError::Fetch(
                error @ (robigus::FetchError::InvalidDigest(_)
                | robigus::FetchError::InvalidCacheKey(_)
                | robigus::FetchError::UnsupportedFormat(_)),
            ) => Self::Usage(error.to_string()),
            other => Self::Analysis(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_required_and_global_on_either_side() {
        for command in ["analyze", "check", "print", "export"] {
            let mut args = vec!["tsp-analyzer", command];
            if command == "analyze" {
                args.push("source");
            }
            let cli = Cli::try_parse_from(&args).unwrap();
            assert_eq!(cli.validate().unwrap_err().exit_code(), 2);
            args.extend(["--db", "fixture.db"]);
            Cli::try_parse_from(&args).unwrap().validate().unwrap();
        }
        Cli::try_parse_from(["tsp-analyzer", "--db", "fixture.db", "check"])
            .unwrap()
            .validate()
            .unwrap();
        Cli::try_parse_from(["tsp-analyzer", "version"])
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn jobs_must_be_positive_and_dot_is_export_only() {
        for jobs in ["0", "-1", "invalid"] {
            assert!(Cli::try_parse_from(["tsp-analyzer", "--jobs", jobs, "version"]).is_err());
        }
        let cli = Cli::try_parse_from(["tsp-analyzer", "version", "--format", "dot"]).unwrap();
        assert_eq!(cli.validate().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn all_failure_exit_codes_including_incomplete() {
        let errors = [
            (CliError::Analysis("fetch failed".into()), 1),
            (CliError::NotImplemented("analyze"), 1),
            (CliError::Usage("bad config".into()), 2),
            (
                CliError::Database(robigus::StoreError::SchemaTooNew {
                    found: 2,
                    supported: 1,
                }),
                3,
            ),
            (
                CliError::Sandbox(robigus::SandboxUnavailable { attempts: vec![] }),
                4,
            ),
            (CliError::Incomplete("node limit reached".into()), 5),
        ];
        for (error, expected) in errors {
            assert_eq!(error.exit_code(), expected);
        }
    }

    #[test]
    fn library_error_mapping_preserves_classes() {
        assert_eq!(
            CliError::from(robigus::RobigusError::from(
                robigus::FetchError::InvalidDigest("bad".into())
            ))
            .exit_code(),
            2
        );
        assert_eq!(
            CliError::from(robigus::RobigusError::from(robigus::FetchError::Download(
                "timeout".into()
            )))
            .exit_code(),
            1
        );
        assert_eq!(
            CliError::from(robigus::RobigusError::from(robigus::StoreError::Corrupt(
                "invalid JSON".into()
            )))
            .exit_code(),
            3
        );
        assert_eq!(
            CliError::from(robigus::RobigusError::from(robigus::SandboxUnavailable {
                attempts: vec![]
            }))
            .exit_code(),
            4
        );
    }

    #[test]
    fn config_rejects_unknown_fields_and_invalid_values() {
        for text in [
            "unknown = true",
            "[network]\nunknown = true",
            "[subagent]\nunknown = true",
            "[limits]\nmax_nodes = 4",
            "[limits.download]\nunknown = 1",
            "[limits.extraction]\nunknown = 1",
            "[limits.git]\nunknown = 1",
            "[limits.download]\ntimeout = 0",
            "[limits.download]\nconnect_timeout = -1",
            "[limits.extraction]\nmax_entries = 0",
            "[limits.git]\nmax_submodules = -1",
        ] {
            assert!(toml::from_str::<Config>(text).is_err(), "accepted {text}");
        }
        for text in [
            "[network]\nallowlist = ['https://crates.io']",
            "[network]\nallowlist = ['*.example.org']",
            "[limits.git]\nsubmodule_schemes = ['https://']",
        ] {
            assert!(toml::from_str::<Config>(text).unwrap().validate().is_err());
        }
    }

    #[test]
    fn every_fetch_limit_is_applied_and_defaults_match_library() {
        let config: Config = toml::from_str(
            "\
[limits.download]
max_bytes = 11
connect_timeout = 12
timeout = 13
[limits.extraction]
max_entries = 14
max_total_size = 15
[limits.git]
timeout = 16
max_submodule_depth = 0
max_submodules = 0
submodule_schemes = ['https', 'http']",
        )
        .unwrap();
        config.validate().unwrap();
        let options = config.fetch_options();
        assert_eq!(options.download.max_bytes, 11);
        assert_eq!(options.download.connect_timeout, Duration::from_secs(12));
        assert_eq!(options.download.timeout, Duration::from_secs(13));
        assert_eq!(options.extraction.max_entries, 14);
        assert_eq!(options.extraction.max_total_size, 15);
        assert_eq!(options.git.timeout, Duration::from_secs(16));
        assert_eq!(options.git.max_submodule_depth, 0);
        assert_eq!(options.git.max_submodules, 0);
        assert_eq!(
            options.git.submodule_schemes,
            BTreeSet::from(["http".into(), "https".into()])
        );
        let actual = Config::default().fetch_options();
        let defaults = FetchOptions::default();
        assert_eq!(actual.download.max_bytes, defaults.download.max_bytes);
        assert_eq!(
            actual.download.connect_timeout,
            defaults.download.connect_timeout
        );
        assert_eq!(actual.download.timeout, defaults.download.timeout);
        assert_eq!(
            actual.extraction.max_entries,
            defaults.extraction.max_entries
        );
        assert_eq!(
            actual.extraction.max_total_size,
            defaults.extraction.max_total_size
        );
        assert_eq!(actual.git.timeout, defaults.git.timeout);
        assert_eq!(
            actual.git.max_submodule_depth,
            defaults.git.max_submodule_depth
        );
        assert_eq!(actual.git.max_submodules, defaults.git.max_submodules);
        assert_eq!(actual.git.submodule_schemes, defaults.git.submodule_schemes);
    }
}
