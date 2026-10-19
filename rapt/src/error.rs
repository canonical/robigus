//! Error types for the rapt library.

use std::path::PathBuf;
use thiserror::Error;

/// Specific error conditions encountered when querying the Ubuntu archive or cache.
#[derive(Debug, Error)]
pub enum RaptError {
    /// Target Ubuntu series was not specified.
    #[error("target series is required: use --series <SERIES>")]
    MissingSeries,

    /// Mutually exclusive filter flags were both specified.
    #[error("mutually exclusive flags: cannot specify both --{0} and --not-{0}")]
    MutuallyExclusiveFilter(String),

    /// An inverse filter was provided with an invalid number of arguments.
    #[error(
        "invalid inverse filter argument count for --not-{name}: expected between 1 and {max}, got {actual}"
    )]
    InvalidInverseFilterCount {
        /// The name of the filter flag (pocket, component, or arch).
        name: String,
        /// Maximum allowed count (N - 1).
        max: usize,
        /// Actual count passed.
        actual: usize,
    },

    /// An invalid pocket was specified.
    #[error(
        "invalid pocket '{0}': expected one of release, proposed, updates, security, backports"
    )]
    InvalidPocket(String),

    /// An invalid component was specified.
    #[error("invalid component '{0}': expected one of main, universe, restricted, multiverse")]
    InvalidComponent(String),

    /// An invalid architecture was specified.
    #[error(
        "invalid architecture '{0}': expected one of amd64, arm64, armhf, ppc64el, s390x, riscv64"
    )]
    InvalidArchitecture(String),

    /// A regular expression pattern was invalid.
    #[error("invalid regular expression '{pattern}': {source}")]
    InvalidRegex {
        /// The invalid regex pattern string.
        pattern: String,
        /// The underlying regex error.
        #[source]
        source: regex::Error,
    },

    /// A package was not found in the archive cache.
    #[error("package '{0}' not found in archive cache")]
    PackageNotFound(String),

    /// Network error communicating with Ubuntu archive.
    #[error("network request error: {0}")]
    Network(#[from] reqwest::Error),

    /// IO error during caching or file operations.
    #[error("IO error for path '{path}': {source}")]
    Io {
        /// The file or directory path where the IO error occurred.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Decompression error while uncompressing archive index files.
    #[error("decompression error: {0}")]
    Decompression(String),

    /// Serialization or deserialization error for cache files.
    #[error("cache serialization error: {0}")]
    CacheSerialization(#[from] serde_json::Error),

    /// Generic error message.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias for `Result<T, RaptError>`.
pub type Result<T> = std::result::Result<T, RaptError>;
