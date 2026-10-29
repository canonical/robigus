//! Error types for robigus (spec §15).
//!
//! Every public fallible API funnels through [`RobigusError`]; the
//! sub-errors are the typed failures of each component. Later work packages
//! refine the sub-errors as their components land (store: WP-1.4, fetch:
//! WP-1.5, sandbox: WP-1.7, predicate parser: WP-1.3).

/// Top-level library error.
#[derive(Debug, thiserror::Error)]
pub enum RobigusError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    Predicate(#[from] PredicateError),
    #[error(transparent)]
    Dpkg(#[from] DpkgError),
    #[error(transparent)]
    Sandbox(#[from] SandboxUnavailable),
    #[error(transparent)]
    Detect(#[from] DetectError),
}

/// SQLite persistence failures.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(String),
    #[error("schema version {found} is newer than the supported version {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("stored data failed validation: {0}")]
    Corrupt(String),
    #[error("invalid analysis status transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Corrupt(error.to_string())
    }
}

impl From<PredicateError> for StoreError {
    fn from(error: PredicateError) -> Self {
        Self::Corrupt(error.to_string())
    }
}

/// Source acquisition failures.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("git operation failed: {0}")]
    Git(String),
    #[error("download failed: {0}")]
    Download(String),
    #[error("checksum mismatch: expected {expected}, computed {actual}")]
    Checksum { expected: String, actual: String },
    #[error("extraction failed: {0}")]
    Extraction(String),
    #[error("source tree walk failed: {0}")]
    Walk(String),
    #[error("unsupported archive format: {0}")]
    UnsupportedFormat(String),
    #[error("registry error: {0}")]
    Registry(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Predicate parse failure. The parser lands in WP-1.3; the type is defined
/// here so the model can reference it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("predicate parse error at bytes {span_start}..{span_end}: {message}")]
pub struct PredicateError {
    pub span_start: usize,
    pub span_end: usize,
    pub message: String,
}

/// Project detection failures (spec §7.3).
#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    #[error("project tree walk failed: {0}")]
    Walk(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Debian version parse failures (see `dpkg`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpkgError {
    #[error("empty version string")]
    Empty,
    #[error("invalid epoch '{epoch}': must be an unsigned integer")]
    InvalidEpoch { epoch: String },
    #[error("upstream version component cannot be empty")]
    EmptyUpstream,
}

/// One failed sandbox-establishment attempt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{mechanism}: {cause}")]
pub struct SandboxAttempt {
    /// The mechanism that was probed (for example `bubblewrap`, `landlock`).
    pub mechanism: String,
    /// Why it failed, with as much OS-level detail as available.
    pub cause: String,
}

/// Sandboxing is mandatory and fail-closed (spec §10.2): analysis MUST NOT
/// run unsandboxed, so this error carries every mechanism that was attempted
/// and why each one failed. The CLI renders the list as the
/// "no sandbox available" diagnostic (exit code 4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no sandbox available")]
pub struct SandboxUnavailable {
    pub attempts: Vec<SandboxAttempt>,
}
