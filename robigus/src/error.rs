//! Error types for robigus (spec §15).
//!
//! Every public fallible API funnels through [`RobigusError`]; the
//! sub-errors are the typed failures of each component. Later work packages
//! refine the sub-errors as their components land (store: WP-1.4, fetch:
//! WP-1.5, sandbox: WP-1.7, predicate parser: WP-1.3).

/// Top-level library error.
///
/// Each variant wraps one component's error unchanged; `Display` is
/// transparent. The CLI maps variants to exit codes (spec §14) as noted on
/// each variant.
#[derive(Debug, thiserror::Error)]
pub enum RobigusError {
    /// A database or schema failure (CLI exit code 3; exit code 1 for
    /// [`StoreError::Clock`]).
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Source acquisition failed. Invalid caller input
    /// ([`FetchError::InvalidDigest`], [`FetchError::InvalidCacheKey`],
    /// [`FetchError::UnsupportedFormat`]) is a usage error (CLI exit code 2);
    /// every other fetch failure is an analysis failure (exit code 1).
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// A predicate failed to parse (CLI exit code 2).
    #[error(transparent)]
    Predicate(#[from] PredicateError),
    /// A Debian version failed to parse (CLI exit code 1).
    #[error(transparent)]
    Dpkg(#[from] DpkgError),
    /// No sandbox mechanism could be established (CLI exit code 4).
    #[error(transparent)]
    Sandbox(#[from] SandboxUnavailable),
    /// Project detection failed (CLI exit code 1).
    #[error(transparent)]
    Detect(#[from] DetectError),
    /// An analyzer failed (CLI exit code 1).
    #[error(transparent)]
    Analyzer(#[from] AnalyzerError),
}

/// Analyzer failures (spec §7.5). Problems confined to one package — a
/// rejected path dependency, a `cargo metadata` failure that falls back to
/// manifest parsing — are not errors: they are recorded as failed plan rows
/// in the analyzer's output. These variants stop the analysis of a root.
#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    /// The analyzer has not been implemented yet.
    #[error("analyzer not implemented: {0}")]
    Unsupported(String),
    /// The root's own manifest is missing, unreadable, malformed, or names
    /// no package or workspace.
    #[error("cannot analyze the project: {0}")]
    Project(String),
    /// Tool introspection was requested (allowlisted network) but no
    /// sandbox was supplied; tools never run outside a sandbox (spec §10).
    #[error("tool introspection requires an established sandbox")]
    SandboxRequired,
    /// A sandboxed tool could not be launched, supervised or recorded.
    #[error(transparent)]
    Sandbox(#[from] crate::sandbox::SandboxError),
    /// A required tool is missing from the sandbox or failed to report its
    /// version (for example `/usr/bin/cargo`).
    #[error("toolchain unavailable: {0}")]
    Toolchain(String),
    /// A tool ran successfully but its output is malformed or oversized.
    #[error("malformed tool output: {0}")]
    ToolOutput(String),
    /// The discovered packages cannot be represented consistently, for
    /// example two different in-tree packages with the same identity.
    #[error("inconsistent analysis result: {0}")]
    Inconsistent(String),
    /// A blocking analysis task failed to run or complete.
    #[error("analysis task failed: {0}")]
    Task(String),
}

/// SQLite persistence failures.
///
/// Every variant except [`StoreError::Clock`] is a database or schema error:
/// the CLI reports it with exit code 3 (spec §14).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite itself failed, or the store could not reach it: an error from
    /// `rusqlite` or a migration, a failure to create the database's parent
    /// directory, a poisoned connection lock, or a failed blocking task.
    #[error("database error: {0}")]
    Sqlite(String),
    /// The database's `PRAGMA user_version` is newer than this build
    /// supports; it is never migrated (spec §11.3).
    #[error("schema version {found} is newer than the supported version {supported}")]
    SchemaTooNew {
        /// The schema version recorded in the database.
        found: u32,
        /// The newest schema version this build can open.
        supported: u32,
    },
    /// Stored or snapshot data is malformed or inconsistent: a JSON column
    /// that does not parse, unrecognized enum text, a missing metadata row,
    /// a dangling package reference, or records that would be merged during
    /// graph reconstruction. Also returned for an inconsistent request, such
    /// as an edge whose `from` does not match the `from` argument or an
    /// unknown invocation ID.
    #[error("stored data failed validation: {0}")]
    Corrupt(String),
    /// [`Store::update_status`](crate::store::Store::update_status) was asked
    /// for a status change that §7.7 does not allow.
    #[error("invalid analysis status transition from {from} to {to}")]
    InvalidTransition {
        /// The current stored status (for example `Complete`).
        from: String,
        /// The requested status (for example `Not_Started`).
        to: String,
    },
    /// The referenced package is not stored. Carries the package name only.
    /// The store never creates a placeholder for it.
    #[error("package not found: {0}")]
    PackageNotFound(String),
    /// A status change that would break a §11.3 invariant, for example
    /// `Started` without plan rows or `Error` without a recorded cause.
    #[error("status change rejected: {0}")]
    Invariant(String),
    /// The value cannot be persisted without loss: reloading it would not
    /// yield an equal value (spec §11.3, lossless round trip).
    #[error("cannot store losslessly: {0}")]
    Unrepresentable(String),
    /// The store could not timestamp a write because the system clock is
    /// unusable. Nothing was written. Unlike the other variants, the CLI
    /// reports this as an analysis failure (exit code 1), since the database
    /// itself is not at fault.
    #[error(transparent)]
    Clock(#[from] ClockError),
}

/// The system clock cannot be represented as a timestamp: it is set before
/// the year -9999 or after 9999, the range `jiff` supports. robigus reports
/// this instead of recording a wrong time.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("system clock is outside the supported timestamp range: {0}")]
pub struct ClockError(pub String);

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
///
/// Through the CLI, [`FetchError::InvalidDigest`],
/// [`FetchError::InvalidCacheKey`], [`FetchError::UnsupportedFormat`], and
/// [`FetchError::InvalidRegistry`] are usage errors (exit code 2); every
/// other variant is an analysis failure (exit code 1).
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// A git clone, fetch, checkout, or submodule step failed, including a
    /// time, entry-count, size, nesting, or URL-scheme limit being exceeded.
    #[error("git operation failed: {0}")]
    Git(String),
    /// An HTTP download failed, returned an error status, or exceeded the
    /// download size limit.
    #[error("download failed: {0}")]
    Download(String),
    /// Offline mode was requested but the source is not in the cache, or was
    /// not pinned precisely enough (full commit ID or SHA-256) to look up.
    #[error("offline source unavailable in cache: {0}")]
    OfflineCacheMiss(String),
    /// Downloaded content does not match its expected SHA-256 digest.
    #[error("checksum mismatch: expected {expected}, computed {actual}")]
    Checksum {
        /// The expected digest (lowercase hex).
        expected: String,
        /// The digest computed from the downloaded bytes (lowercase hex).
        actual: String,
    },
    /// A caller-supplied SHA-256 digest is not 64 hexadecimal characters.
    #[error("invalid SHA-256 digest '{0}': expected 64 hexadecimal characters")]
    InvalidDigest(String),
    /// A cache key component is empty, starts with `.`, or contains
    /// characters outside `[A-Za-z0-9._-]`.
    #[error("invalid cache key '{0}': must be a single path component of [A-Za-z0-9._-]")]
    InvalidCacheKey(String),
    /// An archive could not be extracted safely: it is corrupt, an entry
    /// violates a §7.2 hardening rule (path escape, setuid bits, unsupported
    /// entry type), or an extraction limit was exceeded.
    #[error("extraction failed: {0}")]
    Extraction(String),
    /// Walking or digesting a source tree failed, or the blocking task
    /// doing so did not complete.
    #[error("source tree walk failed: {0}")]
    Walk(String),
    /// The source archive is in a format robigus cannot extract.
    #[error("unsupported archive format: {0}")]
    UnsupportedFormat(String),
    /// A crate registry lookup or download failed: an HTTP error, a missing
    /// crate or version, malformed index data, or a yanked version.
    #[error("registry error: {0}")]
    Registry(String),
    /// A registry source or configuration is invalid: an index URL that is
    /// not `sparse+https`, an invalid crate name, or a version that is not
    /// exact. A usage error (CLI exit code 2).
    #[error("invalid registry source: {0}")]
    InvalidRegistry(String),
    /// A registry requires authentication and no usable token was obtained,
    /// or the registry rejected it. Never contains the token.
    #[error("registry authentication failed: {0}")]
    Credential(String),
    /// An underlying filesystem operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Predicate parse failure. The parser lands in WP-1.3; the type is defined
/// here so the model can reference it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("predicate parse error at bytes {span_start}..{span_end}: {message}")]
pub struct PredicateError {
    /// Byte offset in the input where the offending span starts.
    pub span_start: usize,
    /// Byte offset one past the end of the offending span.
    pub span_end: usize,
    /// What the parser expected or rejected.
    pub message: String,
}

/// A confidence score outside the 0–100 scale (spec §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("confidence {0} is outside 0..=100")]
pub struct ConfidenceOutOfRange(pub u8);

/// Project detection failures (spec §7.3). Through the CLI these are
/// analysis failures (exit code 1).
#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    /// The project root is not a directory, a directory entry could not be
    /// read, or the blocking detection task did not complete.
    #[error("project tree walk failed: {0}")]
    Walk(String),
    /// The tree exceeds [`crate::detect::DetectionLimits::max_entries`].
    #[error("detection limit exceeded: {0}")]
    LimitExceeded(String),
    /// An underlying filesystem operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Debian version parse failures (see `dpkg`), returned by
/// [`DpkgVersion::parse`](crate::dpkg::DpkgVersion::parse).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpkgError {
    /// The version string is empty or only whitespace.
    #[error("empty version string")]
    Empty,
    /// The text before the first `:` is not a `u32`.
    #[error("invalid epoch '{epoch}': must be an unsigned integer")]
    InvalidEpoch {
        /// The rejected epoch text.
        epoch: String,
    },
    /// Nothing remains for the upstream version after removing the epoch
    /// and revision (for example `1:` or `-1`).
    #[error("upstream version component cannot be empty")]
    EmptyUpstream,
    /// The version ends with `-`, leaving an empty Debian revision.
    #[error("debian revision cannot be empty after '-'")]
    EmptyRevision,
}

/// A network allowlist entry or proxy request host that is not a literal DNS
/// host name (spec §10.2). URLs, wildcards, ports and IP addresses are
/// rejected; internationalized names must be given in their ASCII (`xn--`)
/// form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid host name {host:?}: {reason}")]
pub struct InvalidHost {
    /// The rejected input, truncated to 256 characters.
    pub host: String,
    /// Which rule it broke.
    pub reason: &'static str,
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[error("no sandbox available{details}", details = format_sandbox_attempts(.attempts))]
pub struct SandboxUnavailable {
    /// Every mechanism probed, in probe order, with its failure cause.
    pub attempts: Vec<SandboxAttempt>,
}

fn format_sandbox_attempts(attempts: &[SandboxAttempt]) -> String {
    attempts
        .iter()
        .map(|attempt| format!("\n  - {attempt}"))
        .collect()
}
