//! Registry credentials (spec §7.2.2).
//!
//! A registry token grants access to private source code. robigus never
//! stores one: each named registry reads its token from exactly one
//! configured [`CredentialSource`] when, and only when, the registry asks for
//! authentication. Tokens live in [`RegistryToken`], which cannot be
//! displayed, serialized or cloned, redacts itself in `Debug`, and is zeroed
//! when dropped.
//!
//! Zeroization is best effort: the buffers robigus owns (file and process
//! output, the parsed token, and the `Authorization` header bytes it hands
//! to the HTTP client) are zeroed when dropped, but the HTTP stack may copy
//! header bytes into its own write buffers, which robigus cannot reach.
//! Core dumps are therefore disabled *before* any token is read, and a
//! token is refused if that fails, so such copies cannot reach a dump.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::FetchError;

/// Where a registry's token comes from (spec §7.2.2). There is deliberately
/// no source for Cargo's credentials file, Cargo configuration,
/// `CARGO_REGISTRIES_*` variables, `.netrc`, or the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialSource {
    /// No credentials: an authenticated registry fails with a clear error.
    /// Always used for an index given directly (`--index`).
    None,
    /// The environment variable `ROBIGUS_REGISTRY_<NAME>_TOKEN`, where
    /// `<NAME>` is the registry name uppercased with `-` replaced by `_`.
    Env {
        /// The configured registry name.
        registry: String,
    },
    /// A process implementing Cargo's credential provider protocol, run
    /// without a shell: an absolute program path followed by its arguments.
    Process {
        /// Absolute path of the provider executable.
        program: PathBuf,
        /// Arguments passed after `--cargo-plugin`.
        args: Vec<String>,
    },
    /// A token file: a regular file, owned by the invoking user, not reached
    /// through a symlink, and inaccessible to group and others. The token is
    /// its first line.
    File {
        /// Absolute path of the token file.
        path: PathBuf,
    },
}

impl CredentialSource {
    /// The environment variable consulted by [`CredentialSource::Env`].
    pub fn env_var(registry: &str) -> String {
        let name: String = registry
            .chars()
            .map(|c| {
                if c == '-' {
                    '_'
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        format!("ROBIGUS_REGISTRY_{name}_TOKEN")
    }

    /// A short description for diagnostics; never includes a token.
    pub fn describe(&self) -> String {
        match self {
            Self::None => {
                "no credential source (an index given with --index never uses one)".into()
            }
            Self::Env { registry } => format!("environment variable {}", Self::env_var(registry)),
            Self::Process { program, .. } => format!("credential process {}", program.display()),
            Self::File { path } => format!("token file {}", path.display()),
        }
    }

    /// Checks the configured paths: process and file paths must be absolute.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Process { program, .. } if !program.is_absolute() => Err(format!(
                "credential process '{}' must be an absolute path",
                program.display()
            )),
            Self::File { path } if !path.is_absolute() => Err(format!(
                "token file '{}' must be an absolute path",
                path.display()
            )),
            Self::Env { registry } if registry.is_empty() => {
                Err("environment credentials need a registry name".into())
            }
            _ => Ok(()),
        }
    }
}

/// A registry token. It cannot be displayed, serialized or cloned; `Debug`
/// prints `RegistryToken(<redacted>)`; and the bytes are zeroed on drop.
pub struct RegistryToken {
    secret: Zeroizing<String>,
    _no_dumps: Arc<CoreDumpGuard>,
}

impl RegistryToken {
    /// Wraps a token after trimming surrounding whitespace. Empty tokens and
    /// tokens with control characters (which would split headers) are
    /// rejected. `guard` proves core dumps were disabled before the token
    /// was read (see [`CoreDumpGuard::acquire`]).
    fn new(raw: &str, guard: Arc<CoreDumpGuard>) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("the token is empty".into());
        }
        if trimmed.chars().any(char::is_control) {
            return Err("the token contains control characters".into());
        }
        Ok(Self {
            secret: Zeroizing::new(trimmed.to_owned()),
            _no_dumps: guard,
        })
    }

    /// The `Authorization` header value, marked sensitive so HTTP tracing
    /// omits it. Its bytes live in a buffer that is zeroed when the last
    /// copy of the header value is dropped.
    pub(crate) fn header_value(&self) -> Result<reqwest::header::HeaderValue, String> {
        let bytes = bytes::Bytes::from_owner(ZeroizingBytes(Zeroizing::new(
            self.secret.as_bytes().to_vec(),
        )));
        let mut value = reqwest::header::HeaderValue::from_maybe_shared(bytes)
            .map_err(|_| "the token is not a valid HTTP header value".to_string())?;
        value.set_sensitive(true);
        Ok(value)
    }

    /// Replaces every occurrence of the token in `text` with `<redacted>`.
    pub(crate) fn redact(&self, text: &str) -> String {
        text.replace(self.secret.as_str(), "<redacted>")
    }
}

/// A byte buffer zeroed on drop, owned by a [`bytes::Bytes`].
struct ZeroizingBytes(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for ZeroizingBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RegistryToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistryToken(<redacted>)")
    }
}

/// Keeps core dumps (and `ptrace` attachment by other unprivileged
/// processes) disabled while any token, or any read of one, is in progress.
///
/// Guards are reference-counted under one process-wide lock: the first
/// acquisition records the previous setting and disables dumps, and the
/// last release restores it. Acquisition, release and the count update all
/// happen under that lock, so a release cannot restore dumps while another
/// thread is acquiring.
struct CoreDumpGuard(());

/// The number of live guards, and the setting to restore when it reaches 0.
struct DumpState {
    holders: usize,
    #[cfg(target_os = "linux")]
    previous: Option<rustix::process::DumpableBehavior>,
}

static DUMP_STATE: Mutex<DumpState> = Mutex::new(DumpState {
    holders: 0,
    #[cfg(target_os = "linux")]
    previous: None,
});

fn dump_state() -> std::sync::MutexGuard<'static, DumpState> {
    DUMP_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
thread_local! {
    /// Guards acquired minus guards dropped on this thread. Unlike the
    /// process-wide count, other test threads cannot change it.
    static THREAD_GUARDS: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
}

impl CoreDumpGuard {
    /// Disables core dumps for the process, failing closed: if they cannot
    /// be disabled, no token may be read.
    fn acquire() -> Result<Arc<Self>, String> {
        let mut state = dump_state();
        if state.holders == 0 {
            #[cfg(target_os = "linux")]
            {
                use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};
                let previous = dumpable_behavior().ok();
                set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|error| {
                    format!("cannot disable core dumps before reading a registry token: {error}")
                })?;
                state.previous = previous;
            }
        }
        state.holders += 1;
        #[cfg(test)]
        THREAD_GUARDS.with(|count| count.set(count.get() + 1));
        Ok(Arc::new(Self(())))
    }
}

impl Drop for CoreDumpGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        THREAD_GUARDS.with(|count| count.set(count.get() - 1));
        let mut state = dump_state();
        state.holders = state.holders.saturating_sub(1);
        #[cfg(target_os = "linux")]
        if state.holders == 0
            && let Some(previous) = state.previous.take()
        {
            let _ = rustix::process::set_dumpable_behavior(previous);
        }
    }
}

/// Bounds on credential processes and token files.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE: usize = 64 * 1024;
const MAX_TOKEN_FILE: u64 = 64 * 1024;

/// How long an obtained token may be reused in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reuse {
    /// Do not cache (`cache: "never"`).
    Never,
    /// Cache for the rest of this process.
    Session,
    /// Cache until this instant.
    Until(Instant),
}

/// A token obtained for one registry, with its reuse policy.
struct Obtained {
    token: Arc<RegistryToken>,
    reuse: Reuse,
}

/// A cached token and when it expires (`None`: end of this process).
type CachedToken = (Arc<RegistryToken>, Option<Instant>);

/// Obtains tokens on demand and caches reusable ones in memory for this
/// process only. Keyed by normalized index URL.
#[derive(Default)]
pub(crate) struct CredentialCache {
    tokens: Mutex<BTreeMap<String, CachedToken>>,
}

impl fmt::Debug for CredentialCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialCache(<redacted>)")
    }
}

impl CredentialCache {
    /// The token for `index_url` from `source`, reusing a cached one that has
    /// not expired. Runs blocking work (file reads, credential processes) on
    /// a blocking thread.
    pub(crate) async fn token(
        &self,
        index_url: &str,
        registry_name: Option<&str>,
        source: &CredentialSource,
    ) -> Result<Arc<RegistryToken>, FetchError> {
        if let Some(token) = self.cached(index_url) {
            return Ok(token);
        }
        let source = source.clone();
        let index = index_url.to_owned();
        let name = registry_name.map(str::to_owned);
        let obtained =
            tokio::task::spawn_blocking(move || obtain(&source, &index, name.as_deref()))
                .await
                .map_err(|error| {
                    FetchError::Credential(format!("credential task failed: {error}"))
                })??;
        let expiry = match obtained.reuse {
            Reuse::Never => return Ok(obtained.token),
            Reuse::Session => None,
            Reuse::Until(at) => Some(at),
        };
        self.lock()
            .insert(index_url.to_owned(), (obtained.token.clone(), expiry));
        Ok(obtained.token)
    }

    /// Forgets a token (for example after the registry rejected it).
    pub(crate) fn forget(&self, index_url: &str) {
        self.lock().remove(index_url);
    }

    fn cached(&self, index_url: &str) -> Option<Arc<RegistryToken>> {
        let mut tokens = self.lock();
        match tokens.get(index_url) {
            Some((token, expiry)) if expiry.is_none_or(|at| Instant::now() < at) => {
                Some(token.clone())
            }
            Some(_) => {
                tokens.remove(index_url);
                None
            }
            None => None,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, CachedToken>> {
        self.tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn credential_error(source: &CredentialSource, reason: impl fmt::Display) -> FetchError {
    FetchError::Credential(format!("{}: {reason}", source.describe()))
}

fn obtain(
    source: &CredentialSource,
    index_url: &str,
    registry_name: Option<&str>,
) -> Result<Obtained, FetchError> {
    let missing = || {
        credential_error(
            source,
            "the registry requires authentication; configure a credential-provider for it in [registries]",
        )
    };
    if matches!(source, CredentialSource::None) {
        return Err(missing());
    }
    // Disable core dumps before any token bytes exist in this process.
    let guard = CoreDumpGuard::acquire().map_err(|reason| credential_error(source, reason))?;
    let wrap = |raw: &str| {
        RegistryToken::new(raw, guard.clone())
            .map(Arc::new)
            .map_err(|reason| credential_error(source, reason))
    };
    match source {
        CredentialSource::None => Err(missing()),
        CredentialSource::Env { registry } => {
            let variable = CredentialSource::env_var(registry);
            let value = std::env::var_os(&variable)
                .ok_or_else(|| credential_error(source, "the variable is not set"))?;
            let value = Zeroizing::new(
                value
                    .into_string()
                    .map_err(|_| credential_error(source, "the variable is not valid UTF-8"))?,
            );
            Ok(Obtained {
                token: wrap(&value)?,
                reuse: Reuse::Session,
            })
        }
        CredentialSource::File { path } => {
            let contents =
                read_token_file(path).map_err(|reason| credential_error(source, reason))?;
            Ok(Obtained {
                token: wrap(&contents)?,
                reuse: Reuse::Session,
            })
        }
        CredentialSource::Process { program, args } => {
            let response = run_provider(program, args, index_url, registry_name)
                .map_err(|reason| credential_error(source, reason))?;
            Ok(Obtained {
                token: wrap(&response.token)?,
                reuse: response.reuse,
            })
        }
    }
}

/// Reads the first line of a token file, which must be a regular file owned
/// by the invoking user, inaccessible to group and others, and not reached
/// through a symlink.
///
/// The path is walked one component at a time from `/`, each component
/// opened relative to its already-opened parent with `O_NOFOLLOW`, so no
/// component can be swapped for a symlink between a check and the open. The
/// final open is non-blocking, so a FIFO or device cannot hang the read; its
/// type is checked on the opened descriptor before anything is read.
fn read_token_file(path: &Path) -> Result<Zeroizing<String>, String> {
    #[cfg(target_os = "linux")]
    {
        use std::path::Component;

        use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
        use rustix::io::Errno;

        if !path.is_absolute() {
            return Err("the path must be absolute".into());
        }
        let refuse_link = |at: &Path, error: Errno| match error {
            // O_NOFOLLOW on a symlink: ELOOP for the final component,
            // ENOTDIR when a symlink is used as a directory with O_DIRECTORY.
            Errno::LOOP | Errno::NOTDIR | Errno::MLINK => {
                format!(
                    "refusing a path through the symlink or non-directory {}",
                    at.display()
                )
            }
            other => format!("cannot open {}: {other}", at.display()),
        };
        let names: Vec<_> = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(Ok(name)),
                Component::RootDir => None,
                _ => Some(Err(())),
            })
            .collect::<Result<_, ()>>()
            .map_err(|()| "the path must not contain `.` or `..`".to_string())?;
        let (file_name, directories) = names
            .split_last()
            .ok_or_else(|| "the path names no file".to_string())?;
        let directory_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut current = openat(CWD, "/", directory_flags, Mode::empty())
            .map_err(|error| format!("cannot open /: {error}"))?;
        let mut walked = PathBuf::from("/");
        for name in directories {
            walked.push(name);
            current = openat(&current, *name, directory_flags, Mode::empty())
                .map_err(|error| refuse_link(&walked, error))?;
        }
        walked.push(file_name);
        let file = openat(
            &current,
            *file_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| refuse_link(&walked, error))?;
        let stat = fstat(&file).map_err(|error| format!("cannot inspect: {error}"))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err("not a regular file".into());
        }
        if stat.st_uid != rustix::process::geteuid().as_raw() {
            return Err("not owned by the invoking user".into());
        }
        if stat.st_mode & 0o077 != 0 {
            return Err(format!(
                "permissions {:o} allow group or other access; use mode 0600",
                stat.st_mode & 0o777
            ));
        }
        if u64::try_from(stat.st_size).unwrap_or(u64::MAX) > MAX_TOKEN_FILE {
            return Err("the file is too large to be a token".into());
        }
        let mut contents = Zeroizing::new(Vec::new());
        std::fs::File::from(file)
            .take(MAX_TOKEN_FILE)
            .read_to_end(&mut contents)
            .map_err(|error| format!("cannot read: {error}"))?;
        let text =
            std::str::from_utf8(&contents).map_err(|_| "the token is not UTF-8".to_string())?;
        Ok(Zeroizing::new(text.lines().next().unwrap_or("").to_owned()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err("token files are supported only on Linux".into())
    }
}

struct ProviderResponse {
    token: Zeroizing<String>,
    reuse: Reuse,
}

/// Runs a Cargo-protocol credential provider for a `read` token.
fn run_provider(
    program: &Path,
    args: &[String],
    index_url: &str,
    registry_name: Option<&str>,
) -> Result<ProviderResponse, String> {
    if !program.is_absolute() {
        return Err("the program path must be absolute".into());
    }
    let mut command = Command::new(program);
    command
        .arg("--cargo-plugin")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for key in ["PATH", "HOME"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    // Rust opens files and pipes close-on-exec, so the provider inherits
    // only stdio.
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("no stdin pipe")?;
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;

    let (lines_tx, lines_rx) = std::sync::mpsc::channel::<Result<Zeroizing<String>, String>>();
    let reader = std::thread::spawn(move || read_protocol_lines(stdout, &lines_tx));
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let next_line = || -> Result<Zeroizing<String>, String> {
        let wait = deadline.saturating_duration_since(Instant::now());
        match lines_rx.recv_timeout(wait) {
            Ok(line) => line,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "timed out after {} seconds",
                PROCESS_TIMEOUT.as_secs()
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err("exited without a response".into())
            }
        }
    };

    let result = (|| {
        let hello = next_line()?;
        let hello: serde_json::Value = serde_json::from_str(&hello)
            .map_err(|_| "sent an invalid hello message".to_string())?;
        let supports_v1 = hello
            .get("v")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|versions| versions.iter().any(|v| v.as_u64() == Some(1)));
        if !supports_v1 {
            return Err("does not support credential protocol version 1".into());
        }
        let mut registry = serde_json::json!({ "index-url": format!("sparse+{index_url}") });
        if let Some(name) = registry_name {
            registry["name"] = serde_json::Value::String(name.to_owned());
        }
        let request = serde_json::json!({
            "v": 1,
            "kind": "get",
            "operation": "read",
            "registry": registry,
            "args": args,
        });
        writeln!(stdin, "{request}").map_err(|error| format!("cannot send request: {error}"))?;
        stdin
            .flush()
            .map_err(|error| format!("cannot send request: {error}"))?;
        let response = next_line()?;
        parse_provider_response(&response)
    })();
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    result
}

fn read_protocol_lines(
    stdout: std::process::ChildStdout,
    lines: &std::sync::mpsc::Sender<Result<Zeroizing<String>, String>>,
) {
    let mut reader = std::io::BufReader::new(stdout.take(MAX_RESPONSE as u64 * 2));
    loop {
        let mut line = Zeroizing::new(String::new());
        match std::io::BufRead::read_line(&mut reader, &mut line) {
            Ok(0) => return,
            Ok(_) if line.len() > MAX_RESPONSE => {
                let _ = lines.send(Err("sent an oversized message".into()));
                return;
            }
            Ok(_) if line.trim().is_empty() => continue,
            Ok(_) => {
                if lines.send(Ok(line)).is_err() {
                    return;
                }
            }
            Err(_) => {
                let _ = lines.send(Err("sent output that is not UTF-8".into()));
                return;
            }
        }
    }
}

/// A credential provider's response line. The token is deserialized
/// straight into a zeroizing buffer, so no ordinary heap string ever holds
/// it; a JSON escape decoded into serde_json's scratch buffer is the only
/// other copy, and lives only as long as the parse.
#[derive(serde::Deserialize)]
enum ProviderMessage {
    #[serde(rename = "Ok")]
    Ok(ProviderOk),
    #[serde(rename = "Err")]
    Err(ProviderErr),
}

#[derive(serde::Deserialize)]
struct ProviderOk {
    kind: String,
    #[serde(default)]
    token: Option<Zeroizing<String>>,
    #[serde(default)]
    cache: Option<String>,
    #[serde(default)]
    expiration: Option<u64>,
}

#[derive(serde::Deserialize)]
struct ProviderErr {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

fn parse_provider_response(line: &str) -> Result<ProviderResponse, String> {
    let message: ProviderMessage =
        serde_json::from_str(line).map_err(|_| "sent an invalid response".to_string())?;
    let ok = match message {
        ProviderMessage::Err(error) => {
            return Err(match error.kind.as_deref().unwrap_or("other") {
                "not-found" => "has no token for this registry".into(),
                "url-not-supported" => "does not support this registry".into(),
                "operation-not-supported" => "does not support reading tokens".into(),
                _ => format!(
                    "failed: {}",
                    bounded(error.message.as_deref().unwrap_or("failed"))
                ),
            });
        }
        ProviderMessage::Ok(ok) => ok,
    };
    if ok.kind != "get" {
        return Err("sent a response of the wrong kind".into());
    }
    let token = ok.token.ok_or("sent a response without a token")?;
    let reuse = match ok.cache.as_deref() {
        Some("never") => Reuse::Never,
        Some("session") | None => Reuse::Session,
        Some("expires") => {
            let expiration = ok
                .expiration
                .ok_or("sent cache \"expires\" without an expiration")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs());
            Reuse::Until(Instant::now() + Duration::from_secs(expiration.saturating_sub(now)))
        }
        Some(_) => return Err("sent an unknown cache mode".into()),
    };
    Ok(ProviderResponse { token, reuse })
}

/// Bounds untrusted text included in an error.
pub(crate) fn bounded(text: &str) -> String {
    const LIMIT: usize = 512;
    let mut out: String = text
        .chars()
        .take(LIMIT)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.chars().nth(LIMIT).is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "robigus-canary-token-5f1d";

    fn token(text: &str) -> RegistryToken {
        RegistryToken::new(text, CoreDumpGuard::acquire().unwrap()).unwrap()
    }

    /// Serializes the tests that read or change the process-wide dumpable
    /// flag, so they cannot observe each other's guards.
    static DUMPABLE: Mutex<()> = Mutex::new(());

    fn dumpable_lock() -> std::sync::MutexGuard<'static, ()> {
        DUMPABLE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn tokens_are_redacted_and_validated() {
        let _serial = dumpable_lock();
        let secret = token(&format!("  {CANARY}\n"));
        assert_eq!(format!("{secret:?}"), "RegistryToken(<redacted>)");
        assert!(!format!("{secret:?}").contains(CANARY));
        let header = secret.header_value().unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains(CANARY));
        assert_eq!(header.to_str().unwrap(), CANARY);
        assert_eq!(
            secret.redact(&format!("server said: bad token {CANARY}!")),
            "server said: bad token <redacted>!"
        );
        for invalid in ["", "   ", "abc\r\nInjected: header", "a\u{7}b"] {
            assert!(
                RegistryToken::new(invalid, CoreDumpGuard::acquire().unwrap()).is_err(),
                "{invalid:?}"
            );
        }
    }

    /// The header value must own a zeroizing buffer, not an ordinary copy:
    /// `from_maybe_shared` on a `Bytes` keeps the buffer rather than
    /// copying it, so its bytes are the ones `ZeroizingBytes` owns.
    #[test]
    fn header_values_share_the_zeroizing_buffer() {
        let _serial = dumpable_lock();
        let secret = token(CANARY);
        let header = secret.header_value().unwrap();
        let again = secret.header_value().unwrap();
        // Two values from one token are distinct buffers (each zeroized
        // independently), and neither aliases the token's own string.
        assert_ne!(header.as_bytes().as_ptr(), again.as_bytes().as_ptr());
        assert_ne!(header.as_bytes().as_ptr(), secret.secret.as_ptr());
        // A clone shares the zeroizing buffer instead of copying it.
        let clone = header.clone();
        assert_eq!(clone.as_bytes().as_ptr(), header.as_bytes().as_ptr());
    }

    /// The header bytes are owned by a value that is dropped only when the
    /// last header copy is dropped, and that owner is `Zeroizing`, whose
    /// drop zeroes the buffer. This checks the ownership half: the owner
    /// lives exactly as long as the `Bytes` clones (zeroization itself is
    /// `zeroize`'s tested guarantee and cannot be observed after the free
    /// without unsafe code).
    #[test]
    fn header_bytes_are_owned_until_the_last_copy_drops() {
        struct Owner(ZeroizingBytes, std::sync::mpsc::Sender<()>);
        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                let _ = self.1.send(());
            }
        }
        let (dropped, observed) = std::sync::mpsc::channel();
        let bytes = bytes::Bytes::from_owner(Owner(
            ZeroizingBytes(Zeroizing::new(CANARY.as_bytes().to_vec())),
            dropped,
        ));
        let value = reqwest::header::HeaderValue::from_maybe_shared(bytes.clone()).unwrap();
        assert_eq!(value.as_bytes(), CANARY.as_bytes());
        assert_eq!(
            value.as_bytes().as_ptr(),
            bytes.as_ptr(),
            "header copied the token"
        );
        drop(bytes);
        assert!(
            observed.try_recv().is_err(),
            "freed while the header was alive"
        );
        drop(value);
        observed
            .recv_timeout(Duration::from_secs(1))
            .expect("the zeroizing owner was not dropped");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_dumps_stay_disabled_until_the_last_guard_is_released() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};
        let _serial = dumpable_lock();
        let before = dumpable_behavior().unwrap();
        let first = CoreDumpGuard::acquire().unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        let second = CoreDumpGuard::acquire().unwrap();
        drop(first);
        // Another holder remains: dumps must stay disabled.
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        let held = token(CANARY);
        drop(second);
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        drop(held);
        assert_eq!(dumpable_behavior().unwrap(), before);
    }

    /// Acquiring and releasing concurrently must never leave dumps enabled
    /// while a guard is held (the previous design could restore them
    /// between a release and a concurrent acquisition).
    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_guards_never_leave_dumps_enabled() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};
        let _serial = dumpable_lock();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..200 {
                        let guard = CoreDumpGuard::acquire().unwrap();
                        assert_eq!(
                            dumpable_behavior().unwrap(),
                            DumpableBehavior::NotDumpable,
                            "dumps were enabled while a guard was held"
                        );
                        drop(guard);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    /// The guard is taken before a token is read and released when
    /// obtaining fails, so a failed lookup does not pin the process as
    /// non-dumpable. Other tests in this binary acquire guards concurrently,
    /// so this counts only this thread's guards; `obtain` is synchronous and
    /// acquires and drops its guard on the calling thread.
    #[cfg(target_os = "linux")]
    #[test]
    fn obtaining_a_token_holds_the_guard_only_while_needed() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};
        let _serial = dumpable_lock();
        let held = CoreDumpGuard::acquire().unwrap();
        let holders = THREAD_GUARDS.with(std::cell::Cell::get);
        let missing = CredentialSource::Env {
            registry: "robigus-test-unset-variable".into(),
        };
        assert!(obtain(&missing, "https://r.example/", None).is_err());
        assert_eq!(
            THREAD_GUARDS.with(std::cell::Cell::get),
            holders,
            "a failed lookup leaked a guard"
        );
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        let obtained = obtain(
            &CredentialSource::File {
                path: "/nonexistent/robigus-token".into(),
            },
            "https://r.example/",
            None,
        );
        assert!(obtained.is_err());
        assert_eq!(
            THREAD_GUARDS.with(std::cell::Cell::get),
            holders,
            "a failed lookup leaked a guard"
        );
        drop(held);
    }

    #[test]
    fn env_variable_names_follow_the_registry_name() {
        assert_eq!(
            CredentialSource::env_var("my-internal"),
            "ROBIGUS_REGISTRY_MY_INTERNAL_TOKEN"
        );
        assert!(
            CredentialSource::Process {
                program: "provider".into(),
                args: vec![]
            }
            .validate()
            .is_err()
        );
        assert!(
            CredentialSource::File {
                path: "token".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            CredentialSource::File {
                path: "/abs/token".into()
            }
            .validate()
            .is_ok()
        );
        let description = CredentialSource::Env {
            registry: "x".into(),
        }
        .describe();
        assert!(
            description.contains("ROBIGUS_REGISTRY_X_TOKEN"),
            "{description}"
        );
    }

    /// The provider's token is deserialized directly into a zeroizing
    /// buffer: `ProviderOk::token` is `Zeroizing<String>`, so no ordinary
    /// `String` holds it (the earlier version parsed into a
    /// `serde_json::Value` and copied the token out, leaving a plain copy).
    #[test]
    fn provider_tokens_deserialize_into_zeroizing_buffers() {
        fn assert_zeroizing(_: &Option<Zeroizing<String>>) {}
        let parsed: ProviderMessage =
            serde_json::from_str(&format!(r#"{{"Ok":{{"kind":"get","token":"{CANARY}"}}}}"#))
                .unwrap();
        let ProviderMessage::Ok(ok) = parsed else {
            panic!("expected Ok");
        };
        assert_zeroizing(&ok.token);
        assert_eq!(ok.token.as_deref().map(String::as_str), Some(CANARY));
        // Unknown fields from newer providers are tolerated.
        assert!(
            parse_provider_response(
                r#"{"Ok":{"kind":"get","token":"t","operation_independent":true,"extra":1}}"#
            )
            .is_ok()
        );
    }

    #[test]
    fn provider_responses_are_parsed_strictly() {
        let ok = parse_provider_response(
            &format!(r#"{{"Ok":{{"kind":"get","token":"{CANARY}","cache":"session","operation_independent":true}}}}"#),
        )
        .unwrap();
        assert_eq!(ok.token.as_str(), CANARY);
        assert_eq!(ok.reuse, Reuse::Session);
        let never = parse_provider_response(r#"{"Ok":{"kind":"get","token":"t","cache":"never"}}"#)
            .unwrap();
        assert_eq!(never.reuse, Reuse::Never);
        let expires = parse_provider_response(
            r#"{"Ok":{"kind":"get","token":"t","cache":"expires","expiration":4102444800}}"#,
        )
        .unwrap();
        assert!(matches!(expires.reuse, Reuse::Until(_)));
        for (line, expected) in [
            (r#"{"Err":{"kind":"not-found"}}"#, "no token"),
            (
                r#"{"Err":{"kind":"url-not-supported"}}"#,
                "does not support this registry",
            ),
            (r#"{"Err":{"kind":"other","message":"locked"}}"#, "locked"),
            (r#"{"Ok":{"kind":"login"}}"#, "wrong kind"),
            (r#"{"Ok":{"kind":"get"}}"#, "without a token"),
            (
                r#"{"Ok":{"kind":"get","token":"t","cache":"expires"}}"#,
                "without an expiration",
            ),
            ("not json", "invalid response"),
        ] {
            let error = parse_provider_response(line).err().unwrap();
            assert!(error.contains(expected), "{line}: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn token_files_must_be_private_regular_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, format!("{CANARY}\nsecond line\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token_file(&path).unwrap().as_str(), CANARY);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_token_file(&path).unwrap_err().contains("0600"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_token_file(&link).unwrap_err().contains("symlink"));

        let linked_dir = dir.path().join("linked-dir");
        std::os::unix::fs::symlink(dir.path(), &linked_dir).unwrap();
        assert!(
            read_token_file(&linked_dir.join("token"))
                .unwrap_err()
                .contains("symlink")
        );

        assert!(read_token_file(dir.path()).is_err());
        assert!(read_token_file(Path::new("relative")).is_err());
        assert!(
            read_token_file(&dir.path().join("sub/../token"))
                .unwrap_err()
                .contains("`..`")
        );
    }

    /// A FIFO used to block the open forever; it must be refused promptly
    /// without a writer ever connecting.
    #[cfg(target_os = "linux")]
    #[test]
    fn token_files_reject_fifos_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("token");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = done.send(read_token_file(&path));
        });
        let result = finished
            .recv_timeout(Duration::from_secs(5))
            .expect("reading a FIFO token file blocked");
        assert!(result.unwrap_err().contains("not a regular file"));
    }

    /// A directory swapped for a symlink after the path is built is still
    /// refused: every component is opened with `O_NOFOLLOW`, relative to
    /// its already-opened parent.
    #[cfg(target_os = "linux")]
    #[test]
    fn token_files_refuse_symlinked_directories_at_open_time() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let token_path = real.join("token");
        std::fs::write(&token_path, CANARY).unwrap();
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let configured = dir.path().join("config").join("token");
        // The configured parent is a symlink to a directory holding a
        // perfectly valid token file; it must still be refused.
        std::os::unix::fs::symlink(&real, dir.path().join("config")).unwrap();
        let error = read_token_file(&configured).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(!error.contains(CANARY));
        // The same file through its real path is accepted.
        assert_eq!(read_token_file(&token_path).unwrap().as_str(), CANARY);
    }

    /// Writes an executable credential provider script for tests.
    ///
    /// Executing a file fails with `ETXTBSY` while any process holds it open
    /// for writing, and a test thread that forks concurrently inherits our
    /// write descriptor until it execs. Each script therefore gets a fresh
    /// name, and the caller retries `ETXTBSY` (see [`token_with_retry`]).
    #[cfg(unix)]
    fn provider(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = dir.join(format!("provider-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    /// [`CredentialCache::token`], retrying while the freshly written
    /// provider script is still "busy" because of a concurrent fork.
    #[cfg(unix)]
    async fn token_with_retry(
        cache: &CredentialCache,
        name: Option<&str>,
        source: &CredentialSource,
    ) -> Result<Arc<RegistryToken>, FetchError> {
        for _ in 0..50 {
            match cache
                .token("https://registry.example/index/", name, source)
                .await
            {
                Err(error) if error.to_string().contains("Text file busy") => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                result => return result,
            }
        }
        cache
            .token("https://registry.example/index/", name, source)
            .await
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn credential_processes_follow_the_cargo_protocol() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("request.json");
        let program = provider(
            dir.path(),
            &format!(
                r#"echo '{{"v":[1]}}'
read request
printf '%s\n' "$request" > '{}'
env > '{}.env'
echo '{{"Ok":{{"kind":"get","token":"{CANARY}","cache":"session","operation_independent":true}}}}'"#,
                log.display(),
                log.display()
            ),
        );
        let source = CredentialSource::Process {
            program: program.clone(),
            args: vec!["--account".into(), "work".into()],
        };
        let cache = CredentialCache::default();
        let token = token_with_retry(&cache, Some("internal"), &source)
            .await
            .unwrap();
        assert_eq!(token.header_value().unwrap().to_str().unwrap(), CANARY);
        let request: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&log).unwrap()).unwrap();
        assert_eq!(request["kind"], "get");
        assert_eq!(request["operation"], "read");
        assert_eq!(
            request["registry"]["index-url"],
            "sparse+https://registry.example/index/"
        );
        assert_eq!(request["registry"]["name"], "internal");
        assert_eq!(request["args"], serde_json::json!(["--account", "work"]));
        let env = std::fs::read_to_string(dir.path().join("request.json.env")).unwrap();
        let names: Vec<&str> = env
            .lines()
            .filter_map(|line| line.split('=').next())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| ["PATH", "HOME", "PWD", "SHLVL", "_"].contains(name)),
            "provider inherited {names:?}"
        );

        // A session token is reused without running the provider again.
        std::fs::remove_file(&log).unwrap();
        cache
            .token("https://registry.example/index/", Some("internal"), &source)
            .await
            .unwrap();
        assert!(!log.exists());
        // Forgetting it runs the provider again.
        cache.forget("https://registry.example/index/");
        token_with_retry(&cache, Some("internal"), &source)
            .await
            .unwrap();
        assert!(log.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn misbehaving_credential_processes_fail_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        for (body, expected) in [
            ("echo '{\"v\":[2]}'", "version 1"),
            ("echo 'not json'", "hello"),
            ("exit 1", "without a response"),
            (
                "echo '{\"v\":[1]}'; read r; echo '{\"Err\":{\"kind\":\"not-found\"}}'",
                "no token",
            ),
            (
                "echo '{\"v\":[1]}'; read r; head -c 200000 /dev/zero | tr '\\0' 'a'; echo",
                "oversized",
            ),
        ] {
            let program = provider(dir.path(), body);
            let error = token_with_retry(
                &CredentialCache::default(),
                None,
                &CredentialSource::Process {
                    program,
                    args: vec![],
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(error.contains(expected), "{body}: {error}");
            assert!(error.contains("credential process"), "{error}");
        }
    }
}
