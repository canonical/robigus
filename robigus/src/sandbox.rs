//! Fail-closed sandbox foundation (spec §10; WP-1.7).
//!
//! Only bubblewrap is available in M1. Network access and the native backend
//! are deliberately unavailable until their respective work packages land.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

use crate::error::{SandboxAttempt, SandboxUnavailable, StoreError};
use crate::model::PackageId;
use crate::store::{Store, ToolInvocation};

/// Available sandbox mechanisms. Native is reserved for WP-3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    Bwrap,
    Native,
}

/// Requested sandbox mechanism. There is intentionally no unsandboxed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxPreference {
    Auto,
    Bwrap,
    Native,
}

/// Network policy for a command. Allowlisted networking requires WP-2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAccess {
    Offline,
    Allowlist,
}

/// A single sandboxed execution. `program` is an absolute path **inside** the
/// sandbox; `source_subdir` and `log_dir` are relative paths. The log directory
/// is under `workspace`, which is not mounted into the sandbox. Each execution
/// creates a new directory inside `log_dir` for its stdout and stderr files.
///
/// Only explicitly allowlisted `env` keys are accepted; inherited environment
/// variables are never passed through. The canonical sandbox working directory
/// must be UTF-8 so it can be recorded as `PWD`. Callers must not put credentials or
/// other secrets in arguments, since arbitrary command arguments cannot be
/// reliably identified as secrets and are recorded for reproducibility.
///
/// Isolation boundary: user, mount, PID, network, IPC and UTS namespaces; all
/// capabilities dropped and nested user namespaces disabled. The source and system runtime are private read-only
/// overlays (`nodev`, `nosuid`), so host sockets, FIFOs and devices under them
/// cannot be reached. A seccomp filter limits socket creation to IP families
/// (with no route off the host) and fixed-peer Unix stream/seqpacket pairs,
/// and denies io_uring and the kernel keyring syscalls (the host session
/// keyring is not namespaced); named Unix sockets are unavailable even inside
/// the sandbox. Inherited descriptors other than stdio are closed before
/// bubblewrap starts. Not covered here: resource limits (WP-3.5) and
/// allowlisted networking, which needs an explicit proxy transport (WP-2.1).
///
/// Bubblewrap uses a fixed shell wrapper to restore stdin; failure to execute
/// the requested program is reported as the shell's exit status (126 or 127).
#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub source: PathBuf,
    pub source_subdir: PathBuf,
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
    pub network: NetworkAccess,
    pub workspace: PathBuf,
    pub log_dir: PathBuf,
    pub store: Store,
    pub package_id: Option<PackageId>,
    pub tool_version: Option<String>,
}

/// Outcome of an execution, including timeouts.
/// Bubblewrap reports command signals as shell-style exit codes (128 + signal);
/// `Signaled` is reserved for backends that can distinguish signal termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    Exited(i32),
    Signaled,
    TimedOut,
}

/// Result and host paths of the captured output streams.
#[derive(Debug, Clone)]
pub struct ProcessOutput {
    pub status: ProcessStatus,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
}

/// Failure to prepare, launch, or record an execution.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("allowlisted network access is unavailable until the sandbox proxy is implemented")]
    NetworkUnavailable,
    /// Bubblewrap was selected, but setup or supervision did not complete.
    /// The command may already have run if the supervisor failed afterward.
    #[error("bubblewrap setup or supervision failed: {cause} (stderr log: {})", stderr_path.display())]
    BwrapSetup { cause: String, stderr_path: PathBuf },
    #[error("invalid sandbox command: {0}")]
    InvalidCommand(String),
    #[error("sandbox I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to record sandbox invocation: {0}")]
    Store(#[from] StoreError),
}

/// Runs commands inside an established sandbox; never falls back to host execution.
#[async_trait]
pub trait Sandbox: Send + Sync {
    fn mode(&self) -> SandboxMode;
    async fn run(&self, command: &CommandSpec) -> Result<ProcessOutput, SandboxError>;
}

#[derive(Debug)]
struct BwrapSandbox {
    executable: PathBuf,
}

/// Probes the selected mechanism and returns every failure when none works.
/// This performs a real namespace setup, not just an executable lookup.
/// The native mechanism is deliberately unavailable until WP-3.5.
pub async fn establish_sandbox(
    preference: SandboxPreference,
) -> Result<Box<dyn Sandbox>, SandboxUnavailable> {
    let mut attempts = Vec::new();
    if matches!(
        preference,
        SandboxPreference::Auto | SandboxPreference::Bwrap
    ) {
        match probe_bwrap().await {
            Ok(executable) => return Ok(Box::new(BwrapSandbox { executable })),
            Err(cause) => attempts.push(SandboxAttempt {
                mechanism: "bubblewrap (user, mount, PID and network namespaces)".into(),
                cause,
            }),
        }
    }
    if matches!(
        preference,
        SandboxPreference::Auto | SandboxPreference::Native
    ) {
        attempts.push(SandboxAttempt {
            mechanism: "native (Landlock, seccomp and namespaces)".into(),
            cause: "native sandbox backend is not implemented yet (WP-3.5)".into(),
        });
    }
    Err(SandboxUnavailable { attempts })
}

async fn probe_bwrap() -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    if rustix::process::geteuid().is_root() {
        return Err("robigus must run as an unprivileged user; effective uid is root".into());
    }
    #[cfg(not(target_os = "linux"))]
    return Err("bubblewrap sandboxing requires Linux".into());

    #[cfg(target_os = "linux")]
    {
        // Do not search the caller's PATH for a security boundary.
        let executable = PathBuf::from("/usr/bin/bwrap");
        if !executable.is_file() {
            return Err(format!("{} was not found", executable.display()));
        }
        if !Path::new(SANITIZER).is_file() {
            return Err(format!(
                "{SANITIZER} is required to close inherited descriptors before bubblewrap"
            ));
        }
        check_bwrap_version(&executable).await?;
        // Probe with the full isolation policy used for real runs: overlays,
        // seccomp and descriptor sanitation. Availability means all of them work.
        let scratch = tempfile::tempdir()
            .map_err(|error| format!("cannot create sandbox probe directory: {error}"))?;
        let empty = scratch.path().join("empty");
        let source = scratch.path().join("source");
        for dir in [&empty, &source] {
            std::fs::create_dir(dir)
                .map_err(|error| format!("cannot create sandbox probe directory: {error}"))?;
        }
        let status = tempfile::tempfile()
            .map_err(|error| format!("cannot create sandbox probe status file: {error}"))?;
        let mut status_reader = status
            .try_clone()
            .map_err(|error| format!("cannot reopen sandbox probe status file: {error}"))?;
        let mut cmd = isolated_command(
            &executable,
            &empty,
            &source,
            Path::new("/source"),
            &BTreeMap::new(),
            status,
            Stdio::null(),
            Stdio::piped(),
        )?;
        cmd.args(["/usr/bin/true"]);
        let result = tokio::time::timeout(Duration::from_secs(10), cmd.output()).await;
        match result {
            Err(_) => Err("namespace probe timed out after 10 seconds".into()),
            Ok(Err(error)) => Err(format!(
                "failed to launch {}: {error}",
                executable.display()
            )),
            Ok(Ok(output)) if output.status.success() => {
                use std::io::{Read, Seek};
                let mut report = Vec::new();
                status_reader
                    .rewind()
                    .and_then(|()| status_reader.read_to_end(&mut report))
                    .map_err(|error| format!("cannot read namespace probe status: {error}"))?;
                check_bwrap_completion(&report, output.status)
                    .map_err(|cause| format!("namespace probe status failed: {cause}"))?;
                Ok(executable)
            }
            Ok(Ok(output)) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!(
                    "namespace probe failed ({}): {}",
                    output.status,
                    stderr.trim()
                ))
            }
        }
    }
}

/// Oldest bubblewrap with `--overlay-src`/`--ro-overlay`, which the isolation
/// policy requires (Ubuntu 26.04 ships 0.11.1; Ubuntu 24.04's 0.9.0 is too old).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const MIN_BWRAP_VERSION: (u64, u64) = (0, 11);

/// Rejects a bubblewrap too old for the policy with an actionable cause,
/// rather than letting the probe fail on an unknown option.
#[cfg(target_os = "linux")]
async fn check_bwrap_version(executable: &Path) -> Result<(), String> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new(executable)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| format!("{} --version timed out", executable.display()))?
    .map_err(|error| format!("failed to run {} --version: {error}", executable.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(format!(
            "{} --version failed ({})",
            executable.display(),
            output.status
        ));
    }
    require_bwrap_version(stdout.trim())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn require_bwrap_version(reported: &str) -> Result<(), String> {
    let (major, minor) = MIN_BWRAP_VERSION;
    let version = parse_bwrap_version(reported)
        .ok_or_else(|| format!("unrecognized bubblewrap version output {reported:?}"))?;
    if version < MIN_BWRAP_VERSION {
        return Err(format!(
            "bubblewrap {}.{} is too old; {major}.{minor} or newer is required for \
             read-only overlays (Ubuntu 26.04 or later)",
            version.0, version.1
        ));
    }
    Ok(())
}

/// Parses `bubblewrap X.Y[.Z...]` into `(X, Y)`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_bwrap_version(reported: &str) -> Option<(u64, u64)> {
    let mut parts = reported.strip_prefix("bubblewrap ")?.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Bubblewrap emits JSON objects for setup and, only after successful setup and
/// exec, a final shell-encoded exit code. Unknown objects/fields are allowed.
fn check_bwrap_completion(report: &[u8], status: std::process::ExitStatus) -> Result<(), String> {
    let mut exit_code = None;
    for value in serde_json::Deserializer::from_slice(report).into_iter::<serde_json::Value>() {
        let value = value.map_err(|error| format!("invalid bubblewrap status: {error}"))?;
        let object = value
            .as_object()
            .ok_or("invalid bubblewrap status: expected an object")?;
        if let Some(code) = object.get("exit-code") {
            if exit_code.is_some() {
                return Err("invalid bubblewrap status: duplicate exit-code".into());
            }
            exit_code = Some(
                code.as_i64()
                    .filter(|code| (0..=255).contains(code))
                    .ok_or("invalid bubblewrap status: invalid exit-code")? as i32,
            );
        }
    }
    let code = exit_code.ok_or("bubblewrap did not report command completion")?;
    if status.code() != Some(code) {
        return Err(format!(
            "bubblewrap status exit-code {code} disagrees with supervisor status {status}"
        ));
    }
    Ok(())
}

async fn read_bounded(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    Ok(bytes)
}

/// Fixed, trusted host shell that closes every inherited descriptor except
/// stdio and the seccomp filter before exec'ing bubblewrap.
const SANITIZER: &str = "/usr/bin/bash";

/// The sanitizer script. It receives no untrusted text: `$@` is bubblewrap and
/// its arguments, passed as separate words and never evaluated. Descriptor
/// numbers come from `/proc/self/fd` and are checked to be numeric before use.
/// Closing happens in a single-threaded process, so no descriptor can be
/// opened concurrently; the final check fails closed if any survives.
const SANITIZE_FDS: &str = r#"keep=$1; shift
for entry in /proc/self/fd/*; do
  fd=${entry##*/}
  case $fd in ''|*[!0-9]*) echo "robigus: unexpected descriptor entry" >&2; exit 125;; esac
  if [ "$fd" -gt 2 ] && [ "$fd" -ne "$keep" ]; then exec {fd}>&-; fi
done
for entry in /proc/self/fd/*; do
  fd=${entry##*/}
  if [ "$fd" -gt 2 ] && [ "$fd" -ne "$keep" ] && [ -e "$entry" ]; then
    target=$(readlink "$entry" 2>/dev/null)
    case $target in /proc/*/fd) ;; *) echo "robigus: descriptor $fd survived sanitation" >&2; exit 125;; esac
  fi
done
exec "$@""#;

/// Host trees exposed to the sandbox. Directories are mounted as private
/// read-only overlays; symlinks (for example a merged-`/usr` `/bin`) are
/// recreated as symlinks rather than followed.
const RUNTIME_TREES: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

/// Mounts `host` read-only at `target` without exposing host special files.
///
/// A read-only OverlayFS creates its own inodes for sockets and FIFOs, so a
/// host listener or FIFO reader under the tree cannot be reached through it;
/// the final remount adds `nodev`/`nosuid`, which overlays do not inherit.
/// The empty lower layer is required because bubblewrap needs two layers.
/// Bubblewrap stacks `--overlay-src` layers with the last one on top, so the
/// empty layer goes first: the host tree must be the top layer, or the empty
/// directory's own metadata would replace the host root's permissions.
fn overlay_tree(cmd: &mut Command, host: &Path, empty: &Path, target: &Path) {
    cmd.arg("--overlay-src")
        .arg(empty)
        .arg("--overlay-src")
        .arg(host)
        .arg("--ro-overlay")
        .arg(target)
        .arg("--remount-ro")
        .arg(target);
}

/// Exposes only the system runtime, never the host root or home directory.
fn mount_runtime(cmd: &mut Command, empty: &Path) -> Result<(), String> {
    for tree in RUNTIME_TREES {
        let path = Path::new(tree);
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let target = std::fs::read_link(path)
                    .map_err(|error| format!("cannot read runtime symlink {tree}: {error}"))?;
                cmd.arg("--symlink").arg(target).arg(path);
            }
            Ok(metadata) if metadata.is_dir() => overlay_tree(cmd, path, empty, path),
            Ok(_) => {
                return Err(format!(
                    "runtime path {tree} is neither a directory nor a symlink"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect runtime path {tree}: {error}")),
        }
    }
    Ok(())
}

/// Builds a sanitized bubblewrap command with the complete isolation policy,
/// ending with `--` so the caller appends only the workload. `status` becomes
/// bubblewrap's stdin and its `--json-status-fd`.
#[allow(clippy::too_many_arguments)]
fn isolated_command(
    executable: &Path,
    empty: &Path,
    source: &Path,
    workdir: &Path,
    env: &BTreeMap<String, String>,
    status: std::fs::File,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<Command, String> {
    #[cfg(target_os = "linux")]
    let filter = crate::sandbox_seccomp::filter_file()?;
    #[cfg(not(target_os = "linux"))]
    return Err("bubblewrap sandboxing requires Linux".into());

    #[cfg(target_os = "linux")]
    {
        use command_fds::{CommandFdExt, FdMapping};
        let filter_fd = crate::sandbox_seccomp::FILTER_FD;
        let mut cmd = Command::new(SANITIZER);
        cmd.env_clear()
            .kill_on_drop(true)
            .stdin(Stdio::from(status))
            .stdout(stdout)
            .stderr(stderr);
        // All descriptor mappings go through one call: command-fds cannot
        // detect collisions between separate calls.
        cmd.as_std_mut()
            .fd_mappings(vec![FdMapping {
                parent_fd: filter.into(),
                child_fd: filter_fd,
            }])
            .map_err(|error| format!("cannot map sandbox seccomp descriptor: {error}"))?;
        cmd.args([
            "--noprofile",
            "--norc",
            "-c",
            SANITIZE_FDS,
            "robigus-fd-sanitizer",
        ])
        .arg(filter_fd.to_string())
        .arg(executable)
        .args([
            "--unshare-user",
            // A nested user namespace would hand the workload a full
            // capability set over new kernel attack surface; forbid it.
            "--disable-userns",
            "--assert-userns-disabled",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--json-status-fd",
            "0",
            "--seccomp",
        ])
        .arg(filter_fd.to_string());
        mount_runtime(&mut cmd, empty)?;
        cmd.args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/output",
            "--tmpfs",
            "/cargo",
            "--tmpfs",
            "/home",
            "--dir",
            "/home/sandbox",
        ]);
        overlay_tree(&mut cmd, source, empty, Path::new("/source"));
        for (key, value) in env {
            cmd.arg("--setenv").arg(key).arg(value);
        }
        cmd.arg("--chdir").arg(workdir).arg("--");
        Ok(cmd)
    }
}

/// Environment keys permitted from the caller. None may override the fixed
/// sandbox paths or inject a dynamic linker, shell, or Cargo configuration.
fn allowed_env(key: &str) -> bool {
    matches!(
        key,
        "LANG" | "LC_ALL" | "RUST_BACKTRACE" | "CARGO_NET_OFFLINE" | "SOURCE_DATE_EPOCH"
    )
}

fn clean_relative(path: &Path) -> bool {
    path.components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

/// Owns the bubblewrap child and kills its process group on timeout, error or
/// cancellation. `--die-with-parent` also tears down the sandbox when the
/// supervisor dies; the PID namespace prevents its children escaping it.
struct ChildGuard {
    child: Child,
    group: Option<u32>,
}

impl ChildGuard {
    fn terminate(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(id) = self.group.take()
            && let Some(pid) = rustix::process::Pid::from_raw(id as i32)
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.child.start_kill();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.group.is_some() {
            self.terminate();
        }
    }
}

#[async_trait]
impl Sandbox for BwrapSandbox {
    fn mode(&self) -> SandboxMode {
        SandboxMode::Bwrap
    }

    async fn run(&self, spec: &CommandSpec) -> Result<ProcessOutput, SandboxError> {
        if spec.network != NetworkAccess::Offline {
            return Err(SandboxError::NetworkUnavailable);
        }
        if !spec.program.is_absolute() || spec.program.as_os_str().is_empty() {
            return Err(SandboxError::InvalidCommand(
                "program must be an absolute sandbox path".into(),
            ));
        }
        if !clean_relative(&spec.source_subdir) || !clean_relative(&spec.log_dir) {
            return Err(SandboxError::InvalidCommand(
                "source_subdir and log_dir must be relative and cannot contain '..'".into(),
            ));
        }
        if spec.timeout.is_zero() {
            return Err(SandboxError::InvalidCommand(
                "timeout must be nonzero".into(),
            ));
        }
        for (key, value) in &spec.env {
            if !allowed_env(key) || value.contains('\0') {
                return Err(SandboxError::InvalidCommand(format!(
                    "environment variable {key:?} is not allowed"
                )));
            }
        }
        if let Some(package) = &spec.package_id
            && !spec.store.contains_package(package).await?
        {
            return Err(StoreError::PackageNotFound(package.name.clone()).into());
        }

        let source = tokio::fs::canonicalize(&spec.source).await?;
        let workdir = tokio::fs::canonicalize(source.join(&spec.source_subdir)).await?;
        if !workdir.starts_with(&source) || !workdir.is_dir() {
            return Err(SandboxError::InvalidCommand(
                "source_subdir escapes the source tree or is not a directory".into(),
            ));
        }
        let relative_workdir = workdir
            .strip_prefix(&source)
            .map_err(|error| SandboxError::InvalidCommand(error.to_string()))?;
        let sandbox_workdir = if relative_workdir.as_os_str().is_empty() {
            PathBuf::from("/source")
        } else {
            Path::new("/source").join(relative_workdir)
        };
        let pwd = sandbox_workdir.to_str().ok_or_else(|| {
            SandboxError::InvalidCommand("sandbox working directory must be UTF-8".into())
        })?;
        let workspace = tokio::fs::canonicalize(&spec.workspace).await?;
        let mut log_base = workspace.clone();
        for part in spec.log_dir.components() {
            if let Component::Normal(name) = part {
                log_base.push(name);
                if log_base.starts_with(&source) {
                    return Err(SandboxError::InvalidCommand(
                        "log directory must be outside the source tree".into(),
                    ));
                }
                match tokio::fs::create_dir(&log_base).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                let metadata = tokio::fs::symlink_metadata(&log_base).await?;
                if !metadata.is_dir() {
                    return Err(SandboxError::InvalidCommand(
                        "log path cannot traverse symlinks or non-directories".into(),
                    ));
                }
            }
        }
        if !log_base.starts_with(&workspace) || log_base.starts_with(&source) {
            return Err(SandboxError::InvalidCommand(
                "log directory must remain inside the workspace and outside the source tree".into(),
            ));
        }
        static NEXT_LOG: AtomicU64 = AtomicU64::new(0);
        let log_dir = loop {
            let name = format!(
                "invocation-{}-{}",
                std::process::id(),
                NEXT_LOG.fetch_add(1, Ordering::Relaxed)
            );
            let dir = log_base.join(name);
            match tokio::fs::create_dir(&dir).await {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        };
        let stdout_path = log_dir.join("stdout.log");
        let stderr_path = log_dir.join("stderr.log");
        let stdout = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stdout_path)?;
        let stderr = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stderr_path)?;
        let status_path = log_dir.join("bwrap-status.jsonl");
        let status_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&status_path)?;

        let mut env = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), "/home/sandbox".into()),
            ("CARGO_HOME".into(), "/cargo".into()),
            ("CARGO_TARGET_DIR".into(), "/output/target".into()),
            ("TMPDIR".into(), "/tmp".into()),
            ("PWD".into(), pwd.into()),
        ]);
        env.extend(spec.env.clone());
        // The overlay's second lower layer must be an empty directory that does
        // not overlap the source; keep it with this invocation's logs.
        let empty_layer = log_dir.join("empty-layer");
        tokio::fs::create_dir(&empty_layer).await?;
        // Bubblewrap closes the status fd before exec; the fixed shell wrapper
        // restores the command's stdin to /dev/null.
        let launch = isolated_command(
            &self.executable,
            &empty_layer,
            &source,
            &sandbox_workdir,
            &env,
            status_file,
            Stdio::from(stdout),
            Stdio::from(stderr),
        );
        let mut cmd = match launch {
            Ok(cmd) => cmd,
            Err(cause) => {
                return Err(SandboxError::BwrapSetup { cause, stderr_path });
            }
        };
        #[cfg(unix)]
        cmd.process_group(0);
        cmd.args([
            "/bin/sh",
            "-c",
            "exec </dev/null; exec \"$@\"",
            "robigus-sandbox",
        ])
        .arg(&spec.program)
        .args(&spec.args);

        let relative_log = log_dir
            .strip_prefix(&workspace)
            .map_err(|error| SandboxError::InvalidCommand(error.to_string()))?;
        let mut argv = vec![spec.program.to_string_lossy().into_owned()];
        argv.extend(spec.args.iter().cloned());
        let invocation_id = spec
            .store
            .begin_invocation(&ToolInvocation {
                package_id: spec.package_id.clone(),
                tool: spec.program.to_string_lossy().into_owned(),
                argv,
                env,
                tool_version: spec.tool_version.clone(),
                sandbox_mode: "bwrap".into(),
                exit_status: "running".into(),
                started_at: Utc::now().to_rfc3339(),
                duration_ms: 0,
                log_path: Some(relative_log.to_string_lossy().into_owned()),
            })
            .await?;
        let started = Instant::now();
        let outcome = match cmd.spawn() {
            Err(error) => Err(SandboxError::BwrapSetup {
                cause: format!("could not launch {}: {error}", self.executable.display()),
                stderr_path: stderr_path.clone(),
            }),
            Ok(child) => {
                let group = child.id();
                let mut guard = ChildGuard { child, group };
                match tokio::time::timeout(spec.timeout, guard.child.wait()).await {
                    Ok(Ok(status)) => {
                        guard.group = None;
                        const STATUS_LIMIT: usize = 64 * 1024;
                        let report = read_bounded(&status_path, STATUS_LIMIT).await;
                        let completion = match report {
                            Ok(bytes) if bytes.len() <= STATUS_LIMIT => {
                                check_bwrap_completion(&bytes, status)
                            }
                            Ok(_) => Err("bubblewrap status exceeded 64 KiB".into()),
                            Err(error) => Err(format!("could not read bubblewrap status: {error}")),
                        };
                        match completion {
                            Ok(()) => Ok(ProcessStatus::Exited(
                                status.code().expect("verified exit code"),
                            )),
                            Err(mut cause) => {
                                cause.push_str(&format!(" (supervisor status: {status})"));
                                // The log can contain untrusted output if the supervisor failed
                                // after exec. Bound the diagnostic and retain the complete log.
                                const DIAGNOSTIC_LIMIT: usize = 4096;
                                if let Ok(bytes) =
                                    read_bounded(&stderr_path, DIAGNOSTIC_LIMIT).await
                                {
                                    let truncated = bytes.len() > DIAGNOSTIC_LIMIT;
                                    let text = String::from_utf8_lossy(
                                        &bytes[..bytes.len().min(DIAGNOSTIC_LIMIT)],
                                    );
                                    if !text.trim().is_empty() {
                                        cause.push_str(&format!(
                                            ": {}{}",
                                            text.trim(),
                                            if truncated { "…" } else { "" }
                                        ));
                                    }
                                }
                                Err(SandboxError::BwrapSetup {
                                    cause,
                                    stderr_path: stderr_path.clone(),
                                })
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        guard.terminate();
                        Err(SandboxError::Io(error))
                    }
                    Err(_) => {
                        guard.terminate();
                        let _ = guard.child.wait().await;
                        Ok(ProcessStatus::TimedOut)
                    }
                }
            }
        };
        let status_text = match &outcome {
            Ok(ProcessStatus::Exited(code)) => format!("exit:{code}"),
            Ok(ProcessStatus::Signaled) => "signaled".into(),
            Ok(ProcessStatus::TimedOut) => "timeout".into(),
            Err(SandboxError::BwrapSetup { cause, .. }) => format!("setup_error:{cause}"),
            Err(error) => format!("supervision_error:{error}"),
        };
        spec.store
            .finish_invocation(
                invocation_id,
                &status_text,
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            )
            .await?;
        Ok(ProcessOutput {
            status: outcome?,
            stdout_path,
            stderr_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn fixture() -> (TempDir, CommandSpec) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let workspace = dir.path().join("workspace");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        let store = Store::open(&dir.path().join("analysis.db")).await.unwrap();
        let spec = CommandSpec {
            program: "/bin/true".into(),
            args: Vec::new(),
            source,
            source_subdir: PathBuf::new(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(2),
            network: NetworkAccess::Offline,
            workspace,
            log_dir: "logs".into(),
            store,
            package_id: None,
            tool_version: None,
        };
        (dir, spec)
    }

    #[test]
    fn requires_bubblewrap_with_overlay_support() {
        assert_eq!(parse_bwrap_version("bubblewrap 0.11.1"), Some((0, 11)));
        assert_eq!(parse_bwrap_version("bubblewrap 1.0"), Some((1, 0)));
        assert_eq!(parse_bwrap_version("bwrap 0.11.1"), None);
        assert_eq!(parse_bwrap_version("bubblewrap 0"), None);
        assert!(require_bwrap_version("bubblewrap 0.11.0").is_ok());
        assert!(require_bwrap_version("bubblewrap 0.12.0").is_ok());
        assert!(require_bwrap_version("bubblewrap 1.0.0").is_ok());
        let old = require_bwrap_version("bubblewrap 0.9.0").unwrap_err();
        assert!(
            old.contains("0.9 is too old") && old.contains("0.11"),
            "{old}"
        );
        let garbled = require_bwrap_version("garbage").unwrap_err();
        assert!(garbled.contains("unrecognized"), "{garbled}");
    }

    #[cfg(unix)]
    #[test]
    fn checks_bwrap_completion_without_confusing_command_failures() {
        use std::os::unix::process::ExitStatusExt;

        let exited = |code| std::process::ExitStatus::from_raw(code << 8);
        assert!(
            check_bwrap_completion(
                br#"{"child-pid": 1, "new-field": true}
               {"future-status": 2}
               {"exit-code": 42}"#,
                exited(42)
            )
            .is_ok()
        );
        for report in [
            &b""[..],
            &b"{\"child-pid\":1}"[..],
            &b"{\"exit-code\":42}{\"exit-code\":42}"[..],
            &b"{\"exit-code\":256}"[..],
            &b"{\"exit-code\":42}{"[..],
            &b"{\"exit-code\":1}"[..],
        ] {
            assert!(check_bwrap_completion(report, exited(42)).is_err());
        }
        assert!(
            check_bwrap_completion(
                br#"{"exit-code": 42}"#,
                std::process::ExitStatus::from_raw(9)
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_and_auto_are_fail_closed_and_diagnostic() {
        let native = match establish_sandbox(SandboxPreference::Native).await {
            Ok(_) => panic!("native is not implemented"),
            Err(error) => error,
        };
        assert_eq!(native.attempts.len(), 1);
        assert!(native.to_string().contains("native"));
        let result = establish_sandbox(SandboxPreference::Auto).await;
        if let Err(error) = result {
            assert_eq!(error.attempts.len(), 2);
            assert!(error.to_string().contains("no sandbox available"));
            assert!(error.to_string().contains("bubblewrap"));
            assert!(error.to_string().contains("native"));
        }
    }

    #[tokio::test]
    async fn rejects_network_and_unsafe_inputs_before_launch() {
        let (_dir, mut spec) = fixture().await;
        let sandbox = BwrapSandbox {
            executable: "/does/not/exist".into(),
        };
        spec.network = NetworkAccess::Allowlist;
        assert!(matches!(
            sandbox.run(&spec).await,
            Err(SandboxError::NetworkUnavailable)
        ));
        spec.network = NetworkAccess::Offline;
        spec.env.insert("LD_PRELOAD".into(), "evil.so".into());
        assert!(matches!(
            sandbox.run(&spec).await,
            Err(SandboxError::InvalidCommand(_))
        ));
        spec.env.clear();
        spec.env.insert("PWD".into(), "/host/path".into());
        assert!(matches!(
            sandbox.run(&spec).await,
            Err(SandboxError::InvalidCommand(_))
        ));
        spec.env.clear();
        spec.log_dir = "../outside".into();
        assert!(matches!(
            sandbox.run(&spec).await,
            Err(SandboxError::InvalidCommand(_))
        ));
        assert!(!spec.workspace.join("logs").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_non_utf8_canonical_workdir_before_launch() {
        use std::os::unix::ffi::OsStringExt;

        let (dir, mut spec) = fixture().await;
        let name = std::ffi::OsString::from_vec(b"invalid-\xff".to_vec());
        std::fs::create_dir(spec.source.join(&name)).unwrap();
        std::os::unix::fs::symlink(&name, spec.source.join("link")).unwrap();
        let sandbox = BwrapSandbox {
            executable: "/does/not/exist".into(),
        };
        for subdir in [PathBuf::from(name), PathBuf::from("link")] {
            spec.source_subdir = subdir;
            assert!(matches!(
                sandbox.run(&spec).await,
                Err(SandboxError::InvalidCommand(message)) if message.contains("UTF-8")
            ));
        }
        assert!(!spec.workspace.join("logs").exists());
        let db = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM tool_invocation", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinked_log_directory_without_creating_outside() {
        let (dir, mut spec) = fixture().await;
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, spec.workspace.join("link")).unwrap();
        spec.log_dir = "link/child".into();
        let sandbox = BwrapSandbox {
            executable: "/does/not/exist".into(),
        };
        assert!(matches!(
            sandbox.run(&spec).await,
            Err(SandboxError::InvalidCommand(_))
        ));
        assert!(!outside.join("child").exists());
    }

    #[tokio::test]
    async fn launch_failure_is_recorded_without_host_fallback() {
        let (dir, spec) = fixture().await;
        let sandbox = BwrapSandbox {
            executable: "/does/not/exist".into(),
        };
        assert!(matches!(
            sandbox.run(&spec).await,
            Err(SandboxError::BwrapSetup { .. })
        ));
        let db = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
        let (status, path): (String, String) = db
            .query_row(
                "SELECT exit_status, log_path FROM tool_invocation",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(status.starts_with("setup_error:"));
        assert!(spec.workspace.join(path).join("stdout.log").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_and_output_recording_with_test_supervisor() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, mut spec) = fixture().await;
        // This private test double only exercises supervision and recording;
        // it is not used as a sandbox or as an isolation test.
        let script = dir.path().join("supervisor");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf started\nprintf diagnostic >&2\nexec /bin/sleep 30\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sandbox = BwrapSandbox { executable: script };
        spec.timeout = Duration::from_millis(100);
        let out = sandbox.run(&spec).await.unwrap();
        assert_eq!(out.status, ProcessStatus::TimedOut);
        assert_eq!(std::fs::read(out.stdout_path).unwrap(), b"started");
        assert_eq!(std::fs::read(out.stderr_path).unwrap(), b"diagnostic");
        let db = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
        let status: String = db
            .query_row("SELECT exit_status FROM tool_invocation", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "timeout");
    }
}
