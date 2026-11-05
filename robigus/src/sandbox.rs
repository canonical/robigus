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
/// variables are never passed through. Callers must not put credentials or
/// other secrets in arguments, since arbitrary command arguments cannot be
/// reliably identified as secrets and are recorded for reproducibility.
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

/// Outcome of an execution, including timeouts and signal termination.
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
        let mut cmd = Command::new(&executable);
        cmd.env_clear().kill_on_drop(true).stdin(Stdio::null());
        cmd.args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session",
        ]);
        bind_runtime(&mut cmd);
        cmd.args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--",
            "/usr/bin/true",
        ]);
        let result = tokio::time::timeout(Duration::from_secs(10), cmd.output()).await;
        match result {
            Err(_) => Err("namespace probe timed out after 10 seconds".into()),
            Ok(Err(error)) => Err(format!(
                "failed to launch {}: {error}",
                executable.display()
            )),
            Ok(Ok(output)) if output.status.success() => Ok(executable),
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

/// Bind only the system runtime, not the host root or home directory.
fn bind_runtime(cmd: &mut Command) {
    for path in ["/usr", "/bin", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            cmd.args(["--ro-bind", path, path]);
        }
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
        let sandbox_workdir = Path::new("/source").join(relative_workdir);
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

        let mut env = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), "/home/sandbox".into()),
            ("CARGO_HOME".into(), "/cargo".into()),
            ("CARGO_TARGET_DIR".into(), "/output/target".into()),
            ("TMPDIR".into(), "/tmp".into()),
        ]);
        env.extend(spec.env.clone());
        let mut cmd = Command::new(&self.executable);
        cmd.env_clear()
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        #[cfg(unix)]
        cmd.process_group(0);
        cmd.args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ]);
        bind_runtime(&mut cmd);
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
            "--ro-bind",
        ])
        .arg(&source)
        .arg("/source");
        for (key, value) in &env {
            cmd.arg("--setenv").arg(key).arg(value);
        }
        cmd.arg("--chdir")
            .arg(&sandbox_workdir)
            .arg("--")
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
            Err(error) => Err(error),
            Ok(child) => {
                let group = child.id();
                let mut guard = ChildGuard { child, group };
                match tokio::time::timeout(spec.timeout, guard.child.wait()).await {
                    Ok(Ok(status)) => {
                        guard.group = None;
                        Ok(status
                            .code()
                            .map_or(ProcessStatus::Signaled, ProcessStatus::Exited))
                    }
                    Ok(Err(error)) => {
                        guard.terminate();
                        Err(error)
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
            Err(error) => format!("launch_error:{error}"),
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
        spec.log_dir = "../outside".into();
        assert!(matches!(
            sandbox.run(&spec).await,
            Err(SandboxError::InvalidCommand(_))
        ));
        assert!(!spec.workspace.join("logs").exists());
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
        assert!(matches!(sandbox.run(&spec).await, Err(SandboxError::Io(_))));
        let db = rusqlite::Connection::open(dir.path().join("analysis.db")).unwrap();
        let (status, path): (String, String) = db
            .query_row(
                "SELECT exit_status, log_path FROM tool_invocation",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(status.starts_with("launch_error:"));
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
