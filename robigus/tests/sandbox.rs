//! Runner-gated tests for the WP-1.7 bubblewrap sandbox.
//!
//! Each test prints a skip reason if bubblewrap cannot be established. Run with
//! `cargo test -p robigus --test sandbox` on a runner that permits user namespaces
//! to exercise the isolation assertions. Set `ROB_REQUIRE_BWRAP=1` to fail rather
//! than skip when bubblewrap or a required probe tool is unavailable.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use robigus::{
    CommandSpec, NetworkAccess, ProcessOutput, ProcessStatus, Sandbox, SandboxError,
    SandboxPreference, Store, establish_sandbox,
};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};

fn skip(test: &str, reason: &str) {
    assert!(
        std::env::var_os("ROB_REQUIRE_BWRAP").as_deref() != Some(std::ffi::OsStr::new("1")),
        "{test}: required sandbox test cannot run: {reason}"
    );
    // Write directly to stderr so the reason is visible even when libtest captures output.
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

async fn bwrap(test: &str) -> Option<Box<dyn Sandbox>> {
    match establish_sandbox(SandboxPreference::Bwrap).await {
        Ok(sandbox) => Some(sandbox),
        Err(error) => {
            skip(test, &format!("{error}; attempts: {:?}", error.attempts));
            None
        }
    }
}

struct Fixture {
    dir: TempDir,
    db_path: PathBuf,
    spec: CommandSpec,
}

impl Fixture {
    async fn new(script: &str) -> Self {
        let dir = tempfile::tempdir().expect("create workspace");
        let workspace = dir.path().join("workspace");
        let source = dir.path().join("source");
        std::fs::create_dir_all(&workspace).expect("create workspace directory");
        std::fs::create_dir_all(&source).expect("create source directory");
        let db_path = dir.path().join("analysis.db");
        let store = Store::open(&db_path).await.expect("open store");
        let spec = CommandSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".into(), script.into()],
            source,
            source_subdir: PathBuf::new(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(10),
            network: NetworkAccess::Offline,
            workspace,
            log_dir: PathBuf::from("logs"),
            store,
            package_id: None,
            tool_version: Some("sandbox-test-version".into()),
        };
        Self { dir, db_path, spec }
    }
}

fn read_output(path: &Path, workspace: &Path, log_dir: &Path) -> String {
    assert!(path.is_absolute(), "capture path is not absolute: {path:?}");
    assert!(
        path.starts_with(workspace.join(log_dir)),
        "capture is outside the workspace log directory: {path:?}"
    );
    std::fs::read_to_string(path).expect("read captured output")
}

fn assert_success(output: &ProcessOutput) {
    assert!(
        matches!(output.status, ProcessStatus::Exited(0)),
        "unexpected process status: {:?}",
        output.status
    );
}

fn invocation_count(db_path: &Path) -> i64 {
    let db = rusqlite::Connection::open(db_path).expect("open raw database");
    db.query_row("SELECT COUNT(*) FROM tool_invocation", [], |row| row.get(0))
        .expect("count invocations")
}

#[tokio::test]
async fn runs_command_captures_output_and_records_invocation() {
    let Some(sandbox) = bwrap("runs_command_captures_output_and_records_invocation").await else {
        return;
    };
    let mut fixture = Fixture::new(
        "test \"$PWD\" = /source || exit 1; printf 'hello stdout'; printf 'hello stderr' >&2",
    )
    .await;
    fixture
        .spec
        .env
        .insert("RUST_BACKTRACE".into(), "visible".into());

    let output = sandbox.run(&fixture.spec).await.expect("run shell");
    assert_success(&output);
    assert_ne!(output.stdout_path, output.stderr_path);
    assert_eq!(
        read_output(
            &output.stdout_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "hello stdout"
    );
    assert_eq!(
        read_output(
            &output.stderr_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "hello stderr"
    );

    assert_eq!(invocation_count(&fixture.db_path), 1);
    let db = rusqlite::Connection::open(&fixture.db_path).expect("open raw database");
    let (tool, argv, env, version, mode, package_id): (
        String,
        String,
        String,
        Option<String>,
        String,
        Option<i64>,
    ) = db
        .query_row(
            "SELECT tool, argv, env, tool_version, sandbox_mode, package_id FROM tool_invocation",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("read invocation");
    assert!(tool.ends_with("sh"), "unexpected tool: {tool}");
    let argv: Vec<String> = serde_json::from_str(&argv).expect("invocation argv is JSON");
    assert!(
        argv.contains(&"-c".to_string()),
        "missing shell argument: {argv:?}"
    );
    assert!(
        argv.contains(&fixture.spec.args[1]),
        "missing script: {argv:?}"
    );
    let env: BTreeMap<String, String> = serde_json::from_str(&env).expect("invocation env is JSON");
    assert_eq!(
        env.get("RUST_BACKTRACE").map(String::as_str),
        Some("visible")
    );
    assert_eq!(version.as_deref(), Some("sandbox-test-version"));
    assert_eq!(mode, "bwrap");
    assert_eq!(package_id, None);
}

#[cfg(unix)]
#[tokio::test]
async fn recorded_environment_matches_python_for_canonical_workdirs() {
    use std::os::unix::ffi::OsStringExt;

    let test = "recorded_environment_matches_python_for_canonical_workdirs";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    if !Path::new("/usr/bin/python3").is_file() {
        skip(test, "/usr/bin/python3 is required");
        return;
    }

    let mut fixture = Fixture::new("").await;
    let non_utf8_source = fixture
        .dir
        .path()
        .join(std::ffi::OsString::from_vec(b"source-\xff".to_vec()));
    std::fs::rename(&fixture.spec.source, &non_utf8_source).expect("rename source directory");
    fixture.spec.source = non_utf8_source;
    std::fs::create_dir_all(fixture.spec.source.join("real dir/child"))
        .expect("create nested source directory");
    std::os::unix::fs::symlink("real dir", fixture.spec.source.join("alias"))
        .expect("create source symlink");
    let non_utf8_alias = std::ffi::OsString::from_vec(b"alias-\xff".to_vec());
    std::os::unix::fs::symlink("real dir", fixture.spec.source.join(&non_utf8_alias))
        .expect("create non-UTF-8 source symlink");
    fixture.spec.program = "/usr/bin/python3".into();
    fixture.spec.args = vec![
        "-c".into(),
        "import json, os; print(json.dumps({'cwd': os.getcwd(), 'env': dict(os.environ)}))".into(),
    ];
    fixture.spec.env.insert("LC_ALL".into(), "C".into());
    fixture
        .spec
        .env
        .insert("RUST_BACKTRACE".into(), "visible".into());

    for (subdir, expected_cwd) in [
        (PathBuf::new(), "/source"),
        (PathBuf::from("real dir/child"), "/source/real dir/child"),
        (PathBuf::from("alias/child"), "/source/real dir/child"),
        (
            PathBuf::from(non_utf8_alias).join("child"),
            "/source/real dir/child",
        ),
    ] {
        fixture.spec.source_subdir = subdir.clone();
        let output = sandbox.run(&fixture.spec).await.expect("run Python probe");
        assert_success(&output);
        let report: serde_json::Value = serde_json::from_str(&read_output(
            &output.stdout_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir,
        ))
        .expect("Python report is JSON");
        assert_eq!(report["cwd"], expected_cwd, "subdir: {subdir:?}");
        let actual_env: BTreeMap<String, String> =
            serde_json::from_value(report["env"].clone()).expect("Python environment is an object");
        let db = rusqlite::Connection::open(&fixture.db_path).expect("open raw database");
        let recorded: String = db
            .query_row(
                "SELECT env FROM tool_invocation ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("read invocation environment");
        let recorded_env: BTreeMap<String, String> =
            serde_json::from_str(&recorded).expect("invocation env is JSON");
        let expected_env = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), "/home/sandbox".into()),
            ("CARGO_HOME".into(), "/cargo".into()),
            ("CARGO_TARGET_DIR".into(), "/output/target".into()),
            ("TMPDIR".into(), "/tmp".into()),
            ("PWD".into(), expected_cwd.into()),
            ("LC_ALL".into(), "C".into()),
            ("RUST_BACKTRACE".into(), "visible".into()),
        ]);
        assert_eq!(actual_env, expected_env, "subdir: {subdir:?}");
        assert_eq!(recorded_env, actual_env, "subdir: {subdir:?}");
    }
    assert_eq!(invocation_count(&fixture.db_path), 4);
}

#[tokio::test]
async fn source_is_read_only_and_output_and_cargo_home_are_writable() {
    let Some(sandbox) = bwrap("source_is_read_only_and_output_and_cargo_home_are_writable").await
    else {
        return;
    };
    let mut fixture = Fixture::new(
        r#"set -eu
        test "$PWD" = /source/subdir
        test "$(cat /source/subdir/input)" = original
        if (printf changed > /source/subdir/input) 2>/dev/null; then exit 11; fi
        if (printf new > /source/subdir/new) 2>/dev/null; then exit 12; fi
        printf output > /output/check
        test "$(cat /output/check)" = output
        test -n "${CARGO_HOME:-}"
        printf cargo > "$CARGO_HOME/check"
        test "$(cat "$CARGO_HOME/check")" = cargo
        printf isolated"#,
    )
    .await;
    fixture.spec.source_subdir = PathBuf::from("subdir");
    std::fs::create_dir(fixture.spec.source.join("subdir")).expect("create source subdir");
    std::fs::write(fixture.spec.source.join("subdir/input"), "original").expect("write source");

    let output = sandbox.run(&fixture.spec).await.expect("run shell");
    assert_success(&output);
    assert_eq!(
        read_output(
            &output.stdout_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "isolated"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.spec.source.join("subdir/input")).expect("read source"),
        "original"
    );
    assert!(!fixture.spec.source.join("subdir/new").exists());
}

// A separate process supplies known host secrets without unsafe, process-global
// environment mutation while the rest of the test suite is running.
#[tokio::test]
async fn host_environment_and_home_are_hidden() {
    let Some(_sandbox) = bwrap("host_environment_and_home_are_hidden").await else {
        return;
    };
    let home = tempfile::tempdir().expect("create fake host home");
    std::fs::write(home.path().join("secret"), "host-secret-file").expect("write host secret");
    let output = tokio::process::Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "host_environment_probe",
            "--ignored",
            "--nocapture",
        ])
        .env("ROB_REQUIRE_BWRAP", "1")
        .env("ROB_SANDBOX_PROBE_CHILD", "yes")
        .env("ROB_HOST_SECRET", "host-secret-value")
        .env("SSH_AUTH_SOCK", home.path().join("agent.sock"))
        .env("HOME", home.path())
        .output()
        .await
        .expect("run environment probe");
    // Preserve skip messages even with libtest output capture enabled.
    let _ = std::io::stderr().write_all(&output.stderr);
    assert_eq!(
        std::fs::read_to_string(home.path().join("secret")).expect("read host secret"),
        "host-secret-file"
    );
    assert!(
        output.status.success(),
        "environment probe failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("ROB_HOST_ENVIRONMENT_PROBE_COMPLETED"),
        "environment probe did not run: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
#[ignore = "invoked in a subprocess by host_environment_and_home_are_hidden"]
async fn host_environment_probe() {
    if std::env::var_os("ROB_SANDBOX_PROBE_CHILD").is_none() {
        skip(
            "host_environment_probe",
            "requires the parent test's isolated environment",
        );
        return;
    }
    let Some(sandbox) = bwrap("host_environment_and_home_are_hidden").await else {
        return;
    };
    let host_home = PathBuf::from(std::env::var_os("HOME").expect("probe HOME"));
    let mut fixture = Fixture::new(
        r#"set -eu
        test "${RUST_BACKTRACE:-}" = visible
        test -z "${ROB_HOST_SECRET+x}"
        test -z "${ROB_SANDBOX_PROBE_CHILD+x}"
        test -z "${SSH_AUTH_SOCK+x}"
        test "${HOME:-}" != "$1"
        test ! -e "$1/secret"
        if (printf changed > "$1/secret") 2>/dev/null; then exit 13; fi
        printf scrubbed"#,
    )
    .await;
    fixture
        .spec
        .args
        .extend(["probe".into(), host_home.to_string_lossy().into_owned()]);
    fixture
        .spec
        .env
        .insert("RUST_BACKTRACE".into(), "visible".into());

    let output = sandbox
        .run(&fixture.spec)
        .await
        .expect("run environment probe");
    assert_success(&output);
    assert_eq!(
        read_output(
            &output.stdout_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "scrubbed"
    );
    let db = rusqlite::Connection::open(&fixture.db_path).expect("open raw database");
    let env: String = db
        .query_row("SELECT env FROM tool_invocation", [], |row| row.get(0))
        .expect("read invocation environment");
    assert!(
        !env.contains("host-secret-value"),
        "host secret recorded: {env}"
    );
    assert!(!env.contains("SSH_AUTH_SOCK"), "host agent recorded: {env}");
    println!("ROB_HOST_ENVIRONMENT_PROBE_COMPLETED");
}

#[tokio::test]
async fn offline_network_cannot_reach_host_loopback() {
    let Some(sandbox) = bwrap("offline_network_cannot_reach_host_loopback").await else {
        return;
    };
    if !Path::new("/bin/bash").is_file() {
        skip(
            "offline_network_cannot_reach_host_loopback",
            "/bin/bash is required for the TCP probe",
        );
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind host listener");
    let port = listener.local_addr().expect("listener address").port();
    let probe = format!(
        "if (printf probe > /dev/tcp/127.0.0.1/{port}) 2>/dev/null; then printf connected; else printf blocked; fi"
    );
    // Ensure bash supports /dev/tcp and the listener is actually reachable on the host.
    let control = tokio::process::Command::new("/bin/bash")
        .args(["-c", &probe])
        .output()
        .await
        .expect("run host TCP control");
    assert!(control.status.success());
    assert_eq!(control.stdout, b"connected", "host TCP control failed");
    tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("host control connection timed out")
        .expect("accept host control");

    let mut fixture =
        Fixture::new("test -c /dev/null && test -w /dev/null || exit 1; exec /bin/bash -c \"$1\"")
            .await;
    fixture.spec.args.extend(["probe".into(), probe]);
    let output = sandbox
        .run(&fixture.spec)
        .await
        .expect("run offline TCP probe");
    assert_success(&output);
    assert_eq!(
        read_output(
            &output.stdout_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "blocked"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), listener.accept())
            .await
            .is_err(),
        "sandbox connected to the host listener"
    );
    // The host listener is still live after the sandbox probe.
    TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect after sandbox probe");
}

/// Runs a Python probe from `/source` and returns its trimmed stdout.
async fn run_python(
    sandbox: &dyn Sandbox,
    fixture: &mut Fixture,
    test: &str,
    script: &str,
) -> Option<String> {
    if !Path::new("/usr/bin/python3").is_file() {
        skip(test, "/usr/bin/python3 is required");
        return None;
    }
    fixture.spec.program = "/usr/bin/python3".into();
    fixture.spec.args = vec!["-c".into(), script.into()];
    let output = sandbox.run(&fixture.spec).await.expect("run Python probe");
    let stdout = read_output(
        &output.stdout_path,
        &fixture.spec.workspace,
        &fixture.spec.log_dir,
    );
    let stderr = std::fs::read_to_string(&output.stderr_path).unwrap_or_default();
    assert!(
        matches!(output.status, ProcessStatus::Exited(0)),
        "probe failed with {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    Some(stdout.trim().to_owned())
}

/// A host Unix listener that verifies it is reachable from the host and
/// records anything it later receives.
#[cfg(unix)]
struct HostUnixListener {
    listener: std::os::unix::net::UnixListener,
}

#[cfg(unix)]
impl HostUnixListener {
    fn bind(path: &Path) -> Self {
        use std::io::Read;
        let listener = std::os::unix::net::UnixListener::bind(path).expect("bind host socket");
        // Control: the listener works from the host before the sandbox runs.
        let mut client = std::os::unix::net::UnixStream::connect(path).expect("host control");
        client.write_all(b"control").expect("write host control");
        drop(client);
        let (mut accepted, _) = listener.accept().expect("accept host control");
        let mut control = Vec::new();
        accepted
            .read_to_end(&mut control)
            .expect("read host control");
        assert_eq!(control, b"control", "host Unix-socket control failed");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        Self { listener }
    }

    fn assert_unreached(&self) {
        match self.listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("sandbox reached the host Unix listener: {other:?}"),
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn offline_cannot_connect_to_unix_socket_in_source() {
    let test = "offline_cannot_connect_to_unix_socket_in_source";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    let mut fixture = Fixture::new("").await;
    std::fs::create_dir(fixture.spec.source.join("nested")).expect("create nested dir");
    let top = HostUnixListener::bind(&fixture.spec.source.join("host.sock"));
    let nested = HostUnixListener::bind(&fixture.spec.source.join("nested/host.sock"));
    let script = r#"
import socket
results = []
for path in ['/source/host.sock', '/source/nested/host.sock']:
    for kind in [socket.SOCK_STREAM, socket.SOCK_SEQPACKET]:
        try:
            s = socket.socket(socket.AF_UNIX, kind)
            s.connect(path)
            s.send(b'escaped')
            results.append('connected')
        except OSError:
            results.append('blocked')
print(' '.join(results))
"#;
    let Some(stdout) = run_python(sandbox.as_ref(), &mut fixture, test, script).await else {
        return;
    };
    assert_eq!(
        stdout, "blocked blocked blocked blocked",
        "offline sandbox reached a host service through the source mount"
    );
    top.assert_unreached();
    nested.assert_unreached();
}

#[cfg(unix)]
#[tokio::test]
async fn offline_cannot_send_datagrams_to_host_unix_socket() {
    let test = "offline_cannot_send_datagrams_to_host_unix_socket";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    let mut fixture = Fixture::new("").await;
    let path = fixture.spec.source.join("host.dgram");
    let host = std::os::unix::net::UnixDatagram::bind(&path).expect("bind host datagram");
    std::os::unix::net::UnixDatagram::unbound()
        .expect("host datagram client")
        .send_to(b"control", &path)
        .expect("host datagram control");
    let mut buffer = [0u8; 64];
    assert_eq!(host.recv(&mut buffer).expect("receive control"), 7);
    host.set_nonblocking(true).expect("nonblocking datagram");
    let script = r#"
import socket
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b'escaped', '/source/host.dgram')
    print('sent')
except OSError:
    print('blocked')
"#;
    let Some(stdout) = run_python(sandbox.as_ref(), &mut fixture, test, script).await else {
        return;
    };
    assert_eq!(stdout, "blocked");
    match host.recv(&mut buffer) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("sandbox delivered a datagram to the host: {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn offline_cannot_use_host_fifos_in_source() {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let test = "offline_cannot_use_host_fifos_in_source";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    if !Path::new("/usr/bin/mkfifo").is_file() {
        skip(test, "/usr/bin/mkfifo is required to create a host FIFO");
        return;
    }
    let mut fixture = Fixture::new("").await;
    let inbound = fixture.spec.source.join("to-host.fifo");
    let outbound = fixture.spec.source.join("from-host.fifo");
    for fifo in [&inbound, &outbound] {
        let status = std::process::Command::new("/usr/bin/mkfifo")
            .arg(fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed");
    }
    // The host keeps a reader on one FIFO (so a sandbox writer could connect)
    // and a writer with pending data on the other.
    let mut host_reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nonblock())
        .open(&inbound)
        .expect("open host FIFO reader");
    let host_read_end = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nonblock())
        .open(&outbound)
        .expect("hold outbound FIFO open for the host writer");
    let mut host_writer = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc_o_nonblock())
        .open(&outbound)
        .expect("open host FIFO writer");
    host_writer
        .write_all(b"host-secret")
        .expect("write host FIFO");
    let script = r#"
import os
results = []
try:
    fd = os.open('/source/to-host.fifo', os.O_WRONLY | os.O_NONBLOCK)
    os.write(fd, b'escaped')
    results.append('wrote')
except OSError:
    results.append('write-blocked')
try:
    fd = os.open('/source/from-host.fifo', os.O_RDONLY | os.O_NONBLOCK)
    data = os.read(fd, 64)
    results.append('read:' + data.decode() if data else 'read-empty')
except OSError:
    results.append('read-blocked')
print(' '.join(results))
"#;
    let Some(stdout) = run_python(sandbox.as_ref(), &mut fixture, test, script).await else {
        return;
    };
    assert!(
        !stdout.contains("wrote") && !stdout.contains("host-secret"),
        "sandbox communicated through a host FIFO: {stdout}"
    );
    let mut received = Vec::new();
    match host_reader.read_to_end(&mut received) {
        Ok(_) => assert!(received.is_empty(), "host received FIFO data: {received:?}"),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("read host FIFO: {error}"),
    }
    drop(host_read_end);
}

/// `O_NONBLOCK` on Linux, without depending on a libc crate from tests.
#[cfg(unix)]
fn libc_o_nonblock() -> i32 {
    0o4000
}

#[cfg(unix)]
#[tokio::test]
async fn only_stdio_descriptors_reach_the_workload() {
    let test = "only_stdio_descriptors_reach_the_workload";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    // A child test process holds an inheritable host socket at a high fd and
    // runs the sandbox; the workload must not see it.
    if std::env::var_os("ROB_SANDBOX_FD_CHILD").is_some() {
        return;
    }
    let output = tokio::process::Command::new("/usr/bin/bash")
        .arg("-c")
        .arg(r#"exec 47<>"$1"; exec "$2" --exact inherited_descriptor_probe --ignored --nocapture"#)
        .arg("robigus-fd-test")
        .arg("/dev/null")
        .arg(std::env::current_exe().expect("test executable"))
        .env("ROB_REQUIRE_BWRAP", "1")
        .env("ROB_SANDBOX_FD_CHILD", "yes")
        .output()
        .await
        .expect("run descriptor probe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("ROB_FD_PROBE_COMPLETED"),
        "descriptor probe failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    drop(sandbox);
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "invoked in a subprocess by only_stdio_descriptors_reach_the_workload"]
async fn inherited_descriptor_probe() {
    let test = "inherited_descriptor_probe";
    if std::env::var_os("ROB_SANDBOX_FD_CHILD").is_none() {
        skip(test, "requires the parent test's inherited descriptor");
        return;
    }
    assert!(
        Path::new("/proc/self/fd/47").exists(),
        "the parent did not supply the inherited descriptor"
    );
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    let mut fixture = Fixture::new("").await;
    let script = r#"
import os
fds = sorted(int(fd) for fd in os.listdir('/proc/self/fd'))
print(' '.join(map(str, fds)))
"#;
    let Some(stdout) = run_python(sandbox.as_ref(), &mut fixture, test, script).await else {
        return;
    };
    // listdir holds one directory descriptor (3) while it enumerates.
    assert_eq!(stdout, "0 1 2 3", "unexpected workload descriptors");
    println!("ROB_FD_PROBE_COMPLETED");
}

#[cfg(unix)]
#[tokio::test]
async fn fixed_peer_socket_pairs_work_and_unix_sockets_are_denied() {
    let test = "fixed_peer_socket_pairs_work_and_unix_sockets_are_denied";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    let mut fixture = Fixture::new("").await;
    let script = r#"
import errno, socket
for kind in [socket.SOCK_STREAM, socket.SOCK_SEQPACKET]:
    a, b = socket.socketpair(socket.AF_UNIX, kind)
    a.send(b'ipc')
    assert b.recv(3) == b'ipc'
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
except OSError as e:
    assert e.errno == errno.EPERM, e
else:
    raise AssertionError('AF_UNIX socket() allowed')
try:
    socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
except OSError as e:
    assert e.errno == errno.EPERM, e
else:
    raise AssertionError('reconnectable datagram pair allowed')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 0))
print('ok')
"#;
    let Some(stdout) = run_python(sandbox.as_ref(), &mut fixture, test, script).await else {
        return;
    };
    assert_eq!(stdout, "ok");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn nested_user_namespaces_and_capabilities_are_unavailable() {
    let test = "nested_user_namespaces_and_capabilities_are_unavailable";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    let mut fixture = Fixture::new("").await;
    let script = r#"
import os
status = dict(line.split(':', 1) for line in open('/proc/self/status'))
fields = {key: status[key].strip() for key in ['CapEff', 'CapBnd', 'NoNewPrivs', 'Seccomp']}
try:
    os.unshare(os.CLONE_NEWUSER)
    nested = 'allowed'
except OSError:
    nested = 'denied'
print(fields['CapEff'], fields['CapBnd'], fields['NoNewPrivs'], fields['Seccomp'], nested)
"#;
    let Some(stdout) = run_python(sandbox.as_ref(), &mut fixture, test, script).await else {
        return;
    };
    assert_eq!(
        stdout, "0000000000000000 0000000000000000 1 2 denied",
        "unexpected workload privileges"
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
async fn host_keyrings_are_unreachable() {
    let test = "host_keyrings_are_unreachable";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    let mut fixture = Fixture::new("").await;
    // Raw x86-64 syscall numbers: keyctl 250, add_key 248, request_key 249.
    // Namespaces do not isolate the session keyring, so seccomp must deny all
    // three; each must fail with EPERM rather than reach a host keyring.
    let script = r#"
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
results = []
for name, args in [
    ('keyctl', (250, 0, -3, 0)),
    ('add_key', (248, b'user', b'robigus-probe', b'x', 1, -3)),
    ('request_key', (249, b'user', b'robigus-probe', None, 0)),
]:
    rc = libc.syscall(*args)
    results.append(f'{name}:' + ('EPERM' if rc == -1 and ctypes.get_errno() == errno.EPERM else f'allowed({rc})'))
print(' '.join(results))
"#;
    let Some(stdout) = run_python(sandbox.as_ref(), &mut fixture, test, script).await else {
        return;
    };
    assert_eq!(stdout, "keyctl:EPERM add_key:EPERM request_key:EPERM");
}

#[tokio::test]
async fn cargo_toolchain_runs_inside_the_sandbox() {
    let test = "cargo_toolchain_runs_inside_the_sandbox";
    let Some(sandbox) = bwrap(test).await else {
        return;
    };
    // Only the system runtime is visible in the sandbox, so a rustup toolchain
    // under the host home directory cannot be used here.
    if let Some(missing) = ["/usr/bin/cargo", "/usr/bin/rustc"]
        .into_iter()
        .find(|tool| !Path::new(tool).exists())
    {
        skip(
            test,
            &format!(
                "{missing} is required for the toolchain smoke test; install the \
                 distribution `cargo` and `rustc` packages (rustup toolchains under \
                 the home directory are not visible inside the sandbox)"
            ),
        );
        return;
    }
    let mut fixture = Fixture::new("/usr/bin/cargo --version && /usr/bin/rustc --version").await;
    fixture
        .spec
        .env
        .insert("CARGO_NET_OFFLINE".into(), "true".into());
    let output = sandbox.run(&fixture.spec).await.expect("run cargo");
    let stdout = read_output(
        &output.stdout_path,
        &fixture.spec.workspace,
        &fixture.spec.log_dir,
    );
    assert!(
        matches!(output.status, ProcessStatus::Exited(0))
            && stdout.contains("cargo ")
            && stdout.contains("rustc "),
        "cargo failed: {:?}\nstdout: {stdout}\nstderr: {}",
        output.status,
        std::fs::read_to_string(&output.stderr_path).unwrap_or_default()
    );
}

#[tokio::test]
async fn timeout_terminates_the_command() {
    let Some(sandbox) = bwrap("timeout_terminates_the_command").await else {
        return;
    };
    let mut fixture = Fixture::new("printf started; /bin/sleep 3; printf survived").await;
    fixture.spec.timeout = Duration::from_secs(1);
    let started = Instant::now();
    let output = tokio::time::timeout(Duration::from_secs(15), sandbox.run(&fixture.spec))
        .await
        .expect("sandbox did not return after timeout")
        .expect("run timed command");
    assert!(
        matches!(output.status, ProcessStatus::TimedOut),
        "unexpected status: {:?}",
        output.status
    );
    assert!(started.elapsed() < Duration::from_secs(15));
    // A surviving shell would attempt to append after its sleep finishes.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert_eq!(
        read_output(
            &output.stdout_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "started"
    );
    assert_eq!(invocation_count(&fixture.db_path), 1);
}

#[tokio::test]
async fn allowlist_is_rejected_before_launch_until_proxy_exists() {
    let Some(sandbox) = bwrap("allowlist_is_rejected_before_launch_until_proxy_exists").await
    else {
        return;
    };
    let mut fixture = Fixture::new("printf ROB_UNEXPECTED_LAUNCH_MARKER").await;
    fixture.spec.network = NetworkAccess::Allowlist;
    // The nonexistent program checks validation order; the real shell checks
    // that a runnable command cannot execute under the rejected policy.
    for program in [
        fixture.dir.path().join("does-not-exist"),
        PathBuf::from("/bin/sh"),
    ] {
        fixture.spec.program = program;
        let error = match sandbox.run(&fixture.spec).await {
            Ok(_) => panic!("allowlist networking must fail closed before proxy support exists"),
            Err(error) => error,
        };
        let message = error.to_string().to_lowercase();
        assert!(
            message.contains("network")
                || message.contains("allowlist")
                || message.contains("proxy"),
            "expected explicit network-policy error, got: {error}"
        );
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    for entry in walkdir::WalkDir::new(&fixture.spec.workspace) {
        let entry = entry.expect("inspect workspace");
        if entry.file_type().is_file() {
            let contents = std::fs::read(entry.path()).expect("read workspace file");
            assert!(
                !contents
                    .windows(b"ROB_UNEXPECTED_LAUNCH_MARKER".len())
                    .any(|window| window == b"ROB_UNEXPECTED_LAUNCH_MARKER"),
                "rejected command produced output in {:?}",
                entry.path()
            );
        }
    }
    assert_eq!(
        invocation_count(&fixture.db_path),
        0,
        "rejected command was recorded as executed"
    );
}

#[tokio::test]
async fn command_exit_42_is_not_setup_failure_and_stdin_is_eof() {
    let Some(sandbox) = bwrap("command_exit_42_is_not_setup_failure_and_stdin_is_eof").await else {
        return;
    };
    let fixture = Fixture::new(
        r#"if IFS= read -r input; then printf unexpected-stdin; exit 91; fi
        printf stdin-eof
        printf 'bwrap: Failed to chdir: Permission denied\n' >&2
        exit 42"#,
    )
    .await;
    let output = sandbox
        .run(&fixture.spec)
        .await
        .expect("run command exiting 42");
    assert_eq!(output.status, ProcessStatus::Exited(42));
    assert_eq!(
        read_output(
            &output.stdout_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "stdin-eof"
    );
    assert_eq!(
        read_output(
            &output.stderr_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "bwrap: Failed to chdir: Permission denied\n"
    );
    assert_eq!(invocation_count(&fixture.db_path), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn real_bwrap_setup_failure_is_diagnostic_and_recorded() {
    use std::os::unix::fs::PermissionsExt;

    let Some(sandbox) = bwrap("real_bwrap_setup_failure_is_diagnostic_and_recorded").await else {
        return;
    };
    let fixture = Fixture::new("printf ROB_SETUP_UNEXPECTED_COMMAND_EXECUTION").await;
    let permissions = std::fs::metadata(&fixture.spec.source)
        .expect("read source permissions")
        .permissions();
    std::fs::set_permissions(&fixture.spec.source, std::fs::Permissions::from_mode(0o000))
        .expect("make source inaccessible after establishment");
    let result = sandbox.run(&fixture.spec).await;
    // Restore before any assertion, including unexpected results, so TempDir can clean up.
    std::fs::set_permissions(&fixture.spec.source, permissions)
        .expect("restore source permissions");
    let error = result.expect_err("inaccessible source must fail bubblewrap setup");
    let diagnostic = error.to_string();
    let SandboxError::BwrapSetup { cause, stderr_path } = error else {
        panic!("expected BwrapSetup, got: {diagnostic}");
    };
    assert!(!cause.trim().is_empty(), "missing setup cause");
    assert!(
        diagnostic.contains(&cause),
        "diagnostic omits cause: {diagnostic}"
    );
    let stderr = read_output(&stderr_path, &fixture.spec.workspace, &fixture.spec.log_dir);
    assert!(
        stderr.contains("bwrap:"),
        "missing bubblewrap diagnostic: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("permission denied"),
        "unexpected setup diagnostic: {stderr}"
    );
    assert_eq!(invocation_count(&fixture.db_path), 1);
    let db = rusqlite::Connection::open(&fixture.db_path).expect("open raw database");
    let (status, log_path): (String, String) = db
        .query_row(
            "SELECT exit_status, log_path FROM tool_invocation",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read setup failure invocation");
    assert!(
        status.starts_with("setup_error:"),
        "unexpected invocation status: {status}"
    );
    assert_eq!(
        stderr_path,
        fixture.spec.workspace.join(&log_path).join("stderr.log")
    );
    assert_eq!(
        read_output(
            &fixture.spec.workspace.join(log_path).join("stdout.log"),
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        ""
    );
}

#[tokio::test]
async fn missing_requested_program_is_command_exit_127() {
    let Some(sandbox) = bwrap("missing_requested_program_is_command_exit_127").await else {
        return;
    };
    let mut fixture = Fixture::new("").await;
    fixture.spec.program = PathBuf::from("/robigus-nonexistent-requested-program");
    fixture.spec.args.clear();
    let output = sandbox
        .run(&fixture.spec)
        .await
        .expect("missing program is a wrapper command failure");
    assert_eq!(output.status, ProcessStatus::Exited(127));
    let stderr = read_output(
        &output.stderr_path,
        &fixture.spec.workspace,
        &fixture.spec.log_dir,
    );
    assert!(
        stderr.contains("robigus-nonexistent-requested-program"),
        "missing program diagnostic: {stderr}"
    );
    assert_eq!(invocation_count(&fixture.db_path), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn command_cannot_forge_status_through_pid_one_stdin() {
    let Some(sandbox) = bwrap("command_cannot_forge_status_through_pid_one_stdin").await else {
        return;
    };
    let fixture = Fixture::new(
        r#"if (printf '{"child-pid":1}\n{"exit-code":0}\n' > /proc/1/fd/0) 2>/dev/null; then
            printf status-write-succeeded
            exit 92
        fi
        printf status-write-blocked
        exit 42"#,
    )
    .await;
    let output = sandbox
        .run(&fixture.spec)
        .await
        .expect("status forgery must not corrupt supervision");
    assert_eq!(output.status, ProcessStatus::Exited(42));
    assert_eq!(
        read_output(
            &output.stdout_path,
            &fixture.spec.workspace,
            &fixture.spec.log_dir
        ),
        "status-write-blocked"
    );
    let db = rusqlite::Connection::open(&fixture.db_path).expect("open raw database");
    let status: String = db
        .query_row("SELECT exit_status FROM tool_invocation", [], |row| {
            row.get(0)
        })
        .expect("read actual command status");
    assert_eq!(status, "exit:42");
    assert_eq!(invocation_count(&fixture.db_path), 1);
}
