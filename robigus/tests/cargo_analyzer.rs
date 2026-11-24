//! Integration and `insta` snapshot tests for the WP-2.2 Cargo analyzer.
//!
//! Offline, containment, and `acquire_dependency` tests run in every
//! environment. Tests that execute `/usr/bin/cargo metadata` inside bubblewrap
//! skip with a diagnostic when bubblewrap is unavailable (for example when
//! running as `root`), and fail hard if skipped when `ROB_REQUIRE_BWRAP=1` is
//! set (used by CI's `sandbox` job).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use robigus::analyzers::cargo::resolve_path_dependency;
use robigus::fetch::fetch_path;
use robigus::model::{Ecosystem, GitReference, PackageVersion};
use robigus::registry::{IndexUrlPolicy, RegistrySpec};
use robigus::{
    Allowlist, AnalysisContext, AnalysisMetadata, AnalysisStatus, AnalyzerLimits, AnalyzerOutput,
    Cache, CargoAnalyzer, ConfidenceTier, Configuration, CredentialSource, DependencyFetchPolicy,
    FetchOptions, HostName, NetworkAccess, NetworkMode, PackageId, PlanStatus, ProjectAnalyzer,
    ProxyPolicy, Sandbox, SandboxPreference, SourceId, SourceKind, Store, acquire_dependency,
    acquire_dependency_with_policy, establish_sandbox,
};
use sha2::{Digest as _, Sha256};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn skip_sandbox(test: &str, reason: &str) {
    assert!(
        std::env::var_os("ROB_REQUIRE_BWRAP").as_deref() != Some(std::ffi::OsStr::new("1")),
        "{test}: required sandbox test cannot run: {reason}"
    );
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

async fn bwrap_with_cargo(test: &str) -> Option<Box<dyn Sandbox>> {
    let sandbox = match establish_sandbox(SandboxPreference::Bwrap).await {
        Ok(sb) => sb,
        Err(error) => {
            skip_sandbox(test, &format!("{error}; attempts: {:?}", error.attempts));
            return None;
        }
    };
    for bin in ["/usr/bin/cargo", "/usr/bin/rustc", "/usr/bin/python3"] {
        if !Path::new(bin).exists() {
            skip_sandbox(test, &format!("{bin} is required"));
            return None;
        }
    }
    Some(sandbox)
}

fn write_file(root: &Path, rel: &str, contents: &str) {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(full, contents).expect("write fixture file");
}

/// Normalizes environment-dependent strings (temporary paths, dynamic ports,
/// toolchain versions) in serialized [`AnalyzerOutput`] before snapshotting.
fn snapshot_value(output: &AnalyzerOutput, tree_path: &Path) -> serde_json::Value {
    let canonical = std::fs::canonicalize(tree_path).unwrap_or_else(|_| tree_path.to_path_buf());
    let mut val = serde_json::to_value(output).expect("serialize AnalyzerOutput");
    if let Some(toolchain) = val.get_mut("toolchain").and_then(|v| v.as_object_mut()) {
        if toolchain.contains_key("cargo") {
            toolchain.insert(
                "cargo".into(),
                serde_json::Value::String("<CARGO_VER>".into()),
            );
        }
        if toolchain.contains_key("rustc") {
            toolchain.insert(
                "rustc".into(),
                serde_json::Value::String("<RUSTC_VER>".into()),
            );
        }
    }
    let needles = [
        canonical.to_string_lossy().into_owned(),
        tree_path.to_string_lossy().into_owned(),
    ];
    redact_strings(&mut val, &needles);
    val
}

fn redact_strings(value: &mut serde_json::Value, tmp_paths: &[String]) {
    match value {
        serde_json::Value::String(s) => {
            for p in tmp_paths {
                if !p.is_empty() && s.contains(p) {
                    *s = s.replace(p, "<TMP>");
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_strings(item, tmp_paths);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                redact_strings(v, tmp_paths);
            }
        }
        _ => {}
    }
}

macro_rules! assert_analyzer_snapshot {
    ($name:expr, $val:expr) => {
        insta::with_settings!({
            snapshot_path => "snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_json_snapshot!($name, $val);
        });
    };
}

/// Builds a valid `.crate` gzip tarball in memory containing `<name>-<ver>/…`
/// and returns `(bytes, sha256_hex)`.
fn build_crate_archive(
    name: &str,
    version: &str,
    cargo_toml: &str,
    lib_rs: &str,
) -> (Vec<u8>, String) {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        let prefix = format!("{name}-{version}");
        let mut add = |rel: &str, body: &[u8]| {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("{prefix}/{rel}"), body)
                .expect("append tar entry");
        };
        add("Cargo.toml", cargo_toml.as_bytes());
        add("src/lib.rs", lib_rs.as_bytes());
        builder.finish().expect("finish tar");
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).expect("gzip tar");
    let compressed = gz.finish().expect("finish gzip");
    let digest: String = Sha256::digest(&compressed)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    (compressed, digest)
}

#[tokio::test]
async fn offline_features_and_target_cfg_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("project");
    let ws = dir.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();

    write_file(
        &src,
        "Cargo.toml",
        r#"[package]
name = "feat-demo"
version = "0.2.0"
edition = "2021"
links = "z"

[dependencies]
itoa = { version = "^1.0", optional = true }
serde = { version = "^1.0", optional = true, default-features = false }
ryu = { version = "^1.0", optional = true }
hx = { package = "hex", version = "^0.4" }

[build-dependencies]
cc = "^1.0"
pkg-config = "^0.3"

[target.'cfg(unix)'.dependencies]
libc = "^0.2"

[target.'cfg(all(target_os = "linux", target_arch = "x86_64"))'.dependencies]
linux-raw-sys = "^0.6"

[target.aarch64-unknown-linux-gnu.dev-dependencies]
criterion = "^0.5"

[features]
default = ["std"]
std = ["dep:itoa", "serde?/std"]
derive = ["serde/derive"]
"#,
    );
    write_file(&src, "src/lib.rs", "pub fn demo() {}\n");
    write_file(
        &src,
        "build.rs",
        r#"fn main() {
    pkg_config::probe_library("zlib").unwrap();
    cc::Build::new().file("shim.c").compile("shim");
    println!("cargo::rustc-link-lib=z");
}
"#,
    );

    let fetched = fetch_path(&src).await.unwrap();
    let store = Store::open(&dir.path().join("offline.db")).await.unwrap();
    let config = Configuration::default();
    let ctx = AnalysisContext {
        source: &fetched,
        root: Path::new(""),
        configuration: &config,
        registries: &[],
        network: &NetworkAccess::Offline,
        sandbox: None,
        store: &store,
        workspace: &ws,
        limits: AnalyzerLimits::default(),
    };

    let output = CargoAnalyzer.analyze(&ctx).await.unwrap();
    assert_eq!(output.network_mode, NetworkMode::Offline);
    assert!(output.edges.iter().all(|e| e.to.is_none()));
    assert!(output.edges.iter().all(|e| {
        e.confidence.tier() != ConfidenceTier::L0 && e.evidence.iter().all(|ev| !ev.violates_cap())
    }));

    assert_analyzer_snapshot!(
        "cargo_offline_features_and_target_cfg",
        snapshot_value(&output, &src)
    );
}

#[tokio::test]
async fn offline_workspace_and_vendored_crate_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("ws-project");
    let ws = dir.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();

    write_file(
        &src,
        "Cargo.toml",
        r#"[workspace]
members = ["crates/*"]
exclude = ["crates/ignored"]
resolver = "2"

[workspace.package]
version = "1.4.0"

[workspace.dependencies]
vendored-helper = { path = "vendor/vendored-helper", version = "0.1.0" }
log = "0.4"
"#,
    );
    write_file(
        &src,
        "crates/alpha/Cargo.toml",
        r#"[package]
name = "alpha"
version.workspace = true
edition = "2021"

[dependencies]
vendored-helper.workspace = true
log.workspace = true
"#,
    );
    write_file(&src, "crates/alpha/src/main.rs", "fn main() {}\n");

    write_file(
        &src,
        "crates/ignored/Cargo.toml",
        "[package]\nname = \"ignored\"\nversion = \"0.0.1\"\n",
    );
    write_file(&src, "crates/ignored/src/lib.rs", "");

    write_file(
        &src,
        "vendor/vendored-helper/Cargo.toml",
        "[package]\nname = \"vendored-helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(
        &src,
        "vendor/vendored-helper/src/lib.rs",
        "pub fn help() {}\n",
    );

    // Unreferenced crate under `vendor/` MUST NOT be loaded or expanded (spec §7.3).
    write_file(
        &src,
        "vendor/unreferenced/Cargo.toml",
        "[package]\nname = \"unreferenced\"\nversion = \"9.9.9\"\n",
    );
    write_file(&src, "vendor/unreferenced/src/lib.rs", "");

    let fetched = fetch_path(&src).await.unwrap();
    let store = Store::open(&dir.path().join("ws.db")).await.unwrap();
    let config = Configuration::default();
    let ctx = AnalysisContext {
        source: &fetched,
        root: Path::new(""),
        configuration: &config,
        registries: &[],
        network: &NetworkAccess::Offline,
        sandbox: None,
        store: &store,
        workspace: &ws,
        limits: AnalyzerLimits::default(),
    };

    let output = CargoAnalyzer.analyze(&ctx).await.unwrap();
    let node_names: BTreeSet<&str> = output.nodes.iter().map(|n| n.id.name.as_str()).collect();
    assert_eq!(node_names, BTreeSet::from(["alpha", "vendored-helper"]));
    assert_eq!(output.roots.len(), 1);
    assert_eq!(output.roots.iter().next().unwrap().name, "alpha");

    assert_analyzer_snapshot!(
        "cargo_offline_workspace_and_vendor",
        snapshot_value(&output, &src)
    );
}

#[tokio::test]
async fn path_escape_is_rejected_and_marks_plan_failed() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    write_file(
        &outside,
        "Cargo.toml",
        "[package]\nname = \"outside\"\nversion = \"0.1.0\"\n",
    );
    write_file(&outside, "src/lib.rs", "");

    let src = dir.path().join("escaped-project");
    let ws = dir.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();
    write_file(
        &src,
        "Cargo.toml",
        r#"[package]
name = "bad-pkg"
version = "0.1.0"
edition = "2021"

[dependencies]
outside = { path = "../outside" }
"#,
    );
    write_file(&src, "src/lib.rs", "");

    assert!(resolve_path_dependency(&src, Path::new(""), Path::new("../outside")).is_err());

    let fetched = fetch_path(&src).await.unwrap();
    let store = Store::open(&dir.path().join("escape.db")).await.unwrap();
    store
        .write_metadata(&AnalysisMetadata {
            robigus_version: "0.1.0".into(),
            project_name: "bad-pkg".into(),
            project_version: "0.1.0".into(),
            source_kind: "path".into(),
            source_uri: src.to_string_lossy().into_owned(),
            source_digest: fetched.digest.clone(),
            configuration: Configuration::default(),
            toolchain: BTreeMap::new(),
            network_mode: "offline".into(),
            sandbox_mode: "bwrap".into(),
            options: serde_json::json!({}),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        })
        .await
        .unwrap();

    let config = Configuration::default();
    let ctx = AnalysisContext {
        source: &fetched,
        root: Path::new(""),
        configuration: &config,
        registries: &[],
        network: &NetworkAccess::Offline,
        sandbox: None,
        store: &store,
        workspace: &ws,
        limits: AnalyzerLimits::default(),
    };

    let output = CargoAnalyzer.analyze(&ctx).await.unwrap();
    // Outside package must not appear as a node or edge.
    assert_eq!(output.nodes.len(), 1);
    assert_eq!(output.nodes[0].id.name, "bad-pkg");
    assert!(output.edges.is_empty());

    let failed_row = output
        .plan
        .iter()
        .find(|r| r.status == PlanStatus::Failed)
        .expect("escaping path dependency must produce a Failed plan row");
    assert!(
        failed_row
            .error
            .as_deref()
            .is_some_and(|msg| msg.contains("escapes the source tree"))
    );

    // Persisting and transitioning `bad-pkg` to `Error` satisfies all §11.3 invariants.
    let pkg_id = output.nodes[0].id.clone();
    output.persist(&store).await.unwrap();
    store
        .update_status(&pkg_id, AnalysisStatus::Started)
        .await
        .unwrap();
    store
        .update_status(&pkg_id, AnalysisStatus::Error)
        .await
        .unwrap();
    assert!(store.check().await.unwrap().is_ok());
}

#[tokio::test]
async fn acquire_dependency_fetches_registry_crate_with_mandatory_checksum_and_auth() {
    let server = MockServer::start().await;
    let (crate_bytes, cksum) = build_crate_archive(
        "tinydep",
        "0.3.1",
        "[package]\nname = \"tinydep\"\nversion = \"0.3.1\"\nedition = \"2021\"\n",
        "pub fn answer() -> u32 { 42 }\n",
    );

    let tmp = tempfile::tempdir().unwrap();
    let token = "secret-registry-token-wp22";
    let token_path = tmp.path().join("wp22.token");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token_path)
            .unwrap();
        writeln!(f, "{token}").unwrap();
    }
    let reg = RegistrySpec::named_with_policy(
        "wp22priv",
        &format!("sparse+{}", server.uri()),
        CredentialSource::File { path: token_path },
        IndexUrlPolicy::InsecureHttpWithCredentialsForTests,
    )
    .unwrap();

    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dl": format!("{}/dl", server.uri()),
            "auth-required": true
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ti/ny/tinydep"))
        .and(header("authorization", token))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"name":"tinydep","vers":"0.3.1","deps":[],"cksum":"{cksum}","features":{{}},"yanked":false}}"#
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/dl/tinydep/0.3.1/download"))
        .and(header("authorization", token))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(crate_bytes))
        .mount(&server)
        .await;

    let cache = Cache::new(tmp.path().join("cache"));
    let options = FetchOptions::default();

    // 1. Missing checksum is rejected immediately (checksum mandatory!).
    let unpinned = PackageId {
        name: "tinydep".into(),
        version: PackageVersion::SemVer(semver::Version::new(0, 3, 1)),
        source_id: SourceId {
            kind: SourceKind::CargoRegistry {
                index_url: reg.index_url.clone(),
            },
            precise: None,
        },
        ecosystem: Ecosystem::Rust,
    };
    assert!(
        acquire_dependency(
            &unpinned,
            &cache,
            &options,
            std::slice::from_ref(&reg),
            false
        )
        .await
        .is_err()
    );

    // 2. Wrong checksum is rejected.
    let mut wrong = unpinned.clone();
    wrong.source_id.precise = Some("0".repeat(64));
    assert!(
        acquire_dependency(&wrong, &cache, &options, std::slice::from_ref(&reg), false)
            .await
            .is_err()
    );

    // 3. Default policy rejects plain `http://127.0.0.1` loopback; explicit
    //    test policy succeeds, extracts into cache, and serves offline afterward.
    let mut pinned = unpinned;
    pinned.source_id.precise = Some(cksum.clone());
    assert!(
        acquire_dependency(&pinned, &cache, &options, std::slice::from_ref(&reg), false)
            .await
            .is_err(),
        "default DependencyFetchPolicy must reject plain HTTP / loopback"
    );
    let test_policy = DependencyFetchPolicy::allow_local_for_tests();
    let resolved = acquire_dependency_with_policy(
        &pinned,
        &cache,
        &options,
        std::slice::from_ref(&reg),
        false,
        &test_policy,
    )
    .await
    .unwrap();
    assert_eq!(resolved.fetched.digest, cksum);
    assert!(resolved.package_subdir.as_os_str().is_empty());
    assert!(resolved.fetched.tree.join("src/lib.rs").is_file());

    let offline_hit =
        acquire_dependency(&pinned, &cache, &options, std::slice::from_ref(&reg), true)
            .await
            .unwrap();
    assert_eq!(offline_hit.fetched.tree, resolved.fetched.tree);
}

#[tokio::test]
async fn acquire_dependency_fetches_git_workspace_at_locked_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_dir = tmp.path().join("upstream-repo");
    std::fs::create_dir_all(&repo_dir).unwrap();

    let run_git = |args: &[&str]| -> String {
        // Spec §16: clear inherited `GIT_*` variables so pre-commit hooks cannot
        // redirect fixture git commands into the outer repository.
        let out = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args([
                "-c",
                "init.defaultBranch=main",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(&repo_dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", tmp.path())
            .output()
            .expect("invoke git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    run_git(&["init"]);
    write_file(
        &repo_dir,
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/sub\"]\n[workspace.package]\nversion = \"0.1.0\"\n",
    );
    write_file(
        &repo_dir,
        "crates/sub/Cargo.toml",
        "[package]\nname = \"sub\"\nversion.workspace = true\nedition = \"2021\"\n",
    );
    write_file(&repo_dir, "crates/sub/src/lib.rs", "pub const V: u8 = 1;\n");
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "v0.1.0"]);
    let commit_v1 = run_git(&["rev-parse", "HEAD"]);

    // Second commit bumps version to 0.2.0; locked `commit_v1` must still yield 0.1.0!
    write_file(
        &repo_dir,
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/sub\"]\n[workspace.package]\nversion = \"0.2.0\"\n",
    );
    write_file(&repo_dir, "crates/sub/src/lib.rs", "pub const V: u8 = 2;\n");
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "v0.2.0"]);

    let repo_url = url::Url::from_directory_path(&repo_dir).unwrap();
    let cache = Cache::new(tmp.path().join("cache"));
    let options = FetchOptions::default();

    let git_pkg = PackageId {
        name: "sub".into(),
        version: PackageVersion::SemVer(semver::Version::new(0, 1, 0)),
        source_id: SourceId {
            kind: SourceKind::Git {
                url: repo_url.clone(),
                reference: GitReference::Branch("main".into()),
            },
            precise: Some(commit_v1.clone()),
        },
        ecosystem: Ecosystem::Rust,
    };

    // Production policy rejects `file://` git URLs; explicit test policy
    // checks out the exact locked commit and locates `crates/sub`.
    assert!(
        acquire_dependency(&git_pkg, &cache, &options, &[], false)
            .await
            .is_err(),
        "default DependencyFetchPolicy must reject file:// git URLs"
    );
    let test_policy = DependencyFetchPolicy::allow_local_for_tests();
    let resolved =
        acquire_dependency_with_policy(&git_pkg, &cache, &options, &[], false, &test_policy)
            .await
            .unwrap();
    assert_eq!(resolved.fetched.digest, commit_v1);
    assert_eq!(resolved.package_subdir, Path::new("crates/sub"));
    let lib_contents = std::fs::read_to_string(
        resolved
            .fetched
            .tree
            .join(&resolved.package_subdir)
            .join("src/lib.rs"),
    )
    .unwrap();
    assert!(lib_contents.contains("V: u8 = 1"));

    // Short / missing commit hashes are rejected.
    let mut short = git_pkg;
    short.source_id.precise = Some(commit_v1[..12].to_string());
    assert!(
        acquire_dependency(&short, &cache, &options, &[], false)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn sandboxed_workspace_analysis_snapshot() {
    let test = "sandboxed_workspace_analysis_snapshot";
    let Some(sandbox) = bwrap_with_cargo(test).await else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("sandbox-ws");
    let ws = dir.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();

    // Deliberately omit `Cargo.lock` on the host so `SourceMount::Scratch` is
    // exercised inside bubblewrap without modifying `src` on the host.
    write_file(
        &src,
        "Cargo.toml",
        r#"[workspace]
members = ["crates/app", "crates/core-lib"]
resolver = "2"

[workspace.package]
version = "0.5.0"
"#,
    );
    write_file(
        &src,
        "crates/core-lib/Cargo.toml",
        r#"[package]
name = "core-lib"
version.workspace = true
edition = "2021"
links = "m"

[dependencies]
vend = { path = "../../vendor/vend", optional = true }

[features]
extra = ["dep:vend"]
"#,
    );
    write_file(&src, "crates/core-lib/src/lib.rs", "pub fn core() {}\n");
    write_file(
        &src,
        "crates/core-lib/build.rs",
        "fn main() { println!(\"cargo:rustc-link-lib=m\"); }\n",
    );

    write_file(
        &src,
        "crates/app/Cargo.toml",
        r#"[package]
name = "app"
version.workspace = true
edition = "2021"

[dependencies]
core-lib = { path = "../core-lib" }

[build-dependencies]
core-lib = { path = "../core-lib" }

[target.'cfg(unix)'.dev-dependencies]
core-lib = { path = "../core-lib" }
"#,
    );
    write_file(&src, "crates/app/src/main.rs", "fn main() {}\n");

    write_file(
        &src,
        "vendor/vend/Cargo.toml",
        "[package]\nname = \"vend\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write_file(&src, "vendor/vend/src/lib.rs", "");

    write_file(
        &src,
        "vendor/unused/Cargo.toml",
        "[package]\nname = \"unused\"\nversion = \"9.9.9\"\nedition = \"2021\"\n",
    );
    write_file(&src, "vendor/unused/src/lib.rs", "");

    let fetched = fetch_path(&src).await.unwrap();
    let db_path = dir.path().join("sandbox.db");
    let store = Store::open(&db_path).await.unwrap();

    let mut config = Configuration::default();
    config
        .features
        .insert("core-lib".into(), BTreeSet::from(["extra".into()]));

    let ctx = AnalysisContext {
        source: &fetched,
        root: Path::new(""),
        configuration: &config,
        registries: &[],
        network: &NetworkAccess::Allowlist(ProxyPolicy::default()),
        sandbox: Some(sandbox.as_ref()),
        store: &store,
        workspace: &ws,
        limits: AnalyzerLimits {
            tool_timeout: Duration::from_secs(120),
            ..AnalyzerLimits::default()
        },
    };

    let output = CargoAnalyzer.analyze(&ctx).await.unwrap();
    assert_eq!(output.network_mode, NetworkMode::Allowlist);
    assert!(
        output
            .toolchain
            .get("cargo")
            .is_some_and(|v| v.contains("cargo "))
    );
    assert!(
        output
            .toolchain
            .get("rustc")
            .is_some_and(|v| v.contains("rustc "))
    );

    // Scratch mount discarded any lockfile Cargo generated inside the sandbox.
    assert!(!src.join("Cargo.lock").exists());

    // Unreferenced vendored crate is absent; `vend` was pulled in via `--features core-lib/extra`.
    let node_names: BTreeSet<&str> = output.nodes.iter().map(|n| n.id.name.as_str()).collect();
    assert_eq!(node_names, BTreeSet::from(["app", "core-lib", "vend"]));

    // `tool_invocation` recorded `/usr/bin/cargo metadata --format-version 1`.
    store
        .write_metadata(&AnalysisMetadata {
            robigus_version: "0.1.0".into(),
            project_name: "sandbox-ws".into(),
            project_version: "0.5.0".into(),
            source_kind: "path".into(),
            source_uri: src.to_string_lossy().into_owned(),
            source_digest: fetched.digest.clone(),
            configuration: config.clone(),
            toolchain: output.toolchain.clone(),
            network_mode: output.network_mode.as_str().into(),
            sandbox_mode: "bwrap".into(),
            options: serde_json::json!({}),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        })
        .await
        .unwrap();
    output.persist(&store).await.unwrap();
    assert!(store.check().await.unwrap().is_ok());
    let snapshot = store.export_snapshot().await.unwrap();
    assert!(snapshot.invocations.iter().any(|inv| {
        inv.invocation.tool == "/usr/bin/cargo"
            && inv.invocation.argv.contains(&"metadata".to_string())
            && inv.invocation.exit_status == "exit:0"
    }));

    assert_analyzer_snapshot!("cargo_sandboxed_workspace", snapshot_value(&output, &src));
}

#[tokio::test]
async fn sandboxed_sparse_registry_resolution_through_proxy_and_expansion() {
    let test = "sandboxed_sparse_registry_resolution_through_proxy_and_expansion";
    let Some(sandbox) = bwrap_with_cargo(test).await else {
        return;
    };

    let server = MockServer::start().await;
    let port = server.address().port();
    let registry_host: HostName = "sparse.registry.test".parse().unwrap();
    let index_url_str = format!("sparse+http://sparse.registry.test:{port}/");

    let (crate_bytes, cksum) = build_crate_archive(
        "tinydep",
        "1.0.0",
        "[package]\nname = \"tinydep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        "pub fn greet() -> &'static str { \"hi\" }\n",
    );

    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dl": format!("http://sparse.registry.test:{port}/dl")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ti/ny/tinydep"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"name":"tinydep","vers":"1.0.0","deps":[],"cksum":"{cksum}","features":{{}},"yanked":false}}"#
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/dl/tinydep/1.0.0/download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(crate_bytes))
        .mount(&server)
        .await;

    let mut allowlist = Allowlist::empty();
    allowlist.allow(registry_host.clone());
    let policy = ProxyPolicy {
        allowlist,
        ports: [port].into(),
        header_timeout: Duration::from_secs(15),
        connect_timeout: Duration::from_secs(15),
        resolve: [(registry_host, vec!["127.0.0.1".parse().unwrap()])].into(),
        ..ProxyPolicy::default()
    };

    let reg_spec = RegistrySpec::named_with_policy(
        "testreg",
        &index_url_str,
        CredentialSource::None,
        IndexUrlPolicy::AllowInsecureHttp,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("consumer");
    let ws = dir.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();

    write_file(
        &src,
        ".cargo/config.toml",
        &format!("[registries.testreg]\nindex = \"{index_url_str}\"\n"),
    );
    write_file(
        &src,
        "Cargo.toml",
        r#"[package]
name = "consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
tinydep = { version = "1.0.0", registry = "testreg" }
"#,
    );
    write_file(&src, "src/lib.rs", "");
    write_file(
        &src,
        "Cargo.lock",
        &format!(
            r#"version = 4

[[package]]
name = "consumer"
version = "0.1.0"
dependencies = [
 "tinydep",
]

[[package]]
name = "tinydep"
version = "1.0.0"
source = "{index_url_str}"
checksum = "{cksum}"
"#
        ),
    );

    let fetched = fetch_path(&src).await.unwrap();
    let store = Store::open(&dir.path().join("reg.db")).await.unwrap();
    let config = Configuration::default();
    let ctx = AnalysisContext {
        source: &fetched,
        root: Path::new(""),
        configuration: &config,
        registries: std::slice::from_ref(&reg_spec),
        network: &NetworkAccess::Allowlist(policy),
        sandbox: Some(sandbox.as_ref()),
        store: &store,
        workspace: &ws,
        limits: AnalyzerLimits {
            tool_timeout: Duration::from_secs(120),
            ..AnalyzerLimits::default()
        },
    };

    let output = CargoAnalyzer.analyze(&ctx).await.unwrap();
    let edge = output
        .edges
        .iter()
        .find(|e| e.requirement.name == "tinydep")
        .expect("tinydep edge");
    assert_eq!(edge.confidence.tier(), ConfidenceTier::L4);
    let resolved_id = edge.to.as_ref().expect("tinydep must be resolved");
    assert_eq!(
        resolved_id.source_id.precise.as_deref(),
        Some(cksum.as_str())
    );
    assert_eq!(output.expansions.len(), 1);
    assert_eq!(&output.expansions[0].package, resolved_id);

    // Note: host-side `RegistryClient` resolves DNS normally, so point a
    // host-side mock `/config.json` at `127.0.0.1:<port>` to exercise
    // `acquire_dependency` on the exact checksummed `PackageId` logic.
    server.reset().await;
    let (crate_bytes_host, _) = build_crate_archive(
        "tinydep",
        "1.0.0",
        "[package]\nname = \"tinydep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        "pub fn greet() -> &'static str { \"hi\" }\n",
    );
    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dl": format!("{}/dl", server.uri())
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ti/ny/tinydep"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"name":"tinydep","vers":"1.0.0","deps":[],"cksum":"{cksum}","features":{{}},"yanked":false}}"#
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/dl/tinydep/1.0.0/download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(crate_bytes_host))
        .mount(&server)
        .await;
    let host_reg = RegistrySpec::direct_with_policy(
        &format!("sparse+{}", server.uri()),
        IndexUrlPolicy::AllowInsecureHttp,
    )
    .unwrap();
    let mut host_pkg = resolved_id.clone();
    host_pkg.source_id.kind = SourceKind::CargoRegistry {
        index_url: host_reg.index_url.clone(),
    };
    let cache = Cache::new(dir.path().join("cache"));
    let test_policy = DependencyFetchPolicy::allow_local_for_tests();
    let expanded = acquire_dependency_with_policy(
        &host_pkg,
        &cache,
        &FetchOptions::default(),
        std::slice::from_ref(&host_reg),
        false,
        &test_policy,
    )
    .await
    .unwrap();
    assert_eq!(expanded.fetched.digest, cksum);
    assert_eq!(expanded.fetched.source_id(), host_pkg.source_id);
}

#[tokio::test]
async fn sandboxed_authenticated_registry_keeps_tokens_out_of_sandbox() {
    let test = "sandboxed_authenticated_registry_keeps_tokens_out_of_sandbox";
    let Some(sandbox) = bwrap_with_cargo(test).await else {
        return;
    };

    // Start a real mock sparse registry returning 401 Unauthorized through the
    // sandbox proxy so Cargo genuinely fails with an authentication challenge.
    let server = MockServer::start().await;
    let port = server.address().port();
    let corp_host: HostName = "corp.registry.test".parse().unwrap();
    let corp_index = format!("sparse+http://corp.registry.test:{port}/");

    Mock::given(method("GET"))
        .and(path("/config.json"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            "Cargo login_url=\"https://corp.registry.test/me\"",
        ))
        .mount(&server)
        .await;

    let canary = "CANARY_SECRET_WP22_NEVER_IN_SANDBOX";
    let corp = RegistrySpec::named_with_policy(
        "corp",
        &corp_index,
        CredentialSource::Process {
            program: PathBuf::from("/bin/echo"),
            args: vec![format!(
                r#"{{"v":1,"Ok":{{"kind":"token","token":"{canary}","cache":"session"}}}}"#
            )],
        },
        IndexUrlPolicy::InsecureHttpWithCredentialsForTests,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("corp-consumer");
    let ws = dir.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();

    write_file(
        &src,
        ".cargo/config.toml",
        &format!("[registries.corp]\nindex = \"{corp_index}\"\n"),
    );
    write_file(
        &src,
        "Cargo.toml",
        r#"[package]
name = "corp-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
privcrate = { version = "^1.2", registry = "corp" }
"#,
    );
    write_file(&src, "src/lib.rs", "");

    let fetched = fetch_path(&src).await.unwrap();
    let store = Store::open(&dir.path().join("auth.db")).await.unwrap();
    let config = Configuration::default();
    let mut allowlist = Allowlist::empty();
    allowlist.allow(corp_host.clone());
    let policy = ProxyPolicy {
        allowlist,
        ports: [port].into(),
        header_timeout: Duration::from_secs(15),
        connect_timeout: Duration::from_secs(15),
        resolve: [(corp_host, vec!["127.0.0.1".parse().unwrap()])].into(),
        ..ProxyPolicy::default()
    };

    let ctx = AnalysisContext {
        source: &fetched,
        root: Path::new(""),
        configuration: &config,
        registries: std::slice::from_ref(&corp),
        network: &NetworkAccess::Allowlist(policy.clone()),
        sandbox: Some(sandbox.as_ref()),
        store: &store,
        workspace: &ws,
        limits: AnalyzerLimits {
            tool_timeout: Duration::from_secs(60),
            ..AnalyzerLimits::default()
        },
    };

    let output = CargoAnalyzer.analyze(&ctx).await.unwrap();
    let edge = output
        .edges
        .iter()
        .find(|e| e.requirement.name == "privcrate")
        .expect("privcrate edge");
    assert!(edge.to.is_none());
    assert!(edge.evidence.iter().any(|ev| {
        ev.detail
            .as_deref()
            .is_some_and(|d| d.contains("authenticated registry 'corp'"))
    }));
    // No plan row is `Failed`: genuine 401 auth challenges keep ToolIntrospection `Skipped`.
    assert!(output.plan.iter().all(|r| r.status != PlanStatus::Failed));

    // Confirm the mock server received NO `Authorization` header from the sandbox.
    for req in server.received_requests().await.unwrap() {
        assert!(
            req.headers.get("authorization").is_none(),
            "Authorization header must never be sent from inside the sandbox"
        );
    }

    // Regression: an unrelated `cargo metadata` failure in a workspace that
    // also declares a dependency on `corp` MUST NOT be masked as `Skipped`!
    let broken_src = dir.path().join("broken-corp");
    let broken_ws = dir.path().join("broken-work");
    std::fs::create_dir_all(&broken_ws).unwrap();
    write_file(
        &broken_src,
        ".cargo/config.toml",
        &format!("[registries.corp]\nindex = \"{corp_index}\"\n"),
    );
    write_file(
        &broken_src,
        "Cargo.toml",
        r#"[package]
name = "broken-corp"
version = "0.1.0"
edition = "2021"

[dependencies]
missing-local = { path = "nonexistent-subdir" }
privcrate = { version = "^1.2", registry = "corp", optional = true }
"#,
    );
    write_file(&broken_src, "src/lib.rs", "");
    let broken_fetched = fetch_path(&broken_src).await.unwrap();
    let broken_store = Store::open(&dir.path().join("broken.db")).await.unwrap();
    let broken_ctx = AnalysisContext {
        source: &broken_fetched,
        root: Path::new(""),
        configuration: &config,
        registries: std::slice::from_ref(&corp),
        network: &NetworkAccess::Allowlist(policy),
        sandbox: Some(sandbox.as_ref()),
        store: &broken_store,
        workspace: &broken_ws,
        limits: AnalyzerLimits {
            tool_timeout: Duration::from_secs(60),
            ..AnalyzerLimits::default()
        },
    };
    let broken_output = CargoAnalyzer.analyze(&broken_ctx).await.unwrap();
    assert!(
        broken_output
            .plan
            .iter()
            .any(|r| r.status == PlanStatus::Failed),
        "unrelated cargo metadata failure must be recorded as PlanStatus::Failed, got: {:?}",
        broken_output.plan
    );

    // Verify canary never leaked anywhere in serialized output, store, or logs.
    store
        .write_metadata(&AnalysisMetadata {
            robigus_version: "0.1.0".into(),
            project_name: "corp-consumer".into(),
            project_version: "0.1.0".into(),
            source_kind: "path".into(),
            source_uri: src.to_string_lossy().into_owned(),
            source_digest: fetched.digest.clone(),
            configuration: config.clone(),
            toolchain: output.toolchain.clone(),
            network_mode: output.network_mode.as_str().into(),
            sandbox_mode: "bwrap".into(),
            options: serde_json::json!({}),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        })
        .await
        .unwrap();
    output.persist(&store).await.unwrap();
    assert!(store.check().await.unwrap().is_ok());
    let serialized = serde_json::to_string(&output).unwrap();
    assert!(!serialized.contains(canary));
    let snapshot = store.export_snapshot().await.unwrap();
    let snap_json = serde_json::to_string(&snapshot).unwrap();
    assert!(!snap_json.contains(canary));
    for entry in walkdir::WalkDir::new(&ws).into_iter().flatten() {
        if entry.file_type().is_file() {
            let mut bytes = Vec::new();
            std::fs::File::open(entry.path())
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(canary),
                "token leaked into {}",
                entry.path().display()
            );
        }
    }
}

#[tokio::test]
async fn sandboxed_path_escape_marks_plan_failed() {
    let test = "sandboxed_path_escape_marks_plan_failed";
    let Some(sandbox) = bwrap_with_cargo(test).await else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("escape-sb");
    let ws = dir.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();

    write_file(
        &src,
        "Cargo.toml",
        r#"[package]
name = "escape-sb"
version = "0.1.0"
edition = "2021"

[dependencies]
outside = { path = "../../outside" }
"#,
    );
    write_file(&src, "src/lib.rs", "");

    let fetched = fetch_path(&src).await.unwrap();
    let store = Store::open(&dir.path().join("esc.db")).await.unwrap();
    let config = Configuration::default();
    let ctx = AnalysisContext {
        source: &fetched,
        root: Path::new(""),
        configuration: &config,
        registries: &[],
        network: &NetworkAccess::Allowlist(ProxyPolicy::default()),
        sandbox: Some(sandbox.as_ref()),
        store: &store,
        workspace: &ws,
        limits: AnalyzerLimits {
            tool_timeout: Duration::from_secs(30),
            ..AnalyzerLimits::default()
        },
    };

    let output = CargoAnalyzer.analyze(&ctx).await.unwrap();
    assert!(output.plan.iter().any(|r| {
        r.status == PlanStatus::Failed
            && r.error
                .as_deref()
                .is_some_and(|e| e.contains("escapes the source tree"))
    }));
}

/// Live crates.io smoke test behind `ROB_NETWORK_TESTS=1`.
#[tokio::test]
async fn live_sandboxed_crates_io_analysis() {
    let test = "live_sandboxed_crates_io_analysis";
    if std::env::var_os("ROB_NETWORK_TESTS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED {test}: set ROB_NETWORK_TESTS=1 to run tests requiring internet access"
        );
        return;
    }
    let Some(sandbox) = bwrap_with_cargo(test).await else {
        return;
    };

    let cksum = "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b";
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("live-smoke");
    let ws = dir.path().join("work");
    std::fs::create_dir_all(&ws).unwrap();

    write_file(
        &src,
        "Cargo.toml",
        "[package]\nname = \"live-smoke\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\nitoa = \"=1.0.11\"\n",
    );
    write_file(&src, "src/lib.rs", "");
    write_file(
        &src,
        "Cargo.lock",
        &format!(
            "version = 4\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.11\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{cksum}\"\n\n\
             [[package]]\nname = \"live-smoke\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"itoa\",\n]\n"
        ),
    );

    let fetched = fetch_path(&src).await.unwrap();
    let store = Store::open(&dir.path().join("live.db")).await.unwrap();
    let config = Configuration::default();
    let ctx = AnalysisContext {
        source: &fetched,
        root: Path::new(""),
        configuration: &config,
        registries: &[],
        network: &NetworkAccess::Allowlist(ProxyPolicy::default()),
        sandbox: Some(sandbox.as_ref()),
        store: &store,
        workspace: &ws,
        limits: AnalyzerLimits {
            tool_timeout: Duration::from_secs(180),
            ..AnalyzerLimits::default()
        },
    };

    let output = CargoAnalyzer.analyze(&ctx).await.unwrap();
    let itoa_edge = output
        .edges
        .iter()
        .find(|e| e.requirement.name == "itoa")
        .expect("itoa edge");
    let itoa_id = itoa_edge.to.as_ref().expect("itoa resolved");
    assert_eq!(
        itoa_id.source_id.kind.identity_uri(),
        "https://index.crates.io/"
    );
    assert_eq!(itoa_id.source_id.precise.as_deref(), Some(cksum));
    assert_eq!(itoa_edge.confidence.tier(), ConfidenceTier::L4);
}
