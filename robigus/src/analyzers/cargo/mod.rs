//! Rust/Cargo project analyzer (spec §8.1; WP-2.2).
//!
//! Primary path: runs `/usr/bin/cargo metadata --format-version 1` unfiltered
//! inside the established sandbox (`SourceMount::Scratch`, writable
//! `CARGO_HOME` tmpfs, allowlisted network proxy), cross-checks resolved
//! packages against `Cargo.lock` and the parsed in-tree manifests, and scans
//! `build.rs` scripts for native C/C++/system requirements.
//!
//! Offline fallback (`NetworkAccess::Offline`): parses workspace and member
//! `Cargo.toml` manifests with `toml_edit`, producing declared-but-unresolved
//! crate edges (`to = None`) at tier L3 with `network_mode = "offline"`.

mod build_script;
mod cfg;
mod lockfile;
mod manifest;
mod metadata;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use url::Url;

pub use build_script::{BuildScriptFinding, scan_build_script};

use self::lockfile::{CargoLock, normalize_sha256};
use self::manifest::{
    WorkspaceManifests, build_offline_output, is_contained_regular_file, read_contained_utf8,
    resolve_contained_path,
};
use self::metadata::map_cargo_metadata;
use crate::analyzers::{
    AnalysisContext, AnalyzerDiagnostic, AnalyzerLimits, AnalyzerOutput, NetworkMode,
};
use crate::credentials::{CredentialSource, bounded};
use crate::error::{AnalyzerError, FetchError, RobigusError};
use crate::fetch::{
    Cache, FetchOptions, FetchedSource, RegistrySource, SourceInput, fetch, fetch_offline,
    fetch_path,
};
use crate::model::{
    AnalysisStrategy, AnalyzerId, Ecosystem, GitReference, PackageId, PackageVersion, PlanStatus,
    PlanSubject, SourceKind,
};
use crate::registry::{CRATES_IO_INDEX, RegistrySpec};
use crate::sandbox::proxy::{Allowlist, HostName, is_public};
use crate::sandbox::{CommandSpec, NetworkAccess, ProcessStatus, Sandbox, SourceMount};

const CARGO_BIN: &str = "/usr/bin/cargo";
const RUSTC_BIN: &str = "/usr/bin/rustc";
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const STDERR_EXCERPT_LIMIT: u64 = 4_096;

/// Result of acquiring a resolved Cargo dependency's source tree for expansion
/// (spec §8.1; WP-2.2).
#[derive(Debug, Clone)]
pub struct ResolvedDependencySource {
    /// Acquired and verified source in the cache (or local path).
    pub fetched: FetchedSource,
    /// Subdirectory of the package inside `fetched.tree` (empty when the
    /// package is at the top level, such as every `.crate` archive).
    pub package_subdir: PathBuf,
}

/// Host-side destination policy enforced when acquiring dependencies
/// discovered inside an untrusted project (`Cargo.toml` / `Cargo.lock`).
///
/// Unlike the root [`SourceInput`] chosen by the caller, dependency URLs are
/// controlled by the analyzed project. By default only `https` URLs on the
/// default port whose literal DNS [`HostName`] is permitted by [`Allowlist`]
/// (or matches an operator-supplied [`RegistrySpec`]) and resolves exclusively
/// to public unicast addresses may be fetched; `file://`, `ssh://`, `http://`,
/// credential-bearing URLs, IP literals, and private/loopback targets are
/// refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyFetchPolicy {
    /// Host allowlist applied to project-specified dependency URLs.
    pub allowlist: Allowlist,
    allow_local_for_tests: bool,
}

impl DependencyFetchPolicy {
    /// Policy using a custom host [`Allowlist`].
    pub fn with_allowlist(allowlist: Allowlist) -> Self {
        Self {
            allowlist,
            allow_local_for_tests: false,
        }
    }

    /// Tests only: permits loopback `http://` mock servers and temporary
    /// `file://` git fixture repositories. Credentials in URLs remain
    /// forbidden.
    #[doc(hidden)]
    pub fn allow_local_for_tests() -> Self {
        Self {
            allowlist: Allowlist::default(),
            allow_local_for_tests: true,
        }
    }
}

/// Validates and resolves a Cargo `path = "…"` dependency `dep_path` (written
/// in a manifest at `parent_subdir`) against `source_tree_root`, enforcing the
/// §8.1 containment rule.
///
/// Rejects absolute paths, `..` traversal escaping `source_tree_root`, and
/// symlinks resolving outside `source_tree_root` (including `symlink/..`).
/// Returns the clean tree-relative directory of the dependency.
pub fn resolve_path_dependency(
    source_tree_root: &Path,
    parent_subdir: &Path,
    dep_path: &Path,
) -> Result<PathBuf, AnalyzerError> {
    let canonical_root = std::fs::canonicalize(source_tree_root).map_err(|error| {
        AnalyzerError::Project(format!("cannot canonicalize source tree root: {error}"))
    })?;
    resolve_contained_path(&canonical_root, parent_subdir, dep_path).map_err(AnalyzerError::Project)
}

/// Acquires the source tree of a resolved Cargo dependency node using the
/// default [`DependencyFetchPolicy`] (spec §8.1; WP-2.2):
///
/// - **Registry crates**: `https` only, host-validated, fetched via the WP-2.6
///   registry client with a **mandatory** SHA-256 `.crate` checksum
///   (`SourceId.precise`).
/// - **Git crates**: `https` only, host-validated, cloned/checked out via
///   `gix` (in `spawn_blocking`) at the exact locked commit
///   (`SourceId.precise`), with submodules restricted to `https`, then
///   searched for the package's manifest directory inside the checkout.
/// - **Path crates**: verified in place via [`fetch_path`], requiring
///   `SourceId.precise` to match the freshly computed tree digest.
pub async fn acquire_dependency(
    package: &PackageId,
    cache: &Cache,
    options: &FetchOptions,
    registries: &[RegistrySpec],
    offline: bool,
) -> Result<ResolvedDependencySource, RobigusError> {
    acquire_dependency_with_policy(
        package,
        cache,
        options,
        registries,
        offline,
        &DependencyFetchPolicy::default(),
    )
    .await
}

/// Like [`acquire_dependency`], applying an explicit [`DependencyFetchPolicy`].
pub async fn acquire_dependency_with_policy(
    package: &PackageId,
    cache: &Cache,
    options: &FetchOptions,
    registries: &[RegistrySpec],
    offline: bool,
    policy: &DependencyFetchPolicy,
) -> Result<ResolvedDependencySource, RobigusError> {
    if package.ecosystem != Ecosystem::Rust {
        return Err(AnalyzerError::Project(format!(
            "package '{package}' is not a Rust/Cargo package"
        ))
        .into());
    }
    let PackageVersion::SemVer(expected_version) = &package.version else {
        return Err(AnalyzerError::Project(format!(
            "Rust package '{package}' does not carry a SemVer version"
        ))
        .into());
    };

    match &package.source_id.kind {
        SourceKind::CargoRegistry { index_url } => {
            let Some(raw_cksum) = package.source_id.precise.as_deref() else {
                return Err(FetchError::Registry(format!(
                    "registry dependency '{} {}' has no mandatory checksum pin",
                    package.name, expected_version
                ))
                .into());
            };
            let Some(checksum) = normalize_sha256(raw_cksum) else {
                return Err(FetchError::InvalidDigest(raw_cksum.to_string()).into());
            };
            if !offline {
                validate_dependency_url(index_url, registries, policy, "registry").await?;
            } else {
                reject_url_credentials(index_url, "registry")?;
            }

            let registry = registries
                .iter()
                .find(|spec| &spec.index_url == index_url)
                .cloned()
                .unwrap_or_else(|| {
                    if index_url.as_str() == CRATES_IO_INDEX {
                        RegistrySpec::crates_io()
                    } else {
                        RegistrySpec::new(index_url.clone(), None, CredentialSource::None)
                    }
                });
            let input = SourceInput::Registry(RegistrySource {
                registry,
                name: package.name.clone(),
                version: expected_version.clone(),
                digest: Some(checksum.clone()),
                allow_yanked: true,
            });
            let fetched = if offline {
                fetch_offline(input, cache).await?
            } else {
                fetch(input, cache, options).await?
            };
            if fetched.digest != checksum {
                return Err(FetchError::Checksum {
                    expected: checksum,
                    actual: fetched.digest,
                }
                .into());
            }
            Ok(ResolvedDependencySource {
                fetched,
                package_subdir: PathBuf::new(),
            })
        }
        SourceKind::Git { url, .. } => {
            let Some(commit) = package.source_id.precise.as_deref() else {
                return Err(FetchError::Git(format!(
                    "git dependency '{} {}' has no locked commit revision",
                    package.name, expected_version
                ))
                .into());
            };
            let normalized_commit = commit.trim().to_ascii_lowercase();
            let valid_commit = matches!(normalized_commit.len(), 40 | 64)
                && normalized_commit.chars().all(|c| c.is_ascii_hexdigit());
            if !valid_commit {
                return Err(FetchError::Git(format!(
                    "git dependency '{} {}' has invalid commit revision '{}'",
                    package.name,
                    expected_version,
                    bounded(commit)
                ))
                .into());
            }
            if !offline {
                validate_dependency_url(url, registries, policy, "git").await?;
            } else {
                reject_url_credentials(url, "git")?;
            }

            let input = SourceInput::Git {
                url: url.clone(),
                reference: GitReference::Rev(normalized_commit.clone()),
            };
            let fetched = if offline {
                fetch_offline(input, cache).await?
            } else {
                let mut hardened_options = options.clone();
                if !policy.allow_local_for_tests {
                    hardened_options
                        .git
                        .submodule_schemes
                        .retain(|s| s == "https");
                }
                fetch(input, cache, &hardened_options).await?
            };
            if !fetched.digest.eq_ignore_ascii_case(&normalized_commit) {
                return Err(FetchError::Checksum {
                    expected: normalized_commit,
                    actual: fetched.digest,
                }
                .into());
            }

            let tree = fetched.tree.clone();
            let target_name = package.name.clone();
            let target_ver = expected_version.clone();
            let subdir = tokio::task::spawn_blocking(move || {
                locate_package_in_checkout(&tree, &target_name, &target_ver)
            })
            .await
            .map_err(|error| AnalyzerError::Task(error.to_string()))??;
            Ok(ResolvedDependencySource {
                fetched,
                package_subdir: subdir,
            })
        }
        SourceKind::Path { path } => {
            let Some(raw_expected) = package.source_id.precise.as_deref() else {
                return Err(FetchError::OfflineCacheMiss(format!(
                    "path dependency '{} {}' has no pinned tree digest",
                    package.name, expected_version
                ))
                .into());
            };
            let Some(expected_digest) = normalize_sha256(raw_expected) else {
                return Err(FetchError::InvalidDigest(raw_expected.to_string()).into());
            };
            let fetched = fetch_path(path).await?;
            if fetched.digest != expected_digest {
                return Err(FetchError::Checksum {
                    expected: expected_digest,
                    actual: fetched.digest,
                }
                .into());
            }
            let tree = fetched.tree.clone();
            let target_name = package.name.clone();
            let target_ver = expected_version.clone();
            let subdir = tokio::task::spawn_blocking(move || {
                locate_package_in_checkout(&tree, &target_name, &target_ver)
            })
            .await
            .map_err(|error| AnalyzerError::Task(error.to_string()))??;
            Ok(ResolvedDependencySource {
                fetched,
                package_subdir: subdir,
            })
        }
        other => Err(AnalyzerError::Project(format!(
            "unsupported Cargo dependency source kind '{}'",
            other.kind_name()
        ))
        .into()),
    }
}

fn reject_url_credentials(url: &Url, kind_label: &str) -> Result<(), FetchError> {
    if !url.username().is_empty() || url.password().is_some() {
        let mut scrubbed = url.clone();
        let _ = scrubbed.set_username("");
        let _ = scrubbed.set_password(None);
        scrubbed.set_query(None);
        scrubbed.set_fragment(None);
        let msg = format!(
            "{kind_label} dependency URL '{}' must not embed credentials",
            bounded(scrubbed.as_str())
        );
        return Err(if kind_label == "git" {
            FetchError::Git(msg)
        } else {
            FetchError::InvalidRegistry(msg)
        });
    }
    Ok(())
}

async fn validate_dependency_url(
    url: &Url,
    registries: &[RegistrySpec],
    policy: &DependencyFetchPolicy,
    kind_label: &str,
) -> Result<(), FetchError> {
    reject_url_credentials(url, kind_label)?;
    let make_err = |reason: String| {
        if kind_label == "git" {
            FetchError::Git(reason)
        } else {
            FetchError::Registry(reason)
        }
    };

    if policy.allow_local_for_tests {
        return match url.scheme() {
            "https" | "http" | "file" => Ok(()),
            other => Err(make_err(format!(
                "{kind_label} dependency URL scheme '{other}' is not allowed"
            ))),
        };
    }

    if url.scheme() != "https" {
        return Err(make_err(format!(
            "{kind_label} dependency URL scheme '{}' is not allowed; only https is permitted",
            url.scheme()
        )));
    }
    if url.port().is_some() {
        return Err(make_err(format!(
            "{kind_label} dependency URL '{}' must use the default https port",
            bounded(url.as_str())
        )));
    }
    let Some(host_str) = url.host_str() else {
        return Err(make_err(format!("{kind_label} dependency URL has no host")));
    };
    let host_name: HostName = host_str
        .parse()
        .map_err(|error| make_err(format!("{kind_label} dependency host is invalid: {error}")))?;

    let configured_registry_host = registries
        .iter()
        .any(|spec| spec.index_url.host_str() == Some(host_str));
    if !configured_registry_host && !policy.allowlist.permits(&host_name) {
        return Err(make_err(format!(
            "{kind_label} dependency host '{host_str}' is not permitted by the network allowlist"
        )));
    }

    let resolved_addrs: Vec<_> = tokio::net::lookup_host((host_str, 443))
        .await
        .map_err(|error| {
            make_err(format!(
                "cannot resolve {kind_label} dependency host '{host_str}': {error}"
            ))
        })?
        .collect();
    if resolved_addrs.is_empty() {
        return Err(make_err(format!(
            "{kind_label} dependency host '{host_str}' resolved to no addresses"
        )));
    }
    if let Some(non_public) = resolved_addrs.iter().find(|addr| !is_public(addr.ip())) {
        return Err(make_err(format!(
            "refusing {kind_label} dependency host '{host_str}': resolved to non-public address {}",
            non_public.ip()
        )));
    }
    Ok(())
}

/// Runs the Rust/Cargo analyzer on `ctx` (spec §8.1).
pub async fn analyze(ctx: &AnalysisContext<'_>) -> Result<AnalyzerOutput, AnalyzerError> {
    let source_tree = ctx.source.tree.clone();
    let source_id = ctx.source.source_id();
    let root_rel = ctx.root.to_path_buf();
    let limits = ctx.limits;
    let registries_vec: Vec<RegistrySpec> = ctx.registries.to_vec();

    let (manifests, lockfile) = tokio::task::spawn_blocking(move || {
        let mut manifests = WorkspaceManifests::load(&source_tree, &source_id, &root_rel, &limits)?;
        let lockfile = if let Some(lock_rel) = &manifests.lockfile_rel {
            match read_contained_utf8(
                &manifests.canonical_tree_root,
                Path::new(""),
                lock_rel,
                limits.max_file_bytes,
            )
            .and_then(|text| CargoLock::parse(&text, lock_rel.clone(), &registries_vec))
            {
                Ok(parsed) => Some(parsed),
                Err(problem) => {
                    manifests.diagnostics.push(AnalyzerDiagnostic {
                        path: lock_rel.clone(),
                        message: format!("Cargo.lock ignored: {problem}"),
                    });
                    None
                }
            }
        } else {
            None
        };
        Ok::<_, AnalyzerError>((manifests, lockfile))
    })
    .await
    .map_err(|error| AnalyzerError::Task(error.to_string()))??;

    if matches!(ctx.network, NetworkAccess::Offline) {
        return Ok(build_offline_output(
            ctx,
            &manifests,
            "offline mode (--offline): cargo metadata skipped",
            NetworkMode::Offline,
        ));
    }

    let Some(sandbox) = ctx.sandbox else {
        return Err(AnalyzerError::SandboxRequired);
    };

    let toolchain = probe_toolchain(sandbox, ctx).await?;

    // Attribute the invocation to the sole root package only when it is already
    // persisted in `ctx.store` (spec §22.23).
    let attributed_pkg = single_stored_root(&manifests, ctx).await?;

    let mut args = vec![
        "metadata".to_string(),
        "--format-version".to_string(),
        "1".to_string(),
    ];
    let feature_args = configured_feature_args(&manifests, ctx);
    if !feature_args.is_empty() {
        args.push("--features".to_string());
        args.push(feature_args.join(","));
    }

    let spec = CommandSpec {
        program: PathBuf::from(CARGO_BIN),
        args,
        source: ctx.source.tree.clone(),
        source_mount: SourceMount::Scratch,
        source_subdir: manifests.cargo_root_rel.clone(),
        env: BTreeMap::new(),
        timeout: ctx.limits.tool_timeout,
        network: ctx.network.clone(),
        workspace: ctx.workspace.to_path_buf(),
        log_dir: PathBuf::from("cargo"),
        store: ctx.store.clone(),
        package_id: attributed_pkg,
        tool_version: toolchain.get("cargo").cloned(),
    };

    let run_output = sandbox.run(&spec).await?;

    match run_output.status {
        ProcessStatus::Exited(0) => {
            let stdout_bytes =
                read_output_capped(&run_output.stdout_path, ctx.limits.max_tool_output).await?;
            let registries_for_map: Vec<RegistrySpec> = ctx.registries.to_vec();
            let in_tree_sid = ctx.source.source_id();
            let limits = ctx.limits;
            let mut output = tokio::task::spawn_blocking(move || {
                let stdout_str = String::from_utf8(stdout_bytes).map_err(|error| {
                    AnalyzerError::ToolOutput(format!(
                        "cargo metadata stdout is not valid UTF-8: {error}"
                    ))
                })?;
                let parsed: cargo_metadata::Metadata =
                    serde_json::from_str(&stdout_str).map_err(|error| {
                        AnalyzerError::ToolOutput(format!("invalid cargo metadata JSON: {error}"))
                    })?;
                map_cargo_metadata(
                    &parsed,
                    Path::new("/source"),
                    &in_tree_sid,
                    &manifests,
                    lockfile.as_ref(),
                    &registries_for_map,
                    &limits,
                )
            })
            .await
            .map_err(|error| AnalyzerError::Task(error.to_string()))??;
            output.toolchain = toolchain;
            Ok(output)
        }
        other_status => {
            let stderr_excerpt = read_stderr_excerpt(&run_output.stderr_path).await;
            let blocked_auth_regs = matching_authenticated_registry_failures(
                other_status,
                &stderr_excerpt,
                &manifests,
                ctx.registries,
            );
            if !blocked_auth_regs.is_empty() {
                let detail = format!(
                    "cargo metadata could not authenticate to registry {} inside the sandbox \
                     (tokens never enter the sandbox in Phase 1): {stderr_excerpt}",
                    blocked_auth_regs.join(", ")
                );
                let mut output =
                    build_offline_output(ctx, &manifests, &detail, NetworkMode::Allowlist);
                output.toolchain = toolchain;
                return Ok(output);
            }

            let status_desc = match other_status {
                ProcessStatus::Exited(code) => format!("exited with status {code}"),
                ProcessStatus::Signaled => "terminated by signal".to_string(),
                ProcessStatus::TimedOut => {
                    format!("timed out after {}s", ctx.limits.tool_timeout.as_secs())
                }
            };
            let failure_msg = if stderr_excerpt.is_empty() {
                format!("cargo metadata {status_desc}")
            } else {
                format!("cargo metadata {status_desc}: {stderr_excerpt}")
            };

            let mut output =
                build_offline_output(ctx, &manifests, &failure_msg, NetworkMode::Allowlist);
            // Upgrade `ToolIntrospection` rows from `Skipped` to `Failed` with the
            // recorded failure cause so expansion marks affected nodes `Error`.
            for row in &mut output.plan {
                if row.analyzer == AnalyzerId::Cargo
                    && row.strategy == AnalysisStrategy::ToolIntrospection
                {
                    row.status = PlanStatus::Failed;
                    row.attempts = 1;
                    row.error = Some(failure_msg.clone());
                }
            }
            output
                .plan
                .retain(|r| !matches!(r.subject, PlanSubject::Root(_)));
            output.toolchain = toolchain;
            output.normalize();
            Ok(output)
        }
    }
}

/// Classifies a `cargo metadata` failure as Phase 1's in-sandbox authentication
/// limitation **only** when:
/// 1. the process exited normally with a nonzero code (never on a timeout or
///    signal),
/// 2. no in-tree manifest had a validation/containment failure, and
/// 3. Cargo's stderr specifically evidences an authentication challenge or a
///    missing Cargo registry definition for one of the workspace's referenced
///    credentialed registries.
fn matching_authenticated_registry_failures(
    status: ProcessStatus,
    stderr_excerpt: &str,
    manifests: &WorkspaceManifests,
    registries: &[RegistrySpec],
) -> Vec<String> {
    let ProcessStatus::Exited(code) = status else {
        return Vec::new();
    };
    if code == 0
        || manifests
            .packages
            .values()
            .any(|p| !p.node_errors.is_empty())
    {
        return Vec::new();
    }
    let auth_regs = manifests.referenced_authenticated_registries(registries);
    if auth_regs.is_empty() {
        return Vec::new();
    }

    let lower = stderr_excerpt.to_ascii_lowercase();
    const AUTH_MARKERS: [&str; 10] = [
        "status 401",
        "status 403",
        "401 unauthorized",
        "403 forbidden",
        "no token found",
        "cargo login",
        "auth-required",
        "authentication",
        "credential",
        "was not found in any configuration file",
    ];
    if !AUTH_MARKERS.iter().any(|marker| lower.contains(marker)) {
        return Vec::new();
    }

    auth_regs
        .into_iter()
        .filter(|(name, spec)| {
            let name_lower = name.to_ascii_lowercase();
            let url_lower = spec.index_url.as_str().to_ascii_lowercase();
            let host_lower = spec
                .index_url
                .host_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            lower.contains(&name_lower)
                || lower.contains(&url_lower)
                || (!host_lower.is_empty() && lower.contains(&host_lower))
        })
        .map(|(name, _)| name)
        .collect()
}

async fn probe_toolchain(
    sandbox: &dyn Sandbox,
    ctx: &AnalysisContext<'_>,
) -> Result<BTreeMap<String, String>, AnalyzerError> {
    let mut toolchain = BTreeMap::new();
    let probe_timeout = ctx.limits.tool_timeout.min(VERSION_PROBE_TIMEOUT);

    for (key, bin) in [("cargo", CARGO_BIN), ("rustc", RUSTC_BIN)] {
        let spec = CommandSpec {
            program: PathBuf::from(bin),
            args: vec!["--version".to_string()],
            source: ctx.source.tree.clone(),
            source_mount: SourceMount::ReadOnly,
            source_subdir: PathBuf::new(),
            env: BTreeMap::new(),
            timeout: probe_timeout,
            network: NetworkAccess::Offline,
            workspace: ctx.workspace.to_path_buf(),
            log_dir: PathBuf::from("toolchain"),
            store: ctx.store.clone(),
            package_id: None,
            tool_version: None,
        };
        let out = sandbox.run(&spec).await?;
        match out.status {
            ProcessStatus::Exited(0) => {
                let bytes = read_output_capped(&out.stdout_path, 4_096).await?;
                let version_line = String::from_utf8_lossy(&bytes)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if !version_line.is_empty() {
                    toolchain.insert(key.to_string(), version_line);
                }
            }
            status => {
                let stderr = read_stderr_excerpt(&out.stderr_path).await;
                return Err(AnalyzerError::Toolchain(format!(
                    "{bin} --version failed ({status:?}){}",
                    if stderr.is_empty() {
                        String::new()
                    } else {
                        format!(": {stderr}")
                    }
                )));
            }
        }
    }

    Ok(toolchain)
}

async fn single_stored_root(
    manifests: &WorkspaceManifests,
    ctx: &AnalysisContext<'_>,
) -> Result<Option<PackageId>, AnalyzerError> {
    let mut members = manifests
        .packages
        .values()
        .filter(|pkg| pkg.is_workspace_member);
    let (Some(only), None) = (members.next(), members.next()) else {
        return Ok(None);
    };
    match ctx.store.contains_package(&only.id).await {
        Ok(true) => Ok(Some(only.id.clone())),
        Ok(false) => Ok(None),
        Err(error) => Err(crate::sandbox::SandboxError::Store(error).into()),
    }
}

fn configured_feature_args(
    manifests: &WorkspaceManifests,
    ctx: &AnalysisContext<'_>,
) -> Vec<String> {
    let members: Vec<_> = manifests
        .packages
        .values()
        .filter(|p| p.is_workspace_member)
        .collect();
    let single_root_pkg = members.len() == 1 && members[0].rel_dir == manifests.cargo_root_rel;

    let mut args = BTreeSet::new();
    for pkg in members {
        let Some(requested) = ctx.configuration.features.get(&pkg.id.name) else {
            continue;
        };
        let optional_aliases: BTreeSet<String> = pkg
            .declarations
            .iter()
            .filter(|d| d.optional)
            .map(|d| d.alias.clone())
            .collect();
        let (feature_model, _) =
            self::cfg::PackageFeatures::from_raw(&pkg.raw_features, &optional_aliases);
        for feat in requested {
            if feature_model.contains(feat) {
                if single_root_pkg {
                    args.insert(feat.clone());
                } else {
                    args.insert(format!("{}/{feat}", pkg.id.name));
                }
            }
        }
    }
    args.into_iter().collect()
}

async fn read_output_capped(path: &Path, max_bytes: u64) -> Result<Vec<u8>, AnalyzerError> {
    let file = tokio::fs::File::open(path).await.map_err(|error| {
        AnalyzerError::ToolOutput(format!(
            "cannot open tool output '{}': {error}",
            path.display()
        ))
    })?;
    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .await
        .map_err(|error| {
            AnalyzerError::ToolOutput(format!(
                "cannot read tool output '{}': {error}",
                path.display()
            ))
        })?;
    if buf.len() as u64 > max_bytes {
        return Err(AnalyzerError::ToolOutput(format!(
            "tool output '{}' exceeded the {max_bytes}-byte limit",
            path.display()
        )));
    }
    Ok(buf)
}

async fn read_stderr_excerpt(path: &Path) -> String {
    let Ok(file) = tokio::fs::File::open(path).await else {
        return String::new();
    };
    let mut buf = Vec::new();
    if file
        .take(STDERR_EXCERPT_LIMIT)
        .read_to_end(&mut buf)
        .await
        .is_err()
    {
        return String::new();
    }
    bounded(String::from_utf8_lossy(&buf).trim())
}

fn locate_package_in_checkout(
    checkout_root: &Path,
    expected_name: &str,
    expected_version: &semver::Version,
) -> Result<PathBuf, AnalyzerError> {
    let canonical_root = std::fs::canonicalize(checkout_root).map_err(|error| {
        AnalyzerError::Project(format!("cannot resolve checkout root: {error}"))
    })?;
    let limits = AnalyzerLimits::default();

    // Fast path: root `Cargo.toml` is a regular contained file naming the package.
    let mut root_ws_version: Option<String> = None;
    if is_contained_regular_file(&canonical_root, Path::new("Cargo.toml"))
        && let Ok(text) = read_contained_utf8(
            &canonical_root,
            Path::new(""),
            Path::new("Cargo.toml"),
            limits.max_file_bytes,
        )
        && let Ok(doc) = text.parse::<toml_edit::Document<String>>()
    {
        root_ws_version = doc
            .get("workspace")
            .and_then(|w| w.get("package"))
            .and_then(|p| p.get("version"))
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        if manifest_matches_package(
            &doc,
            expected_name,
            expected_version,
            root_ws_version.as_deref(),
        ) {
            return Ok(PathBuf::new());
        }
    }

    let walker = walkdir::WalkDir::new(&canonical_root)
        .min_depth(2)
        .max_depth(16)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !matches!(name.as_ref(), ".git" | "target" | "vendor" | "node_modules")
        });

    let mut visited = 0usize;
    for entry in walker.flatten() {
        if entry.file_name() != "Cargo.toml" {
            continue;
        }
        let Some(parent) = entry.path().parent() else {
            continue;
        };
        let Ok(rel_dir) = parent.strip_prefix(&canonical_root) else {
            continue;
        };
        visited += 1;
        if visited > limits.max_manifests {
            break;
        }
        let Ok(text) = read_contained_utf8(
            &canonical_root,
            rel_dir,
            Path::new("Cargo.toml"),
            limits.max_file_bytes,
        ) else {
            continue;
        };
        let Ok(doc) = text.parse::<toml_edit::Document<String>>() else {
            continue;
        };
        if manifest_matches_package(
            &doc,
            expected_name,
            expected_version,
            root_ws_version.as_deref(),
        ) {
            return resolve_contained_path(&canonical_root, Path::new(""), rel_dir)
                .map_err(AnalyzerError::Project);
        }
    }

    Err(AnalyzerError::Project(format!(
        "checkout at '{}' does not contain Cargo package '{expected_name} {expected_version}'",
        checkout_root.display()
    )))
}

fn manifest_matches_package(
    doc: &toml_edit::Document<String>,
    expected_name: &str,
    expected_version: &semver::Version,
    workspace_version: Option<&str>,
) -> bool {
    let Some(pkg) = doc.get("package").and_then(|i| i.as_table_like()) else {
        return false;
    };
    if pkg.get("name").and_then(|n| n.as_str()) != Some(expected_name) {
        return false;
    }
    let ver_str = match pkg.get("version") {
        Some(v) if v.as_str().is_some() => v.as_str(),
        Some(v)
            if v.as_table_like()
                .and_then(|t| t.get("workspace"))
                .and_then(|b| b.as_bool())
                == Some(true) =>
        {
            workspace_version
        }
        None => Some("0.0.0"),
        _ => None,
    };
    ver_str
        .and_then(|s| s.parse::<semver::Version>().ok())
        .is_some_and(|v| &v == expected_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceId;

    #[test]
    fn authenticated_registry_classification_does_not_mask_unrelated_failures() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
privdep = { version = "1.0", registry = "corp" }
"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "").unwrap();

        let sid = SourceId {
            kind: SourceKind::Path {
                path: dir.path().to_path_buf(),
            },
            precise: Some("a".repeat(64)),
        };
        let manifests =
            WorkspaceManifests::load(dir.path(), &sid, Path::new(""), &AnalyzerLimits::default())
                .unwrap();

        let corp = RegistrySpec::named(
            "corp",
            "sparse+https://cargo.corp.example/index/",
            CredentialSource::Env {
                registry: "corp".into(),
            },
        )
        .unwrap();
        let regs = [corp];

        // 1. Timeouts and signals NEVER match, even if stderr mentions `corp` and `401`.
        let auth_stderr = "error: failed to download from https://cargo.corp.example/index/config.json: status 401 Unauthorized";
        assert!(
            matching_authenticated_registry_failures(
                ProcessStatus::TimedOut,
                auth_stderr,
                &manifests,
                &regs
            )
            .is_empty()
        );
        assert!(
            matching_authenticated_registry_failures(
                ProcessStatus::Signaled,
                auth_stderr,
                &manifests,
                &regs
            )
            .is_empty()
        );

        // 2. Unrelated `cargo metadata` errors (version conflict on crates.io,
        //    manifest error, DNS failure without auth challenge) DO NOT match!
        for unrelated in [
            "error: failed to select a version for the requirement `serde = \"^99\"`",
            "error: failed to parse manifest at `/source/Cargo.toml`",
            "error: failed to download from `https://cargo.corp.example/index/config.json`: Could not resolve host",
            "error: status 401 Unauthorized from https://unrelated.other.example/index/",
        ] {
            assert!(
                matching_authenticated_registry_failures(
                    ProcessStatus::Exited(101),
                    unrelated,
                    &manifests,
                    &regs
                )
                .is_empty(),
                "must not classify unrelated stderr as auth block: {unrelated}"
            );
        }

        // 3. Genuine 401/403/`no token found`/missing-config for `corp` DOES match.
        for genuine in [
            auth_stderr,
            "error: no token found for `corp`, please run `cargo login --registry corp`",
            "error: registry `corp` was not found in any configuration file",
        ] {
            assert_eq!(
                matching_authenticated_registry_failures(
                    ProcessStatus::Exited(101),
                    genuine,
                    &manifests,
                    &regs
                ),
                vec!["corp".to_string()],
                "expected auth match for: {genuine}"
            );
        }
    }

    #[tokio::test]
    async fn default_dependency_fetch_policy_rejects_local_unallowlisted_and_mutated_sources() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().join("cache"));
        let options = FetchOptions::default();
        let commit = "0123456789abcdef0123456789abcdef01234567";

        // 1. `file://`, `ssh://`, `http://`, credential-bearing, IP-literal, and
        //    non-allowlisted `https://` git dependency URLs are all rejected by
        //    the default host acquisition policy.
        for bad_url in [
            "file:///tmp/some-local-repo",
            "ssh://git@github.com/example/repo.git",
            "http://github.com/example/repo.git",
            "https://user:secret_tok@github.com/example/repo.git",
            "https://127.0.0.1/example/repo.git",
            "https://untrusted-host.example/repo.git",
        ] {
            let pkg = PackageId {
                name: "dep".into(),
                version: PackageVersion::SemVer(semver::Version::new(0, 1, 0)),
                source_id: SourceId {
                    kind: SourceKind::Git {
                        url: Url::parse(bad_url).unwrap(),
                        reference: GitReference::DefaultBranch,
                    },
                    precise: Some(commit.into()),
                },
                ecosystem: Ecosystem::Rust,
            };
            let err = acquire_dependency(&pkg, &cache, &options, &[], false)
                .await
                .unwrap_err()
                .to_string();
            assert!(!err.contains("secret_tok"), "leaked URL password: {err}");
        }

        // 2. Local `SourceKind::Path` requires a matching tree digest and
        //    verifies package identity inside the directory; mutating the tree
        //    after recording its `PackageId` fails with a checksum mismatch!
        let proj = tmp.path().join("local-dep");
        std::fs::create_dir_all(proj.join("src")).unwrap();
        std::fs::write(
            proj.join("Cargo.toml"),
            "[package]\nname = \"local-dep\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();
        std::fs::write(proj.join("src/lib.rs"), "pub const X: u8 = 1;\n").unwrap();

        let initial = fetch_path(&proj).await.unwrap();
        let path_pkg = PackageId {
            name: "local-dep".into(),
            version: PackageVersion::SemVer(semver::Version::new(0, 2, 0)),
            source_id: initial.source_id(),
            ecosystem: Ecosystem::Rust,
        };
        let acquired = acquire_dependency(&path_pkg, &cache, &options, &[], false)
            .await
            .unwrap();
        assert_eq!(acquired.fetched.digest, initial.digest);

        // Unpinned `Path` (`precise: None`) is rejected.
        let mut unpinned_path = path_pkg.clone();
        unpinned_path.source_id.precise = None;
        assert!(
            acquire_dependency(&unpinned_path, &cache, &options, &[], false)
                .await
                .is_err()
        );

        // Mutating the local file changes the tree digest → rejected with `Checksum`!
        std::fs::write(proj.join("src/lib.rs"), "pub const X: u8 = 99;\n").unwrap();
        let mutated_err = acquire_dependency(&path_pkg, &cache, &options, &[], false)
            .await
            .unwrap_err();
        assert!(
            matches!(
                mutated_err,
                RobigusError::Fetch(FetchError::Checksum { .. })
            ),
            "expected Checksum mismatch, got: {mutated_err:?}"
        );
    }
}
