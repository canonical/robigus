//! `toml_edit` Cargo manifest & workspace parser (spec §8.1; WP-2.2).
//!
//! Serves two roles:
//! 1. **Always** inspects in-tree manifests on the host to anchor
//!    [`EvidenceMethod::Manifest`] source locations, check path-dependency and
//!    build-script path containment before or alongside `cargo metadata`, and
//!    spot dependencies declared against authenticated registries.
//! 2. **Offline fallback (`--offline`)**: builds the full [`AnalyzerOutput`]
//!    without running `cargo metadata`, producing declared-but-unresolved crate
//!    edges (`to = None`) at tier L3 (`Confidence = 65`) plus tier-L2
//!    `build.rs` / `links` native requirements.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use semver::{Version, VersionReq};

use super::build_script::{findings_to_edges, links_edge, scan_build_script};
use super::cfg::{PackageFeatures, combine_predicates, target_spec_to_predicate};
use super::lockfile::format_toml_error;
use crate::analyzers::{
    AnalysisContext, AnalyzerDiagnostic, AnalyzerLimits, AnalyzerOutput, NetworkMode,
};
use crate::credentials::{CredentialSource, bounded};
use crate::error::AnalyzerError;
use crate::model::{
    AnalysisStrategy, AnalyzerId, BuildSystem, Confidence, DependencyKind, Ecosystem, Edge,
    Evidence, EvidenceMethod, Node, PackageId, PackageVersion, PlanRow, PlanStatus, PlanSubject,
    Requirement, RequirementKind, SourceId, SourceLocation, Target, TargetKind, VersionConstraint,
};
use crate::predicate::Predicate;
use crate::registry::RegistrySpec;

/// Tier L3 confidence for offline manifest-only dependency declarations.
pub(super) const OFFLINE_MANIFEST_CONFIDENCE: Confidence = Confidence::new(65);

const MEMBER_GLOB: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// Resolves `raw` relative to `base_rel` inside `canonical_tree_root`,
/// rejecting absolute paths, `..` traversal above the tree root, and symlinks
/// whose target resolves outside `canonical_tree_root` (spec §8.1).
///
/// Components are walked in order and symlinks are resolved **before** any
/// following `..` component is applied, matching kernel path resolution so an
/// escaping symlink followed by `..` (`escape_link/..`) cannot cancel out
/// lexically. Returns the normalized tree-relative path (empty for the tree
/// root itself).
pub(super) fn resolve_contained_path(
    canonical_tree_root: &Path,
    base_rel: &Path,
    raw: &Path,
) -> Result<PathBuf, String> {
    if raw.is_absolute() || base_rel.is_absolute() {
        return Err(format!(
            "path '{}' is absolute and escapes the source tree",
            bounded(&raw.to_string_lossy())
        ));
    }
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    let mut nonexistent_tail: usize = 0;

    for component in base_rel.components().chain(raw.components()) {
        match component {
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "path '{}' escapes the source tree",
                    bounded(&raw.to_string_lossy())
                ));
            }
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(format!(
                        "path '{}' escapes the source tree",
                        bounded(&raw.to_string_lossy())
                    ));
                }
                nonexistent_tail = nonexistent_tail.saturating_sub(1);
            }
            Component::Normal(part) => {
                if nonexistent_tail > 0 {
                    parts.push(part.to_os_string());
                    nonexistent_tail += 1;
                    continue;
                }
                let mut probe = canonical_tree_root.to_path_buf();
                for existing in &parts {
                    probe.push(existing);
                }
                probe.push(part);

                match std::fs::symlink_metadata(&probe) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        parts.push(part.to_os_string());
                        nonexistent_tail = 1;
                    }
                    Err(error) => {
                        return Err(format!(
                            "path '{}' cannot be inspected inside the source tree: {error}",
                            bounded(&raw.to_string_lossy())
                        ));
                    }
                    Ok(meta) if meta.file_type().is_symlink() => {
                        let resolved = std::fs::canonicalize(&probe).map_err(|error| {
                            format!(
                                "path '{}' traverses invalid symlink: {error}",
                                bounded(&raw.to_string_lossy())
                            )
                        })?;
                        let Ok(rel_inside) = resolved.strip_prefix(canonical_tree_root) else {
                            return Err(format!(
                                "path '{}' resolves outside the source tree via symlink",
                                bounded(&raw.to_string_lossy())
                            ));
                        };
                        parts = rel_inside
                            .components()
                            .filter_map(|c| match c {
                                Component::Normal(seg) => Some(seg.to_os_string()),
                                _ => None,
                            })
                            .collect();
                    }
                    Ok(_) => parts.push(part.to_os_string()),
                }
            }
        }
    }

    let mut normalized = PathBuf::new();
    for part in &parts {
        normalized.push(part);
    }
    Ok(normalized)
}

/// Converts a tree-relative directory (`""` for top level) to the non-empty
/// [`Node::path`] form accepted by the store (`"."` for top level).
pub(super) fn node_rel_path(rel_dir: &Path) -> PathBuf {
    if rel_dir.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        rel_dir.to_path_buf()
    }
}

/// Opens and reads a regular UTF-8 file relative to `canonical_tree_root`,
/// enforcing containment at open time:
///
/// - refuses leaf symlinks (even intra-tree) before and during open;
/// - resolves directory components step-by-step inside `canonical_tree_root`,
///   then opens each directory component and the final file with `O_NOFOLLOW`
///   so a concurrent symlink swap cannot escape the tree;
/// - opens with `O_NONBLOCK | O_NOCTTY` and checks `fstat` for a regular file
///   so FIFOs, sockets, device nodes, and directories fail immediately without
///   blocking;
/// - enforces `max_bytes` **during** the read (`take(max_bytes + 1)`), not
///   solely from `stat.st_size`.
pub(super) fn read_contained_utf8(
    canonical_tree_root: &Path,
    base_rel: &Path,
    raw_rel: &Path,
    max_bytes: u64,
) -> Result<String, String> {
    // Reject a leaf symlink before `resolve_contained_path` can canonicalize an
    // intra-tree symlink target: manifests, lockfiles, Cargo configs, and build
    // scripts must be real regular files.
    let (parent_raw, leaf_name) = match (raw_rel.parent(), raw_rel.file_name()) {
        (Some(parent), Some(name)) => (parent, name),
        _ => {
            return Err(format!(
                "path '{}' does not name a file",
                bounded(&raw_rel.to_string_lossy())
            ));
        }
    };
    let dir_rel = resolve_contained_path(canonical_tree_root, base_rel, parent_raw)?;
    let rel_file = dir_rel.join(leaf_name);

    open_and_read_regular_utf8(canonical_tree_root, &rel_file, max_bytes)
}

/// True when `rel_path` (under `canonical_tree_root`) is a contained,
/// non-symlink regular file, verified without blocking or following a leaf
/// symlink.
pub(super) fn is_contained_regular_file(canonical_tree_root: &Path, rel_path: &Path) -> bool {
    let Some(parent) = rel_path.parent() else {
        return false;
    };
    let Some(leaf) = rel_path.file_name() else {
        return false;
    };
    let Ok(dir_rel) = resolve_contained_path(canonical_tree_root, Path::new(""), parent) else {
        return false;
    };
    let clean = dir_rel.join(leaf);
    check_regular_file_nofollow(canonical_tree_root, &clean)
}

#[cfg(target_os = "linux")]
fn open_and_read_regular_utf8(
    canonical_tree_root: &Path,
    clean_rel: &Path,
    max_bytes: u64,
) -> Result<String, String> {
    use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
    use rustix::io::Errno;

    let names: Vec<_> = clean_rel
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err("internal path contains non-normal component".to_string()),
        })
        .collect::<Result<_, _>>()?;
    let (file_name, directories) = names
        .split_last()
        .ok_or_else(|| "path names no file".to_string())?;

    let refuse_link = |at: &Path, error: Errno| match error {
        Errno::LOOP | Errno::NOTDIR | Errno::MLINK => format!(
            "refusing symlink or non-directory component '{}'",
            bounded(&at.to_string_lossy())
        ),
        other => format!("cannot open '{}': {other}", bounded(&at.to_string_lossy())),
    };

    let dir_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current = openat(
        CWD,
        canonical_tree_root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open source tree root: {error}"))?;

    let mut walked = PathBuf::new();
    for dir_name in directories {
        walked.push(dir_name);
        current = openat(&current, *dir_name, dir_flags, Mode::empty())
            .map_err(|error| refuse_link(&walked, error))?;
    }
    walked.push(file_name);
    let file_fd = openat(
        &current,
        *file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| refuse_link(&walked, error))?;

    let stat = fstat(&file_fd).map_err(|error| format!("cannot inspect file: {error}"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err("not a regular file".to_string());
    }
    let reported_size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    if reported_size > max_bytes {
        return Err(format!(
            "size {reported_size} bytes exceeds {max_bytes}-byte limit"
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(reported_size.min(64 * 1024)).unwrap_or(0));
    std::fs::File::from(file_fd)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("file exceeds {max_bytes}-byte limit while reading"));
    }
    String::from_utf8(bytes).map_err(|_| "file is not valid UTF-8".to_string())
}

#[cfg(target_os = "linux")]
fn check_regular_file_nofollow(canonical_tree_root: &Path, clean_rel: &Path) -> bool {
    use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};

    let mut names = Vec::new();
    for component in clean_rel.components() {
        match component {
            Component::Normal(name) => names.push(name),
            _ => return false,
        }
    }
    let Some((file_name, directories)) = names.split_last() else {
        return false;
    };
    let dir_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let Ok(mut current) = openat(
        CWD,
        canonical_tree_root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    for dir_name in directories {
        let Ok(next) = openat(&current, *dir_name, dir_flags, Mode::empty()) else {
            return false;
        };
        current = next;
    }
    let Ok(leaf) = openat(
        &current,
        *file_name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    fstat(&leaf)
        .map(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile)
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn open_and_read_regular_utf8(
    canonical_tree_root: &Path,
    clean_rel: &Path,
    max_bytes: u64,
) -> Result<String, String> {
    let mut probe = canonical_tree_root.to_path_buf();
    for component in clean_rel.components() {
        let Component::Normal(name) = component else {
            return Err("internal path contains non-normal component".to_string());
        };
        probe.push(name);
        let meta = std::fs::symlink_metadata(&probe)
            .map_err(|error| format!("cannot inspect: {error}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "refusing symlink component '{}'",
                bounded(&clean_rel.to_string_lossy())
            ));
        }
    }
    let file = std::fs::File::open(&probe).map_err(|error| format!("cannot open: {error}"))?;
    let meta = file
        .metadata()
        .map_err(|error| format!("cannot inspect: {error}"))?;
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    if meta.len() > max_bytes {
        return Err(format!(
            "size {} bytes exceeds {max_bytes}-byte limit",
            meta.len()
        ));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("file exceeds {max_bytes}-byte limit while reading"));
    }
    String::from_utf8(bytes).map_err(|_| "file is not valid UTF-8".to_string())
}

#[cfg(not(target_os = "linux"))]
fn check_regular_file_nofollow(canonical_tree_root: &Path, clean_rel: &Path) -> bool {
    let mut probe = canonical_tree_root.to_path_buf();
    for component in clean_rel.components() {
        let Component::Normal(name) = component else {
            return false;
        };
        probe.push(name);
        let Ok(meta) = std::fs::symlink_metadata(&probe) else {
            return false;
        };
        if meta.file_type().is_symlink() {
            return false;
        }
    }
    std::fs::symlink_metadata(&probe)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// Workspace-level `[workspace.dependencies]` entry for inheritance.
#[derive(Debug, Clone, Default)]
struct WorkspaceDepTemplate {
    package: Option<String>,
    version: Option<String>,
    default_features: Option<bool>,
    features: Vec<String>,
    registry: Option<String>,
    registry_index: Option<String>,
    git: Option<String>,
    path: Option<String>,
    /// Tree-relative directory of the workspace root that defined this entry,
    /// so `path = "..."` resolves relative to the workspace manifest.
    workspace_dir: PathBuf,
}

/// One dependency declaration parsed from an in-tree `Cargo.toml`.
#[derive(Debug, Clone)]
pub(super) struct DeclaredDep {
    /// Key in the dependency table (`rename` if renamed, else crate name).
    pub(super) alias: String,
    /// Actual crate package name (`package = "…"` if renamed, else `alias`).
    pub(super) crate_name: String,
    /// Parsed SemVer version requirement, when one was declared.
    pub(super) version_req: Option<VersionConstraint>,
    /// Category table the declaration came from.
    pub(super) kind: DependencyKind,
    /// `optional = true`.
    pub(super) optional: bool,
    /// `default-features` (default `true`).
    #[allow(dead_code)]
    pub(super) default_features: bool,
    /// Raw feature strings declared on this dependency entry.
    #[allow(dead_code)]
    pub(super) features: Vec<String>,
    /// Raw `[target.<spec>.*]` key, if target-specific.
    pub(super) platform_spec: Option<String>,
    /// Parsed predicate for `platform_spec`, when valid.
    pub(super) platform_predicate: Option<Predicate>,
    /// `registry = "<name>"`, when the dependency names an alternative registry.
    pub(super) registry_name: Option<String>,
    /// `registry-index = "<url>"`, when given inline.
    pub(super) registry_index: Option<String>,
    /// `git = "<url>"`, when given.
    #[allow(dead_code)]
    pub(super) git: Option<String>,
    /// Tree-relative directory of an in-tree `path = "…"` dependency, when
    /// valid and contained.
    pub(super) in_tree_path: Option<PathBuf>,
    /// Containment violation message when `path = "…"` escapes the tree.
    pub(super) containment_error: Option<String>,
    /// 1-based `(start_line, end_line)` in `manifest_rel_path`.
    pub(super) lines: Option<(u64, u64)>,
}

/// One in-tree Cargo package parsed via `toml_edit`.
#[derive(Debug, Clone)]
pub(super) struct ParsedCargoPackage {
    pub(super) id: PackageId,
    /// Tree-relative package directory (`""` at top level).
    pub(super) rel_dir: PathBuf,
    /// Tree-relative `Cargo.toml` path.
    pub(super) manifest_rel_path: PathBuf,
    /// True for workspace members (the root nodes of this Cargo root).
    pub(super) is_workspace_member: bool,
    /// Inferred deliverable targets (`[lib]`, `[[bin]]`, standard layouts).
    pub(super) targets: Vec<Target>,
    /// Tree-relative `build.rs` path if the package has a build script.
    pub(super) build_script: Option<PathBuf>,
    /// `package.links` value and 1-based line in `Cargo.toml`.
    pub(super) links: Option<(String, Option<u64>)>,
    /// Raw `[features]` table.
    pub(super) raw_features: BTreeMap<String, Vec<String>>,
    /// Declared dependencies across all tables.
    pub(super) declarations: Vec<DeclaredDep>,
    /// Package-level containment/validation errors that mark this node `Error`.
    pub(super) node_errors: Vec<String>,
}

impl ParsedCargoPackage {
    /// Looks up the best-matching `Cargo.toml` [`SourceLocation`] for an edge
    /// to `crate_name` (and optional `alias` / `kind` / `platform_spec`).
    pub(super) fn declaration_location(
        &self,
        crate_name: &str,
        alias: Option<&str>,
        kind: DependencyKind,
        platform_spec: Option<&str>,
    ) -> SourceLocation {
        let matched = self
            .declarations
            .iter()
            .find(|decl| {
                decl.crate_name == crate_name
                    && alias.is_none_or(|a| decl.alias == a)
                    && decl.kind == kind
                    && decl.platform_spec.as_deref() == platform_spec
            })
            .or_else(|| {
                self.declarations
                    .iter()
                    .find(|decl| decl.crate_name == crate_name)
            });
        SourceLocation {
            path: self.manifest_rel_path.clone(),
            start_line: matched.and_then(|d| d.lines.map(|(s, _)| s)),
            end_line: matched.and_then(|d| d.lines.map(|(_, e)| e)),
        }
    }
}

/// All in-tree manifests loaded for one Cargo analysis root, plus `.cargo`
/// registry mappings found in the tree.
#[derive(Debug, Clone)]
pub(super) struct WorkspaceManifests {
    /// Canonical host path of `ctx.source.tree`.
    pub(super) canonical_tree_root: PathBuf,
    /// Tree-relative Cargo root directory (`ctx.root` normalized).
    pub(super) cargo_root_rel: PathBuf,
    /// Tree-relative `Cargo.lock` path at the Cargo root, if present on disk.
    pub(super) lockfile_rel: Option<PathBuf>,
    /// Packages keyed by tree-relative package directory.
    pub(super) packages: BTreeMap<PathBuf, ParsedCargoPackage>,
    /// Registry name → raw `index` string from `.cargo/config.toml` or
    /// `Cargo.toml` `[registries]`.
    pub(super) cargo_config_registries: BTreeMap<String, String>,
    /// Diagnostics collected while reading manifests.
    pub(super) diagnostics: Vec<AnalyzerDiagnostic>,
}

impl WorkspaceManifests {
    /// Loads the Cargo root at `root_rel` under `source_tree` (blocking; call
    /// inside `spawn_blocking`).
    pub(super) fn load(
        source_tree: &Path,
        source_id: &SourceId,
        root_rel: &Path,
        limits: &AnalyzerLimits,
    ) -> Result<Self, AnalyzerError> {
        let canonical_tree_root = std::fs::canonicalize(source_tree).map_err(|error| {
            AnalyzerError::Project(format!("cannot resolve source tree root: {error}"))
        })?;
        let cargo_root_rel = resolve_contained_path(&canonical_tree_root, Path::new(""), root_rel)
            .map_err(AnalyzerError::Project)?;

        let root_manifest_rel = cargo_root_rel.join("Cargo.toml");
        let root_content = read_contained_utf8(
            &canonical_tree_root,
            &cargo_root_rel,
            Path::new("Cargo.toml"),
            limits.max_file_bytes,
        )
        .map_err(|reason| {
            AnalyzerError::Project(format!(
                "manifest '{}': {reason}",
                root_manifest_rel.display()
            ))
        })?;
        let root_doc = root_content
            .parse::<toml_edit::Document<String>>()
            .map_err(|error| {
                AnalyzerError::Project(format!(
                    "malformed '{}' ({})",
                    root_manifest_rel.display(),
                    format_toml_error(&root_content, &error)
                ))
            })?;

        let has_root_package = root_doc.get("package").is_some_and(|i| i.is_table_like());
        let has_workspace = root_doc.get("workspace").is_some_and(|i| i.is_table_like());
        if !has_root_package && !has_workspace {
            return Err(AnalyzerError::Project(format!(
                "'{}' contains neither [package] nor [workspace]",
                root_manifest_rel.display()
            )));
        }

        let mut diagnostics = Vec::new();
        let cargo_config_registries = load_in_tree_registries(
            &canonical_tree_root,
            &cargo_root_rel,
            &root_doc,
            limits.max_file_bytes,
            &mut diagnostics,
        );

        let workspace_version = root_doc
            .get("workspace")
            .and_then(|ws| ws.get("package"))
            .and_then(|pkg| pkg.get("version"))
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let workspace_deps = parse_workspace_deps(&root_doc, &cargo_root_rel);
        let patch_paths = parse_patch_paths(
            &root_doc,
            &canonical_tree_root,
            &cargo_root_rel,
            &root_manifest_rel,
            &mut diagnostics,
        );

        let mut member_dirs: BTreeSet<PathBuf> = BTreeSet::new();
        if has_root_package {
            member_dirs.insert(cargo_root_rel.clone());
        }
        if has_workspace {
            let discovered = expand_workspace_members(
                &root_doc,
                &canonical_tree_root,
                &cargo_root_rel,
                &root_manifest_rel,
                &mut diagnostics,
            );
            member_dirs.extend(discovered);
        }

        // Work queue: `(pkg_rel_dir, is_workspace_member)`. Workspace members go
        // first; referenced in-tree `path = "…"` and `[patch]` directories follow.
        let mut queue: VecDeque<(PathBuf, bool)> =
            member_dirs.iter().cloned().map(|d| (d, true)).collect();
        for patch_dir in patch_paths {
            if !member_dirs.contains(&patch_dir) {
                queue.push_back((patch_dir, false));
            }
        }

        let mut packages: BTreeMap<PathBuf, ParsedCargoPackage> = BTreeMap::new();
        let mut seen_ids: BTreeMap<PackageId, PathBuf> = BTreeMap::new();

        while let Some((pkg_rel_dir, is_member)) = queue.pop_front() {
            if let Some(existing) = packages.get_mut(&pkg_rel_dir) {
                existing.is_workspace_member |= is_member;
                continue;
            }
            if packages.len() >= limits.max_manifests {
                diagnostics.push(AnalyzerDiagnostic {
                    path: pkg_rel_dir,
                    message: format!(
                        "manifest limit of {} reached; remaining path packages skipped",
                        limits.max_manifests
                    ),
                });
                break;
            }

            let manifest_rel = pkg_rel_dir.join("Cargo.toml");
            let (content, doc) = if pkg_rel_dir == cargo_root_rel {
                (root_content.clone(), root_doc.clone())
            } else {
                let content = match read_contained_utf8(
                    &canonical_tree_root,
                    &pkg_rel_dir,
                    Path::new("Cargo.toml"),
                    limits.max_file_bytes,
                ) {
                    Ok(text) => text,
                    Err(reason) => {
                        diagnostics.push(AnalyzerDiagnostic {
                            path: manifest_rel,
                            message: reason,
                        });
                        continue;
                    }
                };
                match content.parse::<toml_edit::Document<String>>() {
                    Ok(doc) => (content, doc),
                    Err(error) => {
                        diagnostics.push(AnalyzerDiagnostic {
                            path: manifest_rel,
                            message: format!(
                                "malformed Cargo.toml ({})",
                                format_toml_error(&content, &error)
                            ),
                        });
                        continue;
                    }
                }
            };

            let Some(parsed) = parse_package_manifest(
                &doc,
                &content,
                &canonical_tree_root,
                &pkg_rel_dir,
                &manifest_rel,
                is_member,
                source_id,
                workspace_version.as_deref(),
                &workspace_deps,
                &mut diagnostics,
            )?
            else {
                continue;
            };

            if let Some(other_dir) = seen_ids.get(&parsed.id)
                && other_dir != &pkg_rel_dir
            {
                return Err(AnalyzerError::Inconsistent(format!(
                    "duplicate in-tree package identity '{}' at '{}' and '{}'",
                    parsed.id,
                    other_dir.display(),
                    pkg_rel_dir.display()
                )));
            }
            seen_ids.insert(parsed.id.clone(), pkg_rel_dir.clone());

            for decl in &parsed.declarations {
                if let Some(target_dir) = &decl.in_tree_path
                    && !packages.contains_key(target_dir)
                {
                    let also_member = member_dirs.contains(target_dir);
                    queue.push_back((target_dir.clone(), also_member));
                }
            }

            packages.insert(pkg_rel_dir, parsed);
        }

        if packages.is_empty() {
            return Err(AnalyzerError::Project(format!(
                "workspace at '{}' contains no loadable Cargo packages",
                root_manifest_rel.display()
            )));
        }

        // Check `symlink_metadata` rather than `is_file()` so a symlinked or
        // special `Cargo.lock` is surfaced and rejected by `read_contained_utf8`
        // rather than followed or silently ignored.
        let lockfile_candidate = cargo_root_rel.join("Cargo.lock");
        let lockfile_rel = std::fs::symlink_metadata(canonical_tree_root.join(&lockfile_candidate))
            .is_ok()
            .then_some(lockfile_candidate);

        Ok(Self {
            canonical_tree_root,
            cargo_root_rel,
            lockfile_rel,
            packages,
            cargo_config_registries,
            diagnostics,
        })
    }

    /// Names of registries referenced by any in-tree declaration that are
    /// configured with credentials in `registries` (or mapped to an
    /// authenticated URL via `.cargo/config.toml`).
    pub(super) fn referenced_authenticated_registries(
        &self,
        registries: &[RegistrySpec],
    ) -> BTreeMap<String, RegistrySpec> {
        let mut found = BTreeMap::new();
        for pkg in self.packages.values() {
            for decl in &pkg.declarations {
                if let Some(reg_name) = &decl.registry_name
                    && let Some(spec) = self.find_authenticated_registry(reg_name, registries)
                {
                    found.insert(reg_name.clone(), spec);
                }
            }
        }
        found
    }

    pub(super) fn find_authenticated_registry(
        &self,
        reg_name: &str,
        registries: &[RegistrySpec],
    ) -> Option<RegistrySpec> {
        if let Some(spec) = registries
            .iter()
            .find(|s| s.name.as_deref() == Some(reg_name))
        {
            return (!matches!(spec.credentials, CredentialSource::None)).then(|| spec.clone());
        }
        let raw_index = self.cargo_config_registries.get(reg_name)?;
        let normalized = crate::registry::normalize_index_url(
            raw_index,
            crate::registry::IndexUrlPolicy::AllowInsecureHttp,
        )
        .ok()?;
        registries
            .iter()
            .find(|s| s.index_url == normalized && !matches!(s.credentials, CredentialSource::None))
            .cloned()
    }
}

/// Builds a complete [`AnalyzerOutput`] from parsed manifests alone (used for
/// `--offline` and when `cargo metadata` cannot run).
pub(super) fn build_offline_output(
    ctx: &AnalysisContext<'_>,
    manifests: &WorkspaceManifests,
    tool_skip_detail: &str,
    network_mode: NetworkMode,
) -> AnalyzerOutput {
    let mut output = AnalyzerOutput {
        network_mode,
        diagnostics: manifests.diagnostics.clone(),
        ..AnalyzerOutput::default()
    };

    for pkg in manifests.packages.values() {
        if pkg.is_workspace_member {
            output.roots.insert(pkg.id.clone());
        }
        let mut node = Node::new(pkg.id.clone());
        node.path = Some(node_rel_path(&pkg.rel_dir));
        node.targets = pkg.targets.clone();
        output.nodes.push(node);

        let optional_aliases: BTreeSet<String> = pkg
            .declarations
            .iter()
            .filter(|d| d.optional)
            .map(|d| d.alias.clone())
            .collect();
        let (feature_model, feature_errors) =
            PackageFeatures::from_raw(&pkg.raw_features, &optional_aliases);
        for error in feature_errors {
            output.diagnostics.push(AnalyzerDiagnostic {
                path: pkg.manifest_rel_path.clone(),
                message: error.to_string(),
            });
        }

        for decl in &pkg.declarations {
            if decl.containment_error.is_some() {
                continue;
            }
            let opt_pred = decl
                .optional
                .then(|| feature_model.activation_predicate(&decl.alias));
            let predicate = combine_predicates(decl.platform_predicate.clone(), opt_pred);

            let mut detail_parts = Vec::new();
            if let Some(reg_name) = &decl.registry_name {
                if let Some(auth_spec) =
                    manifests.find_authenticated_registry(reg_name, ctx.registries)
                {
                    detail_parts.push(format!(
                        "declared against authenticated registry '{reg_name}' ({}); \
                         in-sandbox registry authentication is not available in Phase 1",
                        auth_spec.index_url
                    ));
                } else {
                    detail_parts.push(format!("declared against registry '{reg_name}'"));
                }
            } else if let Some(index) = &decl.registry_index {
                detail_parts.push(format!(
                    "declared against registry-index '{}'",
                    bounded(index)
                ));
            } else {
                detail_parts.push("offline manifest-only declaration (unresolved)".to_string());
            }
            let forwarded = feature_model.forwarded_subfeatures(&decl.alias);
            if !forwarded.is_empty() {
                detail_parts.push(format!("feature forwarding: {}", forwarded.join(", ")));
            }

            output.edges.push(Edge {
                from: pkg.id.clone(),
                to: None,
                requirement: Requirement {
                    kind: RequirementKind::Crate,
                    name: decl.crate_name.clone(),
                    version_req: decl.version_req.clone(),
                },
                kinds: BTreeSet::from([decl.kind]),
                predicate,
                confidence: OFFLINE_MANIFEST_CONFIDENCE,
                evidence: vec![Evidence {
                    method: EvidenceMethod::Manifest,
                    confidence: OFFLINE_MANIFEST_CONFIDENCE,
                    location: Some(SourceLocation {
                        path: pkg.manifest_rel_path.clone(),
                        start_line: decl.lines.map(|(s, _)| s),
                        end_line: decl.lines.map(|(_, e)| e),
                    }),
                    detail: Some(detail_parts.join("; ")),
                }],
            });
        }

        append_build_script_and_links(
            pkg,
            &manifests.canonical_tree_root,
            &ctx.limits,
            &mut output,
        );

        let mut manifest_row = PlanRow::new(
            PlanSubject::Package(pkg.id.clone()),
            AnalyzerId::Cargo,
            AnalysisStrategy::Manifest,
            None,
            if pkg.node_errors.is_empty() {
                PlanStatus::Complete
            } else {
                PlanStatus::Failed
            },
        );
        manifest_row.attempts = 1;
        if !pkg.node_errors.is_empty() {
            manifest_row.error = Some(pkg.node_errors.join("; "));
        }
        output.plan.push(manifest_row);

        let mut tool_row = PlanRow::new(
            PlanSubject::Package(pkg.id.clone()),
            AnalyzerId::Cargo,
            AnalysisStrategy::ToolIntrospection,
            None,
            PlanStatus::Skipped,
        );
        tool_row.detail = Some(tool_skip_detail.to_string());
        output.plan.push(tool_row);
    }

    output.normalize();
    output
}

/// Scans an in-tree package's `build.rs` and `links` key and appends L2 edges
/// and the `BuildScript` plan row to `output`.
pub(super) fn append_build_script_and_links(
    pkg: &ParsedCargoPackage,
    canonical_tree_root: &Path,
    limits: &AnalyzerLimits,
    output: &mut AnalyzerOutput,
) {
    if let Some((links, line)) = &pkg.links {
        output
            .edges
            .push(links_edge(&pkg.id, links, &pkg.manifest_rel_path, *line));
    }

    let Some(script_rel) = &pkg.build_script else {
        return;
    };
    let mut row = PlanRow::new(
        PlanSubject::Package(pkg.id.clone()),
        AnalyzerId::Cargo,
        AnalysisStrategy::Manifest,
        Some(BuildSystem::BuildScript),
        PlanStatus::Complete,
    );
    row.attempts = 1;

    match read_contained_utf8(
        canonical_tree_root,
        Path::new(""),
        script_rel,
        limits.max_file_bytes,
    ) {
        Ok(source) => {
            let findings = scan_build_script(&source);
            row.detail = Some(format!(
                "scanned '{}' ({} finding(s))",
                script_rel.display(),
                findings.len()
            ));
            output
                .edges
                .extend(findings_to_edges(&pkg.id, script_rel, &findings));
        }
        Err(reason) => {
            output.diagnostics.push(AnalyzerDiagnostic {
                path: script_rel.clone(),
                message: format!("build script not scanned: {reason}"),
            });
            row.detail = Some(format!(
                "could not scan '{}': {reason}",
                script_rel.display()
            ));
        }
    }
    output.plan.push(row);
}

#[allow(clippy::too_many_arguments)]
fn parse_package_manifest(
    doc: &toml_edit::Document<String>,
    raw_content: &str,
    canonical_tree_root: &Path,
    pkg_rel_dir: &Path,
    manifest_rel: &Path,
    is_workspace_member: bool,
    source_id: &SourceId,
    workspace_version: Option<&str>,
    workspace_deps: &BTreeMap<String, WorkspaceDepTemplate>,
    diagnostics: &mut Vec<AnalyzerDiagnostic>,
) -> Result<Option<ParsedCargoPackage>, AnalyzerError> {
    let Some(package_table) = doc.get("package").and_then(|item| item.as_table_like()) else {
        return Ok(None);
    };
    let Some(name) = package_table.get("name").and_then(|i| i.as_str()) else {
        diagnostics.push(AnalyzerDiagnostic {
            path: manifest_rel.to_path_buf(),
            message: "[package] has no string `name`; skipped".to_string(),
        });
        return Ok(None);
    };

    let version_str = match package_table.get("version") {
        Some(item) if item.as_str().is_some() => item.as_str().map(str::to_owned),
        Some(item)
            if item
                .as_table_like()
                .and_then(|t| t.get("workspace"))
                .and_then(|w| w.as_bool())
                == Some(true) =>
        {
            workspace_version.map(str::to_owned)
        }
        None => Some("0.0.0".to_string()),
        _ => None,
    };
    let Some(version_str) = version_str else {
        diagnostics.push(AnalyzerDiagnostic {
            path: manifest_rel.to_path_buf(),
            message: format!("package '{name}' has an unresolved or invalid `version`; skipped"),
        });
        return Ok(None);
    };
    let version = match version_str.parse::<Version>() {
        Ok(ver) => ver,
        Err(error) => {
            diagnostics.push(AnalyzerDiagnostic {
                path: manifest_rel.to_path_buf(),
                message: format!(
                    "package '{name}' version '{}' is not valid SemVer: {error}",
                    bounded(&version_str)
                ),
            });
            return Ok(None);
        }
    };

    let id = PackageId {
        name: name.to_string(),
        version: PackageVersion::SemVer(version),
        source_id: source_id.clone(),
        ecosystem: Ecosystem::Rust,
    };

    let line_starts = line_offsets(raw_content);
    let span_lines = |span: Option<std::ops::Range<usize>>| -> Option<(u64, u64)> {
        let span = span?;
        let start = line_starts.partition_point(|&off| off <= span.start) as u64;
        let end_offset = span.end.saturating_sub(1).max(span.start);
        let end = line_starts.partition_point(|&off| off <= end_offset) as u64;
        Some((start.max(1), end.max(start.max(1))))
    };

    let mut node_errors = Vec::new();

    let links = package_table
        .get_key_value("links")
        .and_then(|(key, value)| {
            let text = value.as_str()?.trim();
            (!text.is_empty()).then(|| {
                let line = span_lines(key.span().or_else(|| value.span())).map(|(s, _)| s);
                (text.to_string(), line)
            })
        });

    let build_script = resolve_build_script_path(
        package_table,
        canonical_tree_root,
        pkg_rel_dir,
        &mut node_errors,
    );
    let targets = infer_targets(
        doc,
        package_table,
        name,
        canonical_tree_root,
        pkg_rel_dir,
        &mut node_errors,
    );
    let raw_features = parse_raw_features(doc);
    let declarations = parse_all_declarations(
        doc,
        &span_lines,
        canonical_tree_root,
        pkg_rel_dir,
        manifest_rel,
        workspace_deps,
        &mut node_errors,
        diagnostics,
    );

    Ok(Some(ParsedCargoPackage {
        id,
        rel_dir: pkg_rel_dir.to_path_buf(),
        manifest_rel_path: manifest_rel.to_path_buf(),
        is_workspace_member,
        targets,
        build_script,
        links,
        raw_features,
        declarations,
        node_errors,
    }))
}

fn resolve_build_script_path(
    package_table: &dyn toml_edit::TableLike,
    canonical_tree_root: &Path,
    pkg_rel_dir: &Path,
    node_errors: &mut Vec<String>,
) -> Option<PathBuf> {
    match package_table.get("build") {
        Some(item) if item.as_bool() == Some(false) => None,
        Some(item) if item.as_str().is_some() => {
            let raw = item.as_str().unwrap_or("build.rs");
            match resolve_contained_path(canonical_tree_root, pkg_rel_dir, Path::new(raw)) {
                Ok(rel) => Some(rel),
                Err(reason) => {
                    node_errors.push(format!("package.build {reason}"));
                    None
                }
            }
        }
        _ => {
            let candidate = pkg_rel_dir.join("build.rs");
            if std::fs::symlink_metadata(canonical_tree_root.join(&candidate)).is_err() {
                return None;
            }
            match resolve_contained_path(canonical_tree_root, pkg_rel_dir, Path::new("build.rs")) {
                Ok(_) => Some(candidate),
                Err(reason) => {
                    node_errors.push(format!("build.rs {reason}"));
                    None
                }
            }
        }
    }
}

fn infer_targets(
    doc: &toml_edit::Document<String>,
    package_table: &dyn toml_edit::TableLike,
    pkg_name: &str,
    canonical_tree_root: &Path,
    pkg_rel_dir: &Path,
    node_errors: &mut Vec<String>,
) -> Vec<Target> {
    let mut targets = Vec::new();
    let autolib = package_table
        .get("autolib")
        .and_then(|i| i.as_bool())
        .unwrap_or(true);
    let autobins = package_table
        .get("autobins")
        .and_then(|i| i.as_bool())
        .unwrap_or(true);

    if let Some(lib_table) = doc.get("lib").and_then(|i| i.as_table_like()) {
        let lib_name = lib_table
            .get("name")
            .and_then(|i| i.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| pkg_name.replace('-', "_"));
        let raw_path = lib_table
            .get("path")
            .and_then(|i| i.as_str())
            .unwrap_or("src/lib.rs");
        let path =
            match resolve_contained_path(canonical_tree_root, pkg_rel_dir, Path::new(raw_path)) {
                Ok(rel) => Some(rel),
                Err(reason) => {
                    node_errors.push(format!("[lib] {reason}"));
                    None
                }
            };
        let proc_macro = lib_table
            .get("proc-macro")
            .or_else(|| lib_table.get("proc_macro"))
            .and_then(|i| i.as_bool())
            .unwrap_or(false);
        let crate_types: Vec<&str> = lib_table
            .get("crate-type")
            .and_then(|i| i.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        if proc_macro {
            targets.push(Target {
                name: lib_name,
                kind: TargetKind::RustLib { proc_macro: true },
                path,
            });
        } else if crate_types.is_empty() {
            targets.push(Target {
                name: lib_name,
                kind: TargetKind::RustLib { proc_macro: false },
                path,
            });
        } else {
            for crate_type in crate_types {
                let kind = match crate_type {
                    "proc-macro" => Some(TargetKind::RustLib { proc_macro: true }),
                    "cdylib" => Some(TargetKind::SharedLibrary { soname: None }),
                    "staticlib" => Some(TargetKind::StaticLibrary),
                    "lib" | "rlib" | "dylib" => Some(TargetKind::RustLib { proc_macro: false }),
                    _ => None,
                };
                if let Some(kind) = kind {
                    targets.push(Target {
                        name: lib_name.clone(),
                        kind,
                        path: path.clone(),
                    });
                }
            }
        }
    } else if autolib
        && let Ok(rel) =
            resolve_contained_path(canonical_tree_root, pkg_rel_dir, Path::new("src/lib.rs"))
        && is_contained_regular_file(canonical_tree_root, &rel)
    {
        targets.push(Target {
            name: pkg_name.replace('-', "_"),
            kind: TargetKind::RustLib { proc_macro: false },
            path: Some(rel),
        });
    }

    let mut explicit_bin_names = BTreeSet::new();
    if let Some(bins) = doc.get("bin").and_then(|i| i.as_array_of_tables()) {
        for bin in bins {
            let Some(bin_name) = bin.get("name").and_then(|i| i.as_str()) else {
                continue;
            };
            explicit_bin_names.insert(bin_name.to_string());
            let default_rel = format!("src/bin/{bin_name}.rs");
            let raw_path = bin.get("path").and_then(|i| i.as_str());
            let path = match raw_path {
                Some(raw) => {
                    match resolve_contained_path(canonical_tree_root, pkg_rel_dir, Path::new(raw)) {
                        Ok(rel) => Some(rel),
                        Err(reason) => {
                            node_errors.push(format!("[[bin]] '{bin_name}' {reason}"));
                            None
                        }
                    }
                }
                None => resolve_contained_path(
                    canonical_tree_root,
                    pkg_rel_dir,
                    Path::new(&default_rel),
                )
                .ok()
                .filter(|rel| is_contained_regular_file(canonical_tree_root, rel))
                .or_else(|| {
                    (bin_name == pkg_name)
                        .then(|| {
                            resolve_contained_path(
                                canonical_tree_root,
                                pkg_rel_dir,
                                Path::new("src/main.rs"),
                            )
                            .ok()
                            .filter(|rel| is_contained_regular_file(canonical_tree_root, rel))
                        })
                        .flatten()
                }),
            };
            targets.push(Target {
                name: bin_name.to_string(),
                kind: TargetKind::Binary,
                path,
            });
        }
    }

    if autobins {
        if !explicit_bin_names.contains(pkg_name)
            && let Ok(main_rel) =
                resolve_contained_path(canonical_tree_root, pkg_rel_dir, Path::new("src/main.rs"))
            && is_contained_regular_file(canonical_tree_root, &main_rel)
        {
            targets.push(Target {
                name: pkg_name.to_string(),
                kind: TargetKind::Binary,
                path: Some(main_rel),
            });
        }
        if let Ok(bins_dir_rel) =
            resolve_contained_path(canonical_tree_root, pkg_rel_dir, Path::new("src/bin"))
            && let Ok(entries) = std::fs::read_dir(canonical_tree_root.join(&bins_dir_rel))
        {
            let mut discovered_bins: Vec<(String, PathBuf)> = Vec::new();
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let Some(name_str) = file_name.to_str() else {
                    continue;
                };
                if let Some(stem) = name_str.strip_suffix(".rs")
                    && !explicit_bin_names.contains(stem)
                {
                    let rel = Path::new("src/bin").join(name_str);
                    if let Ok(contained) =
                        resolve_contained_path(canonical_tree_root, pkg_rel_dir, &rel)
                        && is_contained_regular_file(canonical_tree_root, &contained)
                    {
                        discovered_bins.push((stem.to_string(), contained));
                    }
                }
            }
            discovered_bins.sort();
            for (stem, path) in discovered_bins {
                targets.push(Target {
                    name: stem,
                    kind: TargetKind::Binary,
                    path: Some(path),
                });
            }
        }
    }

    targets
}

fn parse_raw_features(doc: &toml_edit::Document<String>) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let Some(features) = doc.get("features").and_then(|i| i.as_table_like()) else {
        return out;
    };
    for (key, value) in features.iter() {
        let items = value
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        out.insert(key.to_string(), items);
    }
    out
}

fn parse_workspace_deps(
    root_doc: &toml_edit::Document<String>,
    workspace_dir: &Path,
) -> BTreeMap<String, WorkspaceDepTemplate> {
    let mut deps = BTreeMap::new();
    let Some(table) = root_doc
        .get("workspace")
        .and_then(|ws| ws.get("dependencies"))
        .and_then(|d| d.as_table_like())
    else {
        return deps;
    };
    for (key, item) in table.iter() {
        if let Some(ver) = item.as_str() {
            deps.insert(
                key.to_string(),
                WorkspaceDepTemplate {
                    version: Some(ver.to_string()),
                    workspace_dir: workspace_dir.to_path_buf(),
                    ..WorkspaceDepTemplate::default()
                },
            );
        } else if let Some(tbl) = item.as_table_like() {
            deps.insert(
                key.to_string(),
                WorkspaceDepTemplate {
                    package: tbl
                        .get("package")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    version: tbl
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    default_features: tbl
                        .get("default-features")
                        .or_else(|| tbl.get("default_features"))
                        .and_then(|v| v.as_bool()),
                    features: string_array(tbl.get("features")),
                    registry: tbl
                        .get("registry")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    registry_index: tbl
                        .get("registry-index")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    git: tbl.get("git").and_then(|v| v.as_str()).map(str::to_owned),
                    path: tbl.get("path").and_then(|v| v.as_str()).map(str::to_owned),
                    workspace_dir: workspace_dir.to_path_buf(),
                },
            );
        }
    }
    deps
}

#[allow(clippy::too_many_arguments)]
fn parse_all_declarations(
    doc: &toml_edit::Document<String>,
    span_lines: &dyn Fn(Option<std::ops::Range<usize>>) -> Option<(u64, u64)>,
    canonical_tree_root: &Path,
    pkg_rel_dir: &Path,
    manifest_rel: &Path,
    workspace_deps: &BTreeMap<String, WorkspaceDepTemplate>,
    node_errors: &mut Vec<String>,
    diagnostics: &mut Vec<AnalyzerDiagnostic>,
) -> Vec<DeclaredDep> {
    let mut out = Vec::new();
    for (section, kind) in [
        ("dependencies", DependencyKind::Normal),
        ("dev-dependencies", DependencyKind::Development),
        ("dev_dependencies", DependencyKind::Development),
        ("build-dependencies", DependencyKind::Build),
        ("build_dependencies", DependencyKind::Build),
    ] {
        if let Some(table) = doc.get(section).and_then(|i| i.as_table_like()) {
            parse_dep_table(
                table,
                kind,
                None,
                None,
                span_lines,
                canonical_tree_root,
                pkg_rel_dir,
                manifest_rel,
                workspace_deps,
                node_errors,
                diagnostics,
                &mut out,
            );
        }
    }

    if let Some(targets) = doc.get("target").and_then(|i| i.as_table_like()) {
        for (target_spec, target_item) in targets.iter() {
            let Some(target_table) = target_item.as_table_like() else {
                continue;
            };
            let platform_predicate = match target_spec_to_predicate(target_spec) {
                Ok(pred) => Some(pred),
                Err(problem) => {
                    diagnostics.push(AnalyzerDiagnostic {
                        path: manifest_rel.to_path_buf(),
                        message: problem,
                    });
                    continue;
                }
            };
            for (section, kind) in [
                ("dependencies", DependencyKind::Normal),
                ("dev-dependencies", DependencyKind::Development),
                ("dev_dependencies", DependencyKind::Development),
                ("build-dependencies", DependencyKind::Build),
                ("build_dependencies", DependencyKind::Build),
            ] {
                if let Some(table) = target_table.get(section).and_then(|i| i.as_table_like()) {
                    parse_dep_table(
                        table,
                        kind,
                        Some(target_spec.to_string()),
                        platform_predicate.clone(),
                        span_lines,
                        canonical_tree_root,
                        pkg_rel_dir,
                        manifest_rel,
                        workspace_deps,
                        node_errors,
                        diagnostics,
                        &mut out,
                    );
                }
            }
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn parse_dep_table(
    table: &dyn toml_edit::TableLike,
    kind: DependencyKind,
    platform_spec: Option<String>,
    platform_predicate: Option<Predicate>,
    span_lines: &dyn Fn(Option<std::ops::Range<usize>>) -> Option<(u64, u64)>,
    canonical_tree_root: &Path,
    pkg_rel_dir: &Path,
    manifest_rel: &Path,
    workspace_deps: &BTreeMap<String, WorkspaceDepTemplate>,
    node_errors: &mut Vec<String>,
    diagnostics: &mut Vec<AnalyzerDiagnostic>,
    out: &mut Vec<DeclaredDep>,
) {
    for (alias, item) in table.iter() {
        let key_span = table.key(alias).and_then(|k| k.span());
        let lines = span_lines(item.span().or(key_span));

        if let Some(version_text) = item.as_str() {
            let version_req = parse_dep_req(alias, version_text, manifest_rel, diagnostics);
            out.push(DeclaredDep {
                alias: alias.to_string(),
                crate_name: alias.to_string(),
                version_req,
                kind,
                optional: false,
                default_features: true,
                features: Vec::new(),
                platform_spec: platform_spec.clone(),
                platform_predicate: platform_predicate.clone(),
                registry_name: None,
                registry_index: None,
                git: None,
                in_tree_path: None,
                containment_error: None,
                lines,
            });
            continue;
        }

        let Some(dep_table) = item.as_table_like() else {
            diagnostics.push(AnalyzerDiagnostic {
                path: manifest_rel.to_path_buf(),
                message: format!("dependency '{alias}' is neither a string nor a table; skipped"),
            });
            continue;
        };

        let inherited = dep_table
            .get("workspace")
            .and_then(|w| w.as_bool())
            .unwrap_or(false)
            .then(|| workspace_deps.get(alias))
            .flatten();

        let crate_name = dep_table
            .get("package")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| inherited.and_then(|ws| ws.package.clone()))
            .unwrap_or_else(|| alias.to_string());

        let version_str = dep_table
            .get("version")
            .and_then(|v| v.as_str())
            .or_else(|| inherited.and_then(|ws| ws.version.as_deref()));
        let version_req =
            version_str.and_then(|v| parse_dep_req(alias, v, manifest_rel, diagnostics));

        let optional = dep_table
            .get("optional")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let default_features = dep_table
            .get("default-features")
            .or_else(|| dep_table.get("default_features"))
            .and_then(|v| v.as_bool())
            .map(|local| {
                // In Cargo, `[workspace.dependencies] default-features = false`
                // stays false unless `default-features = true` is set locally.
                let ws_df = inherited.and_then(|ws| ws.default_features).unwrap_or(true);
                ws_df || local
            })
            .unwrap_or_else(|| inherited.and_then(|ws| ws.default_features).unwrap_or(true));

        let mut features = inherited.map(|ws| ws.features.clone()).unwrap_or_default();
        features.extend(string_array(dep_table.get("features")));

        let registry_name = dep_table
            .get("registry")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| inherited.and_then(|ws| ws.registry.clone()));
        let registry_index = dep_table
            .get("registry-index")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| inherited.and_then(|ws| ws.registry_index.clone()));
        let git = dep_table
            .get("git")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| inherited.and_then(|ws| ws.git.clone()));

        let path_spec = dep_table
            .get("path")
            .and_then(|v| v.as_str())
            .map(|p| (p, pkg_rel_dir))
            .or_else(|| {
                inherited.and_then(|ws| ws.path.as_deref().map(|p| (p, ws.workspace_dir.as_path())))
            });

        let mut in_tree_path = None;
        let mut containment_error = None;
        if let Some((raw_path, base_dir)) = path_spec {
            match resolve_contained_path(canonical_tree_root, base_dir, Path::new(raw_path)) {
                Ok(resolved) => in_tree_path = Some(resolved),
                Err(reason) => {
                    let message = format!("path dependency '{alias}': {reason}");
                    node_errors.push(message.clone());
                    containment_error = Some(message);
                }
            }
        }

        out.push(DeclaredDep {
            alias: alias.to_string(),
            crate_name,
            version_req,
            kind,
            optional,
            default_features,
            features,
            platform_spec: platform_spec.clone(),
            platform_predicate: platform_predicate.clone(),
            registry_name,
            registry_index,
            git,
            in_tree_path,
            containment_error,
            lines,
        });
    }
}

fn parse_dep_req(
    alias: &str,
    raw: &str,
    manifest_rel: &Path,
    diagnostics: &mut Vec<AnalyzerDiagnostic>,
) -> Option<VersionConstraint> {
    match raw.parse::<VersionReq>() {
        Ok(req) => Some(VersionConstraint::SemVer(req)),
        Err(error) => {
            diagnostics.push(AnalyzerDiagnostic {
                path: manifest_rel.to_path_buf(),
                message: format!(
                    "dependency '{alias}' has invalid SemVer requirement '{}': {error}",
                    bounded(raw)
                ),
            });
            None
        }
    }
}

fn expand_workspace_members(
    root_doc: &toml_edit::Document<String>,
    canonical_tree_root: &Path,
    cargo_root_rel: &Path,
    root_manifest_rel: &Path,
    diagnostics: &mut Vec<AnalyzerDiagnostic>,
) -> BTreeSet<PathBuf> {
    let mut members = BTreeSet::new();
    let Some(ws) = root_doc.get("workspace").and_then(|i| i.as_table_like()) else {
        return members;
    };

    let excludes: Vec<PathBuf> = string_array(ws.get("exclude"))
        .into_iter()
        .filter_map(|raw| {
            match resolve_contained_path(canonical_tree_root, cargo_root_rel, Path::new(&raw)) {
                Ok(rel) => Some(rel),
                Err(reason) => {
                    diagnostics.push(AnalyzerDiagnostic {
                        path: root_manifest_rel.to_path_buf(),
                        message: format!("workspace.exclude: {reason}"),
                    });
                    None
                }
            }
        })
        .collect();

    let patterns = string_array(ws.get("members"));
    for pattern_str in patterns {
        // Check literal prefix containment before expanding any glob characters.
        if pattern_str.starts_with('/')
            || Path::new(&pattern_str).components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            // Normalize only when free of wildcards; otherwise reject `..`.
            if pattern_str.contains(['*', '?', '[']) {
                diagnostics.push(AnalyzerDiagnostic {
                    path: root_manifest_rel.to_path_buf(),
                    message: format!(
                        "workspace.members pattern '{}' cannot use '..' or absolute paths",
                        bounded(&pattern_str)
                    ),
                });
                continue;
            }
            match resolve_contained_path(
                canonical_tree_root,
                cargo_root_rel,
                Path::new(&pattern_str),
            ) {
                Ok(rel) => {
                    if !excludes.iter().any(|ex| rel.starts_with(ex))
                        && std::fs::symlink_metadata(
                            canonical_tree_root.join(&rel).join("Cargo.toml"),
                        )
                        .is_ok()
                    {
                        members.insert(rel);
                    }
                }
                Err(reason) => diagnostics.push(AnalyzerDiagnostic {
                    path: root_manifest_rel.to_path_buf(),
                    message: format!("workspace.members: {reason}"),
                }),
            }
            continue;
        }

        if !pattern_str.contains(['*', '?', '[']) {
            if let Ok(rel) =
                resolve_contained_path(canonical_tree_root, cargo_root_rel, Path::new(&pattern_str))
                && !excludes.iter().any(|ex| rel.starts_with(ex))
                && std::fs::symlink_metadata(canonical_tree_root.join(&rel).join("Cargo.toml"))
                    .is_ok()
            {
                members.insert(rel);
            }
            continue;
        }

        let compiled = match glob::Pattern::new(&pattern_str) {
            Ok(p) => p,
            Err(error) => {
                diagnostics.push(AnalyzerDiagnostic {
                    path: root_manifest_rel.to_path_buf(),
                    message: format!(
                        "invalid workspace.members glob '{}': {error}",
                        bounded(&pattern_str)
                    ),
                });
                continue;
            }
        };

        let root_abs = canonical_tree_root.join(cargo_root_rel);
        let max_depth = pattern_str.split('/').count() + 1;
        let walker = walkdir::WalkDir::new(&root_abs)
            .min_depth(1)
            .max_depth(max_depth)
            .into_iter()
            .filter_entry(|entry| {
                let name = entry.file_name().to_string_lossy();
                !matches!(name.as_ref(), "target" | ".git" | "node_modules")
            });
        for entry in walker.flatten() {
            if !entry.file_type().is_dir() {
                continue;
            }
            let Ok(rel_to_ws) = entry.path().strip_prefix(&root_abs) else {
                continue;
            };
            if !compiled.matches_path_with(rel_to_ws, MEMBER_GLOB) {
                continue;
            }
            if let Ok(rel) = resolve_contained_path(canonical_tree_root, cargo_root_rel, rel_to_ws)
                && !excludes.iter().any(|ex| rel.starts_with(ex))
                && std::fs::symlink_metadata(canonical_tree_root.join(&rel).join("Cargo.toml"))
                    .is_ok()
            {
                members.insert(rel);
            }
        }
    }

    members
}

fn parse_patch_paths(
    root_doc: &toml_edit::Document<String>,
    canonical_tree_root: &Path,
    cargo_root_rel: &Path,
    root_manifest_rel: &Path,
    diagnostics: &mut Vec<AnalyzerDiagnostic>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let Some(patch) = root_doc.get("patch").and_then(|i| i.as_table_like()) else {
        return dirs;
    };
    for (_source_key, source_item) in patch.iter() {
        let Some(source_table) = source_item.as_table_like() else {
            continue;
        };
        for (crate_key, crate_item) in source_table.iter() {
            let Some(raw_path) = crate_item
                .as_table_like()
                .and_then(|t| t.get("path"))
                .and_then(|p| p.as_str())
            else {
                continue;
            };
            match resolve_contained_path(canonical_tree_root, cargo_root_rel, Path::new(raw_path)) {
                Ok(rel) => dirs.push(rel),
                Err(reason) => diagnostics.push(AnalyzerDiagnostic {
                    path: root_manifest_rel.to_path_buf(),
                    message: format!("[patch] '{crate_key}': {reason}"),
                }),
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

fn load_in_tree_registries(
    canonical_tree_root: &Path,
    cargo_root_rel: &Path,
    root_doc: &toml_edit::Document<String>,
    max_file_bytes: u64,
    diagnostics: &mut Vec<AnalyzerDiagnostic>,
) -> BTreeMap<String, String> {
    let mut registries = BTreeMap::new();
    if let Some(table) = root_doc.get("registries").and_then(|i| i.as_table_like()) {
        collect_registries_table(table, &mut registries);
    }

    // Check `.cargo/config.toml` and `.cargo/config` at the tree root and Cargo root.
    let mut candidate_dirs = vec![PathBuf::new()];
    if !cargo_root_rel.as_os_str().is_empty() {
        candidate_dirs.push(cargo_root_rel.to_path_buf());
    }
    for dir in candidate_dirs {
        for name in [".cargo/config.toml", ".cargo/config"] {
            let candidate_rel = dir.join(name);
            if std::fs::symlink_metadata(canonical_tree_root.join(&candidate_rel)).is_err() {
                continue;
            }
            match read_contained_utf8(canonical_tree_root, &dir, Path::new(name), max_file_bytes)
                .and_then(|text| {
                    text.parse::<toml_edit::Document<String>>()
                        .map_err(|e| format_toml_error(&text, &e))
                }) {
                Ok(doc) => {
                    if let Some(table) = doc.get("registries").and_then(|i| i.as_table_like()) {
                        collect_registries_table(table, &mut registries);
                    }
                }
                Err(problem) => diagnostics.push(AnalyzerDiagnostic {
                    path: candidate_rel,
                    message: format!("could not parse Cargo config: {}", problem.trim()),
                }),
            }
        }
    }
    registries
}

fn collect_registries_table(table: &dyn toml_edit::TableLike, out: &mut BTreeMap<String, String>) {
    for (name, item) in table.iter() {
        if let Some(index) = item
            .as_table_like()
            .and_then(|t| t.get("index"))
            .and_then(|v| v.as_str())
        {
            out.insert(name.to_string(), index.to_string());
        }
    }
}

fn string_array(item: Option<&toml_edit::Item>) -> Vec<String> {
    item.and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn line_offsets(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(idx + 1);
        }
    }
    starts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceKind;
    use url::Url;

    fn test_source_id(dir: &Path) -> SourceId {
        SourceId {
            kind: SourceKind::Path {
                path: dir.to_path_buf(),
            },
            precise: Some("a".repeat(64)),
        }
    }

    #[test]
    fn rejects_lexical_and_symlink_path_escapes() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "secret").unwrap();

        let tree = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(tree.path()).unwrap();
        std::fs::create_dir_all(tree.path().join("crates/member")).unwrap();

        assert!(
            resolve_contained_path(
                &canonical,
                Path::new("crates/member"),
                Path::new("../../..")
            )
            .is_err()
        );
        assert!(
            resolve_contained_path(&canonical, Path::new(""), Path::new("/etc/passwd")).is_err()
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), tree.path().join("crates/escape_link"))
                .unwrap();
            assert!(
                resolve_contained_path(
                    &canonical,
                    Path::new("crates/member"),
                    Path::new("../escape_link")
                )
                .is_err()
            );
            // Regression: `escape_link/..` must inspect `escape_link` BEFORE
            // applying `..`, rather than cancelling it lexically!
            assert!(
                resolve_contained_path(
                    &canonical,
                    Path::new("crates"),
                    Path::new("escape_link/..")
                )
                .is_err()
            );

            // Intra-tree directory symlink followed by `..` resolves to the
            // symlink target's parent inside the tree, matching the OS kernel.
            std::fs::create_dir_all(tree.path().join("deep/nested/leaf")).unwrap();
            std::os::unix::fs::symlink(
                tree.path().join("deep/nested/leaf"),
                tree.path().join("crates/in_tree_link"),
            )
            .unwrap();
            let resolved = resolve_contained_path(
                &canonical,
                Path::new("crates"),
                Path::new("in_tree_link/.."),
            )
            .unwrap();
            assert_eq!(resolved, Path::new("deep/nested"));
        }

        let ok = resolve_contained_path(&canonical, Path::new("crates/member"), Path::new(".."))
            .unwrap();
        assert_eq!(ok, Path::new("crates"));
    }

    #[cfg(unix)]
    #[test]
    fn contained_reader_refuses_leaf_symlinks_fifos_and_enforces_read_limit() {
        let outside = tempfile::tempdir().unwrap();
        let secret = "OUT_OF_TREE_SECRET_CANARY_9912";
        let outside_file = outside.path().join("secret.toml");
        std::fs::write(&outside_file, format!("bad = [{secret}")).unwrap();

        let tree = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(tree.path()).unwrap();

        // 1. Leaf symlink at root `Cargo.toml` pointing outside: refused without
        //    reading or echoing `secret`.
        std::os::unix::fs::symlink(&outside_file, tree.path().join("Cargo.toml")).unwrap();
        let err = WorkspaceManifests::load(
            tree.path(),
            &test_source_id(tree.path()),
            Path::new(""),
            &AnalyzerLimits::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(!err.contains(secret), "leaked out-of-tree content: {err}");
        assert!(err.contains("symlink"), "{err}");
        std::fs::remove_file(tree.path().join("Cargo.toml")).unwrap();

        // 2. Intra-tree leaf symlink is also refused for control files.
        std::fs::write(
            tree.path().join("real.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("real.toml", tree.path().join("Cargo.toml")).unwrap();
        assert!(
            read_contained_utf8(&canonical, Path::new(""), Path::new("Cargo.toml"), 4096).is_err()
        );
        std::fs::remove_file(tree.path().join("Cargo.toml")).unwrap();

        // 3. FIFO special file at `Cargo.toml` and `build.rs`: rejected immediately
        //    without blocking on open.
        let fifo_path = tree.path().join("Cargo.toml");
        let cname = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        // Create FIFO via `mkfifo` binary so `#![forbid(unsafe_code)]` holds.
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .unwrap();
        let _ = cname;
        assert!(status.success());
        let err = read_contained_utf8(&canonical, Path::new(""), Path::new("Cargo.toml"), 4096)
            .unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        std::fs::remove_file(&fifo_path).unwrap();

        // 4. Byte limit enforced during read, and malformed TOML never quotes file text.
        std::fs::write(
            tree.path().join("Cargo.toml"),
            format!("[package]\nname = \"{secret}\"\nbroken = [unclosed\n"),
        )
        .unwrap();
        assert!(
            read_contained_utf8(&canonical, Path::new(""), Path::new("Cargo.toml"), 10).is_err()
        );
        let parse_err = WorkspaceManifests::load(
            tree.path(),
            &test_source_id(tree.path()),
            Path::new(""),
            &AnalyzerLimits::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(!parse_err.contains(secret), "{parse_err}");
    }

    #[test]
    fn workspace_inheritance_and_referenced_vendor_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("crates/app/src")).unwrap();
        std::fs::create_dir_all(dir.path().join("vendor/used/src")).unwrap();
        std::fs::create_dir_all(dir.path().join("vendor/unused/src")).unwrap();

        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"
[workspace]
members = ["crates/*"]
package = { version = "1.2.3" }

[workspace.dependencies]
used = { path = "vendor/used", version = "0.4.0" }
itoa = { version = "1.0", registry = "corp" }
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("crates/app/Cargo.toml"),
            r#"
[package]
name = "app"
version.workspace = true

[dependencies]
used.workspace = true
itoa = { workspace = true, optional = true }
"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("crates/app/src/main.rs"), "fn main() {}").unwrap();
        std::fs::write(
            dir.path().join("vendor/used/Cargo.toml"),
            "[package]\nname = \"used\"\nversion = \"0.4.0\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("vendor/used/src/lib.rs"), "").unwrap();
        std::fs::write(
            dir.path().join("vendor/unused/Cargo.toml"),
            "[package]\nname = \"unused\"\nversion = \"9.9.9\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("vendor/unused/src/lib.rs"), "").unwrap();

        let loaded = WorkspaceManifests::load(
            dir.path(),
            &test_source_id(dir.path()),
            Path::new(""),
            &AnalyzerLimits::default(),
        )
        .unwrap();

        let loaded_names: BTreeSet<&str> = loaded
            .packages
            .values()
            .map(|p| p.id.name.as_str())
            .collect();
        // `vendor/used` is referenced via `[workspace.dependencies]`;
        // `vendor/unused` is not referenced and is never loaded.
        assert_eq!(loaded_names, BTreeSet::from(["app", "used"]));

        let corp = RegistrySpec::named(
            "corp",
            "sparse+https://cargo.corp.example/index/",
            CredentialSource::Env {
                registry: "corp".into(),
            },
        )
        .unwrap();
        let _ = Url::parse("https://cargo.corp.example/index/").unwrap();
        let auth = loaded.referenced_authenticated_registries(&[corp]);
        assert!(auth.contains_key("corp"));
    }
}
