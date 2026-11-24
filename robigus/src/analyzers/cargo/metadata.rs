//! Mapping `cargo_metadata::Metadata` + `Cargo.lock` into [`AnalyzerOutput`]
//! (spec §8.1, §5.3; WP-2.2).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use cargo_metadata::{
    DependencyKind as CargoDepKind, Metadata, Package as CargoPackage, PackageId as CargoPackageId,
    TargetKind as CargoTargetKind,
};
use semver::VersionReq;

use super::cfg::{PackageFeatures, combine_predicates, platform_to_predicate};
use super::lockfile::{CargoLock, CargoSourceKind, classify_cargo_source};
use super::manifest::{
    WorkspaceManifests, append_build_script_and_links, node_rel_path, resolve_contained_path,
};
use crate::analyzers::{
    AnalyzerDiagnostic, AnalyzerLimits, AnalyzerOutput, ExpansionTask, NetworkMode,
};
use crate::error::AnalyzerError;
use crate::model::{
    AnalysisStrategy, AnalyzerId, Confidence, DependencyKind, Ecosystem, Edge, Evidence,
    EvidenceMethod, Node, PackageId, PackageVersion, PlanRow, PlanStatus, PlanSubject, Requirement,
    RequirementKind, SourceId, SourceLocation, Target, TargetKind, VersionConstraint,
};
use crate::predicate::Predicate;
use crate::registry::RegistrySpec;

/// Tier L3 confidence for manifest evidence when paired with `cargo metadata`.
const MANIFEST_CONFIDENCE: Confidence = Confidence::new(75);
/// Tier L3 confidence for `cargo metadata` output without a lockfile cross-check.
const TOOL_ALONE_CONFIDENCE: Confidence = Confidence::new(75);
/// Tier L3 confidence for declared-but-unresolved dependencies during online runs.
const UNRESOLVED_ONLINE_CONFIDENCE: Confidence = Confidence::new(70);
/// Tier L4 confidence for `Cargo.lock` pin evidence.
const LOCKFILE_CONFIDENCE: Confidence = Confidence::new(90);
/// Tier L4 confidence when `Manifest` and `ToolOutput` cross-validate an in-tree path crate.
const CROSS_CHECKED_PATH_CONFIDENCE: Confidence = Confidence::new(90);
/// Tier L4 confidence when `Manifest`, `Lockfile`, and `ToolOutput` all agree.
const CROSS_VALIDATED_CONFIDENCE: Confidence = Confidence::new(95);

// Short-lived per-run map entry; boxing `PackageId` would only add noise at
// every match arm (same rationale as `PlanSubject` in `model.rs`).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum PackageResolution {
    Resolved {
        id: PackageId,
        /// Set when the package's manifest lives inside the analyzed source tree
        /// (workspace member, in-tree `path` dep, or vendored crate).
        in_tree_dir: Option<PathBuf>,
        /// Location in `Cargo.lock`, when present.
        lock_location: Option<SourceLocation>,
        /// True when sources live outside the tree and need acquisition for
        /// transitive expansion.
        needs_expansion: bool,
    },
    Unresolved {
        reason: String,
    },
    PathEscaped {
        reason: String,
    },
}

/// Maps parsed `cargo metadata` output, optional host `Cargo.lock`, and
/// host-side [`WorkspaceManifests`] into a normalized [`AnalyzerOutput`].
///
/// `sandbox_source_root` is the path at which `manifests.canonical_tree_root`
/// appeared inside `cargo metadata` (`/source` for bubblewrap runs).
pub(super) fn map_cargo_metadata(
    metadata: &Metadata,
    sandbox_source_root: &Path,
    in_tree_source_id: &SourceId,
    manifests: &WorkspaceManifests,
    lockfile: Option<&CargoLock>,
    registries: &[RegistrySpec],
    limits: &AnalyzerLimits,
) -> Result<AnalyzerOutput, AnalyzerError> {
    let mut output = AnalyzerOutput {
        network_mode: NetworkMode::Allowlist,
        diagnostics: manifests.diagnostics.clone(),
        ..AnalyzerOutput::default()
    };

    let packages_by_id: BTreeMap<&CargoPackageId, &CargoPackage> =
        metadata.packages.iter().map(|pkg| (&pkg.id, pkg)).collect();

    let mut resolutions: BTreeMap<&CargoPackageId, PackageResolution> = BTreeMap::new();
    let mut seen_in_tree_ids: BTreeMap<PackageId, PathBuf> = BTreeMap::new();

    for pkg in &metadata.packages {
        let resolution = resolve_package_identity(
            pkg,
            sandbox_source_root,
            in_tree_source_id,
            manifests,
            lockfile,
            registries,
        );
        if let PackageResolution::Resolved {
            id,
            in_tree_dir: Some(dir),
            ..
        } = &resolution
        {
            if let Some(prev_dir) = seen_in_tree_ids.get(id)
                && prev_dir != dir
            {
                return Err(AnalyzerError::Inconsistent(format!(
                    "duplicate in-tree package identity '{id}' at '{}' and '{}'",
                    prev_dir.display(),
                    dir.display()
                )));
            }
            seen_in_tree_ids.insert(id.clone(), dir.clone());
        }
        resolutions.insert(&pkg.id, resolution);
    }

    let workspace_member_set: BTreeSet<&CargoPackageId> =
        metadata.workspace_members.iter().collect();
    for member_id in &metadata.workspace_members {
        if let Some(PackageResolution::Resolved { id, .. }) = resolutions.get(member_id) {
            output.roots.insert(id.clone());
        }
    }

    let resolve_nodes: BTreeMap<&CargoPackageId, &cargo_metadata::Node> = metadata
        .resolve
        .as_ref()
        .map(|resolve| resolve.nodes.iter().map(|n| (&n.id, n)).collect())
        .unwrap_or_default();

    // Per-package node errors (seeded from `WorkspaceManifests`, extended if
    // `cargo metadata` surfaces any path escape).
    let mut extra_node_errors: BTreeMap<PackageId, Vec<String>> = BTreeMap::new();

    // 1. Emit nodes, targets, active_features, expansion tasks, and build-script scans.
    for pkg in &metadata.packages {
        let Some(PackageResolution::Resolved {
            id,
            in_tree_dir,
            needs_expansion,
            ..
        }) = resolutions.get(&pkg.id)
        else {
            continue;
        };

        let mut node = Node::new(id.clone());
        node.path = in_tree_dir.as_deref().map(node_rel_path);
        if let Some(resolve_node) = resolve_nodes.get(&pkg.id) {
            node.active_features = resolve_node
                .features
                .iter()
                .map(|feat| feat.to_string())
                .collect();
        }
        node.targets = map_targets(
            pkg,
            sandbox_source_root,
            &manifests.canonical_tree_root,
            in_tree_dir.is_some(),
            &mut output.diagnostics,
        );
        output.nodes.push(node);

        if *needs_expansion {
            output.expansions.push(ExpansionTask {
                package: id.clone(),
            });
        }

        if let Some(rel_dir) = in_tree_dir {
            if let Some(parsed_pkg) = manifests.packages.get(rel_dir) {
                append_build_script_and_links(
                    parsed_pkg,
                    &manifests.canonical_tree_root,
                    limits,
                    &mut output,
                );
                if !parsed_pkg.node_errors.is_empty() {
                    extra_node_errors
                        .entry(id.clone())
                        .or_default()
                        .extend(parsed_pkg.node_errors.iter().cloned());
                }
            } else {
                // Vendored crate under `vendor/` discovered via `.cargo/config.toml`
                // replacement (not loaded during workspace manifest pre-pass).
                scan_vendored_package_build_script(
                    pkg,
                    id,
                    rel_dir,
                    sandbox_source_root,
                    &manifests.canonical_tree_root,
                    limits,
                    &mut output,
                );
            }
        }
    }

    // 2. Emit dependency edges for every resolved node in `metadata.packages`.
    for pkg in &metadata.packages {
        let Some(PackageResolution::Resolved {
            id: from_id,
            in_tree_dir,
            ..
        }) = resolutions.get(&pkg.id)
        else {
            continue;
        };

        let parsed_manifest = in_tree_dir
            .as_ref()
            .and_then(|dir| manifests.packages.get(dir));
        let manifest_rel_for_diag = in_tree_dir
            .as_ref()
            .map(|d| d.join("Cargo.toml"))
            .unwrap_or_default();

        let optional_aliases: BTreeSet<String> = pkg
            .dependencies
            .iter()
            .filter(|d| d.optional)
            .map(|d| d.rename.clone().unwrap_or_else(|| d.name.clone()))
            .collect();
        let (feature_model, feature_errors) =
            PackageFeatures::from_raw(&pkg.features, &optional_aliases);
        if in_tree_dir.is_some() {
            for error in feature_errors {
                output.diagnostics.push(AnalyzerDiagnostic {
                    path: manifest_rel_for_diag.clone(),
                    message: error.to_string(),
                });
            }
        }

        let resolve_node = resolve_nodes.get(&pkg.id).copied();
        // Track `(NodeDep index, DepKindInfo index)` consumed by declared deps so
        // any synthetic resolve edge is still emitted afterward.
        let mut consumed_resolve_kinds: BTreeSet<(usize, usize)> = BTreeSet::new();

        // Match constrained declarations (`req != *`) before wildcard (`*`)
        // declarations, sorted deterministically so declaration ordering in
        // `pkg.dependencies` cannot change which candidate is claimed.
        let mut ordered_decls: Vec<&cargo_metadata::Dependency> = pkg.dependencies.iter().collect();
        ordered_decls.sort_by_key(|d| {
            (
                d.req == VersionReq::STAR,
                d.name.as_str(),
                d.rename.as_deref().unwrap_or(""),
                d.req.to_string(),
                d.kind.to_string(),
                d.target.as_ref().map(ToString::to_string),
            )
        });

        for decl in ordered_decls {
            let Some(dep_kind) = map_dep_kind(decl.kind) else {
                continue;
            };
            let alias = decl.rename.as_deref().unwrap_or(&decl.name);
            let extern_alias = alias.replace('-', "_");
            let platform_spec = decl.target.as_ref().map(ToString::to_string);
            let platform_pred = match &decl.target {
                Some(platform) => match platform_to_predicate(platform) {
                    Ok(pred) => Some(pred),
                    Err(problem) => {
                        output.diagnostics.push(AnalyzerDiagnostic {
                            path: manifest_rel_for_diag.clone(),
                            message: problem,
                        });
                        continue;
                    }
                },
                None => None,
            };
            let optional_pred = decl
                .optional
                .then(|| feature_model.activation_predicate(alias));
            let predicate = combine_predicates(platform_pred, optional_pred);

            let version_req = dependency_version_req(decl, parsed_manifest, alias, dep_kind);
            let requirement = Requirement {
                kind: RequirementKind::Crate,
                name: decl.name.clone(),
                version_req,
            };
            let manifest_loc = parsed_manifest.map(|pm| {
                pm.declaration_location(&decl.name, Some(alias), dep_kind, platform_spec.as_deref())
            });
            let forwarded = feature_model.forwarded_subfeatures(alias);
            let forwarded_note = (!forwarded.is_empty())
                .then(|| format!("feature forwarding: {}", forwarded.join(", ")));

            let matched_target = find_matching_resolve_dep(
                resolve_node,
                &packages_by_id,
                decl,
                &extern_alias,
                registries,
                &mut consumed_resolve_kinds,
            );

            match matched_target {
                ResolveMatch::Matched(target_cargo_pkg) => {
                    match resolutions.get(&target_cargo_pkg.id) {
                        Some(PackageResolution::Resolved {
                            id: to_id,
                            in_tree_dir: target_in_tree,
                            lock_location,
                            ..
                        }) => {
                            let (confidence, evidence) = build_resolved_evidence(
                                manifest_loc,
                                lock_location.clone(),
                                target_in_tree.is_some() && target_cargo_pkg.source.is_none(),
                                forwarded_note.as_deref(),
                            );
                            output.edges.push(Edge {
                                from: from_id.clone(),
                                to: Some(to_id.clone()),
                                requirement,
                                kinds: BTreeSet::from([dep_kind]),
                                predicate,
                                confidence,
                                evidence,
                            });
                        }
                        Some(PackageResolution::Unresolved { reason }) => {
                            let detail =
                                join_notes(Some(reason.as_str()), forwarded_note.as_deref());
                            let evidence = build_unresolved_online_evidence(manifest_loc, detail);
                            output.edges.push(Edge {
                                from: from_id.clone(),
                                to: None,
                                requirement,
                                kinds: BTreeSet::from([dep_kind]),
                                predicate,
                                confidence: UNRESOLVED_ONLINE_CONFIDENCE,
                                evidence,
                            });
                        }
                        Some(PackageResolution::PathEscaped { reason }) => {
                            extra_node_errors
                                .entry(from_id.clone())
                                .or_default()
                                .push(reason.clone());
                        }
                        None => {}
                    }
                }
                ResolveMatch::Ambiguous(reason) => {
                    output.diagnostics.push(AnalyzerDiagnostic {
                        path: manifest_rel_for_diag.clone(),
                        message: reason.clone(),
                    });
                    let detail = join_notes(Some(reason.as_str()), forwarded_note.as_deref());
                    let evidence = build_unresolved_online_evidence(manifest_loc, detail);
                    output.edges.push(Edge {
                        from: from_id.clone(),
                        to: None,
                        requirement,
                        kinds: BTreeSet::from([dep_kind]),
                        predicate,
                        confidence: UNRESOLVED_ONLINE_CONFIDENCE,
                        evidence,
                    });
                }
                ResolveMatch::None => {
                    let base_reason = unresolved_declaration_reason(decl, registries);
                    let detail = join_notes(Some(base_reason.as_str()), forwarded_note.as_deref());
                    let evidence = build_unresolved_online_evidence(manifest_loc, detail);
                    output.edges.push(Edge {
                        from: from_id.clone(),
                        to: None,
                        requirement,
                        kinds: BTreeSet::from([dep_kind]),
                        predicate,
                        confidence: UNRESOLVED_ONLINE_CONFIDENCE,
                        evidence,
                    });
                }
            }
        }

        // Safety net: preserve any resolved edge that `P.dependencies` did not consume.
        if let Some(rnode) = resolve_node {
            for (dep_idx, node_dep) in rnode.deps.iter().enumerate() {
                let Some(target_pkg) = packages_by_id.get(&node_dep.pkg).copied() else {
                    continue;
                };
                for (kind_idx, kind_info) in node_dep.dep_kinds.iter().enumerate() {
                    if consumed_resolve_kinds.contains(&(dep_idx, kind_idx)) {
                        continue;
                    }
                    let Some(dep_kind) = map_dep_kind(kind_info.kind) else {
                        continue;
                    };
                    let predicate = match &kind_info.target {
                        Some(platform) => match platform_to_predicate(platform) {
                            Ok(pred) => pred,
                            Err(_) => continue,
                        },
                        None => Predicate::TRUE,
                    };
                    if let Some(PackageResolution::Resolved {
                        id: to_id,
                        lock_location,
                        in_tree_dir: target_in_tree,
                        ..
                    }) = resolutions.get(&target_pkg.id)
                    {
                        output.diagnostics.push(AnalyzerDiagnostic {
                            path: manifest_rel_for_diag.clone(),
                            message: format!(
                                "resolved dependency '{} {}' from '{}' did not match any manifest declaration",
                                target_pkg.name, target_pkg.version, pkg.name
                            ),
                        });
                        let (confidence, evidence) = build_resolved_evidence(
                            None,
                            lock_location.clone(),
                            target_in_tree.is_some() && target_pkg.source.is_none(),
                            Some("unmatched cargo metadata resolve edge"),
                        );
                        output.edges.push(Edge {
                            from: from_id.clone(),
                            to: Some(to_id.clone()),
                            requirement: Requirement {
                                kind: RequirementKind::Crate,
                                name: target_pkg.name.to_string(),
                                version_req: None,
                            },
                            kinds: BTreeSet::from([dep_kind]),
                            predicate,
                            confidence,
                            evidence,
                        });
                    }
                }
            }
        }

        // Emit `Manifest` and `ToolIntrospection` plan rows for in-tree packages
        // (and workspace members).
        if in_tree_dir.is_some() || workspace_member_set.contains(&pkg.id) {
            let errors = extra_node_errors.get(from_id);
            let has_errors = errors.is_some_and(|e| !e.is_empty());

            let mut manifest_row = PlanRow::new(
                PlanSubject::Package(from_id.clone()),
                AnalyzerId::Cargo,
                AnalysisStrategy::Manifest,
                None,
                if has_errors {
                    PlanStatus::Failed
                } else {
                    PlanStatus::Complete
                },
            );
            manifest_row.attempts = 1;
            if let Some(errs) = errors
                && !errs.is_empty()
            {
                manifest_row.error = Some(errs.join("; "));
            }
            output.plan.push(manifest_row);

            let mut tool_row = PlanRow::new(
                PlanSubject::Package(from_id.clone()),
                AnalyzerId::Cargo,
                AnalysisStrategy::ToolIntrospection,
                None,
                PlanStatus::Complete,
            );
            tool_row.attempts = 1;
            tool_row.detail = Some("cargo metadata --format-version 1".to_string());
            output.plan.push(tool_row);
        }
    }

    output.normalize();
    Ok(output)
}

fn resolve_package_identity(
    pkg: &CargoPackage,
    sandbox_source_root: &Path,
    in_tree_source_id: &SourceId,
    manifests: &WorkspaceManifests,
    lockfile: Option<&CargoLock>,
    registries: &[RegistrySpec],
) -> PackageResolution {
    let manifest_std = pkg.manifest_path.as_std_path();
    let in_tree_dir = manifest_std
        .parent()
        .and_then(|dir| dir.strip_prefix(sandbox_source_root).ok())
        .and_then(|rel| {
            resolve_contained_path(&manifests.canonical_tree_root, Path::new(""), rel).ok()
        });

    let Some(source) = &pkg.source else {
        let Some(rel_dir) = in_tree_dir else {
            return PackageResolution::PathEscaped {
                reason: format!(
                    "path package '{} {}' at '{}' escapes the source tree",
                    pkg.name, pkg.version, pkg.manifest_path
                ),
            };
        };
        return PackageResolution::Resolved {
            id: PackageId {
                name: pkg.name.to_string(),
                version: PackageVersion::SemVer(pkg.version.clone()),
                source_id: in_tree_source_id.clone(),
                ecosystem: Ecosystem::Rust,
            },
            in_tree_dir: Some(rel_dir),
            lock_location: None,
            needs_expansion: false,
        };
    };

    match classify_cargo_source(&source.repr, registries) {
        CargoSourceKind::Registry { index_url } => {
            let Some(lock) = lockfile else {
                return PackageResolution::Unresolved {
                    reason: format!(
                        "registry crate '{} {}' ({index_url}) has no Cargo.lock checksum \
                         (project has no Cargo.lock)",
                        pkg.name, pkg.version
                    ),
                };
            };
            match lock.resolve_registry_source_id(pkg.name.as_str(), &pkg.version, &index_url) {
                Ok((source_id, lock_location)) => PackageResolution::Resolved {
                    id: PackageId {
                        name: pkg.name.to_string(),
                        version: PackageVersion::SemVer(pkg.version.clone()),
                        source_id,
                        ecosystem: Ecosystem::Rust,
                    },
                    needs_expansion: in_tree_dir.is_none(),
                    in_tree_dir,
                    lock_location: Some(lock_location),
                },
                Err(reason) => PackageResolution::Unresolved { reason },
            }
        }
        CargoSourceKind::UnsupportedGitRegistry { raw } => PackageResolution::Unresolved {
            reason: format!(
                "crate '{} {}' uses unsupported git-protocol registry '{raw}'; \
                 only sparse+https registries are supported",
                pkg.name, pkg.version
            ),
        },
        CargoSourceKind::Git {
            url,
            reference,
            commit,
        } => {
            let Some(lock) = lockfile else {
                return PackageResolution::Unresolved {
                    reason: format!(
                        "git crate '{} {}' ({url}) is not pinned by a committed Cargo.lock \
                         (commit {commit} was resolved dynamically during analysis)",
                        pkg.name, pkg.version
                    ),
                };
            };
            match lock.resolve_git_source_id(
                pkg.name.as_str(),
                &pkg.version,
                &url,
                reference,
                &commit,
            ) {
                Ok((source_id, lock_location)) => PackageResolution::Resolved {
                    id: PackageId {
                        name: pkg.name.to_string(),
                        version: PackageVersion::SemVer(pkg.version.clone()),
                        source_id,
                        ecosystem: Ecosystem::Rust,
                    },
                    needs_expansion: in_tree_dir.is_none(),
                    in_tree_dir,
                    lock_location: Some(lock_location),
                },
                Err(reason) => PackageResolution::Unresolved { reason },
            }
        }
        CargoSourceKind::UnpinnedGit { reason } | CargoSourceKind::Unsupported { reason } => {
            PackageResolution::Unresolved { reason }
        }
    }
}

enum ResolveMatch<'a> {
    Matched(&'a CargoPackage),
    Ambiguous(String),
    None,
}

fn find_matching_resolve_dep<'a>(
    resolve_node: Option<&'a cargo_metadata::Node>,
    packages_by_id: &BTreeMap<&CargoPackageId, &'a CargoPackage>,
    decl: &cargo_metadata::Dependency,
    extern_alias: &str,
    registries: &[RegistrySpec],
    consumed: &mut BTreeSet<(usize, usize)>,
) -> ResolveMatch<'a> {
    let Some(rnode) = resolve_node else {
        return ResolveMatch::None;
    };

    let mut candidates: Vec<(usize, usize, &'a CargoPackage)> = Vec::new();
    for (dep_idx, node_dep) in rnode.deps.iter().enumerate() {
        let Some(target_pkg) = packages_by_id.get(&node_dep.pkg).copied() else {
            continue;
        };
        if target_pkg.name.as_str() != decl.name {
            continue;
        }
        let target_lib_extern = target_pkg
            .targets
            .iter()
            .find(|t| {
                t.kind.iter().any(|k| {
                    matches!(
                        k,
                        CargoTargetKind::Lib
                            | CargoTargetKind::RLib
                            | CargoTargetKind::DyLib
                            | CargoTargetKind::ProcMacro
                            | CargoTargetKind::CDyLib
                            | CargoTargetKind::StaticLib
                    )
                })
            })
            .map(|t| t.name.replace('-', "_"));
        // When `rename` is set, Cargo always sets `node_dep.name` to the
        // renamed crate identifier; when `rename` is `None`, Cargo uses the
        // target crate's library extern name (falling back to `extern_alias`
        // when no library target is present).
        let alias_matches = if decl.rename.is_some() {
            node_dep.name == extern_alias
        } else {
            match target_lib_extern.as_deref() {
                Some(lib_extern) => node_dep.name == lib_extern,
                None => node_dep.name == extern_alias,
            }
        };
        if !alias_matches {
            continue;
        }
        for (kind_idx, info) in node_dep.dep_kinds.iter().enumerate() {
            if !consumed.contains(&(dep_idx, kind_idx))
                && info.kind == decl.kind
                && info.target == decl.target
            {
                candidates.push((dep_idx, kind_idx, target_pkg));
                break;
            }
        }
    }

    if candidates.is_empty() {
        return ResolveMatch::None;
    }

    // Prefer candidates matching both declared version requirement and source,
    // then candidates matching version requirement (handling `[patch]` source
    // overrides), and finally a sole remaining candidate (handling `[patch]`
    // version overrides). Never pick arbitrarily by iteration order when two
    // candidates tie.
    let exact: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|(_, _, pkg)| {
            decl_version_matches(&decl.req, &pkg.version)
                && decl_source_matches_target(decl, pkg, registries)
        })
        .collect();
    if exact.len() == 1 {
        let (dep_idx, kind_idx, pkg) = exact[0];
        consumed.insert((dep_idx, kind_idx));
        return ResolveMatch::Matched(pkg);
    }
    if exact.len() > 1 {
        return ResolveMatch::Ambiguous(ambiguous_candidates_message(decl, &exact));
    }

    let ver_matched: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|(_, _, pkg)| decl_version_matches(&decl.req, &pkg.version))
        .collect();
    if ver_matched.len() == 1 {
        let (dep_idx, kind_idx, pkg) = ver_matched[0];
        consumed.insert((dep_idx, kind_idx));
        return ResolveMatch::Matched(pkg);
    }
    if ver_matched.len() > 1 {
        return ResolveMatch::Ambiguous(ambiguous_candidates_message(decl, &ver_matched));
    }

    if candidates.len() == 1 {
        let (dep_idx, kind_idx, pkg) = candidates[0];
        consumed.insert((dep_idx, kind_idx));
        return ResolveMatch::Matched(pkg);
    }
    ResolveMatch::Ambiguous(ambiguous_candidates_message(decl, &candidates))
}

fn decl_version_matches(req: &VersionReq, version: &semver::Version) -> bool {
    if req.matches(version) {
        return true;
    }
    // Cargo ignores `+build` metadata when matching SemVer requirements.
    if !version.build.is_empty() {
        let mut stripped = version.clone();
        stripped.build = semver::BuildMetadata::EMPTY;
        return req.matches(&stripped);
    }
    false
}

fn decl_source_matches_target(
    decl: &cargo_metadata::Dependency,
    target_pkg: &CargoPackage,
    registries: &[RegistrySpec],
) -> bool {
    match (&decl.source, &target_pkg.source) {
        (None, None) => true,
        (Some(decl_src), Some(pkg_src)) => {
            match (
                classify_cargo_source(&decl_src.repr, registries),
                classify_cargo_source(&pkg_src.repr, registries),
            ) {
                (
                    CargoSourceKind::Registry { index_url: a },
                    CargoSourceKind::Registry { index_url: b },
                ) => a == b,
                (CargoSourceKind::Git { url: a, .. }, CargoSourceKind::Git { url: b, .. }) => {
                    a == b
                }
                _ => decl_src.repr == pkg_src.repr,
            }
        }
        _ => false,
    }
}

fn ambiguous_candidates_message(
    decl: &cargo_metadata::Dependency,
    candidates: &[(usize, usize, &CargoPackage)],
) -> String {
    let mut ids: Vec<String> = candidates
        .iter()
        .map(|(_, _, pkg)| format!("{} {}", pkg.name, pkg.version))
        .collect();
    ids.sort();
    format!(
        "ambiguous cargo metadata resolution for declaration '{}' ({}): candidates [{}]",
        decl.rename.as_deref().unwrap_or(&decl.name),
        decl.req,
        ids.join(", ")
    )
}

fn dependency_version_req(
    decl: &cargo_metadata::Dependency,
    parsed_manifest: Option<&super::manifest::ParsedCargoPackage>,
    alias: &str,
    dep_kind: DependencyKind,
) -> Option<VersionConstraint> {
    if decl.req != VersionReq::STAR {
        return Some(VersionConstraint::SemVer(decl.req.clone()));
    }
    // `cargo metadata` reports `*` both when the user wrote `version = "*"` and
    // when a path/git dependency omitted `version` entirely. Consult the parsed
    // in-tree manifest when available so omitted versions stay `None`.
    if let Some(pm) = parsed_manifest
        && let Some(found) = pm
            .declarations
            .iter()
            .find(|d| d.crate_name == decl.name && d.alias == alias && d.kind == dep_kind)
    {
        return found.version_req.clone();
    }
    if decl.path.is_some() && decl.source.is_none() {
        None
    } else {
        Some(VersionConstraint::SemVer(decl.req.clone()))
    }
}

fn build_resolved_evidence(
    manifest_loc: Option<SourceLocation>,
    lock_loc: Option<SourceLocation>,
    is_in_tree_path_target: bool,
    extra_note: Option<&str>,
) -> (Confidence, Vec<Evidence>) {
    let mut evidence = Vec::new();
    let has_manifest = manifest_loc.is_some();
    if let Some(loc) = manifest_loc {
        evidence.push(Evidence {
            method: EvidenceMethod::Manifest,
            confidence: MANIFEST_CONFIDENCE,
            location: Some(loc),
            detail: extra_note.map(str::to_owned),
        });
    }
    let has_lock = lock_loc.is_some();
    if let Some(loc) = lock_loc {
        evidence.push(Evidence {
            method: EvidenceMethod::Lockfile,
            confidence: LOCKFILE_CONFIDENCE,
            location: Some(loc),
            detail: Some("pinned in Cargo.lock".to_string()),
        });
    }
    let tool_confidence = if has_lock {
        CROSS_VALIDATED_CONFIDENCE
    } else if has_manifest && is_in_tree_path_target {
        CROSS_CHECKED_PATH_CONFIDENCE
    } else {
        TOOL_ALONE_CONFIDENCE
    };
    evidence.push(Evidence {
        method: EvidenceMethod::ToolOutput,
        confidence: tool_confidence,
        location: None,
        detail: Some(join_notes(Some("resolved by cargo metadata"), extra_note)),
    });
    let max_conf = evidence
        .iter()
        .map(|e| e.confidence)
        .max()
        .unwrap_or(TOOL_ALONE_CONFIDENCE);
    (max_conf, evidence)
}

fn build_unresolved_online_evidence(
    manifest_loc: Option<SourceLocation>,
    detail: String,
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    if let Some(loc) = manifest_loc {
        evidence.push(Evidence {
            method: EvidenceMethod::Manifest,
            confidence: UNRESOLVED_ONLINE_CONFIDENCE,
            location: Some(loc),
            detail: Some(detail.clone()),
        });
    }
    evidence.push(Evidence {
        method: EvidenceMethod::ToolOutput,
        confidence: UNRESOLVED_ONLINE_CONFIDENCE,
        location: None,
        detail: Some(detail),
    });
    evidence
}

fn unresolved_declaration_reason(
    decl: &cargo_metadata::Dependency,
    registries: &[RegistrySpec],
) -> String {
    if let Some(reg_url) = &decl.registry {
        if let CargoSourceKind::Registry { index_url } =
            classify_cargo_source(&format!("sparse+{reg_url}"), registries)
            && let Some(spec) = registries.iter().find(|s| s.index_url == index_url)
        {
            let label = spec.name.as_deref().unwrap_or(index_url.as_str());
            if decl.optional {
                return format!(
                    "optional dependency '{}' from registry '{label}' ({index_url}) \
                     is not enabled in the resolved feature set",
                    decl.name
                );
            }
            return format!(
                "unresolved dependency '{}' from registry '{label}' ({index_url})",
                decl.name
            );
        }
        return format!("unresolved dependency from registry '{reg_url}'");
    }
    if decl.optional {
        return format!(
            "optional dependency '{}' is not enabled in the resolved feature set",
            decl.name
        );
    }
    format!(
        "dependency '{}' was not present in the cargo metadata resolve graph",
        decl.name
    )
}

fn join_notes(primary: Option<&str>, secondary: Option<&str>) -> String {
    match (primary, secondary) {
        (Some(a), Some(b)) if !a.is_empty() && !b.is_empty() => format!("{a}; {b}"),
        (Some(a), _) => a.to_string(),
        (None, Some(b)) => b.to_string(),
        (None, None) => String::new(),
    }
}

fn map_dep_kind(kind: CargoDepKind) -> Option<DependencyKind> {
    match kind {
        CargoDepKind::Normal => Some(DependencyKind::Normal),
        CargoDepKind::Build => Some(DependencyKind::Build),
        CargoDepKind::Development => Some(DependencyKind::Development),
        _ => None,
    }
}

fn map_targets(
    pkg: &CargoPackage,
    sandbox_source_root: &Path,
    canonical_tree_root: &Path,
    in_tree: bool,
    diagnostics: &mut Vec<AnalyzerDiagnostic>,
) -> Vec<Target> {
    let mut out = Vec::new();
    for target in &pkg.targets {
        let rel_src_path = if in_tree {
            target
                .src_path
                .as_std_path()
                .strip_prefix(sandbox_source_root)
                .ok()
                .and_then(|rel| {
                    match resolve_contained_path(canonical_tree_root, Path::new(""), rel) {
                        Ok(contained) if !contained.as_os_str().is_empty() => Some(contained),
                        Ok(_) => None,
                        Err(problem) => {
                            diagnostics.push(AnalyzerDiagnostic {
                                path: PathBuf::new(),
                                message: format!("target '{}': {problem}", target.name),
                            });
                            None
                        }
                    }
                })
        } else {
            None
        };

        for kind in &target.kind {
            let mapped = match kind {
                CargoTargetKind::Lib | CargoTargetKind::RLib | CargoTargetKind::DyLib => {
                    Some(TargetKind::RustLib { proc_macro: false })
                }
                CargoTargetKind::ProcMacro => Some(TargetKind::RustLib { proc_macro: true }),
                CargoTargetKind::CDyLib => Some(TargetKind::SharedLibrary { soname: None }),
                CargoTargetKind::StaticLib => Some(TargetKind::StaticLibrary),
                CargoTargetKind::Bin => Some(TargetKind::Binary),
                CargoTargetKind::CustomBuild
                | CargoTargetKind::Test
                | CargoTargetKind::Bench
                | CargoTargetKind::Example
                | CargoTargetKind::Unknown(_) => None,
                _ => None,
            };
            if let Some(mapped_kind) = mapped {
                out.push(Target {
                    name: target.name.clone(),
                    kind: mapped_kind,
                    path: rel_src_path.clone(),
                });
            }
        }
    }
    out
}

fn scan_vendored_package_build_script(
    pkg: &CargoPackage,
    id: &PackageId,
    rel_dir: &Path,
    sandbox_source_root: &Path,
    canonical_tree_root: &Path,
    limits: &AnalyzerLimits,
    output: &mut AnalyzerOutput,
) {
    let manifest_rel = rel_dir.join("Cargo.toml");
    if let Some(links) = &pkg.links {
        output.edges.push(super::build_script::links_edge(
            id,
            links,
            &manifest_rel,
            None,
        ));
    }
    let Some(custom_build) = pkg
        .targets
        .iter()
        .find(|t| t.kind.contains(&CargoTargetKind::CustomBuild))
    else {
        return;
    };
    let Some(raw_rel) = custom_build
        .src_path
        .as_std_path()
        .strip_prefix(sandbox_source_root)
        .ok()
    else {
        return;
    };
    let Ok(script_rel) = resolve_contained_path(canonical_tree_root, Path::new(""), raw_rel) else {
        return;
    };
    let mut row = PlanRow::new(
        PlanSubject::Package(id.clone()),
        AnalyzerId::Cargo,
        AnalysisStrategy::Manifest,
        Some(crate::model::BuildSystem::BuildScript),
        PlanStatus::Complete,
    );
    row.attempts = 1;
    if let Ok(source) = super::manifest::read_contained_utf8(
        canonical_tree_root,
        Path::new(""),
        &script_rel,
        limits.max_file_bytes,
    ) {
        let findings = super::build_script::scan_build_script(&source);
        row.detail = Some(format!(
            "scanned '{}' ({} finding(s))",
            script_rel.display(),
            findings.len()
        ));
        output.edges.extend(super::build_script::findings_to_edges(
            id,
            &script_rel,
            &findings,
        ));
    }
    output.plan.push(row);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialSource;
    use crate::model::{ConfidenceTier, GitReference, SourceKind};
    use crate::registry::CRATES_IO_INDEX;
    use crate::store::{AnalysisMetadata, Store};
    use serde_json::json;
    use url::Url;

    const ITOA_CKSUM: &str = "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b";
    const HEX_CKSUM: &str = "7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70";
    const GIT_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn setup_workspace(dir: &Path) {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
edition = "2021"
links = "z"

[dependencies]
hx = { package = "hex", version = "^0.4" }
itoa = { version = "^1.0", optional = true }
nocksum = "^0.2"
gitreg = { version = "^0.1", registry = "othergit" }
privdep = { version = "^1.0", registry = "corp" }
gitlib = { git = "https://github.com/example/gitlib.git", tag = "v0.3.0" }

[build-dependencies]
hx = { package = "hex", version = "^0.4" }

[target.'cfg(unix)'.dependencies]
itoa = { version = "^1.0", optional = true }

[features]
default = ["fast"]
fast = ["dep:itoa"]
"#,
        )
        .unwrap();
        std::fs::write(dir.join("src/lib.rs"), "").unwrap();
        std::fs::write(
            dir.join("build.rs"),
            "fn main() { pkg_config::probe_library(\"zlib\").unwrap(); }\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("Cargo.lock"),
            format!(
                r#"version = 4

[[package]]
name = "hex"
version = "0.4.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{HEX_CKSUM}"

[[package]]
name = "itoa"
version = "1.0.11"
source = "sparse+https://index.crates.io/"
checksum = "{ITOA_CKSUM}"

[[package]]
name = "nocksum"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "gitlib"
version = "0.3.0"
source = "git+https://github.com/example/gitlib.git?tag=v0.3.0#{GIT_COMMIT}"
"#
            ),
        )
        .unwrap();
    }

    fn sample_metadata_json() -> serde_json::Value {
        let demo_id = "path+file:///source#demo@0.1.0";
        let hex_id = "registry+https://github.com/rust-lang/crates.io-index#hex@0.4.3";
        let itoa_id = "sparse+https://Index.Crates.IO:443/#itoa@1.0.11";
        let nocksum_id = "registry+https://github.com/rust-lang/crates.io-index#nocksum@0.2.0";
        let gitreg_id = "registry+https://git.other.example/index#gitreg@0.1.0";
        let priv_id = "sparse+https://cargo.corp.example/index/#privdep@1.0.0";
        let gitlib_id =
            format!("git+https://github.com/example/gitlib.git?tag=v0.3.0#{GIT_COMMIT}");

        json!({
            "packages": [
                {
                    "name": "demo",
                    "version": "0.1.0",
                    "id": demo_id,
                    "source": null,
                    "dependencies": [
                        {
                            "name": "hex", "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "req": "^0.4", "kind": null, "rename": "hx", "optional": false,
                            "uses_default_features": true, "features": [], "target": null
                        },
                        {
                            "name": "hex", "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "req": "^0.4", "kind": "build", "rename": "hx", "optional": false,
                            "uses_default_features": true, "features": [], "target": null
                        },
                        {
                            "name": "itoa", "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "req": "^1.0", "kind": null, "rename": null, "optional": true,
                            "uses_default_features": true, "features": [], "target": "cfg(unix)"
                        },
                        {
                            "name": "nocksum", "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "req": "^0.2", "kind": null, "rename": null, "optional": false,
                            "uses_default_features": true, "features": [], "target": null
                        },
                        {
                            "name": "gitreg", "source": "registry+https://git.other.example/index",
                            "req": "^0.1", "kind": null, "rename": null, "optional": false,
                            "uses_default_features": true, "features": [], "target": null
                        },
                        {
                            "name": "privdep", "source": "sparse+https://cargo.corp.example/index/",
                            "req": "^1.0", "kind": null, "rename": null, "optional": false,
                            "uses_default_features": true, "features": [], "target": null,
                            "registry": "https://cargo.corp.example/index/"
                        },
                        {
                            "name": "gitlib", "source": format!("git+https://github.com/example/gitlib.git?tag=v0.3.0#{GIT_COMMIT}"),
                            "req": "*", "kind": null, "rename": null, "optional": false,
                            "uses_default_features": true, "features": [], "target": null
                        }
                    ],
                    "targets": [
                        {
                            "kind": ["lib", "cdylib"], "crate_types": ["lib", "cdylib"],
                            "name": "demo", "src_path": "/source/src/lib.rs", "edition": "2021"
                        },
                        {
                            "kind": ["custom-build"], "crate_types": ["bin"],
                            "name": "build-script-build", "src_path": "/source/build.rs", "edition": "2021"
                        },
                        {
                            "kind": ["test"], "crate_types": ["bin"],
                            "name": "demo", "src_path": "/source/tests/demo.rs", "edition": "2021"
                        }
                    ],
                    "features": { "default": ["fast"], "fast": ["dep:itoa"] },
                    "manifest_path": "/source/Cargo.toml",
                    "links": "z"
                },
                {
                    "name": "hex", "version": "0.4.3", "id": hex_id,
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "dependencies": [], "targets": [{
                        "kind": ["lib"], "crate_types": ["lib"],
                        "name": "hex", "src_path": "/cargo/hex/src/lib.rs", "edition": "2018"
                    }],
                    "features": { "default": ["std"], "std": [] },
                    "manifest_path": "/cargo/hex/Cargo.toml"
                },
                {
                    "name": "itoa", "version": "1.0.11", "id": itoa_id,
                    "source": "sparse+https://Index.Crates.IO:443/",
                    "dependencies": [], "targets": [{
                        "kind": ["lib"], "crate_types": ["lib"],
                        "name": "itoa", "src_path": "/cargo/itoa/src/lib.rs", "edition": "2018"
                    }],
                    "features": {},
                    "manifest_path": "/cargo/itoa/Cargo.toml"
                },
                {
                    "name": "nocksum", "version": "0.2.0", "id": nocksum_id,
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "dependencies": [], "targets": [], "features": {},
                    "manifest_path": "/cargo/nocksum/Cargo.toml"
                },
                {
                    "name": "gitreg", "version": "0.1.0", "id": gitreg_id,
                    "source": "registry+https://git.other.example/index",
                    "dependencies": [], "targets": [], "features": {},
                    "manifest_path": "/cargo/gitreg/Cargo.toml"
                },
                {
                    "name": "privdep", "version": "1.0.0", "id": priv_id,
                    "source": "sparse+https://cargo.corp.example/index/",
                    "dependencies": [], "targets": [], "features": {},
                    "manifest_path": "/cargo/privdep/Cargo.toml"
                },
                {
                    "name": "gitlib", "version": "0.3.0", "id": gitlib_id,
                    "source": format!("git+https://github.com/example/gitlib.git?tag=v0.3.0#{GIT_COMMIT}"),
                    "dependencies": [], "targets": [{
                        "kind": ["proc-macro"], "crate_types": ["proc-macro"],
                        "name": "gitlib", "src_path": "/cargo/gitlib/src/lib.rs", "edition": "2021"
                    }],
                    "features": {},
                    "manifest_path": "/cargo/gitlib/Cargo.toml"
                }
            ],
            "workspace_members": [demo_id],
            "resolve": {
                "nodes": [
                    {
                        "id": demo_id,
                        "dependencies": [hex_id, itoa_id, nocksum_id, gitreg_id, priv_id, gitlib_id],
                        "deps": [
                            { "name": "hx", "pkg": hex_id, "dep_kinds": [
                                { "kind": null, "target": null },
                                { "kind": "build", "target": null }
                            ]},
                            { "name": "itoa", "pkg": itoa_id, "dep_kinds": [
                                { "kind": null, "target": "cfg(unix)" }
                            ]},
                            { "name": "nocksum", "pkg": nocksum_id, "dep_kinds": [
                                { "kind": null, "target": null }
                            ]},
                            { "name": "gitreg", "pkg": gitreg_id, "dep_kinds": [
                                { "kind": null, "target": null }
                            ]},
                            { "name": "privdep", "pkg": priv_id, "dep_kinds": [
                                { "kind": null, "target": null }
                            ]},
                            { "name": "gitlib", "pkg": gitlib_id, "dep_kinds": [
                                { "kind": null, "target": null }
                            ]}
                        ],
                        "features": ["default", "fast"]
                    },
                    { "id": hex_id, "dependencies": [], "deps": [], "features": ["default", "std"] },
                    { "id": itoa_id, "dependencies": [], "deps": [], "features": [] },
                    { "id": nocksum_id, "dependencies": [], "deps": [], "features": [] },
                    { "id": gitreg_id, "dependencies": [], "deps": [], "features": [] },
                    { "id": priv_id, "dependencies": [], "deps": [], "features": [] },
                    { "id": gitlib_id, "dependencies": [], "deps": [], "features": [] }
                ],
                "root": demo_id
            },
            "target_directory": "/output/target",
            "version": 1,
            "workspace_root": "/source"
        })
    }

    #[tokio::test]
    async fn maps_metadata_identities_predicates_confidence_and_persists_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        setup_workspace(dir.path());

        let corp = RegistrySpec::named(
            "corp",
            "sparse+https://cargo.corp.example/index/",
            CredentialSource::Env {
                registry: "corp".into(),
            },
        )
        .unwrap();
        let registries = [corp];
        let in_tree_sid = SourceId {
            kind: SourceKind::Path {
                path: dir.path().to_path_buf(),
            },
            precise: Some("d".repeat(64)),
        };

        let limits = AnalyzerLimits::default();
        let manifests =
            WorkspaceManifests::load(dir.path(), &in_tree_sid, Path::new(""), &limits).unwrap();
        let lock_text = std::fs::read_to_string(dir.path().join("Cargo.lock")).unwrap();
        let lock = CargoLock::parse(&lock_text, PathBuf::from("Cargo.lock"), &registries).unwrap();

        let meta_val = sample_metadata_json();
        let meta: Metadata = serde_json::from_value(meta_val.clone()).unwrap();
        let out = map_cargo_metadata(
            &meta,
            Path::new("/source"),
            &in_tree_sid,
            &manifests,
            Some(&lock),
            &registries,
            &limits,
        )
        .unwrap();

        // Determinism under input permutation: reverse `packages` and `resolve.nodes`.
        let mut permuted_val = meta_val;
        permuted_val["packages"].as_array_mut().unwrap().reverse();
        permuted_val["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let permuted_meta: Metadata = serde_json::from_value(permuted_val).unwrap();
        let permuted_out = map_cargo_metadata(
            &permuted_meta,
            Path::new("/source"),
            &in_tree_sid,
            &manifests,
            Some(&lock),
            &registries,
            &limits,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&out).unwrap(),
            serde_json::to_value(&permuted_out).unwrap(),
            "analyzer output must be permutation-invariant"
        );

        // Resolved nodes: demo, hex, itoa, gitlib (4 nodes; nocksum/gitreg/privdep
        // are declared-but-unresolved and never produce unpinned nodes).
        let node_names: Vec<&str> = out.nodes.iter().map(|n| n.id.name.as_str()).collect();
        assert_eq!(node_names, vec!["demo", "gitlib", "hex", "itoa"]);

        // Root-and-dependency identity agreement for registry crates:
        let itoa_node = out.nodes.iter().find(|n| n.id.name == "itoa").unwrap();
        let root_itoa_id = PackageId {
            name: "itoa".into(),
            version: PackageVersion::SemVer(semver::Version::new(1, 0, 11)),
            source_id: SourceId {
                kind: SourceKind::CargoRegistry {
                    index_url: Url::parse(CRATES_IO_INDEX).unwrap(),
                },
                precise: Some(ITOA_CKSUM.into()),
            },
            ecosystem: Ecosystem::Rust,
        };
        assert_eq!(itoa_node.id, root_itoa_id);

        // Active features populated from resolve.nodes:
        let demo_node = out.nodes.iter().find(|n| n.id.name == "demo").unwrap();
        assert_eq!(
            demo_node.active_features,
            BTreeSet::from(["default".to_string(), "fast".to_string()])
        );
        // `test` and `custom-build` targets excluded; `lib` + `cdylib` retained.
        assert_eq!(demo_node.targets.len(), 2);

        // Git node has exact commit and proc-macro target:
        let git_node = out.nodes.iter().find(|n| n.id.name == "gitlib").unwrap();
        assert_eq!(git_node.id.source_id.precise.as_deref(), Some(GIT_COMMIT));
        assert_eq!(
            git_node.id.source_id.kind,
            SourceKind::Git {
                url: Url::parse("https://github.com/example/gitlib.git").unwrap(),
                reference: GitReference::Tag("v0.3.0".into()),
            }
        );
        assert_eq!(
            git_node.targets[0].kind,
            TargetKind::RustLib { proc_macro: true }
        );

        // Renamed `hx` in `[dependencies]` + `[build-dependencies]` merged into one
        // L4 edge with `{Build, Normal}` kinds!
        let hex_edge = out
            .edges
            .iter()
            .find(|e| e.requirement.name == "hex")
            .unwrap();
        assert!(hex_edge.to.is_some());
        assert_eq!(
            hex_edge.kinds,
            BTreeSet::from([DependencyKind::Build, DependencyKind::Normal])
        );
        assert_eq!(hex_edge.confidence.tier(), ConfidenceTier::L4);

        // Optional + cfg(unix) `itoa` resolved AND carries combined predicate:
        let itoa_edge = out
            .edges
            .iter()
            .find(|e| e.requirement.name == "itoa")
            .unwrap();
        assert_eq!(itoa_edge.to.as_ref(), Some(&root_itoa_id));
        assert_eq!(
            itoa_edge.predicate.canonical_text(),
            r#"cfg("target_family" = "unix") && (feature("default") || feature("fast"))"#
        );

        // Unresolved edges carry explicit reasons and L3 confidence:
        for (crate_name, expected_substr) in [
            ("nocksum", "no checksum in Cargo.lock"),
            ("gitreg", "unsupported git-protocol registry"),
            ("privdep", "is not present in Cargo.lock"),
        ] {
            let edge = out
                .edges
                .iter()
                .find(|e| e.requirement.name == crate_name)
                .unwrap();
            assert!(edge.to.is_none(), "{crate_name} must stay unresolved");
            assert_eq!(edge.confidence.tier(), ConfidenceTier::L3);
            assert!(
                edge.evidence.iter().any(|ev| ev
                    .detail
                    .as_deref()
                    .is_some_and(|d| d.contains(expected_substr))),
                "{crate_name} missing '{expected_substr}': {:?}",
                edge.evidence
            );
        }

        // `build.rs` and `links` produce tier-L2 native unresolved edges:
        let zlib_edge = out
            .edges
            .iter()
            .find(|e| e.requirement.name == "zlib")
            .unwrap();
        assert_eq!(zlib_edge.requirement.kind, RequirementKind::PkgConfig);
        assert_eq!(zlib_edge.confidence.tier(), ConfidenceTier::L2);
        let links_edge = out
            .edges
            .iter()
            .find(|e| e.requirement.name == "z")
            .unwrap();
        assert_eq!(links_edge.confidence.tier(), ConfidenceTier::L2);

        // Every piece of evidence respects §5.3 tier caps, and the entire output
        // persists and passes `Store::check()` losslessly.
        for edge in &out.edges {
            assert!(edge.confidence.tier() != ConfidenceTier::L0);
            for ev in &edge.evidence {
                assert!(!ev.violates_cap(), "{ev:?}");
            }
        }

        let db_dir = tempfile::tempdir().unwrap();
        let store = Store::open(&db_dir.path().join("test.db")).await.unwrap();
        store
            .write_metadata(&AnalysisMetadata {
                robigus_version: "0.1.0".into(),
                project_name: "demo".into(),
                project_version: "0.1.0".into(),
                source_kind: "path".into(),
                source_uri: dir.path().to_string_lossy().into_owned(),
                source_digest: "d".repeat(64),
                configuration: crate::predicate::Configuration::default(),
                toolchain: BTreeMap::new(),
                network_mode: out.network_mode.as_str().into(),
                sandbox_mode: "bwrap".into(),
                options: json!({}),
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
            })
            .await
            .unwrap();
        out.persist(&store).await.unwrap();
        let report = store.check().await.unwrap();
        assert!(report.is_ok(), "integrity violations: {report:?}");
    }

    /// Regression: when a package declares both `a_dep = { package = "foo", version = "^0.1" }`
    /// and `foo = { version = "^0.2", optional = true }` where `foo`'s `[lib]`
    /// target is named `a_dep`, resolved-edge matching must pair each
    /// declaration with its own SemVer-compatible package rather than picking
    /// by `rnode.deps` iteration order or dropping the optional predicate.
    #[test]
    fn disambiguates_renamed_and_unrenamed_multi_version_deps_and_diagnoses_ties() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
a_dep = { package = "foo", version = "^0.1" }
foo = { version = "^0.2", optional = true }

[features]
default = ["v2"]
v2 = ["dep:foo"]
"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "").unwrap();

        let c1 = "1".repeat(64);
        let c2 = "2".repeat(64);
        let lock_text = format!(
            r#"version = 4

[[package]]
name = "foo"
version = "0.1.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{c1}"

[[package]]
name = "foo"
version = "0.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{c2}"
"#
        );
        let in_tree_sid = SourceId {
            kind: SourceKind::Path {
                path: dir.path().to_path_buf(),
            },
            precise: Some("a".repeat(64)),
        };
        let limits = AnalyzerLimits::default();
        let manifests =
            WorkspaceManifests::load(dir.path(), &in_tree_sid, Path::new(""), &limits).unwrap();
        let lock = CargoLock::parse(&lock_text, PathBuf::from("Cargo.lock"), &[]).unwrap();

        let app_id = "path+file:///source#app@0.1.0";
        let foo_01 = "registry+https://github.com/rust-lang/crates.io-index#foo@0.1.5";
        let foo_02 = "registry+https://github.com/rust-lang/crates.io-index#foo@0.2.3";

        let build_meta = |reverse_deps: bool| -> Metadata {
            let mut deps = vec![
                json!({
                    "name": "a_dep", "pkg": foo_01,
                    "dep_kinds": [{ "kind": null, "target": null }]
                }),
                json!({
                    "name": "a_dep", "pkg": foo_02,
                    "dep_kinds": [{ "kind": null, "target": null }]
                }),
            ];
            if reverse_deps {
                deps.reverse();
            }
            serde_json::from_value(json!({
                "packages": [
                    {
                        "name": "app", "version": "0.1.0", "id": app_id, "source": null,
                        "dependencies": [
                            {
                                "name": "foo", "source": "registry+https://github.com/rust-lang/crates.io-index",
                                "req": "^0.1", "kind": null, "rename": "a_dep", "optional": false,
                                "uses_default_features": true, "features": [], "target": null
                            },
                            {
                                "name": "foo", "source": "registry+https://github.com/rust-lang/crates.io-index",
                                "req": "^0.2", "kind": null, "rename": null, "optional": true,
                                "uses_default_features": true, "features": [], "target": null
                            }
                        ],
                        "targets": [{
                            "kind": ["lib"], "crate_types": ["lib"],
                            "name": "app", "src_path": "/source/src/lib.rs", "edition": "2021"
                        }],
                        "features": { "default": ["v2"], "v2": ["dep:foo"] },
                        "manifest_path": "/source/Cargo.toml"
                    },
                    {
                        "name": "foo", "version": "0.1.5", "id": foo_01,
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                        "dependencies": [],
                        "targets": [{
                            "kind": ["lib"], "crate_types": ["lib"],
                            "name": "a_dep", "src_path": "/cargo/foo1/src/lib.rs", "edition": "2021"
                        }],
                        "features": {}, "manifest_path": "/cargo/foo1/Cargo.toml"
                    },
                    {
                        "name": "foo", "version": "0.2.3", "id": foo_02,
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                        "dependencies": [],
                        "targets": [{
                            "kind": ["lib"], "crate_types": ["lib"],
                            "name": "a_dep", "src_path": "/cargo/foo2/src/lib.rs", "edition": "2021"
                        }],
                        "features": {}, "manifest_path": "/cargo/foo2/Cargo.toml"
                    }
                ],
                "workspace_members": [app_id],
                "resolve": {
                    "nodes": [
                        { "id": app_id, "dependencies": [foo_01, foo_02], "deps": deps, "features": ["default", "v2"] },
                        { "id": foo_01, "dependencies": [], "deps": [], "features": [] },
                        { "id": foo_02, "dependencies": [], "deps": [], "features": [] }
                    ],
                    "root": app_id
                },
                "target_directory": "/output/target",
                "version": 1,
                "workspace_root": "/source"
            }))
            .unwrap()
        };

        for reverse in [false, true] {
            let out = map_cargo_metadata(
                &build_meta(reverse),
                Path::new("/source"),
                &in_tree_sid,
                &manifests,
                Some(&lock),
                &[],
                &limits,
            )
            .unwrap();
            assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

            let e01 = out
                .edges
                .iter()
                .find(|e| {
                    e.requirement
                        .version_req
                        .as_ref()
                        .map(|r| r.requirement_text())
                        == Some("^0.1".into())
                })
                .unwrap();
            assert_eq!(e01.to.as_ref().unwrap().version.to_string(), "0.1.5");
            assert_eq!(e01.predicate.canonical_text(), "true");

            let e02 = out
                .edges
                .iter()
                .find(|e| {
                    e.requirement
                        .version_req
                        .as_ref()
                        .map(|r| r.requirement_text())
                        == Some("^0.2".into())
                })
                .unwrap();
            assert_eq!(e02.to.as_ref().unwrap().version.to_string(), "0.2.3");
            assert_eq!(
                e02.predicate.canonical_text(),
                r#"feature("default") || feature("v2")"#
            );
        }

        // Now force a true ambiguity (`req: "*"` on both declarations matching
        // BOTH 0.1.5 and 0.2.3): must diagnose ambiguity rather than picking by
        // iteration order.
        let mut ambiguous_val = serde_json::to_value(build_meta(false)).unwrap();
        ambiguous_val["packages"][0]["dependencies"][0]["req"] = json!("*");
        ambiguous_val["packages"][0]["dependencies"][1]["req"] = json!("*");
        let ambiguous_meta: Metadata = serde_json::from_value(ambiguous_val).unwrap();
        let amb_out = map_cargo_metadata(
            &ambiguous_meta,
            Path::new("/source"),
            &in_tree_sid,
            &manifests,
            Some(&lock),
            &[],
            &limits,
        )
        .unwrap();
        assert!(
            amb_out
                .diagnostics
                .iter()
                .any(|d| d.message.contains("ambiguous cargo metadata resolution")),
            "{:?}",
            amb_out.diagnostics
        );
    }

    /// Regression: a git dependency reported by `cargo metadata` when `Cargo.lock`
    /// is missing or pins a different commit must stay declared-but-unresolved.
    #[test]
    fn unpinned_or_disagreeing_git_dependency_stays_unresolved() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\ngitlib = { git = \"https://github.com/example/gitlib.git\" }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "").unwrap();

        let in_tree_sid = SourceId {
            kind: SourceKind::Path {
                path: dir.path().to_path_buf(),
            },
            precise: Some("a".repeat(64)),
        };
        let limits = AnalyzerLimits::default();
        let manifests =
            WorkspaceManifests::load(dir.path(), &in_tree_sid, Path::new(""), &limits).unwrap();

        let demo_id = "path+file:///source#demo@0.1.0";
        let git_id = format!("git+https://github.com/example/gitlib.git#{GIT_COMMIT}");
        let meta: Metadata = serde_json::from_value(json!({
            "packages": [
                {
                    "name": "demo", "version": "0.1.0", "id": demo_id, "source": null,
                    "dependencies": [{
                        "name": "gitlib", "source": format!("git+https://github.com/example/gitlib.git#{GIT_COMMIT}"),
                        "req": "*", "kind": null, "rename": null, "optional": false,
                        "uses_default_features": true, "features": [], "target": null
                    }],
                    "targets": [], "features": {}, "manifest_path": "/source/Cargo.toml"
                },
                {
                    "name": "gitlib", "version": "0.3.0", "id": git_id,
                    "source": format!("git+https://github.com/example/gitlib.git#{GIT_COMMIT}"),
                    "dependencies": [], "targets": [], "features": {},
                    "manifest_path": "/cargo/gitlib/Cargo.toml"
                }
            ],
            "workspace_members": [demo_id],
            "resolve": {
                "nodes": [
                    { "id": demo_id, "dependencies": [git_id], "deps": [{
                        "name": "gitlib", "pkg": git_id, "dep_kinds": [{ "kind": null, "target": null }]
                    }], "features": [] },
                    { "id": git_id, "dependencies": [], "deps": [], "features": [] }
                ],
                "root": demo_id
            },
            "target_directory": "/output/target", "version": 1, "workspace_root": "/source"
        }))
        .unwrap();

        // 1. No `Cargo.lock` on host → gitlib stays unresolved (no gitlib Node).
        let no_lock_out = map_cargo_metadata(
            &meta,
            Path::new("/source"),
            &in_tree_sid,
            &manifests,
            None,
            &[],
            &limits,
        )
        .unwrap();
        assert_eq!(no_lock_out.nodes.len(), 1);
        let edge = &no_lock_out.edges[0];
        assert!(edge.to.is_none());
        assert!(edge.evidence.iter().any(|ev| {
            ev.detail
                .as_deref()
                .is_some_and(|d| d.contains("not pinned by a committed Cargo.lock"))
        }));

        // 2. `Cargo.lock` present with a DIFFERENT commit → stays unresolved with disagreement reason.
        let other_commit = "ffffffffffffffffffffffffffffffffffffffff";
        let lock_text = format!(
            "version = 4\n[[package]]\nname = \"gitlib\"\nversion = \"0.3.0\"\n\
             source = \"git+https://github.com/example/gitlib.git#{other_commit}\"\n"
        );
        let lock = CargoLock::parse(&lock_text, PathBuf::from("Cargo.lock"), &[]).unwrap();
        let mismatch_out = map_cargo_metadata(
            &meta,
            Path::new("/source"),
            &in_tree_sid,
            &manifests,
            Some(&lock),
            &[],
            &limits,
        )
        .unwrap();
        assert_eq!(mismatch_out.nodes.len(), 1);
        assert!(mismatch_out.edges[0].to.is_none());
        assert!(mismatch_out.edges[0].evidence.iter().any(|ev| {
            ev.detail
                .as_deref()
                .is_some_and(|d| d.contains("disagreeing with resolved commit"))
        }));
    }
}
