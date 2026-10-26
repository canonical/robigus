use async_trait::async_trait;
/// To unify Rust SemVer (which tolerates multiple major versions side-by-side in a DAG) and Debian/APT (which enforces single-instance installation per system namespace and uses epoch/upstream/revision ordering), the solver abstraction must separate three layers:
/// Version Ordering & Matching (VersionScheme): Ecosystem-specific comparison mechanics.
/// Metadata Provider (DependencyProvider): Lazily fetching package candidates and dependency edges across crates.io, apt, git, and local disks.
/// Co-occurrence Policy (ConflictDomain): Rules defining whether multiple versions of a package can co-exist in the resolved dependency graph.
/// Core Solver Trait Architecture
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::sync::Arc;

// Reuse the foundational identity primitives from the data model
use crate::model::{
    Dependency, Ecosystem, PackageId, PackageVersion, Resolve, ResolvedNode, VersionConstraint,
};

// 1. Unified Version Ordering and Constraint Evaluation
/// Trait implemented by versions to abstract disparate ordering algorithms.
pub trait VersionValue: Ord + Eq + Clone + Display + Send + Sync {
    /// Compares two versions according to ecosystem-specific rules.
    fn cmp_version(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

/// Abstract matching engine for version requirements.
pub trait ConstraintChecker: Send + Sync {
    fn matches(&self, version: &PackageVersion) -> bool;
}

impl ConstraintChecker for VersionConstraint {
    fn matches(&self, version: &PackageVersion) -> bool {
        match (self, version) {
            (VersionConstraint::Any, _) => true,
            (VersionConstraint::SemVer(req), PackageVersion::SemVer(ver)) => req.matches(ver),
            (VersionConstraint::Debian { op, target_version }, PackageVersion::Debian { .. }) => {
                // Evaluates upstream epoch:upstream-revision comparison
                compare_debian_constraint(version, op, target_version)
            }
            // Cross-ecosystem mismatches evaluate to false unless bridged
            _ => false,
        }
    }
}

fn compare_debian_constraint(
    ver: &PackageVersion,
    op: &crate::model::DebianOperator,
    target: &str,
) -> bool {
    // Standard Debian deb-version comparison logic:
    // Epoch comparison -> Upstream (alphanumeric with '~' sort rule) -> Debian revision
    let ord = debian_compare_versions(&ver.to_string(), target);
    match op {
        crate::model::DebianOperator::Eq => ord == Ordering::Equal,
        crate::model::DebianOperator::Lt => ord == Ordering::Less,
        crate::model::DebianOperator::Le => ord != Ordering::Greater,
        crate::model::DebianOperator::Gt => ord == Ordering::Greater,
        crate::model::DebianOperator::Ge => ord != Ordering::Less,
    }
}

fn debian_compare_versions(_a: &str, _b: &str) -> Ordering {
    // Stub for pure Rust libapt-pkg dpkg --compare-versions implementation
    Ordering::Equal
}

// 2. Co-existence and Multi-version Policy
/// Dictates how the solver handles duplicate packages with distinct versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictDomain {
    /// Cargo model: Major versions can coexist; duplicate identical SemVer ranges merge.
    SideBySide(u64), // Keyed by major version
    /// Debian/APT model: Exactly one version of this package may exist in the install root.
    Singleton,
    /// Build tools/executables that only conflict if binary names collide.
    NamespacedBinary,
}

pub trait ConflictPolicy: Send + Sync {
    /// Maps a package to its isolation domain. Packages in the same domain
    /// with conflicting versions trigger backtracking or a solver error.
    fn domain_for(&self, pkg: &PackageId) -> ConflictDomain;
}

pub struct DefaultConflictPolicy;

impl ConflictPolicy for DefaultConflictPolicy {
    fn domain_for(&self, pkg: &PackageId) -> ConflictDomain {
        match pkg.ecosystem {
            Ecosystem::Rust => match &pkg.version {
                PackageVersion::SemVer(v) => ConflictDomain::SideBySide(v.major),
                _ => ConflictDomain::Singleton,
            },
            // Ubuntu packages target a unified sysroot; only one instance allowed
            Ecosystem::Ubuntu => ConflictDomain::Singleton,
            Ecosystem::SystemC | Ecosystem::Generic => ConflictDomain::Singleton,
        }
    }
}

// 3. Metadata Provider (Source Catalog Driver)
/// A candidate package that satisfies an edge search.
#[derive(Debug, Clone)]
pub struct CandidateSummary {
    pub package_id: PackageId,
    pub dependencies: Vec<Dependency>,
    /// Flags whether this package is already pulled/cached or available locally
    pub is_available_locally: bool,
}

#[async_trait]
pub trait DependencyProvider: Send + Sync {
    /// Yields all versions available for a given package query, sorted newest-to-oldest.
    async fn find_candidates(
        &self,
        dependency: &Dependency,
    ) -> Result<Vec<CandidateSummary>, ResolveError>;

    /// Fetches the manifest / direct dependencies for a chosen candidate.
    async fn get_dependencies(
        &self,
        candidate: &PackageId,
    ) -> Result<Vec<Dependency>, ResolveError>;
}

// 4. CDCL / PubGrub Solver Interface

// TODO(WP-1.2): this enum is reworked as part of the solver cleanup; the
// large-variant lint is tolerated until then.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("No viable candidate found for requirement: {req:?}")]
    Unsatisfiable {
        req: Dependency,
        traceback: Vec<String>,
    },

    #[error("Conflict detected in domain {domain:?}: {a} and {b} cannot coexist")]
    Conflict {
        domain: ConflictDomain,
        a: PackageId,
        b: PackageId,
    },

    #[error("Failed to query source provider: {0}")]
    ProviderError(String),
}

/// The high-level resolver orchestration trait.
#[async_trait]
pub trait DependencyResolver: Send + Sync {
    async fn resolve(
        &self,
        root_dependencies: &[Dependency],
        provider: Arc<dyn DependencyProvider>,
        policy: Arc<dyn ConflictPolicy>,
    ) -> Result<Resolve, ResolveError>;
}

// 5. Solver Engine Implementation Sketch

pub struct ModularSolver {
    pub target_platform: String,
}

impl ModularSolver {
    pub fn new(target_platform: impl Into<String>) -> Self {
        Self {
            target_platform: target_platform.into(),
        }
    }

    /// Evaluates if a dependency should be pruned due to target architecture or platform.
    fn is_active(&self, dep: &Dependency) -> bool {
        if let Some(ref target) = dep.platform {
            return target == &self.target_platform;
        }
        true
    }
}

#[async_trait]
impl DependencyResolver for ModularSolver {
    async fn resolve(
        &self,
        root_dependencies: &[Dependency],
        provider: Arc<dyn DependencyProvider>,
        policy: Arc<dyn ConflictPolicy>,
    ) -> Result<Resolve, ResolveError> {
        let mut resolved_nodes: BTreeMap<PackageId, ResolvedNode> = BTreeMap::new();
        let mut domain_assignments: HashMap<(String, ConflictDomain), PackageId> = HashMap::new();
        // WP-1.1: clippy iter_cloned_collect
        let mut work_queue: Vec<Dependency> = root_dependencies.to_vec();

        while let Some(current_req) = work_queue.pop() {
            if !self.is_active(&current_req) {
                continue;
            }

            // 1. Fetch viable candidates from the registry/APT/git provider
            let candidates = provider.find_candidates(&current_req).await?;

            // 2. Filter candidates matching the version constraint
            let matching_candidate = candidates
                .into_iter()
                .find(|c| current_req.version_req.matches(&c.package_id.version))
                .ok_or_else(|| ResolveError::Unsatisfiable {
                    req: current_req.clone(),
                    traceback: vec![],
                })?;

            let cand_id = matching_candidate.package_id;
            let domain = policy.domain_for(&cand_id);
            let domain_key = (cand_id.name.clone(), domain);

            // 3. Enforce Conflict Rules
            if let Some(existing) = domain_assignments.get(&domain_key) {
                if existing != &cand_id {
                    return Err(ResolveError::Conflict {
                        domain,
                        a: existing.clone(),
                        b: cand_id.clone(),
                    });
                }
                // Already resolved and compatible
                continue;
            }

            // 4. Lock candidate into graph
            domain_assignments.insert(domain_key, cand_id.clone());

            let child_deps = provider.get_dependencies(&cand_id).await?;
            // WP-1.1: clippy unused_mut (the set is never populated; WP-1.2 replaces this sketch)
            let dep_ids = BTreeSet::new();

            for child in &child_deps {
                if self.is_active(child) {
                    work_queue.push(child.clone());
                }
            }

            resolved_nodes.insert(
                cand_id.clone(),
                ResolvedNode {
                    id: cand_id,
                    dependencies: dep_ids,
                    active_features: current_req.features.clone(),
                },
            );
        }

        Ok(Resolve {
            nodes: resolved_nodes,
            root: None,
        })
    }
}
