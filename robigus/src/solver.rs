//! Phase 2 solver seams (spec §9).
//!
//! Phase 1 is a graph-expansion problem, not a version-solving problem: the
//! expander consumes ecosystem-native resolution (`cargo metadata`,
//! `Cargo.lock`). The traits here remain the provider seam for Phase 2's CDCL
//! solver (`pubgrub` or `resolvo`).

use async_trait::async_trait;
use semver::Version;
use std::cmp::Ordering;

use crate::dpkg::DpkgVersion;
use crate::model::{
    DebianOperator, Dependency, Ecosystem, PackageId, PackageVersion, VersionConstraint,
};

// 1. Version Ordering and Constraint Evaluation
/// Abstract matching engine for version requirements.
///
/// # Examples
///
/// ```
/// use robigus::VersionConstraint;
/// use robigus::model::{DebianOperator, PackageVersion};
/// use robigus::solver::ConstraintChecker;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let at_least_1_0 = VersionConstraint::Debian {
///     op: DebianOperator::Ge,
///     target_version: "1.0".into(),
/// };
/// assert!(at_least_1_0.matches(&PackageVersion::Debian("1.0-1".parse()?)));
/// assert!(!at_least_1_0.matches(&PackageVersion::Debian("1.0~rc1".parse()?)));
/// // Cross-ecosystem comparisons never match.
/// assert!(!at_least_1_0.matches(&PackageVersion::SemVer("1.0.0".parse()?)));
/// # Ok(())
/// # }
/// ```
pub trait ConstraintChecker: Send + Sync {
    /// Whether `version` satisfies this requirement. Versions from a
    /// different ecosystem than the requirement never match.
    fn matches(&self, version: &PackageVersion) -> bool;
}

impl ConstraintChecker for VersionConstraint {
    fn matches(&self, version: &PackageVersion) -> bool {
        match (self, version) {
            (VersionConstraint::Any, _) => true,
            (VersionConstraint::SemVer(req), PackageVersion::SemVer(ver)) => req.matches(ver),
            (VersionConstraint::Debian { op, target_version }, PackageVersion::Debian(_)) => {
                compare_debian_constraint(version, op, target_version)
            }
            // Cross-ecosystem mismatches evaluate to false unless bridged.
            _ => false,
        }
    }
}

/// Debian constraint comparison via the shared `dpkg` implementation
/// (Debian Policy §5.6.12). Unparseable targets never match.
fn compare_debian_constraint(version: &PackageVersion, op: &DebianOperator, target: &str) -> bool {
    let Ok(target_version) = DpkgVersion::parse(target) else {
        return false;
    };
    let PackageVersion::Debian(actual) = version else {
        return false;
    };
    let ord = actual.cmp(&target_version);
    match op {
        DebianOperator::Eq => ord == Ordering::Equal,
        DebianOperator::Lt => ord == Ordering::Less,
        DebianOperator::Le => ord != Ordering::Greater,
        DebianOperator::Gt => ord == Ordering::Greater,
        DebianOperator::Ge => ord != Ordering::Less,
    }
}

// 2. Co-existence and Multi-version Policy
/// Dictates how the solver handles duplicate packages with distinct versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictDomain {
    /// Cargo model: semver-compatible versions share a domain; incompatible
    /// versions coexist side by side.
    SideBySide(SemverCompatKey),
    /// Debian/APT model: exactly one version of this package may exist in the
    /// install root.
    Singleton,
    /// Build tools/executables that only conflict if binary names collide.
    NamespacedBinary,
}

/// Cargo's compatibility bucket: the leftmost non-zero version component.
/// `1.2.3` keys by major, `0.2.3` by major.minor, and `0.0.3` by
/// major.minor.patch — matching Cargo's semver-compatibility rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SemverCompatKey {
    /// The major version (`0` for pre-1.0 versions).
    pub major: u64,
    /// The minor version, set only when `major` is `0`.
    pub minor: Option<u64>,
    /// The patch version, set only when `major` and `minor` are both `0`.
    pub patch: Option<u64>,
}

impl SemverCompatKey {
    /// The compatibility bucket of `version`.
    ///
    /// # Examples
    ///
    /// ```
    /// use robigus::solver::SemverCompatKey;
    /// use semver::Version;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key = |v: &str| -> Result<SemverCompatKey, semver::Error> {
    ///     Ok(SemverCompatKey::of(&Version::parse(v)?))
    /// };
    /// assert_eq!(key("1.2.3")?, key("1.9.0")?);
    /// // Pre-1.0 versions key by major.minor: Cargo treats 0.1 and 0.2 as incompatible.
    /// assert_ne!(key("0.1.0")?, key("0.2.0")?);
    /// assert_eq!(key("0.1.0")?, key("0.1.9")?);
    /// assert_ne!(key("0.0.1")?, key("0.0.2")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn of(version: &Version) -> Self {
        if version.major > 0 {
            Self {
                major: version.major,
                minor: None,
                patch: None,
            }
        } else if version.minor > 0 {
            Self {
                major: 0,
                minor: Some(version.minor),
                patch: None,
            }
        } else {
            Self {
                major: 0,
                minor: Some(0),
                patch: Some(version.patch),
            }
        }
    }
}

/// Phase 2 seam: decides which packages may coexist in one solution (spec
/// §9). Unused by the Phase 1 graph expander.
pub trait ConflictPolicy: Send + Sync {
    /// Maps a package to its isolation domain. Packages in the same domain
    /// with conflicting versions trigger backtracking or a solver error.
    fn domain_for(&self, pkg: &PackageId) -> ConflictDomain;
}

/// The built-in [`ConflictPolicy`]: Rust crates with SemVer versions coexist
/// side by side per [`SemverCompatKey`]; every other package (including Rust
/// crates without a SemVer version) is a [`ConflictDomain::Singleton`].
pub struct DefaultConflictPolicy;

impl ConflictPolicy for DefaultConflictPolicy {
    fn domain_for(&self, pkg: &PackageId) -> ConflictDomain {
        match pkg.ecosystem {
            Ecosystem::Rust => match &pkg.version {
                PackageVersion::SemVer(v) => ConflictDomain::SideBySide(SemverCompatKey::of(v)),
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
    /// The candidate package's identity.
    pub package_id: PackageId,
    /// The candidate's direct dependencies.
    pub dependencies: Vec<Dependency>,
    /// Flags whether this package is already pulled/cached or available locally
    pub is_available_locally: bool,
}

/// A failure reported by a [`DependencyProvider`].
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The provider could not be queried; carries a human-readable cause.
    #[error("failed to query source provider: {0}")]
    ProviderError(String),
}

/// Phase 2 seam: the package-metadata source a CDCL solver (`pubgrub` or
/// `resolvo`) queries for candidates and their dependencies (spec §9, §15).
/// Phase 1 does not use it; Cargo nodes are resolved by `cargo metadata`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SourceId, SourceKind};
    use std::path::PathBuf;

    fn semver_id(name: &str, version: &str) -> PackageId {
        PackageId {
            name: name.into(),
            version: PackageVersion::SemVer(version.parse().unwrap()),
            source_id: SourceId {
                kind: SourceKind::Path {
                    path: PathBuf::from("/tmp"),
                },
                precise: None,
            },
            ecosystem: Ecosystem::Rust,
        }
    }

    #[test]
    fn semver_compat_key_follows_cargo_rules() {
        assert_eq!(
            SemverCompatKey::of(&"1.2.3".parse().unwrap()),
            SemverCompatKey::of(&"1.9.0".parse().unwrap())
        );
        assert_ne!(
            SemverCompatKey::of(&"0.1.0".parse().unwrap()),
            SemverCompatKey::of(&"0.2.0".parse().unwrap())
        );
        assert_eq!(
            SemverCompatKey::of(&"0.1.0".parse().unwrap()),
            SemverCompatKey::of(&"0.1.9".parse().unwrap())
        );
        assert_ne!(
            SemverCompatKey::of(&"0.0.1".parse().unwrap()),
            SemverCompatKey::of(&"0.0.2".parse().unwrap())
        );
    }

    #[test]
    fn default_policy_keys_pre_1_0_by_minor() {
        let policy = DefaultConflictPolicy;
        assert_eq!(
            policy.domain_for(&semver_id("a", "0.1.0")),
            policy.domain_for(&semver_id("a", "0.1.9"))
        );
        assert_ne!(
            policy.domain_for(&semver_id("a", "0.1.0")),
            policy.domain_for(&semver_id("a", "0.2.0"))
        );
        assert_eq!(
            policy.domain_for(&semver_id("a", "1.2.3")),
            policy.domain_for(&semver_id("a", "1.9.0"))
        );
    }

    #[test]
    fn debian_constraints_compare_semantically() {
        let ge_1_0 = VersionConstraint::Debian {
            op: DebianOperator::Ge,
            target_version: "1.0".into(),
        };
        let candidate = PackageVersion::Debian("1.0-1".parse().unwrap());
        assert!(ge_1_0.matches(&candidate));

        let lt_1_0 = VersionConstraint::Debian {
            op: DebianOperator::Lt,
            target_version: "1.0".into(),
        };
        let prerelease = PackageVersion::Debian("1.0~beta1".parse().unwrap());
        assert!(lt_1_0.matches(&prerelease));

        // Epochs dominate.
        let lt_newer_epoch = VersionConstraint::Debian {
            op: DebianOperator::Lt,
            target_version: "1:0.1".into(),
        };
        assert!(lt_newer_epoch.matches(&PackageVersion::Debian("0.9.9".parse().unwrap())));

        // Cross-ecosystem mismatches never match.
        assert!(!ge_1_0.matches(&PackageVersion::SemVer("1.0.0".parse().unwrap())));
    }
}
