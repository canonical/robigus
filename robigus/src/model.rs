/// Core Architectural Concepts
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use ubuntu_info_rust::{Architecture, Component, Suite};
use url::Url;

// 1. Source Identification
/// Identifies the repository, transport mechanism, or upstream archive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// crates.io or alternative Cargo sparse/git registries
    CargoRegistry { index_url: Url },
    /// Direct Git checkout with precise tree reference
    Git { url: Url, reference: GitReference },
    /// Local filesystem path
    Path { path: PathBuf },
    /// Ubuntu APT repository archive
    Apt {
        mirror_url: Url,
        /// Series and pocket, e.g. `noble` or `noble-updates`.
        suite: Suite,
        /// Archive components, e.g. `main` and `universe`.
        components: BTreeSet<Component>,
        /// Machine architecture, e.g. `amd64` or `arm64`.
        arch: Architecture,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GitReference {
    Branch(String),
    Tag(String),
    Rev(String),
    DefaultBranch,
}

/// SourceId: Identifies where artifacts come from. In standard Cargo, sources are registries, git URLs, or directory paths. In a generalized model, this expands to include Debian/Ubuntu repositories (apt/deb), alongside custom package archives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceId {
    pub kind: SourceKind,
    /// Exact hash, commit ID, or cryptographic digest locking this source instance
    pub precise: Option<String>,
}

// 2. Package Identity & Ecosystem Abstraction
/// Tracks the packaging ecosystem to govern version parsing and linking semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Rust,
    Ubuntu,
    SystemC,
    Generic,
}

/// A generalized version identifier covering SemVer and Debian epoch/upstream/revision versions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PackageVersion {
    SemVer(Version),
    Debian {
        epoch: Option<u32>,
        upstream: String,
        debian_revision: Option<String>,
    },
    Opaque(String),
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageVersion::SemVer(version) => write!(f, "{version}"),
            PackageVersion::Debian {
                epoch,
                upstream,
                debian_revision,
            } => {
                if let Some(epoch) = epoch {
                    write!(f, "{epoch}:")?;
                }
                write!(f, "{upstream}")?;
                if let Some(revision) = debian_revision {
                    write!(f, "-{revision}")?;
                }
                Ok(())
            }
            PackageVersion::Opaque(raw) => write!(f, "{raw}"),
        }
    }
}

/// PackageId: A globally unique, immutable identifier for a concrete package instance (Name + Version + SourceId).
/// Gives the concrete, resolved identity of a single package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageId {
    pub name: String,
    pub version: PackageVersion,
    pub source_id: SourceId,
    pub ecosystem: Ecosystem,
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.name, self.version)
    }
}

// 3. Targets and Artifact Delivery
/// Represents what a package exposes or builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    /// Rust rlib/proc-macro/dylib
    RustLib { proc_macro: bool },
    /// Executable binary
    Binary,
    /// System shared library (.so, .dylib, .dll) with SONAME
    SharedLibrary { soname: Option<String> },
    /// Static library archive (.a)
    StaticLibrary,
    /// C/C++ Header include directory
    Headers,
    /// Pkg-config `.pc` integration
    PkgConfig(String),
}

/// Target: What artifacts the package produces or provides (libraries, binaries, C/C++ headers, dynamic shared objects, system tools).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    pub kind: TargetKind,
    pub path: Option<PathBuf>,
}

// 4. Dependency Declarations
/// General version constraint solver compatibility layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionConstraint {
    SemVer(VersionReq),
    /// Debian comparison: e.g. ">= 2:1.18.0-1"
    Debian {
        op: DebianOperator,
        target_version: String,
    },
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebianOperator {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DependencyKind {
    /// Needed for compilation and runtime
    Normal,
    /// Host-system tooling required during build (e.g., clang, protoc, bindgen)
    Build,
    /// Test harness and unit test execution
    Development,
}

/// Dependency: A query/requirement specified in a manifest (Name + Version Requirement + Source Specification + Constraints).
/// Expresses a dependency relationship in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub ecosystem: Ecosystem,
    pub version_req: VersionConstraint,
    pub source_id: Option<SourceId>,
    pub kind: DependencyKind,
    pub optional: bool,
    /// Target platform triple filter (e.g., "x86_64-unknown-linux-gnu")
    pub platform: Option<String>,
    /// Cargo features or Debian package configurations/recommends
    pub features: BTreeSet<String>,
    pub default_features: bool,
}

// 5. Packages and Workspaces

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub package_id: PackageId,
    pub dependencies: Vec<Dependency>,
    pub targets: Vec<Target>,
    pub features: BTreeMap<String, Vec<String>>,
    /// Native system linker flags, include paths, or environment hooks
    pub system_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub manifest: Manifest,
    pub root_dir: PathBuf,
}

// 6. Resolved Dependency Graph (Lockfile Representation)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedNode {
    pub id: PackageId,
    pub dependencies: BTreeSet<PackageId>,
    pub active_features: BTreeSet<String>,
}

/// The fully resolved DAG, isomorphic to Cargo.lock but cross-distribution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resolve {
    pub nodes: BTreeMap<PackageId, ResolvedNode>,
    pub root: Option<PackageId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubuntu_info_rust::{Pocket, SeriesInfo};

    fn apt_source(suite: Suite, arch: Architecture) -> SourceKind {
        SourceKind::Apt {
            mirror_url: Url::parse("http://archive.ubuntu.com/ubuntu").unwrap(),
            suite,
            components: [Component::Main, Component::Universe].into_iter().collect(),
            arch,
        }
    }

    #[test]
    fn apt_source_round_trips_through_serde() {
        let suite = Suite::new(
            SeriesInfo::from_short_name("noble").unwrap(),
            Pocket::Updates,
        );
        let source = apt_source(suite, Architecture::Amd64);

        let json = serde_json::to_string(&source).unwrap();
        let decoded: SourceKind = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, source);
    }

    #[test]
    fn apt_source_ordering_is_consistent() {
        let noble = Suite::new(
            SeriesInfo::from_short_name("noble").unwrap(),
            Pocket::Release,
        );
        let jammy = Suite::new(
            SeriesInfo::from_short_name("jammy").unwrap(),
            Pocket::Release,
        );

        let noble_source = apt_source(noble, Architecture::Amd64);
        let jammy_source = apt_source(jammy, Architecture::Amd64);

        assert!(jammy_source < noble_source);
    }
}
