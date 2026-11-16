//! Core data model for the dependency graph (spec §5).
//!
//! Identity types (`SourceKind`, `SourceId`, `PackageId`), the version
//! model, dependency declarations, the analysis lifecycle, evidence, and the
//! in-memory [`DependencyGraph`].

use crate::dpkg::DpkgVersion;
use crate::error::{FetchError, RobigusError, StoreError};
use crate::feature::FeatureExpr;
use crate::predicate::Predicate;
use petgraph::Direction;
use petgraph::stable_graph::{EdgeIndex, NodeIndex, StableDiGraph};
use petgraph::visit::EdgeRef;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use ubuntu_info_rust::{Architecture, Component, Suite};
use url::Url;
use walkdir::WalkDir;

// 1. Source Identification
/// Identifies the repository, transport mechanism, or upstream archive.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// crates.io or alternative Cargo sparse/git registries
    CargoRegistry {
        /// Registry index URL, e.g. `https://index.crates.io/`.
        index_url: Url,
    },
    /// Direct Git checkout with precise tree reference
    Git {
        /// Repository URL; part of the source identity.
        url: Url,
        /// The branch, tag, or revision that was requested. Recorded but not
        /// part of the identity; the resolved commit is [`SourceId::precise`].
        reference: GitReference,
    },
    /// Local filesystem path
    Path {
        /// Directory containing the source tree. Reproducibility comes from
        /// the tree digest in [`SourceId::precise`] (see [`path_tree_digest`]).
        path: PathBuf,
    },
    /// Direct download of a source tarball. `digest` is the trusted checksum
    /// when one was supplied; otherwise the computed digest is recorded with
    /// `unverified` provenance (spec §7.2).
    Tarball {
        /// Download URL of the archive.
        url: Url,
        /// Trusted SHA-256 checksum, if one was supplied. Used as the
        /// identity digest when [`SourceId::precise`] is unset.
        digest: Option<String>,
    },
    /// Ubuntu APT repository archive
    Apt {
        /// Base URL of the archive mirror, e.g.
        /// `http://archive.ubuntu.com/ubuntu`.
        mirror_url: Url,
        /// Series and pocket, e.g. `noble` or `noble-updates`.
        suite: Suite,
        /// Archive components, e.g. `main` and `universe`.
        components: BTreeSet<Component>,
        /// Machine architecture, e.g. `amd64` or `arm64`.
        arch: Architecture,
    },
}

impl SourceKind {
    /// Short machine-friendly name used in logs, `PackageId` display, and
    /// the store's `source_kind` column.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::CargoRegistry { .. } => "cargo-registry",
            Self::Git { .. } => "git",
            Self::Path { .. } => "path",
            Self::Tarball { .. } => "tarball",
            Self::Apt { .. } => "apt",
        }
    }

    /// The URI component of the persisted package identity (spec §11.2):
    /// the index URL, repository URL, filesystem path, tarball URL, or
    /// mirror URL.
    pub fn identity_uri(&self) -> String {
        match self {
            Self::CargoRegistry { index_url } => index_url.to_string(),
            Self::Git { url, .. } => url.to_string(),
            Self::Path { path } => path.to_string_lossy().into_owned(),
            Self::Tarball { url, .. } => url.to_string(),
            Self::Apt { mirror_url, .. } => mirror_url.to_string(),
        }
    }
}

/// The git ref a [`SourceKind::Git`] source was requested by.
///
/// This is provenance only: it is stored in `package.source_reference` but is
/// not part of the [`SourceId`] identity, which uses the resolved commit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GitReference {
    /// A named branch.
    Branch(String),
    /// A named tag.
    Tag(String),
    /// An explicit revision (commit hash or other rev-spec).
    Rev(String),
    /// The remote's default branch (`HEAD`).
    DefaultBranch,
}

/// SourceId: Identifies where artifacts come from. In standard Cargo, sources are registries, git URLs, or directory paths. In a generalized model, this expands to include Debian/Ubuntu repositories (apt/deb), alongside custom package archives.
///
/// Equality, ordering, and hashing follow *identity* (spec §5.1, §22.21),
/// which matches the persisted identity columns exactly:
///
/// - a git source is identified by its URL plus the exact commit
///   ([`SourceId::precise`]); the requested [`GitReference`] (branch, tag,
///   …) is kept but is not part of the identity, so requesting the same
///   commit by branch or by tag yields the same package;
/// - a tarball is identified by its URL plus its digest, taken from
///   `precise` or, when that is unset, from the kind's `digest`;
/// - every other source compares structurally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceId {
    /// Where the source comes from and how it is fetched.
    pub kind: SourceKind,
    /// Exact hash, commit ID, or cryptographic digest locking this source instance
    pub precise: Option<String>,
}

impl SourceId {
    /// The exact revision or digest pinning this source: `precise`, or for a
    /// tarball without `precise`, its `digest`. This is the value persisted
    /// in `package.source_precise`.
    pub fn effective_precise(&self) -> Option<&str> {
        self.precise.as_deref().or(match &self.kind {
            SourceKind::Tarball { digest, .. } => digest.as_deref(),
            _ => None,
        })
    }

    fn identity_key(&self) -> (SourceIdentityKey<'_>, Option<&str>) {
        let kind = match &self.kind {
            SourceKind::CargoRegistry { index_url } => SourceIdentityKey::CargoRegistry(index_url),
            SourceKind::Git { url, .. } => SourceIdentityKey::Git(url),
            SourceKind::Path { path } => SourceIdentityKey::Path(path),
            SourceKind::Tarball { url, .. } => SourceIdentityKey::Tarball(url),
            SourceKind::Apt {
                mirror_url,
                suite,
                components,
                arch,
            } => SourceIdentityKey::Apt(mirror_url, suite, components, arch),
        };
        (kind, self.effective_precise())
    }
}

/// The identity-relevant part of a [`SourceKind`]; variant order matches
/// `SourceKind` so identity ordering follows declaration order.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SourceIdentityKey<'a> {
    CargoRegistry(&'a Url),
    Git(&'a Url),
    Path(&'a Path),
    Tarball(&'a Url),
    Apt(
        &'a Url,
        &'a Suite,
        &'a BTreeSet<Component>,
        &'a Architecture,
    ),
}

impl PartialEq for SourceId {
    fn eq(&self, other: &Self) -> bool {
        self.identity_key() == other.identity_key()
    }
}

impl Eq for SourceId {}

impl PartialOrd for SourceId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SourceId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.identity_key().cmp(&other.identity_key())
    }
}

impl std::hash::Hash for SourceId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identity_key().hash(state);
    }
}

impl GitReference {
    /// The stored form in `package.source_reference` (spec §11.2):
    /// `default`, `branch:<name>`, `tag:<name>`, or `rev:<rev>`.
    pub fn to_stored_text(&self) -> String {
        match self {
            Self::DefaultBranch => "default".to_string(),
            Self::Branch(name) => format!("branch:{name}"),
            Self::Tag(name) => format!("tag:{name}"),
            Self::Rev(rev) => format!("rev:{rev}"),
        }
    }

    /// Parses [`GitReference::to_stored_text`] output.
    pub fn from_stored_text(text: &str) -> Option<Self> {
        if text == "default" {
            return Some(Self::DefaultBranch);
        }
        let (kind, value) = text.split_once(':')?;
        let value = value.to_string();
        match kind {
            "branch" => Some(Self::Branch(value)),
            "tag" => Some(Self::Tag(value)),
            "rev" => Some(Self::Rev(value)),
            _ => None,
        }
    }
}

// 2. Package Identity & Ecosystem Abstraction
/// Tracks the packaging ecosystem to govern version parsing and linking semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    /// Cargo crates; versions are SemVer.
    Rust,
    /// Ubuntu/Debian binary or source packages; versions are dpkg versions.
    Ubuntu,
    /// Native C/C++ system libraries outside a package archive; versions
    /// are opaque.
    SystemC,
    /// Any other ecosystem; versions are opaque.
    Generic,
}

impl Ecosystem {
    /// The stored form in `package.ecosystem` (spec §11.2); matches the
    /// serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Ubuntu => "ubuntu",
            Self::SystemC => "system_c",
            Self::Generic => "generic",
        }
    }

    /// Parses [`Ecosystem::as_str`] output.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rust" => Some(Self::Rust),
            "ubuntu" => Some(Self::Ubuntu),
            "system_c" => Some(Self::SystemC),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rust => write!(f, "rust"),
            Self::Ubuntu => write!(f, "ubuntu"),
            Self::SystemC => write!(f, "system-c"),
            Self::Generic => write!(f, "generic"),
        }
    }
}

/// A generalized version identifier covering SemVer and Debian
/// epoch/upstream/revision versions.
///
/// The derived `Ord` is *identity* ordering for `BTreeMap` keys; semantic
/// version comparison goes through the ecosystem-specific comparators (see
/// `dpkg` and `solver`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PackageVersion {
    /// A SemVer version, used by [`Ecosystem::Rust`].
    SemVer(Version),
    /// A Debian `[epoch:]upstream[-revision]` version, used by
    /// [`Ecosystem::Ubuntu`].
    Debian(DpkgVersion),
    /// Uninterpreted version text, compared only for identity.
    Opaque(String),
}

impl PackageVersion {
    /// Parses the stored text form for `ecosystem` (spec §11.2): SemVer for
    /// Rust, dpkg for Ubuntu, opaque otherwise. Unparseable text degrades to
    /// `Opaque` carrying the identity-preserving original.
    pub fn from_stored_text(ecosystem: Ecosystem, text: &str) -> Self {
        match ecosystem {
            Ecosystem::Rust => text
                .parse::<Version>()
                .map(Self::SemVer)
                .unwrap_or_else(|_| Self::Opaque(text.to_string())),
            Ecosystem::Ubuntu => DpkgVersion::parse(text)
                .map(Self::Debian)
                .unwrap_or_else(|_| Self::Opaque(text.to_string())),
            _ => Self::Opaque(text.to_string()),
        }
    }
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SemVer(version) => write!(f, "{version}"),
            // `DpkgVersion`'s Display already omits epoch 0 and an empty
            // revision (spec §5.4).
            Self::Debian(version) => write!(f, "{version}"),
            Self::Opaque(raw) => write!(f, "{raw}"),
        }
    }
}

/// PackageId: A globally unique, immutable identifier for a concrete package instance (Name + Version + SourceId).
/// Gives the concrete, resolved identity of a single package.
///
/// All four fields participate in identity; source identity follows
/// [`SourceId`]'s rules. `Display` renders `name version (ecosystem/kind)`.
///
/// # Examples
///
/// ```
/// use robigus::model::{Ecosystem, PackageVersion};
/// use robigus::{PackageId, SourceId, SourceKind};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let id = PackageId {
///     name: "serde".into(),
///     version: PackageVersion::from_stored_text(Ecosystem::Rust, "1.0.219"),
///     source_id: SourceId {
///         kind: SourceKind::CargoRegistry {
///             index_url: "https://index.crates.io/".parse()?,
///         },
///         precise: None,
///     },
///     ecosystem: Ecosystem::Rust,
/// };
/// assert_eq!(id.to_string(), "serde 1.0.219 (rust/cargo-registry)");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageId {
    /// Package name as known in its ecosystem (crate name, Debian package
    /// name, library name, ...).
    pub name: String,
    /// The concrete version; its variant should match what `ecosystem`
    /// parses back to (see [`PackageVersion::from_stored_text`]), or the
    /// store rejects the id.
    pub version: PackageVersion,
    /// Where this instance comes from.
    pub source_id: SourceId,
    /// The ecosystem governing version parsing and linking semantics.
    pub ecosystem: Ecosystem,
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({}/{})",
            self.name,
            self.version,
            self.ecosystem,
            self.source_id.kind.kind_name()
        )
    }
}

// 3. Architectures
/// A machine architecture as tracked by robigus (spec §4.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MachineArch {
    /// An architecture defined by the `ubuntu-info-rust` crate.
    Ubuntu(Architecture),
    /// Expands to every `ubuntu-info-rust` architecture at evaluation time.
    All,
    /// Detected but not supported: recorded as a stub, never expanded. The
    /// `_unsupported` suffix is a display convention only.
    Unsupported(String),
}

impl MachineArch {
    /// The default analysis set: every `ubuntu-info-rust` architecture except
    /// `i386` (spec §4.4).
    pub fn default_analysis_set() -> Vec<Self> {
        Architecture::ALL
            .iter()
            .copied()
            .filter(|arch| *arch != Architecture::I386)
            .map(Self::Ubuntu)
            .collect()
    }

    /// `All` expands to every supported architecture; other variants yield
    /// themselves unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// use robigus::MachineArch;
    /// use ubuntu_info_rust::Architecture;
    ///
    /// assert_eq!(MachineArch::All.expand().len(), Architecture::ALL.len());
    ///
    /// let arm64 = MachineArch::Ubuntu(Architecture::Arm64);
    /// assert_eq!(arm64.expand(), vec![arm64.clone()]);
    ///
    /// // Unsupported architectures are kept as stubs, never expanded.
    /// let mips = MachineArch::Unsupported("mips".into());
    /// assert_eq!(mips.expand(), vec![mips.clone()]);
    /// assert!(!mips.is_supported());
    /// assert_eq!(mips.to_string(), "mips_unsupported");
    /// ```
    pub fn expand(&self) -> Vec<Self> {
        match self {
            Self::All => Architecture::ALL
                .iter()
                .copied()
                .map(Self::Ubuntu)
                .collect(),
            other => vec![other.clone()],
        }
    }

    /// Unsupported architectures are recorded but never expanded.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported(_))
    }
}

impl fmt::Display for MachineArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ubuntu(arch) => write!(f, "{arch}"),
            Self::All => write!(f, "all"),
            Self::Unsupported(name) => write!(f, "{name}_unsupported"),
        }
    }
}

// 4. Targets and Artifact Delivery
/// Represents what a package exposes or builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    /// Rust rlib/proc-macro/dylib
    RustLib {
        /// True for a `proc-macro` crate, which runs on the build host.
        proc_macro: bool,
    },
    /// Executable binary
    Binary,
    /// System shared library (.so, .dylib, .dll) with SONAME
    SharedLibrary {
        /// The library's SONAME (e.g. `libz.so.1`), when known.
        soname: Option<String>,
    },
    /// Static library archive (.a)
    StaticLibrary,
    /// C/C++ Header include directory
    Headers,
    /// Pkg-config `.pc` integration; carries the module name.
    PkgConfig(String),
}

/// Target: What artifacts the package produces or provides (libraries, binaries, C/C++ headers, dynamic shared objects, system tools).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Target name (crate target, binary, library, or module name).
    pub name: String,
    /// What kind of artifact this is.
    pub kind: TargetKind,
    /// Workspace-relative path of the target's source or artifact, if known.
    pub path: Option<PathBuf>,
}

// 5. Dependency Declarations
/// General version constraint solver compatibility layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionConstraint {
    /// A Cargo/SemVer requirement such as `^1.2` or `>=0.4, <0.6`.
    SemVer(VersionReq),
    /// Debian comparison: e.g. ">= 2:1.18.0-1"
    Debian {
        /// The relational operator.
        op: DebianOperator,
        /// The dpkg version text compared against, e.g. `2:1.18.0-1`.
        target_version: String,
    },
    /// No version constraint; any version satisfies it.
    Any,
}

impl VersionConstraint {
    /// Canonical text for `version_req` columns; empty means `Any` (spec
    /// §11.2). Debian requirements are `op version` with a space after the
    /// operator; Cargo requirement strings never have one, so the two forms
    /// are unambiguous.
    pub fn requirement_text(&self) -> String {
        match self {
            Self::Any => String::new(),
            Self::SemVer(req) => req.to_string(),
            Self::Debian { op, target_version } => format!("{} {target_version}", op.as_str()),
        }
    }

    /// Parses [`VersionConstraint::requirement_text`] output; empty is `Any`.
    pub fn from_requirement_text(text: &str) -> Result<Self, StoreError> {
        if text.is_empty() {
            return Ok(Self::Any);
        }
        for (spelling, operator) in [
            ("<<", DebianOperator::Lt),
            ("<=", DebianOperator::Le),
            (">>", DebianOperator::Gt),
            (">=", DebianOperator::Ge),
            ("=", DebianOperator::Eq),
        ] {
            if let Some(version) = text
                .strip_prefix(spelling)
                .and_then(|rest| rest.strip_prefix(' '))
                .filter(|version| !version.is_empty())
            {
                return Ok(Self::Debian {
                    op: operator,
                    target_version: version.to_string(),
                });
            }
        }
        text.parse::<VersionReq>()
            .map(Self::SemVer)
            .map_err(|error| {
                StoreError::Corrupt(format!("invalid version requirement '{text}': {error}"))
            })
    }
}

/// A Debian version relation operator (Debian Policy §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebianOperator {
    /// `=`: exactly equal.
    Eq,
    /// `<<`: strictly earlier.
    Lt,
    /// `<=`: earlier or equal.
    Le,
    /// `>>`: strictly later.
    Gt,
    /// `>=`: later or equal.
    Ge,
}

impl DebianOperator {
    /// The Debian relational operator spelling (Debian Policy §7.1).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Lt => "<<",
            Self::Le => "<=",
            Self::Gt => ">>",
            Self::Ge => ">=",
        }
    }
}

/// The category a dependency serves (spec §3). Edges and declarations carry
/// a *set* of these, since one dependency may serve several categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Compiled or linked into the TSP itself; runtime needs are `Runtime`.
    Normal,
    /// Host-system tooling required during build (e.g., clang, protoc, bindgen)
    Build,
    /// Test harness and unit test execution
    Development,
    /// Present in the execution environment when the TSP runs: interpreters,
    /// configuration files, data files, and similar (spec §3).
    Runtime,
}

/// Dependency: A query/requirement specified in a manifest (Name + Version Requirement + Source Specification + Constraints).
/// Expresses a dependency relationship in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// Name of the depended-on package as written in the manifest.
    pub name: String,
    /// Ecosystem the dependency is resolved in.
    pub ecosystem: Ecosystem,
    /// Acceptable versions; [`VersionConstraint::Any`] when unconstrained.
    pub version_req: VersionConstraint,
    /// An explicit source (git, path, alternative registry), or `None` for
    /// the ecosystem's default source.
    pub source_id: Option<SourceId>,
    /// The categories this dependency serves; a dependency may appear in
    /// several (spec §3).
    pub kinds: BTreeSet<DependencyKind>,
    /// True when the dependency is only pulled in by enabling a feature
    /// (Cargo `optional = true`).
    pub optional: bool,
    /// Activation condition (spec §4); `Predicate::TRUE` is always active.
    pub predicate: Predicate,
    /// Cargo feature expressions (`foo`, `foo?`, `dep:foo`, `foo?/bar`).
    pub features: BTreeSet<FeatureExpr>,
    /// Whether the dependency's `default` feature is enabled (Cargo
    /// `default-features`).
    pub default_features: bool,
}

// 6. Analysis Lifecycle
/// Per-node state of the dependency analysis (spec §5.1, §7.7).
///
/// Serialized (and stored) exactly as `Not_Started`, `Started`, `Complete`,
/// and `Error`; `Display` uses the same spelling.
///
/// # Examples
///
/// ```
/// use robigus::AnalysisStatus;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(serde_json::to_string(&AnalysisStatus::NotStarted)?, "\"Not_Started\"");
/// assert_eq!(AnalysisStatus::NotStarted.to_string(), "Not_Started");
///
/// let status: AnalysisStatus = serde_json::from_str("\"Complete\"")?;
/// assert_eq!(status, AnalysisStatus::Complete);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnalysisStatus {
    /// Initial state: no analysis has been performed for this node.
    #[serde(rename = "Not_Started")]
    NotStarted,
    /// Analysis has begun but is not complete. Persisted before work starts
    /// so an interrupted run can resume.
    Started,
    /// Analysis is done, and every resolved dependency edge leads to a node
    /// that is also `Complete` (unresolved requirements are exempt).
    Complete,
    /// An error must be resolved before analysis can complete; the cause is
    /// recorded in the node's plan rows ([`PlanRow::error`]).
    Error,
}

impl AnalysisStatus {
    /// The exact serialized form, also used by the store's `status` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotStarted => "Not_Started",
            Self::Started => "Started",
            Self::Complete => "Complete",
            Self::Error => "Error",
        }
    }
}

impl fmt::Display for AnalysisStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// Analysis plan (spec §2, §7.3, §7.6, §11.2)

/// Generates `as_str`/`parse` for a fieldless enum with a fixed stored form.
macro_rules! stored_names {
    ($ty:ident { $($variant:ident => $name:literal),+ $(,)? }) => {
        impl $ty {
            /// The stored/serialized name (spec §11.2).
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            /// Parses [`Self::as_str`] output.
            pub fn parse(value: &str) -> Option<Self> {
                match value {
                    $($name => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

/// The analyzers robigus knows about (spec §7.3). Only [`AnalyzerId::Cargo`]
/// and [`AnalyzerId::Cpp`] ship in v1; the rest are detected and recorded as
/// `Skipped` plan rows so the record shows what was seen but not analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzerId {
    /// Rust/Cargo projects, including `build.rs` native-code discovery.
    Cargo,
    /// C/C++ projects built with CMake, Meson, Autotools, or Make.
    Cpp,
    /// Python projects (detected only in v1).
    Python,
    /// Go modules (detected only in v1).
    Go,
    /// Node.js packages (detected only in v1).
    Node,
}

stored_names!(AnalyzerId {
    Cargo => "cargo",
    Cpp => "cpp",
    Python => "python",
    Go => "go",
    Node => "node",
});

impl AnalyzerId {
    /// True for analyzers shipped in v1 (spec §7.3).
    pub fn is_shipped(self) -> bool {
        matches!(self, Self::Cargo | Self::Cpp)
    }
}

/// The analysis strategies of spec §7.6, stored in `analysis_plan.strategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStrategy {
    /// Parse declarative manifests and build descriptions.
    Manifest,
    /// Run ecosystem tooling in the sandbox (for example `cargo metadata`).
    ToolIntrospection,
    /// Execute a build or configure step in the sandbox and observe outputs.
    BuildObservation,
    /// Parse README and build instructions, optionally LLM-assisted.
    Documentation,
    /// Independently re-analyze or cross-check a node.
    Validation,
}

stored_names!(AnalysisStrategy {
    Manifest => "manifest",
    ToolIntrospection => "tool_introspection",
    BuildObservation => "build_observation",
    Documentation => "documentation",
    Validation => "validation",
});

/// The build system a plan row targets, stored in `analysis_plan.build_system`
/// (spec §7.3). CMake, Meson, Autotools, and Make are strategies inside the
/// `cpp` analyzer; `BuildScript` is `build.rs` C/C++/assembly discovery inside
/// the `cargo` analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildSystem {
    /// A Cargo `build.rs` script compiling or linking native code.
    BuildScript,
    /// CMake (`CMakeLists.txt`).
    Cmake,
    /// Meson (`meson.build`).
    Meson,
    /// GNU Autotools (`configure.ac` or a generated `configure`).
    Autotools,
    /// Plain Make (`GNUmakefile`, `makefile`, or `Makefile`).
    Make,
}

stored_names!(BuildSystem {
    BuildScript => "build_script",
    Cmake => "cmake",
    Meson => "meson",
    Autotools => "autotools",
    Make => "make",
});

/// The lifecycle of one plan row (spec §11.2). Distinct from the node-level
/// [`AnalysisStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PlanStatus {
    /// Planned but not yet attempted.
    Pending,
    /// Currently being executed.
    Running,
    /// Finished successfully.
    Complete,
    /// Attempted and failed; see [`PlanRow::error`].
    Failed,
    /// Deliberately not run, e.g. for an analyzer that is detected but not
    /// shipped (see [`AnalyzerId::is_shipped`]).
    Skipped,
}

stored_names!(PlanStatus {
    Pending => "Pending",
    Running => "Running",
    Complete => "Complete",
    Failed => "Failed",
    Skipped => "Skipped",
});

/// What a plan row is about (spec §22.20): a detected root directory —
/// detection runs before any package exists — or a package node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
// Plan rows are few and short-lived; boxing the id would only make
// construction and matching noisier.
#[allow(clippy::large_enum_variant)]
pub enum PlanSubject {
    /// Workspace-relative root directory; empty for the top level.
    Root(PathBuf),
    /// A package node in the dependency graph.
    Package(PackageId),
}

/// One row of the dependency mapping plan (spec §2, §11.2). Rows are keyed
/// by `(subject, analyzer, strategy, build_system)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PlanRow {
    /// The root directory or package this row analyzes (part of the key).
    pub subject: PlanSubject,
    /// The analyzer that executes the row (part of the key).
    pub analyzer: AnalyzerId,
    /// How the analyzer examines the subject (part of the key).
    pub strategy: AnalysisStrategy,
    /// The build system targeted, or `None` for the analyzer's own manifest
    /// (part of the key; stored as `''` when `None`).
    pub build_system: Option<BuildSystem>,
    /// Where the row is in its lifecycle.
    pub status: PlanStatus,
    /// How many times execution has been attempted.
    pub attempts: u32,
    /// The recorded cause of a failure; required for a node marked `Error`.
    pub error: Option<String>,
    /// Free-form supplementary information, such as a pointer to a log.
    pub detail: Option<String>,
}

impl PlanRow {
    /// A row with no attempts, error, or detail yet.
    pub fn new(
        subject: PlanSubject,
        analyzer: AnalyzerId,
        strategy: AnalysisStrategy,
        build_system: Option<BuildSystem>,
        status: PlanStatus,
    ) -> Self {
        Self {
            subject,
            analyzer,
            strategy,
            build_system,
            status,
            attempts: 0,
            error: None,
            detail: None,
        }
    }
}

// 7. Requirements
/// The kind of requirement a dependency edge expresses (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementKind {
    /// A crate from a registry, git, or path source.
    Crate,
    /// A pkg-config module.
    PkgConfig,
    /// A system header (`#include <...>`).
    Header,
    /// A shared-library soname.
    Soname,
    /// An executable tool required at build time.
    Tool,
    /// Anything else (e.g., CMake packages, Meson dependencies).
    Generic,
}

impl RequirementKind {
    /// The stored form in `dependency_edge.requirement_kind` (spec §11.2);
    /// matches the serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Crate => "crate",
            Self::PkgConfig => "pkg_config",
            Self::Header => "header",
            Self::Soname => "soname",
            Self::Tool => "tool",
            Self::Generic => "generic",
        }
    }

    /// Parses [`RequirementKind::as_str`] output.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "crate" => Some(Self::Crate),
            "pkg_config" => Some(Self::PkgConfig),
            "header" => Some(Self::Header),
            "soname" => Some(Self::Soname),
            "tool" => Some(Self::Tool),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }
}

/// The declared dependency need, independent of any resolved node (spec §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirement {
    /// What sort of thing is required; determines how `name` is read.
    pub kind: RequirementKind,
    /// Crate name, pkg-config module, header path, soname, or tool name.
    pub name: String,
    /// Acceptable versions, or `None` when the declaration states none.
    pub version_req: Option<VersionConstraint>,
}

// 8. Evidence and Confidence
/// How a piece of [`Evidence`] was obtained (spec §5.3). Each method has a
/// confidence cap, see [`EvidenceMethod::max_confidence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMethod {
    /// Declared in a package manifest (e.g. `Cargo.toml`).
    Manifest,
    /// Pinned in a lockfile (e.g. `Cargo.lock`).
    Lockfile,
    /// Found in a build script such as `build.rs`.
    BuildScript,
    /// Reported by ecosystem tooling run in the sandbox.
    ToolOutput,
    /// Found by scanning source files (e.g. `#include` lines).
    SourceScan,
    /// Taken from README or build instructions.
    Documentation,
    /// Observed while executing a build or configure step.
    BuildObservation,
    /// Produced by an LLM sub-agent; capped at tier L3.
    LlmSubAgent,
    /// Supplied or corrected manually by a person.
    HumanOverride,
}

impl EvidenceMethod {
    /// The stored/serde name of the method (spec §11.2 evidence JSON).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Lockfile => "lockfile",
            Self::BuildScript => "build_script",
            Self::ToolOutput => "tool_output",
            Self::SourceScan => "source_scan",
            Self::Documentation => "documentation",
            Self::BuildObservation => "build_observation",
            Self::LlmSubAgent => "llm_sub_agent",
            Self::HumanOverride => "human_override",
        }
    }

    /// The highest confidence this method may produce (spec §5.3).
    /// LLM-derived evidence is capped at tier L3 (§7.6).
    pub fn max_confidence(&self) -> Confidence {
        match self {
            Self::LlmSubAgent => Confidence::new(79),
            _ => Confidence::MAX,
        }
    }
}

/// A confidence score on the 0–100 scale (spec §5.3), shared by evidence,
/// edges, and detection signals.
///
/// A value above 100 cannot exist: [`Confidence::new`] clamps, and
/// [`TryFrom<u8>`] — also used when deserializing, so JSON and database
/// values are checked on load — rejects it. Serializes as a plain number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct Confidence(u8);

impl Confidence {
    /// No confidence.
    pub const ZERO: Self = Self(0);
    /// Full confidence.
    pub const MAX: Self = Self(100);

    /// A confidence, clamping values above 100 to 100.
    pub const fn new(value: u8) -> Self {
        Self(if value > 100 { 100 } else { value })
    }

    /// The raw 0–100 score.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// The qualitative tier this score falls into (§5.3).
    pub fn tier(self) -> ConfidenceTier {
        ConfidenceTier::from_confidence(self.0)
    }
}

impl TryFrom<u8> for Confidence {
    type Error = crate::error::ConfidenceOutOfRange;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 100 {
            Err(crate::error::ConfidenceOutOfRange(value))
        } else {
            Ok(Self(value))
        }
    }
}

impl From<Confidence> for u8 {
    fn from(confidence: Confidence) -> Self {
        confidence.0
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Where in the source tree a claim was anchored (spec §5.3, §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Workspace-relative file path.
    pub path: PathBuf,
    /// First line of the anchored span, if known.
    pub start_line: Option<u64>,
    /// Last line of the anchored span, if known.
    pub end_line: Option<u64>,
}

/// One record supporting a claim such as an edge (spec §5.3). Evidence is
/// retained and merged, never discarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// How the evidence was obtained.
    pub method: EvidenceMethod,
    /// Confidence in this record; should not exceed the method's cap (see
    /// [`Evidence::violates_cap`]).
    pub confidence: Confidence,
    /// Where in the source tree the claim is anchored, if anywhere.
    pub location: Option<SourceLocation>,
    /// Free-form explanation of what was observed.
    pub detail: Option<String>,
}

impl Evidence {
    /// The qualitative tier of [`Evidence::confidence`].
    pub fn tier(&self) -> ConfidenceTier {
        self.confidence.tier()
    }

    /// True when the evidence exceeds its method's confidence cap (§5.3).
    pub fn violates_cap(&self) -> bool {
        self.confidence > self.method.max_confidence()
    }
}

/// Qualitative confidence ladder over the 0–100 scale (spec §5.3):
/// L0 0–19, L1 20–39, L2 40–59, L3 60–79, L4 80–100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfidenceTier {
    /// 0–19: unsupported guess; must not be persisted as sole evidence.
    L0,
    /// 20–39: documentation or naming heuristic only.
    L1,
    /// 40–59: source scan with unverified anchors.
    L2,
    /// 60–79: verified anchor or sandboxed tool output, not independently
    /// cross-checked.
    L3,
    /// 80–100: cross-validated; two independent methods agree.
    L4,
}

impl ConfidenceTier {
    /// The tier for a raw score; values above 100 map to [`ConfidenceTier::L4`].
    pub fn from_confidence(confidence: u8) -> Self {
        match confidence {
            0..=19 => Self::L0,
            20..=39 => Self::L1,
            40..=59 => Self::L2,
            60..=79 => Self::L3,
            _ => Self::L4,
        }
    }
}

// 9. Graph Nodes and Edges
/// A virtual package provided by a node (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provide {
    /// Name of the virtual package.
    pub name: String,
    /// Version provided, or `None` for an unversioned provide.
    pub version: Option<PackageVersion>,
}

/// A conflict declared by a node (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// Name of the conflicting package.
    pub name: String,
    /// Versions that conflict, or `None` for every version.
    pub version_req: Option<VersionConstraint>,
}

/// A concrete package instance in the graph (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// The node's identity; the graph holds at most one node per id.
    pub id: PackageId,
    /// Workspace-relative source directory, if the node exists in the
    /// analysis tree.
    pub path: Option<PathBuf>,
    /// Analysis progress for this node.
    pub status: AnalysisStatus,
    /// Features unified across the graph (Cargo resolver v2 semantics).
    pub active_features: BTreeSet<String>,
    /// Artifacts the package produces or provides.
    pub targets: Vec<Target>,
    /// Virtual packages this node provides.
    pub provides: Vec<Provide>,
    /// Packages this node declares a conflict with.
    pub conflicts: Vec<Conflict>,
}

impl Node {
    /// A placeholder node for a discovered-but-not-yet-analyzed package.
    pub fn new(id: PackageId) -> Self {
        Self {
            id,
            path: None,
            status: AnalysisStatus::NotStarted,
            active_features: BTreeSet::new(),
            targets: Vec::new(),
            provides: Vec::new(),
            conflicts: Vec::new(),
        }
    }
}

/// A dependency relationship between nodes (spec §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    /// The dependent package.
    pub from: PackageId,
    /// `None` = unresolved requirement preserved for Phase 2.
    pub to: Option<PackageId>,
    /// The declared need this edge satisfies; part of the edge identity.
    pub requirement: Requirement,
    /// The categories this dependency serves; a dependency may appear in
    /// several (spec §3).
    pub kinds: BTreeSet<DependencyKind>,
    /// Activation condition; `Predicate::TRUE` is always active.
    pub predicate: Predicate,
    /// Confidence in the edge: the maximum over its evidence.
    pub confidence: Confidence,
    /// Every record supporting the edge, merged without duplicates.
    pub evidence: Vec<Evidence>,
}

/// The in-memory dependency graph (spec §5.4): a petgraph-backed graph for
/// resolved edges plus a side list for unresolved requirements, which have no
/// target node to attach to. Unresolved requirements map to
/// `dependency_edge` rows with a NULL `to_package_id` in the store (§11.2).
///
/// Nodes are keyed by [`PackageId`]; edges are deduplicated by identity and
/// merged (see [`DependencyGraph::add_edge`]).
///
/// # Examples
///
/// ```
/// use robigus::model::{Confidence, Ecosystem, PackageVersion};
/// use robigus::{
///     AnalysisStatus, DependencyGraph, DependencyKind, Edge, Node, PackageId, Predicate,
///     Requirement, RequirementKind, SourceId, SourceKind,
/// };
/// use std::collections::BTreeSet;
///
/// fn crate_id(name: &str) -> PackageId {
///     PackageId {
///         name: name.into(),
///         version: PackageVersion::from_stored_text(Ecosystem::Rust, "1.0.0"),
///         source_id: SourceId {
///             kind: SourceKind::Path { path: format!("/src/{name}").into() },
///             precise: None,
///         },
///         ecosystem: Ecosystem::Rust,
///     }
/// }
///
/// let app = crate_id("app");
/// let log = crate_id("log");
/// let mut graph = DependencyGraph::new();
/// graph.add_root(app.clone());
/// graph.add_node(Node::new(app.clone()));
///
/// let edge = |kind, confidence| Edge {
///     from: app.clone(),
///     to: Some(log.clone()),
///     requirement: Requirement {
///         kind: RequirementKind::Crate,
///         name: "log".into(),
///         version_req: None,
///     },
///     kinds: BTreeSet::from([kind]),
///     predicate: Predicate::TRUE,
///     confidence: Confidence::new(confidence),
///     evidence: Vec::new(),
/// };
/// graph.add_edge(edge(DependencyKind::Normal, 60));
/// // Same `from`, `to`, requirement, and predicate: merged, not duplicated.
/// graph.add_edge(edge(DependencyKind::Build, 90));
///
/// // A requirement with no target node is kept on the side for Phase 2.
/// graph.add_edge(Edge {
///     to: None,
///     requirement: Requirement {
///         kind: RequirementKind::PkgConfig,
///         name: "zlib".into(),
///         version_req: None,
///     },
///     ..edge(DependencyKind::Normal, 40)
/// });
///
/// // `log` was inserted as a placeholder node.
/// assert_eq!(graph.node_count(), 2);
/// assert_eq!(graph.node(&log).map(|n| n.status), Some(AnalysisStatus::NotStarted));
///
/// assert_eq!(graph.edge_count(), 2);
/// assert_eq!(graph.unresolved().len(), 1);
/// let resolved = graph.edges_to(&log);
/// assert_eq!(resolved.len(), 1);
/// assert_eq!(
///     resolved[0].kinds,
///     BTreeSet::from([DependencyKind::Normal, DependencyKind::Build])
/// );
/// assert_eq!(resolved[0].confidence.value(), 90);
/// assert!(graph.cycles().is_empty());
/// ```
#[derive(Debug, Default, Clone)]
pub struct DependencyGraph {
    graph: StableDiGraph<Node, Edge>,
    index: BTreeMap<PackageId, NodeIndex>,
    roots: BTreeSet<PackageId>,
    unresolved: Vec<Edge>,
}

impl DependencyGraph {
    /// An empty graph with no nodes, edges, or roots.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `id` as a root of the analysis (the TSP or a workspace member).
    pub fn add_root(&mut self, id: PackageId) {
        self.roots.insert(id);
    }

    /// The ids marked with [`DependencyGraph::add_root`]. A root need not
    /// have a node in the graph.
    pub fn roots(&self) -> &BTreeSet<PackageId> {
        &self.roots
    }

    /// Inserts a node, deduplicating by `PackageId`. An existing node's
    /// payload is replaced and its edges are kept, but its `status` is not:
    /// status is set only on first insert and otherwise changes only through
    /// [`DependencyGraph::node_mut`] (in memory) or `Store::update_status`
    /// (persisted), mirroring the store (spec §22.19). Re-discovering a
    /// `Complete` dependency therefore never resets it.
    ///
    /// # Examples
    ///
    /// ```
    /// use robigus::{AnalysisStatus, DependencyGraph, Node};
    /// # use robigus::model::{Ecosystem, PackageVersion};
    /// # use robigus::{PackageId, SourceId, SourceKind};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let id = PackageId {
    /// #     name: "zlib".into(),
    /// #     version: PackageVersion::Opaque("1.3".into()),
    /// #     source_id: SourceId {
    /// #         kind: SourceKind::Path { path: "/src/zlib".into() },
    /// #         precise: None,
    /// #     },
    /// #     ecosystem: Ecosystem::SystemC,
    /// # };
    /// let mut graph = DependencyGraph::new();
    /// graph.add_node(Node::new(id.clone()));
    /// graph.node_mut(&id).ok_or("missing node")?.status = AnalysisStatus::Complete;
    ///
    /// // Re-discovering the package replaces its payload but keeps its status.
    /// let mut rediscovered = Node::new(id.clone());
    /// rediscovered.path = Some("third_party/zlib".into());
    /// graph.add_node(rediscovered);
    ///
    /// let node = graph.node(&id).ok_or("missing node")?;
    /// assert_eq!(graph.node_count(), 1);
    /// assert_eq!(node.status, AnalysisStatus::Complete);
    /// assert_eq!(node.path.as_deref(), Some(std::path::Path::new("third_party/zlib")));
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_node(&mut self, mut node: Node) -> NodeIndex {
        if let Some(&ix) = self.index.get(&node.id) {
            node.status = self.graph[ix].status;
            self.graph[ix] = node;
            ix
        } else {
            let id = node.id.clone();
            let ix = self.graph.add_node(node);
            self.index.insert(id, ix);
            ix
        }
    }

    fn ensure_node(&mut self, id: &PackageId) -> NodeIndex {
        if let Some(&ix) = self.index.get(id) {
            return ix;
        }
        self.add_node(Node::new(id.clone()))
    }

    /// The node for `id`, if present.
    pub fn node(&self, id: &PackageId) -> Option<&Node> {
        self.index.get(id).map(|&ix| &self.graph[ix])
    }

    /// Mutable access to the node for `id`, if present; the only in-memory
    /// way to change a node's `status`. Do not change the node's `id`: the
    /// graph's index is keyed by it and would no longer match.
    pub fn node_mut(&mut self, id: &PackageId) -> Option<&mut Node> {
        self.index
            .get(id)
            .copied()
            .map(move |ix| &mut self.graph[ix])
    }

    /// Number of nodes, including placeholder nodes created by
    /// [`DependencyGraph::add_edge`].
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Resolved and unresolved edges together.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count() + self.unresolved.len()
    }

    /// Iterates `(id, node)` in `PackageId` order.
    pub fn nodes(&self) -> impl Iterator<Item = (&PackageId, &Node)> {
        self.index.iter().map(|(id, &ix)| (id, &self.graph[ix]))
    }

    /// Adds an edge, merging with an existing edge of the same identity (same
    /// `from`, `to`, `requirement`, and `predicate`): `kinds` are unioned,
    /// confidence is the maximum, and evidence records are merged (§5.2).
    ///
    /// The edge's predicate is replaced by its canonical form first, so
    /// identity follows predicate *meaning* (`a && b` is the same edge as
    /// `b && a`), exactly as in the store, which keys edges by
    /// [`Predicate::canonical_text`]. A graph therefore round-trips through
    /// the store unchanged.
    ///
    /// Endpoints that do not exist yet are inserted as placeholder
    /// `AnalysisStatus::NotStarted` nodes. Edges with `to = None` are
    /// unresolved requirements: they are recorded in the side list and
    /// `EdgeIndex::end()` is returned.
    pub fn add_edge(&mut self, mut edge: Edge) -> EdgeIndex {
        edge.predicate = edge.predicate.canonicalized();
        let from_id = edge.from.clone();
        let from_ix = self.ensure_node(&from_id);
        match edge.to.clone() {
            Some(to_id) => {
                let to_ix = self.ensure_node(&to_id);
                if let Some(ix) = self.find_matching_edge(from_ix, &edge) {
                    if let Some(existing) = self.graph.edge_weight_mut(ix) {
                        merge_edge_weights(existing, &edge);
                    }
                    ix
                } else {
                    self.graph.add_edge(from_ix, to_ix, edge)
                }
            }
            None => {
                if let Some(existing) = self.unresolved.iter_mut().find(|e| {
                    e.from == from_id
                        && e.requirement == edge.requirement
                        && e.predicate == edge.predicate
                }) {
                    merge_edge_weights(existing, &edge);
                } else {
                    self.unresolved.push(edge);
                }
                EdgeIndex::end()
            }
        }
    }

    fn find_matching_edge(&self, from_ix: NodeIndex, edge: &Edge) -> Option<EdgeIndex> {
        self.graph
            .edges_directed(from_ix, Direction::Outgoing)
            .find(|e| {
                let weight = e.weight();
                weight.to == edge.to
                    && weight.requirement == edge.requirement
                    && weight.predicate == edge.predicate
            })
            .map(|e| e.id())
    }

    /// All edges originating at `id`, including unresolved requirements.
    pub fn edges_from(&self, id: &PackageId) -> Vec<&Edge> {
        let mut out = Vec::new();
        if let Some(&ix) = self.index.get(id) {
            out.extend(
                self.graph
                    .edges_directed(ix, Direction::Outgoing)
                    .map(|e| e.weight()),
            );
        }
        out.extend(self.unresolved.iter().filter(|e| &e.from == id));
        out
    }

    /// All edges terminating at `id`.
    pub fn edges_to(&self, id: &PackageId) -> Vec<&Edge> {
        self.index
            .get(id)
            .map(|&ix| {
                self.graph
                    .edges_directed(ix, Direction::Incoming)
                    .map(|e| e.weight())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The unresolved requirements recorded for Phase 2 (spec §5.2).
    pub fn unresolved(&self) -> &[Edge] {
        &self.unresolved
    }

    /// The backing petgraph graph (resolved edges only). Unresolved
    /// requirements live in [`DependencyGraph::unresolved`].
    pub fn raw_graph(&self) -> &StableDiGraph<Node, Edge> {
        &self.graph
    }

    /// Cycles as strongly-connected components with more than one node, plus
    /// single nodes with a self-loop. Cycles are legal (Cargo dev-dependency
    /// cycles) and are recorded, not errors (spec §7.7).
    pub fn cycles(&self) -> Vec<Vec<PackageId>> {
        petgraph::algo::tarjan_scc(&self.graph)
            .into_iter()
            .filter(|scc| scc.len() > 1 || self.graph.find_edge(scc[0], scc[0]).is_some())
            .map(|scc| scc.iter().map(|&ix| self.graph[ix].id.clone()).collect())
            .collect()
    }
}

/// Merge policy for same-identity edges (spec §5.2): union `kinds`, take the
/// maximum confidence, and merge evidence without duplicates.
fn merge_edge_weights(existing: &mut Edge, incoming: &Edge) {
    existing.kinds.extend(incoming.kinds.iter().copied());
    existing.confidence = existing.confidence.max(incoming.confidence);
    for evidence in &incoming.evidence {
        if !existing.evidence.contains(evidence) {
            existing.evidence.push(evidence.clone());
        }
    }
}

// 10. Packages and Workspaces

/// The parsed, ecosystem-neutral content of a package manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Identity of the package the manifest describes.
    pub package_id: PackageId,
    /// Declared dependencies, before resolution to graph nodes.
    pub dependencies: Vec<Dependency>,
    /// Artifacts the package declares.
    pub targets: Vec<Target>,
    /// Feature declarations (`[features]`): feature name → the feature
    /// expressions it enables.
    pub features: BTreeMap<String, Vec<FeatureExpr>>,
    /// Native system linker flags, include paths, or environment hooks
    pub system_metadata: BTreeMap<String, String>,
}

/// A package's manifest together with the directory it was read from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// The package's parsed manifest.
    pub manifest: Manifest,
    /// Directory containing the manifest and package sources.
    pub root_dir: PathBuf,
}

// 11. Source Tree Digest
/// Deterministic digest of a directory tree: SHA-256 over a domain tag, the
/// canonically sorted file list, and each entry's contents (spec §7.2). Used
/// to make local-path analyses reproducible.
///
/// Regular files and symlinks participate; other entry types and empty
/// directories do not. Non-UTF-8 file names are hashed lossily. Symlinks are
/// not followed: their target path is hashed instead of the target content.
///
/// Returns the digest as 64 lowercase hex characters.
///
/// # Errors
///
/// Fails with a fetch error if `root` cannot be canonicalized, the tree
/// cannot be walked, or an entry cannot be read.
///
/// # Examples
///
/// ```
/// use robigus::path_tree_digest;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = tempfile::tempdir()?;
/// std::fs::write(dir.path().join("a.txt"), b"hello")?;
///
/// let digest = path_tree_digest(dir.path())?;
/// assert_eq!(digest.len(), 64);
/// assert_eq!(path_tree_digest(dir.path())?, digest);
///
/// std::fs::write(dir.path().join("a.txt"), b"changed")?;
/// assert_ne!(path_tree_digest(dir.path())?, digest);
/// # Ok(())
/// # }
/// ```
pub fn path_tree_digest(root: &Path) -> Result<String, RobigusError> {
    let root = root.canonicalize().map_err(FetchError::from)?;
    let mut entries: Vec<(String, PathBuf, bool)> = Vec::new();
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.map_err(|e| FetchError::Walk(e.to_string()))?;
        if entry.depth() == 0 || entry.file_type().is_dir() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&root)
            .map_err(|_| FetchError::Walk("entry outside source root".to_string()))?
            .to_string_lossy()
            .into_owned();
        let is_symlink = entry.file_type().is_symlink();
        entries.push((relative, entry.path().to_path_buf(), is_symlink));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"robigus-tree-digest-v1\n");
    for (relative, path, is_symlink) in entries {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        if is_symlink {
            hasher.update(b"l");
            let target = std::fs::read_link(&path).map_err(FetchError::from)?;
            hasher.update(target.to_string_lossy().as_bytes());
        } else {
            hasher.update(b"f");
            let mut file = std::fs::File::open(&path).map_err(FetchError::from)?;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(FetchError::from)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        }
        hasher.update([0]);
    }
    Ok(to_hex(hasher.finalize().as_slice()))
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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

    #[test]
    fn source_kind_names_are_stable() {
        assert_eq!(
            SourceKind::Tarball {
                url: Url::parse("https://example.com/x.tar.gz").unwrap(),
                digest: None,
            }
            .kind_name(),
            "tarball"
        );
        assert_eq!(
            SourceKind::Path {
                path: PathBuf::from("/tmp/x")
            }
            .kind_name(),
            "path"
        );
    }

    #[test]
    fn default_analysis_set_excludes_i386() {
        let set = MachineArch::default_analysis_set();
        assert_eq!(set.len(), 7);
        assert!(set.contains(&MachineArch::Ubuntu(Architecture::Amd64)));
        assert!(set.contains(&MachineArch::Ubuntu(Architecture::Amd64v3)));
        assert!(!set.contains(&MachineArch::Ubuntu(Architecture::I386)));
    }

    #[test]
    fn all_expands_to_every_supported_architecture() {
        assert_eq!(MachineArch::All.expand().len(), Architecture::ALL.len());
        assert_eq!(MachineArch::Ubuntu(Architecture::Arm64).expand().len(), 1);
    }

    #[test]
    fn unsupported_architectures_display_with_suffix() {
        assert_eq!(
            MachineArch::Unsupported("mips".into()).to_string(),
            "mips_unsupported"
        );
        assert_eq!(MachineArch::All.to_string(), "all");
        assert_eq!(
            MachineArch::Ubuntu(Architecture::Amd64).to_string(),
            "amd64"
        );
        assert!(!MachineArch::Unsupported("mips".into()).is_supported());
    }

    #[test]
    fn debian_version_display_omits_defaults() {
        let no_epoch: PackageVersion = PackageVersion::Debian("1.0".parse().unwrap());
        assert_eq!(no_epoch.to_string(), "1.0");
        let with_epoch: PackageVersion = PackageVersion::Debian("2:1.0-1".parse().unwrap());
        assert_eq!(with_epoch.to_string(), "2:1.0-1");
    }

    #[test]
    fn package_id_display_includes_ecosystem_and_source() {
        let id = PackageId {
            name: "serde".into(),
            version: PackageVersion::SemVer(Version::new(1, 0, 219)),
            source_id: SourceId {
                kind: SourceKind::CargoRegistry {
                    index_url: Url::parse("https://index.crates.io/").unwrap(),
                },
                precise: None,
            },
            ecosystem: Ecosystem::Rust,
        };
        assert_eq!(id.to_string(), "serde 1.0.219 (rust/cargo-registry)");
    }

    #[test]
    fn analysis_status_serializes_with_spec_names() {
        assert_eq!(
            serde_json::to_string(&AnalysisStatus::NotStarted).unwrap(),
            "\"Not_Started\""
        );
        assert_eq!(
            serde_json::to_string(&AnalysisStatus::Started).unwrap(),
            "\"Started\""
        );
        assert_eq!(
            serde_json::to_string(&AnalysisStatus::Complete).unwrap(),
            "\"Complete\""
        );
        assert_eq!(
            serde_json::to_string(&AnalysisStatus::Error).unwrap(),
            "\"Error\""
        );
        let back: AnalysisStatus = serde_json::from_str("\"Not_Started\"").unwrap();
        assert_eq!(back, AnalysisStatus::NotStarted);
        assert_eq!(AnalysisStatus::NotStarted.to_string(), "Not_Started");
    }

    #[test]
    fn dependency_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&DependencyKind::Runtime).unwrap(),
            "\"runtime\""
        );
        assert_eq!(
            serde_json::to_string(&DependencyKind::Normal).unwrap(),
            "\"normal\""
        );
        assert_eq!(
            serde_json::to_string(&DependencyKind::Build).unwrap(),
            "\"build\""
        );
        assert_eq!(
            serde_json::to_string(&DependencyKind::Development).unwrap(),
            "\"development\""
        );
    }

    #[test]
    fn requirement_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&RequirementKind::PkgConfig).unwrap(),
            "\"pkg_config\""
        );
    }

    #[test]
    fn llm_evidence_is_capped_at_l3() {
        assert_eq!(EvidenceMethod::LlmSubAgent.max_confidence().value(), 79);
        assert_eq!(EvidenceMethod::Manifest.max_confidence(), Confidence::MAX);
        let evidence = Evidence {
            method: EvidenceMethod::LlmSubAgent,
            confidence: Confidence::new(90),
            location: None,
            detail: None,
        };
        assert!(evidence.violates_cap());
        assert_eq!(evidence.tier(), ConfidenceTier::L4);
    }

    #[test]
    fn confidence_tier_boundaries() {
        assert_eq!(ConfidenceTier::from_confidence(0), ConfidenceTier::L0);
        assert_eq!(ConfidenceTier::from_confidence(19), ConfidenceTier::L0);
        assert_eq!(ConfidenceTier::from_confidence(20), ConfidenceTier::L1);
        assert_eq!(ConfidenceTier::from_confidence(59), ConfidenceTier::L2);
        assert_eq!(ConfidenceTier::from_confidence(60), ConfidenceTier::L3);
        assert_eq!(ConfidenceTier::from_confidence(79), ConfidenceTier::L3);
        assert_eq!(ConfidenceTier::from_confidence(80), ConfidenceTier::L4);
        assert_eq!(ConfidenceTier::from_confidence(100), ConfidenceTier::L4);
    }

    /// A confidence above 100 cannot be constructed or deserialized; it
    /// serializes as a plain number.
    #[test]
    fn confidence_is_bounded() {
        assert_eq!(Confidence::new(150), Confidence::MAX);
        assert_eq!(Confidence::try_from(100).unwrap().value(), 100);
        assert!(Confidence::try_from(101).is_err());
        assert_eq!(serde_json::to_string(&Confidence::new(42)).unwrap(), "42");
        assert_eq!(
            serde_json::from_str::<Confidence>("42").unwrap().value(),
            42
        );
        assert!(serde_json::from_str::<Confidence>("200").is_err());
        assert_eq!(Confidence::new(79).tier(), ConfidenceTier::L3);
        assert_eq!(Confidence::new(80).tier(), ConfidenceTier::L4);
    }

    fn test_id(name: &str, major: u64) -> PackageId {
        PackageId {
            name: name.into(),
            version: PackageVersion::SemVer(Version::new(major, 0, 0)),
            source_id: SourceId {
                kind: SourceKind::Path {
                    path: PathBuf::from("/tmp"),
                },
                precise: None,
            },
            ecosystem: Ecosystem::Rust,
        }
    }

    fn test_edge(
        from: PackageId,
        to: Option<PackageId>,
        kind: DependencyKind,
        confidence: u8,
    ) -> Edge {
        Edge {
            from,
            to,
            requirement: Requirement {
                kind: RequirementKind::Crate,
                name: "dep".into(),
                version_req: None,
            },
            kinds: BTreeSet::from([kind]),
            predicate: Predicate::TRUE,
            confidence: Confidence::new(confidence),
            evidence: vec![Evidence {
                method: EvidenceMethod::Manifest,
                confidence: Confidence::new(confidence),
                location: None,
                detail: None,
            }],
        }
    }

    /// High 4: git identity is URL + commit; the requested reference is not
    /// part of it, and Eq, Ord, and Hash agree.
    #[test]
    fn git_source_identity_ignores_the_reference() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let git = |reference, precise: &str| SourceId {
            kind: SourceKind::Git {
                url: Url::parse("https://github.com/example/repo").unwrap(),
                reference,
            },
            precise: Some(precise.to_string()),
        };
        let hash = |id: &SourceId| {
            let mut hasher = DefaultHasher::new();
            id.hash(&mut hasher);
            hasher.finish()
        };
        let branch = git(GitReference::Branch("main".into()), "abc");
        let tag = git(GitReference::Tag("v1".into()), "abc");
        assert_eq!(branch, tag);
        assert_eq!(branch.cmp(&tag), std::cmp::Ordering::Equal);
        assert_eq!(hash(&branch), hash(&tag));
        assert_ne!(branch, git(GitReference::Branch("main".into()), "def"));

        // A tarball's digest stands in for an unset `precise`.
        let url = Url::parse("https://example.com/x.tar.gz").unwrap();
        let by_digest = SourceId {
            kind: SourceKind::Tarball {
                url: url.clone(),
                digest: Some("d".into()),
            },
            precise: None,
        };
        let by_precise = SourceId {
            kind: SourceKind::Tarball {
                url,
                digest: Some("d".into()),
            },
            precise: Some("d".into()),
        };
        assert_eq!(by_digest, by_precise);
        assert_eq!(by_digest.effective_precise(), Some("d"));
    }

    #[test]
    fn stored_names_round_trip() {
        for reference in [
            GitReference::DefaultBranch,
            GitReference::Branch("feature:x".into()),
            GitReference::Tag("v1.0".into()),
            GitReference::Rev("abc".into()),
        ] {
            assert_eq!(
                GitReference::from_stored_text(&reference.to_stored_text()),
                Some(reference)
            );
        }
        assert_eq!(GitReference::from_stored_text(""), None);
        assert_eq!(GitReference::from_stored_text("bogus:x"), None);
        for status in [
            PlanStatus::Pending,
            PlanStatus::Running,
            PlanStatus::Complete,
            PlanStatus::Failed,
            PlanStatus::Skipped,
        ] {
            assert_eq!(PlanStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(
            AnalysisStrategy::ToolIntrospection.as_str(),
            "tool_introspection"
        );
        assert_eq!(
            BuildSystem::parse("build_script"),
            Some(BuildSystem::BuildScript)
        );
        assert_eq!(AnalyzerId::parse("cpp"), Some(AnalyzerId::Cpp));
    }

    #[test]
    fn add_node_deduplicates_by_package_id() {
        let mut graph = DependencyGraph::new();
        let id = test_id("a", 1);
        let mut node = Node::new(id.clone());
        node.status = AnalysisStatus::Complete;
        graph.add_node(node);
        let mut rediscovered = Node::new(id.clone());
        rediscovered.active_features = BTreeSet::from(["std".to_string()]);
        graph.add_node(rediscovered);
        assert_eq!(graph.node_count(), 1);
        let node = graph.node(&id).unwrap();
        // The payload is replaced, but status is set only on first insert
        // (High 2): a re-discovered Complete node stays Complete.
        assert_eq!(node.status, AnalysisStatus::Complete);
        assert!(node.active_features.contains("std"));
    }

    #[test]
    fn add_edge_merges_same_identity() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Normal,
            40,
        ));
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Development,
            80,
        ));
        assert_eq!(graph.edge_count(), 1);
        let edges = graph.edges_from(&a);
        assert_eq!(edges.len(), 1);
        let edge = edges[0];
        assert!(edge.kinds.contains(&DependencyKind::Normal));
        assert!(edge.kinds.contains(&DependencyKind::Development));
        assert_eq!(edge.confidence.value(), 80);
        assert_eq!(edge.evidence.len(), 2);
    }

    #[test]
    fn distinct_predicates_are_distinct_edges() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        let mut first = test_edge(a.clone(), Some(b.clone()), DependencyKind::Normal, 50);
        first.predicate = Predicate::feature("serde");
        graph.add_edge(first);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Normal,
            50,
        ));
        assert_eq!(graph.edge_count(), 2);
    }

    /// Regression (High 5): edge identity follows predicate meaning, as in
    /// the store. `a && b` and `b && a` used to be two edges in memory but
    /// one `dependency_edge` row.
    #[test]
    fn equivalent_predicates_are_the_same_edge() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        let with_predicate = |text: &str, kind| {
            let mut edge = test_edge(a.clone(), Some(b.clone()), kind, 50);
            edge.predicate = Predicate::parse(text).unwrap();
            edge
        };
        graph.add_edge(with_predicate(
            r#"feature("x") && feature("y")"#,
            DependencyKind::Normal,
        ));
        graph.add_edge(with_predicate(
            r#"feature("y") && feature("x") && true"#,
            DependencyKind::Build,
        ));
        assert_eq!(graph.edge_count(), 1);
        let edge = graph.edges_from(&a)[0];
        assert_eq!(edge.kinds.len(), 2, "the two declarations were merged");
        assert_eq!(edge.predicate, edge.predicate.canonicalized());

        // The same holds for unresolved requirements.
        let mut unresolved =
            with_predicate(r#"arch("amd64") || arch("arm64")"#, DependencyKind::Normal);
        unresolved.to = None;
        graph.add_edge(unresolved.clone());
        unresolved.predicate = Predicate::parse(r#"arch("arm64") || arch("amd64")"#).unwrap();
        graph.add_edge(unresolved);
        assert_eq!(graph.unresolved().len(), 1);
    }

    #[test]
    fn unresolved_requirements_are_recorded_separately() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        graph.add_edge(test_edge(a.clone(), None, DependencyKind::Build, 50));
        graph.add_edge(test_edge(a.clone(), None, DependencyKind::Build, 70));
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.unresolved().len(), 1);
        assert_eq!(graph.unresolved()[0].confidence.value(), 70);
        assert_eq!(graph.edges_from(&a).len(), 1);
        assert!(graph.edges_to(&a).is_empty());
    }

    #[test]
    fn cycles_are_detected_as_sccs() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Development,
            50,
        ));
        graph.add_edge(test_edge(
            b.clone(),
            Some(a.clone()),
            DependencyKind::Development,
            50,
        ));
        let cycles = graph.cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 2);
    }

    #[test]
    fn acyclic_graphs_report_no_cycles() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        let c = test_id("c", 1);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Normal,
            50,
        ));
        graph.add_edge(test_edge(
            b.clone(),
            Some(c.clone()),
            DependencyKind::Normal,
            50,
        ));
        assert!(graph.cycles().is_empty());
    }

    #[test]
    fn edges_to_reports_incoming_edges() {
        let mut graph = DependencyGraph::new();
        let a = test_id("a", 1);
        let b = test_id("b", 1);
        graph.add_edge(test_edge(
            a.clone(),
            Some(b.clone()),
            DependencyKind::Normal,
            50,
        ));
        assert_eq!(graph.edges_to(&b).len(), 1);
        assert!(graph.edges_to(&a).is_empty());
    }

    #[test]
    fn tree_digest_is_deterministic_and_content_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        std::fs::write(&a, b"hello").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("c.txt"), b"world").unwrap();

        let first = path_tree_digest(dir.path()).unwrap();
        let second = path_tree_digest(dir.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);

        std::fs::write(&a, b"changed").unwrap();
        let third = path_tree_digest(dir.path()).unwrap();
        assert_ne!(third, first);
    }

    #[test]
    fn tree_digest_covers_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.txt"), b"data").unwrap();
        std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();

        let with_link = path_tree_digest(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("link.txt")).unwrap();
        let without_link = path_tree_digest(dir.path()).unwrap();
        assert_ne!(with_link, without_link);
    }
}
