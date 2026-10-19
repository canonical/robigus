//! Data models for binary and source packages in the Ubuntu archive.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::types::{Architecture, Component, Pocket};

/// A single dependency item with an optional version constraint and architecture constraint.
/// E.g. `libc6 (>= 2.38)` or `debhelper-compat (= 13)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DependencyItem {
    name: String,
    operator: Option<String>,
    version: Option<String>,
    architecture: Option<String>,
}

impl DependencyItem {
    /// Creates a new `DependencyItem`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        operator: Option<impl Into<String>>,
        version: Option<impl Into<String>>,
        architecture: Option<impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            operator: operator.map(Into::into),
            version: version.map(Into::into),
            architecture: architecture.map(Into::into),
        }
    }

    /// Package name for this dependency.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Comparison operator (e.g., ">=", "=", "<<").
    #[must_use]
    pub fn operator(&self) -> Option<&str> {
        self.operator.as_deref()
    }

    /// Target version string.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Target architecture restriction if any.
    #[must_use]
    pub fn architecture(&self) -> Option<&str> {
        self.architecture.as_deref()
    }
}

impl fmt::Display for DependencyItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let (Some(op), Some(ver)) = (&self.operator, &self.version) {
            write!(f, " ({op} {ver})")?;
        }
        if let Some(arch) = &self.architecture {
            write!(f, " [{arch}]")?;
        }
        Ok(())
    }
}

/// A dependency relation which may consist of alternative packages separated by `|`.
/// E.g. `debconf (>= 0.5) | debconf-2.0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DependencyClause {
    alternatives: Vec<DependencyItem>,
}

impl DependencyClause {
    /// Creates a new clause with alternatives.
    #[must_use]
    pub fn new(alternatives: Vec<DependencyItem>) -> Self {
        Self { alternatives }
    }

    /// Returns the alternatives in this clause.
    #[must_use]
    pub fn alternatives(&self) -> &[DependencyItem] {
        &self.alternatives
    }
}

/// Dependency relation type (Depends, Pre-Depends, Recommends, Suggests, Conflicts, Breaks, Replaces, Enhances).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DependencyType {
    /// Depends field.
    Depends,
    /// Pre-Depends field.
    PreDepends,
    /// Recommends field.
    Recommends,
    /// Suggests field.
    Suggests,
    /// Conflicts field.
    Conflicts,
    /// Breaks field.
    Breaks,
    /// Replaces field.
    Replaces,
    /// Enhances field.
    Enhances,
}

impl DependencyType {
    /// Returns the header label for this dependency type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DependencyType::Depends => "Depends",
            DependencyType::PreDepends => "Pre-Depends",
            DependencyType::Recommends => "Recommends",
            DependencyType::Suggests => "Suggests",
            DependencyType::Conflicts => "Conflicts",
            DependencyType::Breaks => "Breaks",
            DependencyType::Replaces => "Replaces",
            DependencyType::Enhances => "Enhances",
        }
    }
}

impl fmt::Display for DependencyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A declared dependency relationship containing the type and clauses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyGroup {
    dep_type: DependencyType,
    clauses: Vec<DependencyClause>,
}

impl DependencyGroup {
    /// Creates a new dependency group.
    #[must_use]
    pub fn new(dep_type: DependencyType, clauses: Vec<DependencyClause>) -> Self {
        Self { dep_type, clauses }
    }

    /// Returns the dependency type.
    #[must_use]
    pub fn dep_type(&self) -> DependencyType {
        self.dep_type
    }

    /// Returns the clauses in this group.
    #[must_use]
    pub fn clauses(&self) -> &[DependencyClause] {
        &self.clauses
    }
}

/// A provided virtual or real package name with optional version constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProvideItem {
    name: String,
    version: Option<String>,
}

impl ProvideItem {
    /// Creates a new `ProvideItem`.
    #[must_use]
    pub fn new(name: impl Into<String>, version: Option<impl Into<String>>) -> Self {
        Self {
            name: name.into(),
            version: version.map(Into::into),
        }
    }

    /// Name of provided package.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Optional version of provided package.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

/// Metadata identifying where in the archive an index/package came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageOrigin {
    pocket: Pocket,
    component: Component,
    architecture: Architecture,
    archive_url: String,
    suite: String,
}

impl PackageOrigin {
    /// Creates a new `PackageOrigin`.
    #[must_use]
    pub fn new(
        pocket: Pocket,
        component: Component,
        architecture: Architecture,
        archive_url: impl Into<String>,
        suite: impl Into<String>,
    ) -> Self {
        Self {
            pocket,
            component,
            architecture,
            archive_url: archive_url.into(),
            suite: suite.into(),
        }
    }

    /// The archive pocket.
    #[must_use]
    pub fn pocket(&self) -> Pocket {
        self.pocket
    }

    /// The repository component.
    #[must_use]
    pub fn component(&self) -> Component {
        self.component
    }

    /// The CPU architecture.
    #[must_use]
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Base archive URL.
    #[must_use]
    pub fn archive_url(&self) -> &str {
        &self.archive_url
    }

    /// Archive suite (e.g. resolute, resolute-updates).
    #[must_use]
    pub fn suite(&self) -> &str {
        &self.suite
    }

    /// Formats the origin into an apt-cache madison / Packages index style string.
    /// E.g. "`http://archive.ubuntu.com/ubuntu` resolute-updates/main amd64 Packages"
    #[must_use]
    pub fn madison_archive_label(&self) -> String {
        format!(
            "{} {}/{} {} Packages",
            self.archive_url,
            self.suite,
            self.component.as_str(),
            self.architecture.as_str()
        )
    }

    /// Path tag used in `showpkg` output.
    #[must_use]
    pub fn showpkg_path_label(&self) -> String {
        format!(
            "{}_{}_{}_{}_Packages",
            self.archive_url.replace("://", "_").replace('/', "_"),
            self.suite,
            self.component.as_str(),
            self.architecture.as_str()
        )
    }
}

/// A binary package record as retrieved from `Packages.xz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryPackage {
    package: String,
    version: String,
    architecture: String,
    maintainer: Option<String>,
    installed_size: Option<String>,
    depends: Vec<DependencyGroup>,
    provides: Vec<ProvideItem>,
    section: Option<String>,
    priority: Option<String>,
    homepage: Option<String>,
    description: Option<String>,
    description_md5: Option<String>,
    filename: Option<String>,
    size: Option<u64>,
    md5sum: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    sha512: Option<String>,
    source: Option<String>,
    origin: PackageOrigin,
    raw_fields: Vec<(String, String)>,
}

impl BinaryPackage {
    /// Creates a new binary package record.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        package: impl Into<String>,
        version: impl Into<String>,
        architecture: impl Into<String>,
        maintainer: Option<impl Into<String>>,
        installed_size: Option<impl Into<String>>,
        depends: Vec<DependencyGroup>,
        provides: Vec<ProvideItem>,
        section: Option<impl Into<String>>,
        priority: Option<impl Into<String>>,
        homepage: Option<impl Into<String>>,
        description: Option<impl Into<String>>,
        description_md5: Option<impl Into<String>>,
        filename: Option<impl Into<String>>,
        size: Option<u64>,
        md5sum: Option<impl Into<String>>,
        sha1: Option<impl Into<String>>,
        sha256: Option<impl Into<String>>,
        sha512: Option<impl Into<String>>,
        source: Option<impl Into<String>>,
        origin: PackageOrigin,
        raw_fields: Vec<(String, String)>,
    ) -> Self {
        Self {
            package: package.into(),
            version: version.into(),
            architecture: architecture.into(),
            maintainer: maintainer.map(Into::into),
            installed_size: installed_size.map(Into::into),
            depends,
            provides,
            section: section.map(Into::into),
            priority: priority.map(Into::into),
            homepage: homepage.map(Into::into),
            description: description.map(Into::into),
            description_md5: description_md5.map(Into::into),
            filename: filename.map(Into::into),
            size,
            md5sum: md5sum.map(Into::into),
            sha1: sha1.map(Into::into),
            sha256: sha256.map(Into::into),
            sha512: sha512.map(Into::into),
            source: source.map(Into::into),
            origin,
            raw_fields,
        }
    }

    /// Package name.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Package version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Target architecture string.
    #[must_use]
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// Package maintainer string.
    #[must_use]
    pub fn maintainer(&self) -> Option<&str> {
        self.maintainer.as_deref()
    }

    /// Package section.
    #[must_use]
    pub fn section(&self) -> Option<&str> {
        self.section.as_deref()
    }

    /// Package priority.
    #[must_use]
    pub fn priority(&self) -> Option<&str> {
        self.priority.as_deref()
    }

    /// Package homepage.
    #[must_use]
    pub fn homepage(&self) -> Option<&str> {
        self.homepage.as_deref()
    }

    /// Full description text (short + long).
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Description short line (first line of description).
    #[must_use]
    pub fn short_description(&self) -> Option<&str> {
        self.description
            .as_deref()
            .and_then(|d| d.lines().next())
            .map(str::trim)
    }

    /// Description md5 hash.
    #[must_use]
    pub fn description_md5(&self) -> Option<&str> {
        self.description_md5.as_deref()
    }

    /// Package filename inside the archive pool.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Installed size in kilobytes.
    #[must_use]
    pub fn installed_size(&self) -> Option<&str> {
        self.installed_size.as_deref()
    }

    /// Package file size in bytes.
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// MD5 checksum.
    #[must_use]
    pub fn md5sum(&self) -> Option<&str> {
        self.md5sum.as_deref()
    }

    /// SHA1 checksum.
    #[must_use]
    pub fn sha1(&self) -> Option<&str> {
        self.sha1.as_deref()
    }

    /// SHA256 checksum.
    #[must_use]
    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }

    /// SHA512 checksum.
    #[must_use]
    pub fn sha512(&self) -> Option<&str> {
        self.sha512.as_deref()
    }

    /// Source package name if different from binary package.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Dependencies and relations.
    #[must_use]
    pub fn depends(&self) -> &[DependencyGroup] {
        &self.depends
    }

    /// Provided package names and virtual packages.
    #[must_use]
    pub fn provides(&self) -> &[ProvideItem] {
        &self.provides
    }

    /// Archive origin metadata.
    #[must_use]
    pub fn origin(&self) -> &PackageOrigin {
        &self.origin
    }

    /// Raw deb822 fields preserving original formatting.
    #[must_use]
    pub fn raw_fields(&self) -> &[(String, String)] {
        &self.raw_fields
    }

    /// Reconstructs the raw package paragraph text matching `apt-cache show`.
    #[must_use]
    pub fn format_raw_record(&self) -> String {
        let mut out = String::new();
        for (key, val) in &self.raw_fields {
            out.push_str(key);
            out.push_str(": ");
            out.push_str(val);
            out.push('\n');
        }
        out
    }
}

/// A source package record as retrieved from `Sources.xz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePackage {
    package: String,
    version: String,
    binary: Vec<String>,
    maintainer: Option<String>,
    directory: Option<String>,
    raw_fields: Vec<(String, String)>,
}

impl SourcePackage {
    /// Creates a new `SourcePackage`.
    #[must_use]
    pub fn new(
        package: impl Into<String>,
        version: impl Into<String>,
        binary: Vec<String>,
        maintainer: Option<impl Into<String>>,
        directory: Option<impl Into<String>>,
        raw_fields: Vec<(String, String)>,
    ) -> Self {
        Self {
            package: package.into(),
            version: version.into(),
            binary,
            maintainer: maintainer.map(Into::into),
            directory: directory.map(Into::into),
            raw_fields,
        }
    }

    /// Source package name.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Source package version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Binary packages generated by this source package.
    #[must_use]
    pub fn binary(&self) -> &[String] {
        &self.binary
    }

    /// Maintainer field.
    #[must_use]
    pub fn maintainer(&self) -> Option<&str> {
        self.maintainer.as_deref()
    }

    /// Directory in archive pool.
    #[must_use]
    pub fn directory(&self) -> Option<&str> {
        self.directory.as_deref()
    }

    /// Raw deb822 fields.
    #[must_use]
    pub fn raw_fields(&self) -> &[(String, String)] {
        &self.raw_fields
    }

    /// Reconstructs the raw record matching `apt-cache showsrc`.
    #[must_use]
    pub fn format_raw_record(&self) -> String {
        let mut out = String::new();
        for (key, val) in &self.raw_fields {
            out.push_str(key);
            out.push_str(": ");
            out.push_str(val);
            out.push('\n');
        }
        out
    }
}

/// Statistics about the rapt package cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total package names in cache.
    pub total_package_names: usize,
    /// Normal packages.
    pub normal_packages: usize,
    /// Pure virtual packages.
    pub pure_virtual_packages: usize,
    /// Single virtual packages.
    pub single_virtual_packages: usize,
    /// Mixed virtual packages.
    pub mixed_virtual_packages: usize,
    /// Missing packages referenced in dependencies but not provided.
    pub missing: usize,
    /// Total distinct versions found in the cache.
    pub total_distinct_versions: usize,
    /// Total dependency relationships declared by all packages in the cache.
    pub total_dependencies: usize,
}

impl CacheStats {
    /// Formats cache stats matching `apt-cache stats`.
    #[must_use]
    pub fn format_stats(&self) -> String {
        format!(
            "Total package names: {}\n\
             Normal packages: {}\n\
             Pure virtual packages: {}\n\
             Single virtual packages: {}\n\
             Mixed virtual packages: {}\n\
             Missing: {}\n\
             Total distinct versions: {}\n\
             Total dependencies: {}",
            self.total_package_names,
            self.normal_packages,
            self.pure_virtual_packages,
            self.single_virtual_packages,
            self.mixed_virtual_packages,
            self.missing,
            self.total_distinct_versions,
            self.total_dependencies
        )
    }
}

/// Cache data bundle for a specific Ubuntu series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeriesCache {
    /// Series name (e.g. resolute, noble).
    pub series: String,
    /// Timestamp of when the cache was generated/updated in RFC 3339 format.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Map of package name to all binary package versions.
    pub packages: BTreeMap<String, Vec<BinaryPackage>>,
    /// Map of source package name to all source package versions.
    pub source_packages: BTreeMap<String, Vec<SourcePackage>>,
    /// Map of provided package name to list of (provider package name, provider version, provided version).
    pub provides: BTreeMap<String, Vec<(String, String, Option<String>)>>,
}

impl SeriesCache {
    /// Creates an empty series cache.
    #[must_use]
    pub fn new(series: impl Into<String>) -> Self {
        Self {
            series: series.into(),
            updated_at: chrono::Utc::now(),
            packages: BTreeMap::new(),
            source_packages: BTreeMap::new(),
            provides: BTreeMap::new(),
        }
    }

    /// Checks if the cache was updated within the last hour.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        let one_hour = chrono::Duration::hours(1);
        chrono::Utc::now().signed_duration_since(self.updated_at) < one_hour
    }

    /// Computes cache statistics.
    #[must_use]
    pub fn compute_stats(&self) -> CacheStats {
        let mut all_names = std::collections::BTreeSet::new();
        for name in self.packages.keys() {
            all_names.insert(name.clone());
        }
        for name in self.provides.keys() {
            all_names.insert(name.clone());
        }

        let mut normal_packages = 0;
        let mut pure_virtual_packages = 0;
        let mut single_virtual_packages = 0;
        let mut mixed_virtual_packages = 0;

        for name in &all_names {
            let has_real = self.packages.contains_key(name);
            let providers = self.provides.get(name);
            let provider_count = providers.map_or(0, Vec::len);

            if has_real && provider_count > 0 {
                mixed_virtual_packages += 1;
            } else if has_real {
                normal_packages += 1;
            } else if provider_count == 1 {
                single_virtual_packages += 1;
            } else if provider_count > 1 {
                pure_virtual_packages += 1;
            }
        }

        // Count missing packages referenced in dependencies but neither real nor provided
        let mut missing_names = std::collections::BTreeSet::new();
        let mut total_dependencies = 0;
        let mut total_distinct_versions = 0;

        for versions in self.packages.values() {
            total_distinct_versions += versions.len();
            for pkg in versions {
                for group in pkg.depends() {
                    for clause in group.clauses() {
                        total_dependencies += 1;
                        for item in clause.alternatives() {
                            if !all_names.contains(item.name()) {
                                missing_names.insert(item.name().to_string());
                            }
                        }
                    }
                }
            }
        }

        CacheStats {
            total_package_names: all_names.len() + missing_names.len(),
            normal_packages,
            pure_virtual_packages,
            single_virtual_packages,
            mixed_virtual_packages,
            missing: missing_names.len(),
            total_distinct_versions,
            total_dependencies,
        }
    }
}
