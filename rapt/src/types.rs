//! Core domain types, enumerations, and query filter definitions for rapt.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{RaptError, Result};

/// Ubuntu archive pocket types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pocket {
    /// Initial release pocket.
    Release,
    /// Pre-release proposed updates pocket.
    Proposed,
    /// Stable maintenance updates pocket.
    Updates,
    /// Critical security updates pocket.
    Security,
    /// Backports of newer software pocket.
    Backports,
}

impl Pocket {
    /// Returns all available pockets.
    #[must_use]
    pub fn all() -> &'static [Pocket] {
        &[
            Pocket::Release,
            Pocket::Proposed,
            Pocket::Updates,
            Pocket::Security,
            Pocket::Backports,
        ]
    }

    /// Returns the pocket name as a lowercase string slice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Pocket::Release => "release",
            Pocket::Proposed => "proposed",
            Pocket::Updates => "updates",
            Pocket::Security => "security",
            Pocket::Backports => "backports",
        }
    }

    /// Formats the pocket as a suite suffix relative to the series name.
    /// E.g. `Release` -> "", `Updates` -> "-updates", `Security` -> "-security".
    #[must_use]
    pub const fn suite_suffix(self) -> &'static str {
        match self {
            Pocket::Release => "",
            Pocket::Proposed => "-proposed",
            Pocket::Updates => "-updates",
            Pocket::Security => "-security",
            Pocket::Backports => "-backports",
        }
    }

    /// Constructs the suite name for a given series name.
    /// E.g. ("resolute", `Pocket::Updates`) -> "resolute-updates".
    #[must_use]
    pub fn suite_for_series(self, series: &str) -> String {
        format!("{series}{}", self.suite_suffix())
    }
}

impl fmt::Display for Pocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Pocket {
    type Err = RaptError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "release" => Ok(Pocket::Release),
            "proposed" => Ok(Pocket::Proposed),
            "updates" => Ok(Pocket::Updates),
            "security" => Ok(Pocket::Security),
            "backports" => Ok(Pocket::Backports),
            other => Err(RaptError::InvalidPocket(other.to_string())),
        }
    }
}

/// Ubuntu archive repository components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    /// Canonical-supported free/open-source software.
    Main,
    /// Community-maintained free/open-source software.
    Universe,
    /// Proprietary device drivers and restricted hardware software.
    Restricted,
    /// Software restricted by copyright or legal issues.
    Multiverse,
}

impl Component {
    /// Returns all available components.
    #[must_use]
    pub fn all() -> &'static [Component] {
        &[
            Component::Main,
            Component::Universe,
            Component::Restricted,
            Component::Multiverse,
        ]
    }

    /// Returns the component name as a string slice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Component::Main => "main",
            Component::Universe => "universe",
            Component::Restricted => "restricted",
            Component::Multiverse => "multiverse",
        }
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Component {
    type Err = RaptError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "main" => Ok(Component::Main),
            "universe" => Ok(Component::Universe),
            "restricted" => Ok(Component::Restricted),
            "multiverse" => Ok(Component::Multiverse),
            other => Err(RaptError::InvalidComponent(other.to_string())),
        }
    }
}

/// Target CPU architectures supported by the Ubuntu archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    /// 64-bit x86 architecture.
    Amd64,
    /// 64-bit ARM architecture (AArch64).
    Arm64,
    /// 32-bit ARM hard-float architecture.
    Armhf,
    /// 64-bit PowerPC Little Endian architecture.
    Ppc64el,
    /// IBM System/390x 64-bit mainframe architecture.
    S390x,
    /// 64-bit RISC-V architecture.
    Riscv64,
}

impl Architecture {
    /// Returns all supported architectures.
    #[must_use]
    pub fn all() -> &'static [Architecture] {
        &[
            Architecture::Amd64,
            Architecture::Arm64,
            Architecture::Armhf,
            Architecture::Ppc64el,
            Architecture::S390x,
            Architecture::Riscv64,
        ]
    }

    /// Returns the architecture name as a string slice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
            Architecture::Armhf => "armhf",
            Architecture::Ppc64el => "ppc64el",
            Architecture::S390x => "s390x",
            Architecture::Riscv64 => "riscv64",
        }
    }

    /// Whether this architecture is served by ports.ubuntu.com rather than archive.ubuntu.com.
    #[must_use]
    pub const fn is_ports(self) -> bool {
        match self {
            Architecture::Amd64 => false,
            Architecture::Arm64
            | Architecture::Armhf
            | Architecture::Ppc64el
            | Architecture::S390x
            | Architecture::Riscv64 => true,
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Architecture {
    type Err = RaptError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "amd64" => Ok(Architecture::Amd64),
            "arm64" => Ok(Architecture::Arm64),
            "armhf" => Ok(Architecture::Armhf),
            "ppc64el" => Ok(Architecture::Ppc64el),
            "s390x" => Ok(Architecture::S390x),
            "riscv64" => Ok(Architecture::Riscv64),
            other => Err(RaptError::InvalidArchitecture(other.to_string())),
        }
    }
}

/// Parsed package specifier consisting of a package name and an optional package version number.
/// Typically parsed from `PKG` or `PKG=PKG_VERSION_NUMBER`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackageTarget {
    name: String,
    version: Option<String>,
}

impl PackageTarget {
    /// Creates a new `PackageTarget` with optional version.
    #[must_use]
    pub fn new(name: impl Into<String>, version: Option<impl Into<String>>) -> Self {
        Self {
            name: name.into(),
            version: version.map(Into::into),
        }
    }

    /// Returns the target package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional target package version.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

impl FromStr for PackageTarget {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Some((name, version)) = s.split_once('=') {
            Ok(Self {
                name: name.to_string(),
                version: Some(version.to_string()),
            })
        } else {
            Ok(Self {
                name: s.to_string(),
                version: None,
            })
        }
    }
}

impl fmt::Display for PackageTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(v) = &self.version {
            write!(f, "={v}")?;
        }
        Ok(())
    }
}

/// Query filter configuration for scoping queries across pockets, components, and architectures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryFilter {
    series: String,
    pockets: BTreeSet<Pocket>,
    components: BTreeSet<Component>,
    architectures: BTreeSet<Architecture>,
}

impl QueryFilter {
    /// Creates a new `QueryFilterBuilder`.
    #[must_use]
    pub fn builder(series: impl Into<String>) -> QueryFilterBuilder {
        QueryFilterBuilder::new(series)
    }

    /// Returns the target Ubuntu series.
    #[must_use]
    pub fn series(&self) -> &str {
        &self.series
    }

    /// Returns the set of pockets to query.
    #[must_use]
    pub fn pockets(&self) -> &BTreeSet<Pocket> {
        &self.pockets
    }

    /// Returns the set of components to query.
    #[must_use]
    pub fn components(&self) -> &BTreeSet<Component> {
        &self.components
    }

    /// Returns the set of architectures to query.
    #[must_use]
    pub fn architectures(&self) -> &BTreeSet<Architecture> {
        &self.architectures
    }

    /// Checks if a pocket is included.
    #[must_use]
    pub fn contains_pocket(&self, pocket: Pocket) -> bool {
        self.pockets.contains(&pocket)
    }

    /// Checks if a component is included.
    #[must_use]
    pub fn contains_component(&self, component: Component) -> bool {
        self.components.contains(&component)
    }

    /// Checks if an architecture is included.
    #[must_use]
    pub fn contains_arch(&self, arch: Architecture) -> bool {
        self.architectures.contains(&arch)
    }
}

/// Builder for constructing a validated `QueryFilter`.
#[derive(Debug, Clone)]
pub struct QueryFilterBuilder {
    series: String,
    pocket: Option<Vec<Pocket>>,
    not_pocket: Option<Vec<Pocket>>,
    component: Option<Vec<Component>>,
    not_component: Option<Vec<Component>>,
    arch: Option<Vec<Architecture>>,
    not_arch: Option<Vec<Architecture>>,
}

impl QueryFilterBuilder {
    /// Creates a new builder for the specified Ubuntu series.
    #[must_use]
    pub fn new(series: impl Into<String>) -> Self {
        Self {
            series: series.into(),
            pocket: None,
            not_pocket: None,
            component: None,
            not_component: None,
            arch: None,
            not_arch: None,
        }
    }

    /// Sets positive pocket filters.
    #[must_use]
    pub fn pockets(mut self, pockets: Vec<Pocket>) -> Self {
        self.pocket = Some(pockets);
        self
    }

    /// Sets inverse pocket filters.
    #[must_use]
    pub fn not_pockets(mut self, not_pockets: Vec<Pocket>) -> Self {
        self.not_pocket = Some(not_pockets);
        self
    }

    /// Sets positive component filters.
    #[must_use]
    pub fn components(mut self, components: Vec<Component>) -> Self {
        self.component = Some(components);
        self
    }

    /// Sets inverse component filters.
    #[must_use]
    pub fn not_components(mut self, not_components: Vec<Component>) -> Self {
        self.not_component = Some(not_components);
        self
    }

    /// Sets positive architecture filters.
    #[must_use]
    pub fn architectures(mut self, archs: Vec<Architecture>) -> Self {
        self.arch = Some(archs);
        self
    }

    /// Sets inverse architecture filters.
    #[must_use]
    pub fn not_architectures(mut self, not_archs: Vec<Architecture>) -> Self {
        self.not_arch = Some(not_archs);
        self
    }

    /// Validates filter arguments and builds a `QueryFilter`.
    pub fn build(self) -> Result<QueryFilter> {
        let series = self.series.trim().to_string();
        if series.is_empty() {
            return Err(RaptError::MissingSeries);
        }

        // Validate pockets
        let pockets = match (self.pocket, self.not_pocket) {
            (Some(_), Some(_)) => {
                return Err(RaptError::MutuallyExclusiveFilter("pocket".to_string()));
            }
            (Some(list), None) => {
                let set: BTreeSet<Pocket> = list.into_iter().collect();
                if set.is_empty() {
                    default_pockets()
                } else {
                    set
                }
            }
            (None, Some(list)) => {
                let all_pockets = Pocket::all();
                let count = list.len();
                if count < 1 || count > all_pockets.len() - 1 {
                    return Err(RaptError::InvalidInverseFilterCount {
                        name: "pocket".to_string(),
                        max: all_pockets.len() - 1,
                        actual: count,
                    });
                }
                let excluded: BTreeSet<Pocket> = list.into_iter().collect();
                all_pockets
                    .iter()
                    .copied()
                    .filter(|p| !excluded.contains(p))
                    .collect()
            }
            (None, None) => default_pockets(),
        };

        // Validate components
        let components = match (self.component, self.not_component) {
            (Some(_), Some(_)) => {
                return Err(RaptError::MutuallyExclusiveFilter("component".to_string()));
            }
            (Some(list), None) => {
                let set: BTreeSet<Component> = list.into_iter().collect();
                if set.is_empty() {
                    default_components()
                } else {
                    set
                }
            }
            (None, Some(list)) => {
                let all_components = Component::all();
                let count = list.len();
                if count < 1 || count > all_components.len() - 1 {
                    return Err(RaptError::InvalidInverseFilterCount {
                        name: "component".to_string(),
                        max: all_components.len() - 1,
                        actual: count,
                    });
                }
                let excluded: BTreeSet<Component> = list.into_iter().collect();
                all_components
                    .iter()
                    .copied()
                    .filter(|c| !excluded.contains(c))
                    .collect()
            }
            (None, None) => default_components(),
        };

        // Validate architectures
        let architectures = match (self.arch, self.not_arch) {
            (Some(_), Some(_)) => {
                return Err(RaptError::MutuallyExclusiveFilter("arch".to_string()));
            }
            (Some(list), None) => {
                let set: BTreeSet<Architecture> = list.into_iter().collect();
                if set.is_empty() {
                    default_architectures()
                } else {
                    set
                }
            }
            (None, Some(list)) => {
                let all_archs = Architecture::all();
                let count = list.len();
                if count < 1 || count > all_archs.len() - 1 {
                    return Err(RaptError::InvalidInverseFilterCount {
                        name: "arch".to_string(),
                        max: all_archs.len() - 1,
                        actual: count,
                    });
                }
                let excluded: BTreeSet<Architecture> = list.into_iter().collect();
                all_archs
                    .iter()
                    .copied()
                    .filter(|a| !excluded.contains(a))
                    .collect()
            }
            (None, None) => default_architectures(),
        };

        Ok(QueryFilter {
            series,
            pockets,
            components,
            architectures,
        })
    }
}

fn default_pockets() -> BTreeSet<Pocket> {
    [Pocket::Release, Pocket::Updates, Pocket::Security]
        .into_iter()
        .collect()
}

fn default_components() -> BTreeSet<Component> {
    Component::all().iter().copied().collect()
}

fn default_architectures() -> BTreeSet<Architecture> {
    Architecture::all().iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_filter() {
        let filter = QueryFilter::builder("resolute").build().unwrap();
        assert_eq!(filter.series(), "resolute");
        assert_eq!(filter.pockets().len(), 3);
        assert!(filter.contains_pocket(Pocket::Release));
        assert!(filter.contains_pocket(Pocket::Updates));
        assert!(filter.contains_pocket(Pocket::Security));
        assert!(!filter.contains_pocket(Pocket::Proposed));
        assert!(!filter.contains_pocket(Pocket::Backports));

        assert_eq!(filter.components().len(), 4);
        assert_eq!(filter.architectures().len(), 6);
    }

    #[test]
    fn test_mutually_exclusive_pocket_filters() {
        let err = QueryFilter::builder("resolute")
            .pockets(vec![Pocket::Release])
            .not_pockets(vec![Pocket::Updates])
            .build()
            .unwrap_err();
        assert!(matches!(err, RaptError::MutuallyExclusiveFilter(ref s) if s == "pocket"));
    }

    #[test]
    fn test_inverse_filter_bounds() {
        // pocket max is 4
        let err = QueryFilter::builder("resolute")
            .not_pockets(vec![
                Pocket::Release,
                Pocket::Proposed,
                Pocket::Updates,
                Pocket::Security,
                Pocket::Backports,
            ])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            RaptError::InvalidInverseFilterCount {
                ref name,
                max: 4,
                actual: 5
            } if name == "pocket"
        ));
    }

    #[test]
    fn test_package_target_parsing() {
        let target1: PackageTarget = "curl".parse().unwrap();
        assert_eq!(target1.name(), "curl");
        assert_eq!(target1.version(), None);

        let target2: PackageTarget = "curl=8.18.0-1ubuntu2".parse().unwrap();
        assert_eq!(target2.name(), "curl");
        assert_eq!(target2.version(), Some("8.18.0-1ubuntu2"));
    }
}
