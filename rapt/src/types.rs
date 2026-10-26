//! Core domain types, enumerations, and query filter definitions for rapt.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ubuntu_info_rust::SeriesInfo;

pub use ubuntu_info_rust::{Architecture, Component, Pocket};

use crate::error::{RaptError, Result};

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

    /// Returns the `ubuntu-info-rust` metadata for the target series.
    ///
    /// The series is validated when the filter is built, so this always returns
    /// `Some` for filters produced by [`QueryFilterBuilder::build`].
    #[must_use]
    pub fn series_info(&self) -> Option<&'static SeriesInfo> {
        SeriesInfo::from_short_name(&self.series)
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
        let series = self.series.trim();
        if series.is_empty() {
            return Err(RaptError::MissingSeries);
        }

        // Resolve the series through `ubuntu-info-rust` so that short code names,
        // full code names, and version numbers are all accepted and normalized to
        // the canonical short code name used in archive suites.
        let series_info = SeriesInfo::from_short_name(series)
            .or_else(|| SeriesInfo::from_code_name(series))
            .or_else(|| SeriesInfo::from_version(series))
            .ok_or_else(|| RaptError::InvalidSeries(series.to_string()))?;
        let series = series_info.code_name_short.to_string();

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
                let all_pockets = Pocket::ALL;
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
                let all_components = Component::ALL;
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
                let all_archs = Architecture::ALL;
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
    Component::ALL.into_iter().collect()
}

/// The architectures rapt queries when no `--arch` filter is given.
///
/// `amd64v3` and `i386` are available through `ubuntu-info-rust` and can be
/// requested explicitly, but they are not part of the default set because they
/// are not present in every series and pocket.
fn default_architectures() -> BTreeSet<Architecture> {
    [
        Architecture::Amd64,
        Architecture::Arm64,
        Architecture::Armhf,
        Architecture::Ppc64el,
        Architecture::S390x,
        Architecture::Riscv64,
    ]
    .into_iter()
    .collect()
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

    #[test]
    fn test_series_is_normalized() {
        for input in ["resolute", "Resolute Raccoon", "26.04", "26.04 LTS"] {
            let filter = QueryFilter::builder(input).build().unwrap();
            assert_eq!(filter.series(), "resolute", "input: {input}");
            assert_eq!(filter.series_info().map(|info| info.version), Some("26.04"));
        }
    }

    #[test]
    fn test_unknown_series_is_rejected() {
        let err = QueryFilter::builder("not-a-series").build().unwrap_err();
        assert!(matches!(err, RaptError::InvalidSeries(ref s) if s == "not-a-series"));
    }

    #[test]
    fn test_architectures_accept_ubuntu_info_variants() {
        let filter = QueryFilter::builder("resolute")
            .architectures(vec![Architecture::Amd64v3, Architecture::I386])
            .build()
            .unwrap();
        assert!(filter.contains_arch(Architecture::Amd64v3));
        assert!(filter.contains_arch(Architecture::I386));
    }
}
