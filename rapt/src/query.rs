//! Implementation of rapt query operations matching apt-cache behavior.

use std::collections::BTreeSet;

use regex::Regex;

use crate::archive::DEFAULT_ARCHIVE_URL;
use crate::error::{RaptError, Result};
use crate::models::{BinaryPackage, CacheStats, SeriesCache};
use crate::types::{PackageTarget, QueryFilter};

/// Client facade providing query methods on a target series archive cache.
#[derive(Debug, Clone)]
pub struct RaptQuery<'a> {
    cache: &'a SeriesCache,
    filter: &'a QueryFilter,
}

impl<'a> RaptQuery<'a> {
    /// Creates a new `RaptQuery` runner.
    #[must_use]
    pub fn new(cache: &'a SeriesCache, filter: &'a QueryFilter) -> Self {
        Self { cache, filter }
    }

    /// Filters a slice of packages based on the active query filter (pockets, components, archs).
    #[must_use]
    pub fn filter_packages<'p>(&self, pkgs: &'p [BinaryPackage]) -> Vec<&'p BinaryPackage> {
        pkgs.iter()
            .filter(|pkg| {
                let origin = pkg.origin();
                self.filter.contains_pocket(origin.pocket())
                    && self.filter.contains_component(origin.component())
                    && self.filter.contains_arch(origin.architecture())
            })
            .collect()
    }

    /// `showpkg PKG...`
    /// Displays information about the package(s), available versions, forward and reverse dependencies.
    pub fn showpkg(&self, package_name: &str) -> String {
        let mut out = String::new();
        out.push_str(&format!("Package: {package_name}\n"));

        let pkgs = self.cache.packages.get(package_name);
        let matching_pkgs = pkgs.map_or_else(Vec::new, |p| self.filter_packages(p));

        out.push_str("Versions: \n");
        for pkg in &matching_pkgs {
            let path_label = pkg.origin().showpkg_path_label();
            out.push_str(&format!(
                "{} (/var/lib/apt/lists/{path_label})\n",
                pkg.version()
            ));
            out.push_str(" Description Language: \n");
            out.push_str(&format!(
                "                 File: /var/lib/apt/lists/{path_label}\n"
            ));
            if let Some(md5) = pkg.description_md5() {
                out.push_str(&format!("                  MD5: {md5}\n\n"));
            } else {
                out.push('\n');
            }
        }
        if matching_pkgs.is_empty() {
            out.push('\n');
        }

        // Reverse depends across whole cache
        out.push_str("Reverse Depends: \n");
        let mut rdepends_entries = Vec::new();
        for (other_name, other_versions) in &self.cache.packages {
            for other_pkg in self.filter_packages(other_versions) {
                for group in other_pkg.depends() {
                    for clause in group.clauses() {
                        for alt in clause.alternatives() {
                            if alt.name() == package_name {
                                if let (Some(op), Some(ver)) = (alt.operator(), alt.version()) {
                                    rdepends_entries
                                        .push(format!("  {other_name},{package_name} {op} {ver}"));
                                } else {
                                    rdepends_entries.push(format!("  {other_name},{package_name}"));
                                }
                            }
                        }
                    }
                }
            }
        }
        for entry in rdepends_entries {
            out.push_str(&entry);
            out.push('\n');
        }

        // Dependencies: forward dependencies of each version
        out.push_str("Dependencies: \n");
        for pkg in &matching_pkgs {
            let mut dep_line = format!("{} - ", pkg.version());
            for group in pkg.depends() {
                for clause in group.clauses() {
                    for alt in clause.alternatives() {
                        let ver_str = alt.version().unwrap_or("(null)");
                        dep_line.push_str(&format!(
                            "{} ({} {}) ",
                            alt.name(),
                            group.dep_type().as_str(),
                            ver_str
                        ));
                    }
                }
            }
            out.push_str(dep_line.trim_end());
            out.push('\n');
        }

        // Provides: packages provided by this package
        out.push_str("Provides: \n");
        for pkg in &matching_pkgs {
            let mut prov_line = format!("{} - ", pkg.version());
            for prov in pkg.provides() {
                if let Some(ver) = prov.version() {
                    prov_line.push_str(&format!("{} (= {ver}) ", prov.name()));
                } else {
                    prov_line.push_str(&format!("{} (= ) ", prov.name()));
                }
            }
            out.push_str(&prov_line);
            out.push('\n');
        }

        // Reverse Provides: other packages that provide this package name
        out.push_str("Reverse Provides: \n");
        if let Some(providers) = self.cache.provides.get(package_name) {
            for (provider_pkg, provider_ver, provided_ver) in providers {
                if let Some(ver) = provided_ver {
                    out.push_str(&format!("{provider_pkg} {provider_ver} (= {ver})\n"));
                } else {
                    out.push_str(&format!("{provider_pkg} {provider_ver} (= )\n"));
                }
            }
        }

        out
    }

    /// `showsrc PKG...`
    /// Displays information about the source package(s).
    pub fn showsrc(&self, package_name: &str) -> Option<String> {
        let sources = self.cache.source_packages.get(package_name)?;
        let mut out = String::new();
        for src in sources {
            out.push_str(&src.format_raw_record());
            out.push('\n');
        }
        Some(out)
    }

    /// `stats`
    /// Returns statistical summary of the cache.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.cache.compute_stats()
    }

    /// `dump`
    /// Shows a short listing of every package in the cache.
    #[must_use]
    pub fn dump(&self) -> String {
        let mut out = String::from("Using Versioning System: Standard .deb\n");
        for (name, versions) in &self.cache.packages {
            out.push_str(&format!("Package: {name}\n"));
            for pkg in self.filter_packages(versions) {
                out.push_str(&format!(" Version: {}\n", pkg.version()));
                let path_label = pkg.origin().showpkg_path_label();
                out.push_str(&format!("     File: /var/lib/apt/lists/{path_label}\n"));
                for group in pkg.depends() {
                    for clause in group.clauses() {
                        for alt in clause.alternatives() {
                            let ver_str = alt.version().unwrap_or("(null)");
                            out.push_str(&format!(
                                "  {}: {} {}\n",
                                group.dep_type().as_str(),
                                alt.name(),
                                ver_str
                            ));
                        }
                    }
                }
                out.push_str(" Description Language: \n");
                out.push_str(&format!(
                    "                 File: /var/lib/apt/lists/{path_label}\n"
                ));
                if let Some(md5) = pkg.description_md5() {
                    out.push_str(&format!("                  MD5: {md5}\n"));
                }
            }
        }
        out
    }

    /// `unmet`
    /// Displays a summary of all unmet dependencies in the local rapt package cache.
    #[must_use]
    pub fn unmet(&self) -> String {
        let mut out = String::new();

        // Collect available provided and real package names
        let mut available_names = BTreeSet::new();
        for name in self.cache.packages.keys() {
            available_names.insert(name.as_str());
        }
        for name in self.cache.provides.keys() {
            available_names.insert(name.as_str());
        }

        for (pkg_name, versions) in &self.cache.packages {
            for pkg in self.filter_packages(versions) {
                let mut unmet_for_version = Vec::new();

                for group in pkg.depends() {
                    for clause in group.clauses() {
                        // A clause is satisfied if ANY of the alternatives is satisfied
                        let satisfied = clause
                            .alternatives()
                            .iter()
                            .any(|alt| available_names.contains(alt.name()));

                        if !satisfied {
                            for alt in clause.alternatives() {
                                if let (Some(op), Some(ver)) = (alt.operator(), alt.version()) {
                                    unmet_for_version.push(format!(
                                        " {}: {} ({} {})",
                                        group.dep_type().as_str(),
                                        alt.name(),
                                        op,
                                        ver
                                    ));
                                } else {
                                    unmet_for_version.push(format!(
                                        " {}: {}",
                                        group.dep_type().as_str(),
                                        alt.name()
                                    ));
                                }
                            }
                        }
                    }
                }

                if !unmet_for_version.is_empty() {
                    out.push_str(&format!(
                        "Package {pkg_name} version {} has an unmet dep:\n",
                        pkg.version()
                    ));
                    for u in unmet_for_version {
                        out.push_str(&u);
                        out.push('\n');
                    }
                }
            }
        }

        out
    }

    /// `show PKG[=PKG_VERSION_NUMBER]...`
    /// Shows the full package record(s) for the named package(s).
    pub fn show(&self, target: &PackageTarget) -> Result<String> {
        let pkgs = self
            .cache
            .packages
            .get(target.name())
            .ok_or_else(|| RaptError::PackageNotFound(target.name().to_string()))?;

        let filtered = self.filter_packages(pkgs);
        if filtered.is_empty() {
            return Err(RaptError::PackageNotFound(target.name().to_string()));
        }

        let mut out = String::new();
        let mut found = false;

        for pkg in filtered {
            if let Some(target_ver) = target.version()
                && pkg.version() != target_ver
            {
                continue;
            }
            found = true;
            out.push_str(&pkg.format_raw_record());
            out.push('\n');
        }

        if !found {
            return Err(RaptError::PackageNotFound(format!("{target}")));
        }

        Ok(out)
    }

    /// `search REGEX...`
    /// Full-text search with regexes AND'ed together.
    pub fn search(&self, patterns: &[Regex], full: bool, names_only: bool) -> String {
        let mut out = String::new();

        for (pkg_name, versions) in &self.cache.packages {
            let filtered = self.filter_packages(versions);
            if filtered.is_empty() {
                continue;
            }

            // A package might have multiple versions; pick first or highest
            let rep_pkg = filtered[0];

            let text_to_check = if names_only {
                let mut s = pkg_name.clone();
                for prov in rep_pkg.provides() {
                    s.push(' ');
                    s.push_str(prov.name());
                }
                s
            } else {
                let mut s = pkg_name.clone();
                if let Some(desc) = rep_pkg.description() {
                    s.push(' ');
                    s.push_str(desc);
                }
                for prov in rep_pkg.provides() {
                    s.push(' ');
                    s.push_str(prov.name());
                }
                s
            };

            let matches_all = patterns.iter().all(|regex| regex.is_match(&text_to_check));
            if matches_all {
                if full {
                    for pkg in filtered {
                        out.push_str(&pkg.format_raw_record());
                        out.push('\n');
                    }
                } else {
                    let short_desc = rep_pkg.short_description().unwrap_or("");
                    out.push_str(&format!("{pkg_name} - {short_desc}\n"));
                }
            }
        }

        out
    }

    /// `depends PKG[=PKG_VERSION_NUMBER]...`
    /// Shows listing of each dependency a package has.
    pub fn depends(&self, target: &PackageTarget) -> Result<String> {
        let pkgs = self
            .cache
            .packages
            .get(target.name())
            .ok_or_else(|| RaptError::PackageNotFound(target.name().to_string()))?;

        let filtered = self.filter_packages(pkgs);
        if filtered.is_empty() {
            return Err(RaptError::PackageNotFound(target.name().to_string()));
        }

        let mut out = String::new();
        let target_pkg = if let Some(target_ver) = target.version() {
            filtered.iter().find(|p| p.version() == target_ver).copied()
        } else {
            filtered.first().copied()
        };

        let target_pkg =
            target_pkg.ok_or_else(|| RaptError::PackageNotFound(format!("{target}")))?;

        out.push_str(&format!("{}\n", target_pkg.package()));
        for group in target_pkg.depends() {
            for clause in group.clauses() {
                let is_or = clause.alternatives().len() > 1;
                for (idx, alt) in clause.alternatives().iter().enumerate() {
                    let prefix = if is_or && idx > 0 { " |" } else { "  " };
                    out.push_str(&format!(
                        "{prefix}{}: {}\n",
                        group.dep_type().as_str(),
                        alt.name()
                    ));
                }
            }
        }

        Ok(out)
    }

    /// `rdepends PKG[=PKG_VERSION_NUMBER]...`
    /// Shows listing of each reverse dependency a package has.
    pub fn rdepends(&self, target: &PackageTarget) -> Result<String> {
        let pkg_name = target.name();
        let mut out = String::new();
        out.push_str(&format!("{pkg_name}\nReverse Depends:\n"));

        let mut seen_rdeps = BTreeSet::new();

        for (other_name, versions) in &self.cache.packages {
            for other_pkg in self.filter_packages(versions) {
                let matches_dep = other_pkg.depends().iter().any(|group| {
                    group.clauses().iter().any(|clause| {
                        clause.alternatives().iter().any(|alt| {
                            if alt.name() != pkg_name {
                                return false;
                            }
                            if let (Some(target_ver), Some(alt_ver)) =
                                (target.version(), alt.version())
                            {
                                // Basic version match or target match
                                alt_ver == target_ver
                            } else {
                                true
                            }
                        })
                    })
                });

                if matches_dep && seen_rdeps.insert(other_name.clone()) {
                    out.push_str(&format!("  {other_name}\n"));
                }
            }
        }

        Ok(out)
    }

    /// `pkgnames [PREFIX]`
    /// Prints the name of each package in the local rapt package cache.
    #[must_use]
    pub fn pkgnames(&self, prefix: Option<&str>) -> Vec<String> {
        let mut names = BTreeSet::new();
        for name in self.cache.packages.keys() {
            names.insert(name.clone());
        }
        for name in self.cache.provides.keys() {
            names.insert(name.clone());
        }

        if let Some(pfx) = prefix {
            names.into_iter().filter(|n| n.starts_with(pfx)).collect()
        } else {
            names.into_iter().collect()
        }
    }

    /// `madison PKG...`
    /// Mimics output format and functionality of `madison`.
    pub fn madison(&self, package_name: &str) -> String {
        let mut out = String::new();
        let mut rows: Vec<(String, String, String)> = Vec::new();

        // Binary packages
        if let Some(versions) = self.cache.packages.get(package_name) {
            for pkg in self.filter_packages(versions) {
                let label = pkg.origin().madison_archive_label();
                rows.push((pkg.package().to_string(), pkg.version().to_string(), label));
            }
        }

        // Also check if any source package matches
        if let Some(srcs) = self.cache.source_packages.get(package_name) {
            for src in srcs {
                let label = format!(
                    "{} {}/main Sources",
                    DEFAULT_ARCHIVE_URL,
                    self.filter.series()
                );
                rows.push((src.package().to_string(), src.version().to_string(), label));
            }
        }

        // Format tabular columns with padding
        let max_name = rows
            .iter()
            .map(|(n, _, _)| n.len())
            .max()
            .unwrap_or(package_name.len());
        let max_ver = rows.iter().map(|(_, v, _)| v.len()).max().unwrap_or(0);

        for (name, ver, archive) in rows {
            out.push_str(&format!(
                "{name:>width$} | {ver:>vwidth$} | {archive}\n",
                width = max_name + 4,
                vwidth = max_ver
            ));
        }

        out
    }
}
