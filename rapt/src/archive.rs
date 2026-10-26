//! Network client and decompression routines for downloading archive indices.

use std::io::Read;

use flate2::read::GzDecoder;
use reqwest::Client;
use ubuntu_info_rust::{Architecture, Archive, Component, Pocket, SeriesInfo, Suite};
use xz2::read::XzDecoder;

use crate::error::{RaptError, Result};
use crate::models::{BinaryPackage, PackageOrigin, SeriesCache, SourcePackage};
use crate::parser::{parse_binary_package, parse_rfc822_paragraphs, parse_source_package};
use crate::types::QueryFilter;

/// Network client for communicating with the Ubuntu archive.
#[derive(Debug, Clone)]
pub struct ArchiveClient {
    client: Client,
}

impl Default for ArchiveClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveClient {
    /// Creates a new `ArchiveClient`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .user_agent("rapt/0.1.0 (Ubuntu archive client)")
                .build()
                .unwrap_or_default(),
        }
    }

    /// Downloads and decompresses a remote URL to raw text string.
    pub async fn fetch_decompressed(&self, url: &str) -> Result<String> {
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(RaptError::Other(format!(
                "HTTP error {} when fetching {url}",
                resp.status()
            )));
        }

        let bytes = resp.bytes().await?;
        decompress_bytes(&bytes, url)
    }

    /// Downloads binary `Packages` index for the given pocket, component, and arch.
    pub async fn fetch_packages(
        &self,
        series: &str,
        pocket: Pocket,
        component: Component,
        arch: Architecture,
    ) -> Result<Vec<BinaryPackage>> {
        let suite = suite_for(series, pocket)?;
        let archive = archive_for(pocket, arch);
        let dists_url = archive.dists_url(&suite, component, arch);

        // Try Packages.xz first, fallback to Packages.gz
        let url_xz = format!("{dists_url}Packages.xz");
        let uncompressed_text = match self.fetch_decompressed(&url_xz).await {
            Ok(text) => text,
            Err(_) => {
                let url_gz = format!("{dists_url}Packages.gz");
                self.fetch_decompressed(&url_gz).await?
            }
        };

        let origin = PackageOrigin::new(
            pocket,
            component,
            arch,
            archive.base_url(),
            suite.to_string(),
        );
        let paragraphs = parse_rfc822_paragraphs(&uncompressed_text);
        let mut packages = Vec::with_capacity(paragraphs.len());

        for fields in paragraphs {
            if let Ok(pkg) = parse_binary_package(fields, origin.clone()) {
                packages.push(pkg);
            }
        }

        Ok(packages)
    }

    /// Downloads `Sources` index for the given pocket and component.
    pub async fn fetch_sources(
        &self,
        series: &str,
        pocket: Pocket,
        component: Component,
    ) -> Result<Vec<SourcePackage>> {
        let suite = suite_for(series, pocket)?;
        let base_url = archive_for_pocket(pocket).base_url();

        let url_xz = format!(
            "{base_url}/dists/{suite}/{}/source/Sources.xz",
            component.as_str()
        );

        let uncompressed_text = match self.fetch_decompressed(&url_xz).await {
            Ok(text) => text,
            Err(_) => {
                let url_gz = format!(
                    "{base_url}/dists/{suite}/{}/source/Sources.gz",
                    component.as_str()
                );
                self.fetch_decompressed(&url_gz).await?
            }
        };

        let paragraphs = parse_rfc822_paragraphs(&uncompressed_text);
        let mut sources = Vec::with_capacity(paragraphs.len());

        for fields in paragraphs {
            if let Ok(src) = parse_source_package(fields) {
                sources.push(src);
            }
        }

        Ok(sources)
    }

    /// Fetches all packages and sources for a given `QueryFilter` and populates a `SeriesCache`.
    pub async fn populate_cache(&self, filter: &QueryFilter) -> Result<SeriesCache> {
        let mut cache = SeriesCache::new(filter.series());
        let series = filter.series();

        // Download binary packages for each pocket, component, arch
        for pocket in filter.pockets() {
            for component in filter.components() {
                // Download source packages once per (pocket, component)
                if let Ok(sources) = self.fetch_sources(series, *pocket, *component).await {
                    for src in sources {
                        cache
                            .source_packages
                            .entry(src.package().to_string())
                            .or_default()
                            .push(src);
                    }
                }

                for arch in filter.architectures() {
                    match self
                        .fetch_packages(series, *pocket, *component, *arch)
                        .await
                    {
                        Ok(pkgs) => {
                            for pkg in pkgs {
                                let pkg_name = pkg.package().to_string();
                                let pkg_ver = pkg.version().to_string();

                                for prov in pkg.provides() {
                                    cache
                                        .provides
                                        .entry(prov.name().to_string())
                                        .or_default()
                                        .push((
                                            pkg_name.clone(),
                                            pkg_ver.clone(),
                                            prov.version().map(str::to_string),
                                        ));
                                }

                                cache.packages.entry(pkg_name).or_default().push(pkg);
                            }
                        }
                        Err(e) => {
                            // Non-fatal if a specific pocket/component/arch doesn't exist
                            // but log or continue
                            eprintln!(
                                "Warning: could not fetch {series}/{pocket}/{component}/{arch}: {e}"
                            );
                        }
                    }
                }
            }
        }

        Ok(cache)
    }
}

/// Resolves a series name to a `Suite` for the given pocket.
fn suite_for(series: &str, pocket: Pocket) -> Result<Suite> {
    let series = SeriesInfo::from_short_name(series)
        .or_else(|| SeriesInfo::from_code_name(series))
        .or_else(|| SeriesInfo::from_version(series))
        .ok_or_else(|| RaptError::InvalidSeries(series.to_string()))?;
    Ok(Suite::new(series, pocket))
}

/// Selects the archive that hosts the given pocket and architecture.
fn archive_for(pocket: Pocket, arch: Architecture) -> Archive {
    if pocket == Pocket::Security {
        arch.security_archive()
    } else {
        arch.archive()
    }
}

/// Selects the archive that hosts source indices for the given pocket.
fn archive_for_pocket(pocket: Pocket) -> Archive {
    if pocket == Pocket::Security {
        Archive::Security
    } else {
        Archive::Primary
    }
}

/// Decompresses raw bytes based on URL extension or magic header.
pub fn decompress_bytes(bytes: &[u8], url_hint: &str) -> Result<String> {
    if url_hint.ends_with(".xz") || (bytes.len() >= 6 && &bytes[0..6] == b"\xFD7zXZ\x00") {
        let mut decoder = XzDecoder::new(bytes);
        let mut s = String::new();
        decoder
            .read_to_string(&mut s)
            .map_err(|e| RaptError::Decompression(format!("failed to decompress XZ: {e}")))?;
        Ok(s)
    } else if url_hint.ends_with(".gz") || (bytes.len() >= 2 && &bytes[0..2] == b"\x1F\x8B") {
        let mut decoder = GzDecoder::new(bytes);
        let mut s = String::new();
        decoder
            .read_to_string(&mut s)
            .map_err(|e| RaptError::Decompression(format!("failed to decompress GZ: {e}")))?;
        Ok(s)
    } else {
        // Plain text
        String::from_utf8(bytes.to_vec())
            .map_err(|e| RaptError::Decompression(format!("invalid UTF-8 data: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_pocket_uses_the_security_archive() {
        assert_eq!(
            archive_for(Pocket::Security, Architecture::Amd64),
            Archive::Security
        );
        assert_eq!(
            archive_for(Pocket::Security, Architecture::Arm64),
            Archive::Ports
        );
        assert_eq!(
            archive_for(Pocket::Updates, Architecture::Amd64),
            Archive::Primary
        );
        assert_eq!(
            archive_for(Pocket::Updates, Architecture::Arm64),
            Archive::Ports
        );
    }

    #[test]
    fn suite_resolution_accepts_series_forms() {
        for input in ["resolute", "Resolute Raccoon", "26.04"] {
            let suite = suite_for(input, Pocket::Security).unwrap();
            assert_eq!(suite.to_string(), "resolute-security");
        }
        assert!(suite_for("not-a-series", Pocket::Release).is_err());
    }

    #[test]
    fn dists_url_uses_the_expected_archive() {
        let suite = suite_for("resolute", Pocket::Security).unwrap();
        let url = archive_for(Pocket::Security, Architecture::Amd64).dists_url(
            &suite,
            Component::Main,
            Architecture::Amd64,
        );
        assert_eq!(
            url,
            "http://security.ubuntu.com/ubuntu/dists/resolute-security/main/binary-amd64/"
        );
    }
}
