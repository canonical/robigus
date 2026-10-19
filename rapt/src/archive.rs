//! Network client and decompression routines for downloading archive indices.

use std::io::Read;

use flate2::read::GzDecoder;
use reqwest::Client;
use xz2::read::XzDecoder;

use crate::error::{RaptError, Result};
use crate::models::{BinaryPackage, PackageOrigin, SeriesCache, SourcePackage};
use crate::parser::{parse_binary_package, parse_rfc822_paragraphs, parse_source_package};
use crate::types::{Architecture, Component, Pocket, QueryFilter};

/// Default primary Ubuntu archive URL.
pub const DEFAULT_ARCHIVE_URL: &str = "http://archive.ubuntu.com/ubuntu";

/// Default ports Ubuntu archive URL for architectures other than amd64.
pub const DEFAULT_PORTS_URL: &str = "http://ports.ubuntu.com/ubuntu-ports";

/// Network client for communicating with the Ubuntu archive.
#[derive(Debug, Clone)]
pub struct ArchiveClient {
    client: Client,
    archive_url: String,
    ports_url: String,
}

impl Default for ArchiveClient {
    fn default() -> Self {
        Self::new(DEFAULT_ARCHIVE_URL, DEFAULT_PORTS_URL)
    }
}

impl ArchiveClient {
    /// Creates a new `ArchiveClient`.
    #[must_use]
    pub fn new(archive_url: impl Into<String>, ports_url: impl Into<String>) -> Self {
        Self {
            client: Client::builder()
                .user_agent("rapt/0.1.0 (Ubuntu archive client)")
                .build()
                .unwrap_or_default(),
            archive_url: archive_url.into(),
            ports_url: ports_url.into(),
        }
    }

    /// Selects the appropriate base URL for the given architecture.
    #[must_use]
    pub fn base_url_for_arch(&self, arch: Architecture) -> &str {
        if arch.is_ports() {
            &self.ports_url
        } else {
            &self.archive_url
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
        let base_url = self.base_url_for_arch(arch);
        let suite = pocket.suite_for_series(series);

        // Try Packages.xz first, fallback to Packages.gz
        let url_xz = format!(
            "{base_url}/dists/{suite}/{}/binary-{}/Packages.xz",
            component.as_str(),
            arch.as_str()
        );

        let uncompressed_text = match self.fetch_decompressed(&url_xz).await {
            Ok(text) => text,
            Err(_) => {
                let url_gz = format!(
                    "{base_url}/dists/{suite}/{}/binary-{}/Packages.gz",
                    component.as_str(),
                    arch.as_str()
                );
                self.fetch_decompressed(&url_gz).await?
            }
        };

        let origin = PackageOrigin::new(pocket, component, arch, base_url, &suite);
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
        let base_url = &self.archive_url;
        let suite = pocket.suite_for_series(series);

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
