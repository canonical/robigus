//! Local cache management for rapt.
//!
//! Stores series-specific cache files timestamped with last update date/time.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use crate::error::{RaptError, Result};
use crate::models::SeriesCache;

/// Cache directory manager.
#[derive(Debug, Clone)]
pub struct CacheManager {
    cache_dir: PathBuf,
}

impl Default for CacheManager {
    fn default() -> Self {
        let dir = dirs_fallback_cache_dir();
        Self::new(dir)
    }
}

impl CacheManager {
    /// Creates a new `CacheManager` with a custom directory.
    #[must_use]
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    /// Returns the cache directory path.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Cache file path for a specific series.
    #[must_use]
    pub fn cache_file_path(&self, series: &str) -> PathBuf {
        self.cache_dir.join(format!("{series}.json"))
    }

    /// Loads the cache file for the given series if it exists.
    pub fn load_cache(&self, series: &str) -> Result<Option<SeriesCache>> {
        let path = self.cache_file_path(series);
        if !path.exists() {
            return Ok(None);
        }

        let file = File::open(&path).map_err(|source| RaptError::Io {
            path: path.clone(),
            source,
        })?;
        let reader = BufReader::new(file);
        let cache: SeriesCache = serde_json::from_reader(reader)?;
        Ok(Some(cache))
    }

    /// Saves the cache for the given series to disk.
    pub fn save_cache(&self, cache: &SeriesCache) -> Result<()> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir).map_err(|source| RaptError::Io {
                path: self.cache_dir.clone(),
                source,
            })?;
        }

        let path = self.cache_file_path(&cache.series);
        let file = File::create(&path).map_err(|source| RaptError::Io {
            path: path.clone(),
            source,
        })?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, cache)?;
        Ok(())
    }
}

fn dirs_fallback_cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("RAPT_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("rapt");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".cache").join("rapt");
    }
    PathBuf::from("/tmp/rapt-cache")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cache_save_and_load() {
        let dir = tempdir().unwrap();
        let manager = CacheManager::new(dir.path());

        assert!(manager.load_cache("resolute").unwrap().is_none());

        let cache = SeriesCache::new("resolute");
        manager.save_cache(&cache).unwrap();

        let loaded = manager.load_cache("resolute").unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.series, "resolute");
        assert!(loaded.is_fresh());
    }
}
