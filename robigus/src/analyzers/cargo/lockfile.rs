//! `Cargo.lock` parsing and Cargo `source` string classification (spec §8.1,
//! §7.2.1; WP-2.2).

use std::collections::BTreeMap;
use std::path::PathBuf;

use semver::Version;
use url::Url;

use crate::credentials::bounded;
use crate::model::{GitReference, SourceId, SourceKind, SourceLocation};
use crate::registry::{IndexUrlPolicy, RegistrySpec, crates_io_alias, normalize_index_url};
use crate::sandbox::proxy::HostName;

/// Classification of a Cargo `source` string from `Cargo.lock` or
/// `cargo metadata`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CargoSourceKind {
    /// A supported sparse registry (including crates.io's legacy git alias).
    Registry { index_url: Url },
    /// A non-crates.io git-protocol registry (`registry+https://…`).
    UnsupportedGitRegistry { raw: String },
    /// A git repository over `https` with a literal DNS host, no credentials
    /// or extra query parameters, pinned to an exact commit hash.
    Git {
        url: Url,
        reference: GitReference,
        commit: String,
    },
    /// A git source without a full 40- or 64-hex commit hash.
    UnpinnedGit { reason: String },
    /// An unrecognized, unsafe, or malformed Cargo source string.
    Unsupported { reason: String },
}

/// Classifies a Cargo `source` string (such as
/// `"registry+https://github.com/rust-lang/crates.io-index"`,
/// `"sparse+https://registry.example/index/"`, or
/// `"git+https://github.com/org/repo.git?tag=v1.0#0123…"`).
///
/// Configured `registries` are matched by normalized index URL without
/// assuming a configured credential source implies the registry rejected
/// unauthenticated access: if `cargo metadata` succeeded inside the tokenless
/// sandbox, the registry served metadata publicly.
pub(super) fn classify_cargo_source(raw: &str, registries: &[RegistrySpec]) -> CargoSourceKind {
    let trimmed = raw.trim();
    if let Some(crates_io) = crates_io_alias(trimmed) {
        return CargoSourceKind::Registry {
            index_url: crates_io,
        };
    }
    if let Some(rest) = trimmed.strip_prefix("git+") {
        return parse_git_source(rest);
    }
    // Match operator-configured registries before enforcing `HttpsOnly` so test
    // registries constructed with `AllowInsecureHttp` resolve consistently.
    if let Ok(candidate) = normalize_index_url(trimmed, IndexUrlPolicy::AllowInsecureHttp)
        && let Some(spec) = registries.iter().find(|spec| spec.index_url == candidate)
    {
        return CargoSourceKind::Registry {
            index_url: spec.index_url.clone(),
        };
    }
    if trimmed.starts_with("registry+") {
        return CargoSourceKind::UnsupportedGitRegistry {
            raw: scrub_url_credentials_in_text(trimmed),
        };
    }
    match normalize_index_url(trimmed, IndexUrlPolicy::HttpsOnly) {
        Ok(index_url) => CargoSourceKind::Registry { index_url },
        Err(error) => CargoSourceKind::Unsupported {
            reason: error.to_string(),
        },
    }
}

fn parse_git_source(without_prefix: &str) -> CargoSourceKind {
    let Ok(mut url) = Url::parse(without_prefix) else {
        return CargoSourceKind::Unsupported {
            reason: "invalid git dependency URL".to_string(),
        };
    };
    // Reject credentials before formatting any diagnostic so userinfo in an
    // untrusted manifest or lockfile can never reach stored or exported text.
    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        return CargoSourceKind::Unsupported {
            reason: format!(
                "git dependency URL '{}' must not embed credentials",
                bounded(url.as_str())
            ),
        };
    }
    if url.scheme() != "https" {
        let scheme = url.scheme().to_string();
        url.set_query(None);
        url.set_fragment(None);
        return CargoSourceKind::Unsupported {
            reason: format!(
                "git dependency URL scheme '{scheme}' is not allowed; only https is supported"
            ),
        };
    }
    let Some(host_str) = url.host_str() else {
        return CargoSourceKind::Unsupported {
            reason: "git dependency URL has no host".to_string(),
        };
    };
    if let Err(invalid_host) = host_str.parse::<HostName>() {
        return CargoSourceKind::Unsupported {
            reason: format!("git dependency URL has invalid host: {invalid_host}"),
        };
    }
    if url.port().is_some() {
        return CargoSourceKind::Unsupported {
            reason: "git dependency URL must use the default https port".to_string(),
        };
    }

    let Some(fragment) = url.fragment().map(str::to_owned) else {
        return CargoSourceKind::UnpinnedGit {
            reason: "git dependency source has no locked commit fragment".to_string(),
        };
    };
    let commit = fragment.trim().to_ascii_lowercase();
    if !matches!(commit.len(), 40 | 64) || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return CargoSourceKind::UnpinnedGit {
            reason: format!(
                "git commit '{}' is not a 40- or 64-character hex object id",
                bounded(&fragment)
            ),
        };
    }

    let mut reference: Option<GitReference> = None;
    for (key, value) in url.query_pairs() {
        let parsed = match key.as_ref() {
            "branch" => GitReference::Branch(value.into_owned()),
            "tag" => GitReference::Tag(value.into_owned()),
            "rev" => GitReference::Rev(value.into_owned()),
            other => {
                return CargoSourceKind::Unsupported {
                    reason: format!(
                        "git dependency URL carries unsupported query parameter '{}'",
                        bounded(other)
                    ),
                };
            }
        };
        if reference.replace(parsed).is_some() {
            return CargoSourceKind::Unsupported {
                reason: "git dependency URL specifies multiple ref query parameters".to_string(),
            };
        }
    }
    url.set_fragment(None);
    url.set_query(None);

    CargoSourceKind::Git {
        url,
        reference: reference.unwrap_or(GitReference::DefaultBranch),
        commit,
    }
}

fn scrub_url_credentials_in_text(raw: &str) -> String {
    let prefix = raw
        .find('+')
        .map(|idx| (&raw[..=idx], &raw[idx + 1..]))
        .unwrap_or(("", raw));
    if let Ok(mut parsed) = Url::parse(prefix.1)
        && (!parsed.username().is_empty() || parsed.password().is_some())
    {
        let _ = parsed.set_username("");
        let _ = parsed.set_password(None);
        return bounded(&format!("{}{parsed}", prefix.0));
    }
    bounded(raw)
}

/// Formats a `toml_edit::TomlError` with line/offset context without quoting
/// raw document text.
pub(super) fn format_toml_error(content: &str, error: &toml_edit::TomlError) -> String {
    if let Some(span) = error.span() {
        let starts = line_offsets(content);
        let line = starts.partition_point(|&off| off <= span.start).max(1);
        format!("line {line}: {}", bounded(error.message()))
    } else {
        bounded(error.message())
    }
}

/// One locked package record from `Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LockedPackage {
    /// Verified 64-hex SHA-256 `.crate` checksum, when recorded.
    pub(super) checksum: Option<String>,
    /// 1-based line span in `Cargo.lock`, when known.
    pub(super) lines: Option<(u64, u64)>,
}

/// Key into [`CargoLock`] for registry packages: `(name, version, index_url)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RegistryLockKey {
    name: String,
    version: Version,
    index_url: Url,
}

/// Key into [`CargoLock`] for git packages: `(name, version, clean_repo_url, commit)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GitLockKey {
    name: String,
    version: Version,
    url: Url,
    commit: String,
}

/// Key indexing any commit locked for `(name, version, clean_repo_url)` so a
/// commit mismatch between `Cargo.lock` and `cargo metadata` can be diagnosed
/// explicitly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GitPkgKey {
    name: String,
    version: Version,
    url: Url,
}

/// Parsed `Cargo.lock` used to attach `.crate` checksums, verify git commit
/// pins, and record lockfile evidence.
#[derive(Debug, Clone, Default)]
pub(super) struct CargoLock {
    /// Workspace-relative path of `Cargo.lock` (for example `"Cargo.lock"`).
    relative_path: PathBuf,
    registry: BTreeMap<RegistryLockKey, LockedPackage>,
    git: BTreeMap<GitLockKey, LockedPackage>,
    git_by_pkg: BTreeMap<GitPkgKey, Vec<String>>,
}

impl CargoLock {
    /// Parses `content` as a `Cargo.lock` located at `relative_path`
    /// (workspace-relative). Supports lockfile v1 (`[metadata]` checksums)
    /// through v4 (`[[package]] checksum = "…"`).
    pub(super) fn parse(
        content: &str,
        relative_path: PathBuf,
        registries: &[RegistrySpec],
    ) -> Result<Self, String> {
        let doc = toml_edit::Document::parse(content).map_err(|error| {
            format!(
                "malformed Cargo.lock ({})",
                format_toml_error(content, &error)
            )
        })?;
        let line_starts = line_offsets(content);
        let span_lines = |span: Option<std::ops::Range<usize>>| -> Option<(u64, u64)> {
            let span = span?;
            let start = line_starts.partition_point(|&off| off <= span.start) as u64;
            let end_offset = span.end.saturating_sub(1).max(span.start);
            let end = line_starts.partition_point(|&off| off <= end_offset) as u64;
            Some((start.max(1), end.max(start.max(1))))
        };

        // v1 lockfiles stored checksums under `[metadata]`:
        // `"checksum <name> <ver> (<source>)" = "<sha256>"`.
        let mut legacy_checksums: BTreeMap<(String, String, String), String> = BTreeMap::new();
        if let Some(metadata) = doc.get("metadata").and_then(|item| item.as_table_like()) {
            for (key, value) in metadata.iter() {
                if let Some(parsed_key) = parse_legacy_checksum_key(key)
                    && let Some(hex) = value.as_str().and_then(normalize_sha256)
                {
                    legacy_checksums.insert(parsed_key, hex);
                }
            }
        }

        let mut lock = Self {
            relative_path,
            registry: BTreeMap::new(),
            git: BTreeMap::new(),
            git_by_pkg: BTreeMap::new(),
        };

        let Some(packages) = doc
            .get("package")
            .and_then(|item| item.as_array_of_tables())
        else {
            return Ok(lock);
        };

        for table in packages {
            let Some(name) = table.get("name").and_then(|i| i.as_str()) else {
                continue;
            };
            let Some(version_str) = table.get("version").and_then(|i| i.as_str()) else {
                continue;
            };
            let Ok(version) = version_str.parse::<Version>() else {
                continue;
            };
            let Some(source_str) = table.get("source").and_then(|i| i.as_str()) else {
                continue;
            };
            let inline_checksum = table.get("checksum").and_then(|i| i.as_str());
            let checksum = match inline_checksum {
                Some(raw) => match normalize_sha256(raw) {
                    Some(valid) => Some(valid),
                    None => {
                        return Err(format!(
                            "Cargo.lock package '{name} {version}' has an invalid SHA-256 checksum '{}'",
                            bounded(raw)
                        ));
                    }
                },
                None => legacy_checksums
                    .get(&(
                        name.to_string(),
                        version_str.to_string(),
                        source_str.to_string(),
                    ))
                    .cloned(),
            };
            let lines = span_lines(table.span());

            match classify_cargo_source(source_str, registries) {
                CargoSourceKind::Registry { index_url } => {
                    lock.registry.insert(
                        RegistryLockKey {
                            name: name.to_string(),
                            version,
                            index_url,
                        },
                        LockedPackage { checksum, lines },
                    );
                }
                CargoSourceKind::Git { url, commit, .. } => {
                    lock.git_by_pkg
                        .entry(GitPkgKey {
                            name: name.to_string(),
                            version: version.clone(),
                            url: url.clone(),
                        })
                        .or_default()
                        .push(commit.clone());
                    lock.git.insert(
                        GitLockKey {
                            name: name.to_string(),
                            version,
                            url,
                            commit,
                        },
                        LockedPackage {
                            checksum: None,
                            lines,
                        },
                    );
                }
                CargoSourceKind::UnsupportedGitRegistry { .. }
                | CargoSourceKind::UnpinnedGit { .. }
                | CargoSourceKind::Unsupported { .. } => {}
            }
        }

        Ok(lock)
    }

    /// Looks up a registry package and returns its locked record (including
    /// its `.crate` SHA-256 checksum when present).
    pub(super) fn registry_package(
        &self,
        name: &str,
        version: &Version,
        index_url: &Url,
    ) -> Option<&LockedPackage> {
        self.registry.get(&RegistryLockKey {
            name: name.to_string(),
            version: version.clone(),
            index_url: index_url.clone(),
        })
    }

    /// Looks up a git package at `(name, version, repo_url, commit)`.
    #[cfg(test)]
    pub(super) fn git_package(
        &self,
        name: &str,
        version: &Version,
        url: &Url,
        commit: &str,
    ) -> Option<&LockedPackage> {
        self.git.get(&GitLockKey {
            name: name.to_string(),
            version: version.clone(),
            url: url.clone(),
            commit: commit.to_string(),
        })
    }

    /// Builds a [`SourceLocation`] pointing into this `Cargo.lock`.
    pub(super) fn location(&self, lines: Option<(u64, u64)>) -> SourceLocation {
        SourceLocation {
            path: self.relative_path.clone(),
            start_line: lines.map(|(start, _)| start),
            end_line: lines.map(|(_, end)| end),
        }
    }

    /// Builds the pinned [`SourceId`] for a registry crate when `Cargo.lock`
    /// has a checksum for it, or `Err(reason)` explaining why it must stay
    /// declared-but-unresolved.
    pub(super) fn resolve_registry_source_id(
        &self,
        name: &str,
        version: &Version,
        index_url: &Url,
    ) -> Result<(SourceId, SourceLocation), String> {
        let Some(locked) = self.registry_package(name, version, index_url) else {
            return Err(format!(
                "registry crate '{name} {version}' ({index_url}) is not present in Cargo.lock"
            ));
        };
        let Some(checksum) = &locked.checksum else {
            return Err(format!(
                "registry crate '{name} {version}' ({index_url}) has no checksum in Cargo.lock"
            ));
        };
        Ok((
            SourceId {
                kind: SourceKind::CargoRegistry {
                    index_url: index_url.clone(),
                },
                precise: Some(checksum.clone()),
            },
            self.location(locked.lines),
        ))
    }

    /// Verifies that `Cargo.lock` pins `(name, version, url)` at `commit` and
    /// returns the pinned [`SourceId`] and lockfile [`SourceLocation`], or
    /// `Err(reason)` when the git dependency is absent from `Cargo.lock` or
    /// locked at a different commit.
    pub(super) fn resolve_git_source_id(
        &self,
        name: &str,
        version: &Version,
        url: &Url,
        reference: GitReference,
        commit: &str,
    ) -> Result<(SourceId, SourceLocation), String> {
        let exact_key = GitLockKey {
            name: name.to_string(),
            version: version.clone(),
            url: url.clone(),
            commit: commit.to_string(),
        };
        if let Some(locked) = self.git.get(&exact_key) {
            return Ok((
                SourceId {
                    kind: SourceKind::Git {
                        url: url.clone(),
                        reference,
                    },
                    precise: Some(commit.to_string()),
                },
                self.location(locked.lines),
            ));
        }
        let pkg_key = GitPkgKey {
            name: name.to_string(),
            version: version.clone(),
            url: url.clone(),
        };
        if let Some(other_commits) = self.git_by_pkg.get(&pkg_key) {
            return Err(format!(
                "Cargo.lock pins git crate '{name} {version}' ({url}) at [{}], \
                 disagreeing with resolved commit {commit}",
                other_commits.join(", ")
            ));
        }
        Err(format!(
            "git crate '{name} {version}' ({url}) is not pinned in Cargo.lock \
             (commit {commit} was resolved dynamically during analysis)"
        ))
    }
}

fn parse_legacy_checksum_key(key: &str) -> Option<(String, String, String)> {
    let rest = key.strip_prefix("checksum ")?;
    let (name, rest) = rest.split_once(' ')?;
    let (version, paren) = rest.split_once(' ')?;
    let source = paren.strip_prefix('(')?.strip_suffix(')')?;
    // `<none>` was Cargo's v1 marker for a replaced source without checksum.
    (source != "<none>").then(|| (name.to_string(), version.to_string(), source.to_string()))
}

pub(super) fn normalize_sha256(raw: &str) -> Option<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    (normalized.len() == 64 && normalized.chars().all(|c| c.is_ascii_hexdigit()))
        .then_some(normalized)
}

fn line_offsets(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(idx + 1);
        }
    }
    starts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::CredentialSource;
    use crate::registry::CRATES_IO_INDEX;
    use std::path::Path;

    #[test]
    fn classifies_sources_and_rejects_unsafe_git_urls_without_leaking_userinfo() {
        let configured = RegistrySpec::named(
            "corp",
            "sparse+https://cargo.corp.example/index",
            CredentialSource::Env {
                registry: "corp".into(),
            },
        )
        .unwrap();
        let registries = [configured];

        assert_eq!(
            classify_cargo_source(
                "registry+https://github.com/rust-lang/crates.io-index",
                &registries
            ),
            CargoSourceKind::Registry {
                index_url: Url::parse(CRATES_IO_INDEX).unwrap(),
            }
        );
        // A configured registry with a credential source still classifies as a
        // normal sparse registry if `cargo metadata` succeeded without a token.
        assert_eq!(
            classify_cargo_source("sparse+https://cargo.corp.example/index/", &registries),
            CargoSourceKind::Registry {
                index_url: Url::parse("https://cargo.corp.example/index/").unwrap(),
            }
        );
        assert!(matches!(
            classify_cargo_source("registry+https://git.other.example/index", &registries),
            CargoSourceKind::UnsupportedGitRegistry { .. }
        ));

        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            classify_cargo_source(
                &format!("git+https://github.com/example/lib.git?tag=v1.2.0#{commit}"),
                &registries
            ),
            CargoSourceKind::Git {
                url: Url::parse("https://github.com/example/lib.git").unwrap(),
                reference: GitReference::Tag("v1.2.0".into()),
                commit: commit.into(),
            }
        );
        assert!(matches!(
            classify_cargo_source("git+https://github.com/example/lib.git#short", &registries),
            CargoSourceKind::UnpinnedGit { .. }
        ));

        // Non-https schemes (`file://`, `ssh://`, `http://`), IP literals,
        // non-default ports, extra query params, and userinfo are all rejected,
        // and userinfo secrets never appear in the reason string.
        let canary = "ghp_SUPER_SECRET_GIT_TOKEN";
        for bad in [
            format!("git+file:///tmp/local-repo#{commit}"),
            format!("git+ssh://git@github.com/example/lib.git#{commit}"),
            format!("git+http://github.com/example/lib.git#{commit}"),
            format!("git+https://127.0.0.1/example/lib.git#{commit}"),
            format!("git+https://github.com:8443/example/lib.git#{commit}"),
            format!("git+https://github.com/example/lib.git?tag=v1&extra=1#{commit}"),
            format!("git+https://github.com/example/lib.git?branch=a&tag=b#{commit}"),
            format!("git+https://user:{canary}@github.com/example/lib.git#{commit}"),
        ] {
            match classify_cargo_source(&bad, &registries) {
                CargoSourceKind::Unsupported { reason } => {
                    assert!(!reason.contains(canary), "leaked secret in: {reason}");
                }
                other => panic!("expected Unsupported for {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parses_v4_and_v1_lockfiles_verifies_git_pins_and_omits_raw_snippets() {
        let cksum_a = "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b";
        let cksum_b = "b".repeat(64);
        let commit = "fedcba9876543210fedcba9876543210fedcba98";
        let other_commit = "1111111111111111111111111111111111111111";
        let text = format!(
            r#"version = 4

[[package]]
name = "itoa"
version = "1.0.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{cksum_a}"

[[package]]
name = "legacy"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "gitdep"
version = "0.3.1"
source = "git+https://github.com/example/gitdep?branch=main#{commit}"

[metadata]
"checksum legacy 0.2.0 (registry+https://github.com/rust-lang/crates.io-index)" = "{cksum_b}"
"#
        );

        let lock = CargoLock::parse(&text, PathBuf::from("Cargo.lock"), &[]).unwrap();
        let crates_io = Url::parse(CRATES_IO_INDEX).unwrap();
        let (itoa_id, itoa_loc) = lock
            .resolve_registry_source_id("itoa", &Version::new(1, 0, 11), &crates_io)
            .unwrap();
        assert_eq!(itoa_id.precise.as_deref(), Some(cksum_a));
        assert_eq!(itoa_loc.path, Path::new("Cargo.lock"));
        assert!(itoa_loc.start_line.unwrap() >= 3);

        let (legacy_id, _) = lock
            .resolve_registry_source_id("legacy", &Version::new(0, 2, 0), &crates_io)
            .unwrap();
        assert_eq!(legacy_id.precise.as_deref(), Some(cksum_b.as_str()));

        let git_url = Url::parse("https://github.com/example/gitdep").unwrap();
        assert!(
            lock.git_package("gitdep", &Version::new(0, 3, 1), &git_url, commit)
                .is_some()
        );
        let (git_sid, _) = lock
            .resolve_git_source_id(
                "gitdep",
                &Version::new(0, 3, 1),
                &git_url,
                GitReference::Branch("main".into()),
                commit,
            )
            .unwrap();
        assert_eq!(git_sid.precise.as_deref(), Some(commit));

        // Disagreement with Cargo.lock's commit or missing git entry is an error.
        let mismatch = lock
            .resolve_git_source_id(
                "gitdep",
                &Version::new(0, 3, 1),
                &git_url,
                GitReference::Branch("main".into()),
                other_commit,
            )
            .unwrap_err();
        assert!(mismatch.contains("disagreeing"), "{mismatch}");

        let missing = lock
            .resolve_git_source_id(
                "unpinned-git",
                &Version::new(0, 1, 0),
                &git_url,
                GitReference::DefaultBranch,
                commit,
            )
            .unwrap_err();
        assert!(missing.contains("not pinned in Cargo.lock"), "{missing}");

        // Malformed TOML error does not echo raw file contents.
        let secret_line = "SECRET_RAW_FILE_CONTENT_CANARY = [unclosed";
        let parse_err =
            CargoLock::parse(secret_line, PathBuf::from("Cargo.lock"), &[]).unwrap_err();
        assert!(
            !parse_err.contains("SECRET_RAW_FILE_CONTENT_CANARY"),
            "{parse_err}"
        );
    }
}
