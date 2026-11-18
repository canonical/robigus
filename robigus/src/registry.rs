//! Cargo sparse registries (spec §7.2.1, §7.2.2).
//!
//! Index URL normalization (shared with the Cargo analyzer), crate-name and
//! version rules, index-record parsing, download-URL templates, and the
//! registry HTTP client with authentication.

use std::fmt;
use std::sync::Arc;

use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, HeaderMap, WWW_AUTHENTICATE};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::credentials::{CredentialCache, CredentialSource, RegistryToken, bounded};
use crate::error::FetchError;
use crate::fetch::{DownloadLimits, read_capped};

/// crates.io's sparse index, the single crates.io identity (spec §7.2.1).
pub const CRATES_IO_INDEX: &str = "https://index.crates.io/";

/// crates.io's legacy git index URL, mapped to [`CRATES_IO_INDEX`].
const CRATES_IO_GIT_INDEX: &str = "https://github.com/rust-lang/crates.io-index";

/// Highest index-record schema version understood (`features2` is `v: 2`).
const MAX_RECORD_SCHEMA: u64 = 2;

/// The longest crate name crates.io accepts.
const MAX_NAME_LEN: usize = 64;

/// Which index URL schemes are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexUrlPolicy {
    /// Production: only `sparse+https://…` is accepted.
    HttpsOnly,
    /// Tests only: `sparse+http://…` is accepted too, for local mock
    /// registries. The CLI and configuration cannot select it, and a
    /// registry with a credential source is still refused over `http` by
    /// [`RegistryClient::new`], so a token is never sent unencrypted.
    #[doc(hidden)]
    AllowInsecureHttp,
    /// Tests only: like `AllowInsecureHttp`, and also lets a credentialed
    /// registry use `http`, so authentication can be tested against a local
    /// mock server without TLS. It sends tokens in clear text and must never
    /// be used against a real registry; the CLI and configuration cannot
    /// select it.
    #[doc(hidden)]
    InsecureHttpWithCredentialsForTests,
}

impl IndexUrlPolicy {
    fn allows_http(self) -> bool {
        !matches!(self, Self::HttpsOnly)
    }
}

/// Parses and normalizes a sparse registry index URL (spec §7.2.1).
///
/// The `sparse+` prefix is required: in Cargo a URL without it is a git
/// index. The result has an `https` (or, for tests, `http`) scheme, a
/// lowercase host, no default port, a trailing slash, and no userinfo,
/// query or fragment. crates.io's legacy git URL normalizes to
/// [`CRATES_IO_INDEX`].
///
/// # Examples
///
/// ```
/// use robigus::registry::{IndexUrlPolicy, normalize_index_url};
///
/// let url = normalize_index_url("sparse+https://Index.Crates.IO:443", IndexUrlPolicy::HttpsOnly)?;
/// assert_eq!(url.as_str(), "https://index.crates.io/");
///
/// let legacy = normalize_index_url(
///     "registry+https://github.com/rust-lang/crates.io-index",
///     IndexUrlPolicy::HttpsOnly,
/// )?;
/// assert_eq!(legacy.as_str(), "https://index.crates.io/");
///
/// // Without `sparse+`, Cargo treats a URL as a git index.
/// assert!(normalize_index_url("https://registry.example/index/", IndexUrlPolicy::HttpsOnly).is_err());
/// # Ok::<(), robigus::FetchError>(())
/// ```
pub fn normalize_index_url(input: &str, policy: IndexUrlPolicy) -> Result<Url, FetchError> {
    let invalid = |reason: &str| {
        FetchError::InvalidRegistry(format!("index URL '{}': {reason}", bounded(input)))
    };
    let trimmed = input.trim();
    if let Some(crates_io) = crates_io_alias(trimmed) {
        return Ok(crates_io);
    }
    let Some(rest) = trimmed.strip_prefix("sparse+") else {
        return Err(invalid(
            "only sparse registries are supported; a URL without the `sparse+` prefix is a git \
             index in Cargo (use the registry's `sparse+https://…` URL)",
        ));
    };
    let mut url = Url::parse(rest).map_err(|error| invalid(&error.to_string()))?;
    match url.scheme() {
        "https" => {}
        "http" if policy.allows_http() => {}
        "http" => return Err(invalid("registries must use https")),
        _ => return Err(invalid("the scheme must be https")),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid("the URL has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("credentials must not appear in the URL"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("a query or fragment is not allowed"));
    }
    // `Url` already lowercases the scheme and host and drops default ports.
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

/// Maps crates.io's legacy git index URL, in any of Cargo's spellings, to
/// [`CRATES_IO_INDEX`]; `None` for anything else.
///
/// This is the one place the mapping is defined, so fetched roots and
/// dependencies from `Cargo.lock` agree on crates.io's identity.
pub fn crates_io_alias(source: &str) -> Option<Url> {
    let bare = source
        .strip_prefix("registry+")
        .unwrap_or(source)
        .trim_end_matches('/');
    let bare = bare.strip_suffix(".git").unwrap_or(bare);
    let is_crates_io = bare.eq_ignore_ascii_case(CRATES_IO_GIT_INDEX)
        || source
            .trim_end_matches('/')
            .eq_ignore_ascii_case("sparse+https://index.crates.io");
    is_crates_io.then(|| Url::parse(CRATES_IO_INDEX).expect("constant URL is valid"))
}

/// Validates a crate name: ASCII alphanumerics, `-` and `_`, starting with
/// a letter, at most 64 characters (spec §7.2.1).
pub fn validate_crate_name(name: &str) -> Result<(), FetchError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(FetchError::InvalidRegistry(format!(
            "invalid crate name '{}': use ASCII letters, digits, `-` or `_`, start with a letter, \
             at most {MAX_NAME_LEN} characters",
            bounded(name)
        )))
    }
}

/// Parses an exact version; requirement operators and wildcards are
/// rejected (spec §7.2.1).
pub fn parse_exact_version(text: &str) -> Result<semver::Version, FetchError> {
    semver::Version::parse(text.trim()).map_err(|error| {
        FetchError::InvalidRegistry(format!(
            "'{}' is not an exact version ({error}); give a version such as 1.2.3, not a \
             requirement such as ^1.2",
            bounded(text)
        ))
    })
}

/// The sparse-index file path of a crate: tiered by name length and built
/// from the lowercased name.
pub(crate) fn index_path(name: &str) -> Result<String, FetchError> {
    validate_crate_name(name)?;
    let lower = name.to_ascii_lowercase();
    Ok(match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    })
}

/// The `{prefix}` directory for a name, keeping its case.
fn prefix(name: &str) -> String {
    match name.len() {
        1 => "1".into(),
        2 => "2".into(),
        3 => format!("3/{}", &name[..1]),
        _ => format!("{}/{}", &name[..2], &name[2..4]),
    }
}

/// One published version from a sparse-index file.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IndexRecord {
    /// Crate name, as the index spells it.
    pub name: String,
    /// Crate version, as the index spells it (may include build metadata).
    pub vers: String,
    /// SHA-256 of the `.crate` file as 64 lowercase hex characters
    /// (validated and lowercased when the record is looked up).
    pub cksum: String,
    /// Whether the version is yanked (`false` when absent).
    #[serde(default)]
    pub yanked: bool,
    /// Record schema version (`1` when absent).
    #[serde(default = "default_schema")]
    pub v: u64,
}

fn default_schema() -> u64 {
    1
}

/// Finds the record for `name` and `version` in a sparse-index file.
///
/// Name matching is case-insensitive (the index file path is lowercase) but
/// does not treat `-` and `_` as equivalent. Versions match ignoring build
/// metadata. Lines that do not parse, or whose schema version is newer than
/// robigus understands, are skipped unless they could be the requested
/// version; a malformed or duplicated record for the requested version is
/// an error.
pub(crate) fn find_record(
    index_file: &str,
    name: &str,
    version: &semver::Version,
) -> Result<Option<IndexRecord>, FetchError> {
    let malformed = |reason: String| {
        FetchError::Registry(format!(
            "malformed index entry for {name} {version}: {reason}"
        ))
    };
    let mut found: Option<IndexRecord> = None;
    for line in index_file.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let record: IndexRecord = match serde_json::from_str(line) {
            Ok(record) => record,
            Err(error) => {
                // A line we cannot parse could be the requested version.
                if mentions_version(line, version) {
                    return Err(malformed(error.to_string()));
                }
                continue;
            }
        };
        if record.v > MAX_RECORD_SCHEMA || !record.name.eq_ignore_ascii_case(name) {
            continue;
        }
        let Ok(record_version) = semver::Version::parse(&record.vers) else {
            continue;
        };
        if !same_version(&record_version, version) {
            continue;
        }
        if !is_sha256_hex(&record.cksum) {
            return Err(malformed(format!(
                "checksum '{}' is not 64 hex characters",
                bounded(&record.cksum)
            )));
        }
        if found.is_some() {
            return Err(malformed(
                "the version appears more than once (versions must be unique ignoring build metadata)"
                    .into(),
            ));
        }
        found = Some(IndexRecord {
            cksum: record.cksum.to_ascii_lowercase(),
            ..record
        });
    }
    Ok(found)
}

fn mentions_version(line: &str, version: &semver::Version) -> bool {
    let core = format!("{}.{}.{}", version.major, version.minor, version.patch);
    line.contains(&format!("\"{core}")) || line.contains(&version.to_string())
}

fn same_version(a: &semver::Version, b: &semver::Version) -> bool {
    a.major == b.major && a.minor == b.minor && a.patch == b.patch && a.pre == b.pre
}

/// The name and version recorded in a cached `.crate` directory, if that
/// directory is `<name>-<version>` for the requested crate, with the same
/// matching rules as an index lookup: the name case-insensitively (`-` and
/// `_` distinct) and the version ignoring build metadata. Returns the
/// spellings from the directory, which come from the index.
///
/// The name is matched by length rather than by splitting at a hyphen,
/// because both crate names and versions may contain `-`.
pub(crate) fn cached_crate_identity(
    directory: &str,
    name: &str,
    version: &semver::Version,
) -> Option<(String, String)> {
    let cached_name = directory.get(..name.len())?;
    let cached_version = directory.get(name.len()..)?.strip_prefix('-')?;
    if !cached_name.eq_ignore_ascii_case(name) {
        return None;
    }
    let parsed = semver::Version::parse(cached_version).ok()?;
    same_version(&parsed, version).then(|| (cached_name.to_owned(), cached_version.to_owned()))
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The registry `config.json`; unknown fields are ignored.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct IndexConfig {
    pub(crate) dl: String,
    #[serde(default, rename = "auth-required")]
    pub(crate) auth_required: bool,
}

/// The `.crate` download URL from `config.json`'s `dl` (spec §7.2.1).
///
/// The markers `{crate}`, `{version}`, `{prefix}`, `{lowerprefix}` and
/// `{sha256-checksum}` are substituted (percent-encoded); without any
/// marker, `/{crate}/{version}/download` is appended.
pub(crate) fn download_url(dl: &str, record: &IndexRecord) -> Result<Url, FetchError> {
    const MARKERS: [&str; 5] = [
        "{crate}",
        "{version}",
        "{prefix}",
        "{lowerprefix}",
        "{sha256-checksum}",
    ];
    let encode = |text: &str| -> String {
        url::form_urlencoded::byte_serialize(text.as_bytes())
            .collect::<String>()
            .replace("%2F", "/")
    };
    let name = encode(&record.name);
    let version = encode(&record.vers);
    let template = if MARKERS.iter().any(|marker| dl.contains(marker)) {
        dl.replace("{crate}", &name)
            .replace("{version}", &version)
            .replace("{prefix}", &prefix(&record.name))
            .replace("{lowerprefix}", &prefix(&record.name.to_ascii_lowercase()))
            .replace("{sha256-checksum}", &record.cksum)
    } else {
        format!("{}/{name}/{version}/download", dl.trim_end_matches('/'))
    };
    Url::parse(&template).map_err(|error| {
        FetchError::Registry(format!(
            "registry download URL '{}' is invalid: {error}",
            bounded(&template)
        ))
    })
}

/// A registry to fetch from: its normalized index URL plus, for a
/// configured registry, its name and credential source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySpec {
    /// Normalized index URL; the `SourceKind::CargoRegistry` identity.
    pub index_url: Url,
    /// Configured name, for credential lookup and diagnostics only.
    pub name: Option<String>,
    /// Where a token comes from if the registry requires one.
    pub credentials: CredentialSource,
    /// Set only by [`IndexUrlPolicy::InsecureHttpWithCredentialsForTests`].
    /// Not public: production code cannot construct it.
    insecure_credentials_for_tests: bool,
}

impl RegistrySpec {
    /// A registry with an already-normalized `index_url` (for example from
    /// [`normalize_index_url`] or a stored identity). [`RegistryClient::new`]
    /// re-validates it.
    pub fn new(index_url: Url, name: Option<String>, credentials: CredentialSource) -> Self {
        Self {
            index_url,
            name,
            credentials,
            insecure_credentials_for_tests: false,
        }
    }
}

impl RegistrySpec {
    /// crates.io, which never uses credentials.
    pub fn crates_io() -> Self {
        Self::new(
            Url::parse(CRATES_IO_INDEX).expect("constant URL is valid"),
            None,
            CredentialSource::None,
        )
    }

    /// An index given directly (`--index`): never uses credentials.
    pub fn direct(index: &str) -> Result<Self, FetchError> {
        Self::direct_with_policy(index, IndexUrlPolicy::HttpsOnly)
    }

    /// [`RegistrySpec::direct`] with an explicit URL policy. Only tests
    /// should pass [`IndexUrlPolicy::AllowInsecureHttp`].
    #[doc(hidden)]
    pub fn direct_with_policy(index: &str, policy: IndexUrlPolicy) -> Result<Self, FetchError> {
        Ok(Self::new(
            normalize_index_url(index, policy)?,
            None,
            CredentialSource::None,
        ))
    }

    /// A named registry from configuration with its credential source.
    pub fn named(
        name: &str,
        index: &str,
        credentials: CredentialSource,
    ) -> Result<Self, FetchError> {
        Self::named_with_policy(name, index, credentials, IndexUrlPolicy::HttpsOnly)
    }

    /// [`RegistrySpec::named`] with an explicit URL policy. Only tests
    /// should pass [`IndexUrlPolicy::AllowInsecureHttp`]; a credentialed
    /// registry is refused over `http` anyway (see [`RegistryClient::new`]).
    #[doc(hidden)]
    pub fn named_with_policy(
        name: &str,
        index: &str,
        credentials: CredentialSource,
        policy: IndexUrlPolicy,
    ) -> Result<Self, FetchError> {
        credentials.validate().map_err(|reason| {
            FetchError::InvalidRegistry(format!("registry '{name}': {reason}"))
        })?;
        let mut spec = Self::new(
            normalize_index_url(index, policy)?,
            Some(name.to_owned()),
            credentials,
        );
        spec.insecure_credentials_for_tests =
            policy == IndexUrlPolicy::InsecureHttpWithCredentialsForTests;
        Ok(spec)
    }

    fn label(&self) -> String {
        match &self.name {
            Some(name) => format!("registry '{name}' ({})", self.index_url),
            None => format!("registry {}", self.index_url),
        }
    }
}

/// The outcome of a `.crate` download.
pub(crate) struct DownloadedCrate {
    pub(crate) bytes: Vec<u8>,
    pub(crate) record: IndexRecord,
}

/// An HTTP client for one sparse registry: index lookups and checksum-
/// verified `.crate` downloads, with authentication when the registry
/// requires it (spec §7.2.1, §7.2.2).
pub struct RegistryClient {
    registry: RegistrySpec,
    http: reqwest::Client,
    limits: DownloadLimits,
    config: tokio::sync::OnceCell<IndexConfig>,
    credentials: CredentialCache,
    /// Hosts that may receive the token: the index host, then the `dl` host.
    token_hosts: std::sync::Mutex<Vec<(String, String, u16)>>,
}

impl fmt::Debug for RegistryClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistryClient")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl RegistryClient {
    /// A client for `registry` bounded by `limits`.
    ///
    /// `RegistrySpec`'s fields are public, so the registry is re-validated
    /// here rather than trusting how it was built: its index URL must be a
    /// normalized `https` index (or `http`, from the test-only policy), and
    /// a registry with any credential source must use `https`, so a token
    /// is never sent over plain HTTP.
    pub fn new(registry: RegistrySpec, limits: DownloadLimits) -> Result<Self, FetchError> {
        validate_spec(&registry)?;
        let http = crate::fetch::http_client(&limits)
            .map_err(|error| FetchError::Registry(format!("http client failed: {error}")))?;
        let index = &registry.index_url;
        let token_hosts = vec![scope_of(index)];
        Ok(Self {
            registry,
            http,
            limits,
            config: tokio::sync::OnceCell::new(),
            credentials: CredentialCache::default(),
            token_hosts: std::sync::Mutex::new(token_hosts),
        })
    }

    /// The registry this client talks to.
    pub fn registry(&self) -> &RegistrySpec {
        &self.registry
    }

    /// Looks up the index record for one exact version. `Ok(None)` means
    /// the crate or version does not exist.
    pub(crate) async fn index_record(
        &self,
        name: &str,
        version: &semver::Version,
    ) -> Result<Option<IndexRecord>, FetchError> {
        let path = index_path(name)?;
        // Cargo requests config.json first; it also reveals auth-required.
        self.config().await?;
        let url = self.registry.index_url.join(&path).map_err(|error| {
            FetchError::Registry(format!("invalid index path '{path}': {error}"))
        })?;
        let Some(body) = self.get(url, "index lookup", true).await? else {
            return Ok(None);
        };
        let text = String::from_utf8(body)
            .map_err(|_| FetchError::Registry(format!("index file for '{name}' is not UTF-8")))?;
        find_record(&text, name, version)
    }

    /// Downloads and verifies a `.crate`. The record must exist; yanked
    /// versions are refused unless `allow_yanked`. `expected` is an optional
    /// caller-supplied SHA-256 that must equal the index checksum.
    pub(crate) async fn download_crate(
        &self,
        name: &str,
        version: &semver::Version,
        expected: Option<&str>,
        allow_yanked: bool,
    ) -> Result<DownloadedCrate, FetchError> {
        let record = self.index_record(name, version).await?.ok_or_else(|| {
            let other = if name.contains('-') {
                Some(name.replace('-', "_"))
            } else if name.contains('_') {
                Some(name.replace('_', "-"))
            } else {
                None
            };
            let hint = other.map_or(String::new(), |other| {
                format!(" (`-` and `_` are distinct in registry names; did you mean '{other}'?)")
            });
            FetchError::Registry(format!(
                "{name} {version} was not found in {}{hint}",
                self.registry.label()
            ))
        })?;
        if let Some(expected) = expected
            && expected.trim().to_ascii_lowercase() != record.cksum
        {
            return Err(FetchError::Checksum {
                expected: expected.trim().to_ascii_lowercase(),
                actual: record.cksum.clone(),
            });
        }
        if record.yanked && !allow_yanked {
            return Err(FetchError::Registry(format!(
                "{} {} is yanked in {}; pass --allow-yanked to fetch it anyway",
                record.name,
                record.vers,
                self.registry.label()
            )));
        }
        let config = self.config().await?;
        let url = download_url(&config.dl, &record)?;
        let bytes = self
            .get(url, "crate download", false)
            .await?
            .ok_or_else(|| {
                FetchError::Registry(format!(
                    "the registry has no download for {} {}",
                    record.name, record.vers
                ))
            })?;
        let digest = crate::model::to_hex(Sha256::digest(&bytes).as_slice());
        if digest != record.cksum {
            return Err(FetchError::Checksum {
                expected: record.cksum,
                actual: digest,
            });
        }
        Ok(DownloadedCrate { bytes, record })
    }

    async fn config(&self) -> Result<&IndexConfig, FetchError> {
        self.config
            .get_or_try_init(|| async {
                let url = self
                    .registry
                    .index_url
                    .join("config.json")
                    .map_err(|error| FetchError::Registry(format!("invalid index URL: {error}")))?;
                let body = self
                    .get(url, "index config lookup", false)
                    .await?
                    .ok_or_else(|| {
                        FetchError::Registry(format!(
                            "{} has no config.json; is it a sparse registry index?",
                            self.registry.label()
                        ))
                    })?;
                let config: IndexConfig = serde_json::from_slice(&body).map_err(|error| {
                    FetchError::Registry(format!(
                        "invalid config.json from {}: {error}",
                        self.registry.label()
                    ))
                })?;
                let dl = Url::parse(&config.dl.replace(['{', '}'], "")).map_err(|error| {
                    FetchError::Registry(format!(
                        "config.json `dl` from {} is not a URL: {error}",
                        self.registry.label()
                    ))
                })?;
                if dl.scheme() != "https" && self.registry.index_url.scheme() == "https" {
                    return Err(FetchError::Registry(format!(
                        "config.json `dl` from {} must use https",
                        self.registry.label()
                    )));
                }
                {
                    let mut hosts = self.token_hosts.lock().unwrap_or_else(|p| p.into_inner());
                    let scope = scope_of(&dl);
                    if !hosts.contains(&scope) {
                        hosts.push(scope);
                    }
                }
                if config.auth_required {
                    self.auth_token().await?;
                }
                Ok(config)
            })
            .await
    }

    /// The token for this registry; fails with a clear error when no
    /// credential source is configured.
    async fn auth_token(&self) -> Result<Arc<RegistryToken>, FetchError> {
        self.credentials
            .token(
                self.registry.index_url.as_str(),
                self.registry.name.as_deref(),
                &self.registry.credentials,
            )
            .await
            .map_err(|error| match error {
                FetchError::Credential(reason) => FetchError::Credential(format!(
                    "{} requires authentication: {reason}",
                    self.registry.label()
                )),
                other => other,
            })
    }

    /// Whether the token may be sent to `url`: HTTPS (or the test-only HTTP
    /// index scheme) to the index host or the configured `dl` host.
    fn in_scope(&self, url: &Url) -> bool {
        if url.scheme() != self.registry.index_url.scheme() {
            return false;
        }
        let hosts = self.token_hosts.lock().unwrap_or_else(|p| p.into_inner());
        hosts.contains(&scope_of(url))
    }

    /// GETs `url` within the download limits. `Ok(None)` for 404, 410 or
    /// 451 when `missing_ok`. Attaches the token when the registry requires
    /// authentication (declared, or discovered by a 401) and `url` is in
    /// scope. Error text is bounded and the token redacted.
    async fn get(
        &self,
        url: Url,
        what: &str,
        missing_ok: bool,
    ) -> Result<Option<Vec<u8>>, FetchError> {
        let auth_known = self.config.get().is_some_and(|config| config.auth_required);
        let mut token = if auth_known && self.in_scope(&url) {
            Some(self.auth_token().await?)
        } else {
            None
        };
        let mut retried = false;
        loop {
            let mut request = self.http.get(url.clone());
            if let Some(token) = &token {
                let value = token.header_value().map_err(|reason| {
                    FetchError::Credential(format!("{}: {reason}", self.registry.label()))
                })?;
                request = request.header(AUTHORIZATION, value);
            }
            let request = request
                .build()
                .map_err(|error| self.failure(what, &url, &error.to_string(), token.as_deref()))?;
            // The header map is traced in full: the token's value is marked
            // sensitive, so `Debug` prints it as `Sensitive`.
            tracing::debug!(
                target: "robigus::registry",
                %url,
                headers = ?request.headers(),
                authenticated = token.is_some(),
                "{what}"
            );
            let response =
                self.http.execute(request).await.map_err(|error| {
                    self.failure(what, &url, &error.to_string(), token.as_deref())
                })?;
            let status = response.status();
            tracing::debug!(target: "robigus::registry", %url, %status, "{what} response");
            if status == StatusCode::UNAUTHORIZED
                && token.is_none()
                && !retried
                && self.in_scope(&url)
            {
                // Discovered authentication: obtain a token and retry once,
                // as Cargo does for config.json.
                retried = true;
                token = Some(self.auth_token().await?);
                continue;
            }
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                let hint = login_hint(response.headers());
                if token.is_some() {
                    self.credentials.forget(self.registry.index_url.as_str());
                }
                let reason = if status == StatusCode::UNAUTHORIZED {
                    "authentication required"
                } else {
                    "the token was rejected or lacks access"
                };
                // The login URL is registry-controlled and may echo the
                // token back, so the whole message is redacted.
                return Err(FetchError::Credential(redacted(
                    format!(
                        "{what} from {} failed: {reason} (credentials: {}){hint}",
                        self.registry.label(),
                        self.registry.credentials.describe()
                    ),
                    token.as_deref(),
                )));
            }
            if missing_ok
                && matches!(
                    status,
                    StatusCode::NOT_FOUND
                        | StatusCode::GONE
                        | StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
                )
            {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(self.failure(what, &url, &format!("HTTP {status}"), token.as_deref()));
            }
            let body = read_capped(response, self.limits.max_bytes)
                .await
                .map_err(|error| self.failure(what, &url, &error, token.as_deref()))?;
            return Ok(Some(body));
        }
    }

    fn failure(
        &self,
        what: &str,
        url: &Url,
        reason: &str,
        token: Option<&RegistryToken>,
    ) -> FetchError {
        FetchError::Registry(redacted(
            format!(
                "{what} from {} failed ({url}): {}",
                self.registry.label(),
                bounded(reason)
            ),
            token,
        ))
    }
}

/// Removes the active token, if any, from an error message built from
/// registry-controlled text.
fn redacted(message: String, token: Option<&RegistryToken>) -> String {
    match token {
        Some(token) => token.redact(&message),
        None => message,
    }
}

/// Checks a [`RegistrySpec`] whose fields may have been set directly.
fn validate_spec(registry: &RegistrySpec) -> Result<(), FetchError> {
    let url = &registry.index_url;
    let invalid =
        |reason: &str| FetchError::InvalidRegistry(format!("registry index {url}: {reason}"));
    match url.scheme() {
        "https" => {}
        "http"
            if registry.credentials == CredentialSource::None
                || registry.insecure_credentials_for_tests => {}
        "http" => {
            return Err(invalid(
                "a registry with a credential source must use https; tokens are never sent over plain http",
            ));
        }
        _ => return Err(invalid("the scheme must be https")),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid("the URL has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("credentials must not appear in the URL"));
    }
    if url.query().is_some() || url.fragment().is_some() || !url.path().ends_with('/') {
        return Err(invalid(
            "the URL is not normalized; build it with normalize_index_url",
        ));
    }
    registry
        .credentials
        .validate()
        .map_err(|reason| invalid(&reason))
}

/// The scheme, host and port a token is scoped to.
fn scope_of(url: &Url) -> (String, String, u16) {
    (
        url.scheme().to_owned(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        url.port_or_known_default().unwrap_or(0),
    )
}

/// A `WWW-Authenticate: Cargo login_url="…"` hint, if the registry sent one.
/// Only an `https` URL without credentials is shown, and it is bounded; the
/// caller still redacts the result, since the URL is registry-controlled.
fn login_hint(headers: &HeaderMap) -> String {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let rest = value.split_once("login_url=")?.1;
            let url = rest.trim_start_matches('"').split('"').next()?;
            Url::parse(url).ok().filter(|url| {
                url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
            })
        })
        .map_or(String::new(), |url| {
            format!("; obtain a token at {}", bounded(url.as_str()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &str) -> semver::Version {
        semver::Version::parse(text).unwrap()
    }

    fn record(name: &str, vers: &str) -> String {
        format!(
            r#"{{"name":"{name}","vers":"{vers}","cksum":"{}","yanked":false}}"#,
            "a".repeat(64)
        )
    }

    #[test]
    fn index_urls_must_be_sparse_https_and_are_normalized() {
        let https = IndexUrlPolicy::HttpsOnly;
        for (input, expected) in [
            (
                "sparse+https://Registry.Example/Index",
                "https://registry.example/Index/",
            ),
            (
                "sparse+https://registry.example:443/index/",
                "https://registry.example/index/",
            ),
            (
                "sparse+https://registry.example:8443/",
                "https://registry.example:8443/",
            ),
            ("sparse+https://index.crates.io", CRATES_IO_INDEX),
            ("sparse+https://index.crates.io/", CRATES_IO_INDEX),
            (
                "https://github.com/rust-lang/crates.io-index",
                CRATES_IO_INDEX,
            ),
            (
                "registry+https://github.com/rust-lang/crates.io-index",
                CRATES_IO_INDEX,
            ),
            (
                "https://github.com/rust-lang/crates.io-index.git",
                CRATES_IO_INDEX,
            ),
        ] {
            assert_eq!(
                normalize_index_url(input, https).unwrap().as_str(),
                expected,
                "{input}"
            );
        }
        for (input, reason) in [
            ("https://registry.example/index/", "git index"),
            ("registry+https://registry.example/index", "git index"),
            ("sparse+http://registry.example/", "https"),
            ("sparse+file:///tmp/index", "https"),
            ("sparse+https://user:pw@registry.example/", "credentials"),
            ("sparse+https://registry.example/?q=1", "query"),
            ("sparse+https://registry.example/#frag", "fragment"),
            ("sparse+not a url", "index URL"),
        ] {
            let error = normalize_index_url(input, https).unwrap_err().to_string();
            assert!(error.contains(reason), "{input}: {error}");
        }
        assert_eq!(
            normalize_index_url(
                "sparse+http://127.0.0.1:8080",
                IndexUrlPolicy::AllowInsecureHttp
            )
            .unwrap()
            .as_str(),
            "http://127.0.0.1:8080/"
        );
        assert!(crates_io_alias("sparse+https://registry.example/").is_none());
    }

    #[test]
    fn names_versions_and_index_paths_follow_the_index_format() {
        for valid in [
            "a",
            "ab",
            "abc",
            "serde",
            "Serde_JSON",
            "foo-bar",
            &"a".repeat(64),
        ] {
            validate_crate_name(valid).unwrap();
        }
        for invalid in [
            "",
            "1abc",
            "-a",
            "a b",
            "café",
            "../evil",
            "a/b",
            &"a".repeat(65),
        ] {
            assert!(validate_crate_name(invalid).is_err(), "{invalid}");
        }
        assert_eq!(index_path("a").unwrap(), "1/a");
        assert_eq!(index_path("cc").unwrap(), "2/cc");
        assert_eq!(index_path("syn").unwrap(), "3/s/syn");
        assert_eq!(index_path("Itoa").unwrap(), "it/oa/itoa");
        assert_eq!(index_path("Serde_JSON").unwrap(), "se/rd/serde_json");
        assert_eq!(
            parse_exact_version("1.0.0-rc.1").unwrap(),
            version("1.0.0-rc.1")
        );
        for requirement in ["^1.2", "~1", ">=1.0.0", "*", "1.2", "1", "latest", ""] {
            assert!(parse_exact_version(requirement).is_err(), "{requirement}");
        }
    }

    #[test]
    fn records_match_case_insensitively_and_ignore_build_metadata() {
        let file = [
            record("Foo", "1.0.0+build.5"),
            record("Foo", "1.0.1"),
            "not json at all".into(),
            r#"{"name":"Foo","vers":"2.0.0","cksum":"x","v":3}"#.into(),
        ]
        .join("\n");
        let found = find_record(&file, "foo", &version("1.0.0"))
            .unwrap()
            .unwrap();
        assert_eq!(found.name, "Foo");
        assert_eq!(found.vers, "1.0.0+build.5");
        assert!(
            find_record(&file, "foo", &version("1.0.0+other"))
                .unwrap()
                .is_some()
        );
        assert!(
            find_record(&file, "foo", &version("1.0.2"))
                .unwrap()
                .is_none()
        );
        // Records with a newer schema are skipped, not errors.
        assert!(
            find_record(&file, "foo", &version("2.0.0"))
                .unwrap()
                .is_none()
        );
        // `-` and `_` are distinct names.
        assert!(
            find_record(&record("foo-bar", "1.0.0"), "foo_bar", &version("1.0.0"))
                .unwrap()
                .is_none()
        );
        // Pre-releases are part of the version.
        assert!(
            find_record(&record("foo", "1.0.0-rc.1"), "foo", &version("1.0.0"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_or_duplicate_records_for_the_version_are_errors() {
        let duplicate = [record("foo", "1.0.0"), record("foo", "1.0.0+again")].join("\n");
        assert!(
            find_record(&duplicate, "foo", &version("1.0.0"))
                .unwrap_err()
                .to_string()
                .contains("more than once")
        );
        let bad_cksum = r#"{"name":"foo","vers":"1.0.0","cksum":"abc"}"#;
        assert!(
            find_record(bad_cksum, "foo", &version("1.0.0"))
                .unwrap_err()
                .to_string()
                .contains("64 hex")
        );
        let truncated = r#"{"name":"foo","vers":"1.0.0","cks"#;
        assert!(find_record(truncated, "foo", &version("1.0.0")).is_err());
        // A malformed line for another version is skipped.
        let other = [
            r#"{"name":"foo","vers":"9.9.9","cks"#.to_string(),
            record("foo", "1.0.0"),
        ]
        .join("\n");
        assert!(
            find_record(&other, "foo", &version("1.0.0"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn download_urls_follow_the_dl_rules() {
        let record = IndexRecord {
            name: "My-Crate".into(),
            vers: "1.0.0+meta".into(),
            cksum: "b".repeat(64),
            yanked: false,
            v: 1,
        };
        assert_eq!(
            download_url("https://dl.example/crates", &record)
                .unwrap()
                .as_str(),
            "https://dl.example/crates/My-Crate/1.0.0%2Bmeta/download"
        );
        assert_eq!(
            download_url("https://dl.example/crates/", &record)
                .unwrap()
                .as_str(),
            "https://dl.example/crates/My-Crate/1.0.0%2Bmeta/download"
        );
        assert_eq!(
            download_url("https://dl.example/{prefix}/{lowerprefix}/{crate}-{version}.crate?sum={sha256-checksum}", &record)
                .unwrap()
                .as_str(),
            format!("https://dl.example/My/-C/my/-c/My-Crate-1.0.0%2Bmeta.crate?sum={}", "b".repeat(64))
        );
        let short = IndexRecord {
            name: "ab".into(),
            ..record.clone()
        };
        assert_eq!(
            download_url("https://dl.example/{prefix}/{crate}", &short)
                .unwrap()
                .as_str(),
            "https://dl.example/2/ab"
        );
        assert!(download_url("not a url {crate}", &record).is_err());
    }

    #[test]
    fn cached_directories_must_name_the_requested_crate() {
        let v = |text| version(text);
        for (directory, name, requested, expected) in [
            ("serde-1.0.0", "serde", "1.0.0", Some(("serde", "1.0.0"))),
            ("Serde-1.0.0", "serde", "1.0.0", Some(("Serde", "1.0.0"))),
            (
                "foo-bar-1.0.0-rc.1",
                "foo-bar",
                "1.0.0-rc.1",
                Some(("foo-bar", "1.0.0-rc.1")),
            ),
            (
                "meta-1.0.0+build.7",
                "meta",
                "1.0.0",
                Some(("meta", "1.0.0+build.7")),
            ),
            // A different crate cached under the pinned checksum.
            ("serde-1.0.0", "tokio", "1.0.0", None),
            ("serde_json-1.0.0", "serde", "1.0.0", None),
            // Same crate, wrong version or pre-release.
            ("serde-1.0.1", "serde", "1.0.0", None),
            ("serde-1.0.0-rc.1", "serde", "1.0.0", None),
            // `-` and `_` are distinct names.
            ("foo_bar-1.0.0", "foo-bar", "1.0.0", None),
            // Malformed directory names.
            ("serde", "serde", "1.0.0", None),
            ("serde1.0.0", "serde", "1.0.0", None),
            ("serde-", "serde", "1.0.0", None),
            ("ser", "serde", "1.0.0", None),
            ("sérde-1.0.0", "serde", "1.0.0", None),
        ] {
            let found = cached_crate_identity(directory, name, &v(requested));
            let expected = expected.map(|(n, ver): (&str, &str)| (n.to_owned(), ver.to_owned()));
            assert_eq!(found, expected, "{directory} for {name} {requested}");
        }
    }

    #[test]
    fn login_hints_come_from_cargo_challenges() {
        let mut headers = HeaderMap::new();
        headers.insert(
            WWW_AUTHENTICATE,
            r#"Cargo login_url="https://registry.example/me""#.parse().unwrap(),
        );
        assert_eq!(
            login_hint(&headers),
            "; obtain a token at https://registry.example/me"
        );
        headers.insert(
            WWW_AUTHENTICATE,
            r#"Cargo login_url="javascript:alert(1)""#.parse().unwrap(),
        );
        assert_eq!(login_hint(&headers), "");
    }
}
