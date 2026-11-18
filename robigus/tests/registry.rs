//! WP-2.6: registry source inputs and authentication (spec §7.2.1, §7.2.2).
//!
//! Every registry here is a local `wiremock` server reached over plain HTTP
//! through the test-only `IndexUrlPolicy::AllowInsecureHttp`, or
//! `InsecureHttpWithCredentialsForTests` where a credential source is
//! configured (production refuses credentials over `http`). Tokens use a
//! canary value that each test checks never escapes its in-scope
//! `Authorization` header.

use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use robigus::fetch::{RegistrySource, SourceInput, fetch, fetch_offline};
use robigus::model::{Ecosystem, Node, PackageId, PackageVersion, SourceKind};
use robigus::predicate::Configuration;
use robigus::registry::{IndexUrlPolicy, RegistrySpec, parse_exact_version};
use robigus::{
    AnalysisMetadata, Cache, CredentialSource, FetchError, FetchOptions, RobigusError, Store,
};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const CANARY: &str = "robigus-canary-token-0f3a9c";

/// A gzip-compressed tar archive with the given `(path, contents)` entries.
fn crate_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, *contents).unwrap();
    }
    let tar = builder.into_inner().unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

/// A gzip-compressed tar whose single entry has a raw `name` (the `tar`
/// crate refuses to create `..` paths, so the header is written by hand).
fn hostile_crate(name: &str) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"000644\0 ");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"00000000001\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut tar = header.to_vec();
    tar.push(b'x');
    tar.extend(std::iter::repeat_n(0u8, 511 + 1024));
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

/// A well-formed `.crate` for `name` `version`.
fn well_formed(name: &str, version: &str) -> Vec<u8> {
    let root = format!("{name}-{version}");
    let manifest = format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n");
    crate_bytes(&[
        (&format!("{root}/Cargo.toml"), manifest.as_bytes()),
        (&format!("{root}/Cargo.toml.orig"), manifest.as_bytes()),
        (&format!("{root}/src/lib.rs"), b"pub fn hello() {}\n"),
    ])
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn index_line(name: &str, version: &str, cksum: &str, yanked: bool) -> String {
    format!(
        r#"{{"name":"{name}","vers":"{version}","deps":[],"cksum":"{cksum}","features":{{}},"yanked":{yanked}}}"#
    )
}

/// The sparse-index path for a name (tests use names of four or more
/// characters unless they test the tiers).
fn index_path(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.len() {
        1 => format!("/1/{lower}"),
        2 => format!("/2/{lower}"),
        3 => format!("/3/{}/{lower}", &lower[..1]),
        _ => format!("/{}/{}/{lower}", &lower[..2], &lower[2..4]),
    }
}

/// A public sparse registry serving one crate version.
struct Registry {
    server: MockServer,
}

impl Registry {
    async fn new() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    fn spec(&self) -> RegistrySpec {
        RegistrySpec::direct_with_policy(
            &format!("sparse+{}/index/", self.uri()),
            IndexUrlPolicy::AllowInsecureHttp,
        )
        .unwrap()
    }

    async fn config(&self, dl: &str, auth_required: bool) {
        let body = serde_json::json!({ "dl": dl, "auth-required": auth_required });
        Mock::given(method("GET"))
            .and(path("/index/config.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    async fn index(&self, name: &str, lines: &[String]) {
        Mock::given(method("GET"))
            .and(path(format!("/index{}", index_path(name))))
            .respond_with(ResponseTemplate::new(200).set_body_string(lines.join("\n")))
            .mount(&self.server)
            .await;
    }

    async fn serve(&self, url_path: &str, bytes: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(url_path.to_owned()))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(&self.server)
            .await;
    }

    /// Serves `name` `version` with the default (marker-less) `dl` layout.
    async fn publish(&self, name: &str, version: &str, bytes: Vec<u8>, yanked: bool) -> String {
        let cksum = sha256(&bytes);
        self.config(&format!("{}/dl", self.uri()), false).await;
        self.index(name, &[index_line(name, version, &cksum, yanked)])
            .await;
        self.serve(&format!("/dl/{name}/{version}/download"), bytes)
            .await;
        cksum
    }

    async fn requests(&self) -> Vec<Request> {
        self.server.received_requests().await.unwrap_or_default()
    }
}

fn request(registry: RegistrySpec, name: &str, version: &str) -> RegistrySource {
    RegistrySource {
        registry,
        name: name.into(),
        version: parse_exact_version(version).unwrap(),
        digest: None,
        allow_yanked: false,
    }
}

async fn fetch_crate(
    cache: &Cache,
    source: RegistrySource,
) -> Result<robigus::FetchedSource, RobigusError> {
    fetch(
        SourceInput::Registry(source),
        cache,
        &FetchOptions::default(),
    )
    .await
}

fn temp_cache() -> (tempfile::TempDir, Cache) {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::new(dir.path().join("cache"));
    (dir, cache)
}

fn fetch_error(result: Result<robigus::FetchedSource, RobigusError>) -> FetchError {
    match result {
        Err(RobigusError::Fetch(error)) => error,
        Err(other) => panic!("expected a fetch error, got {other}"),
        Ok(fetched) => panic!("expected an error, fetched {}", fetched.tree.display()),
    }
}

// Registry protocol

#[tokio::test]
async fn fetches_verifies_and_caches_a_registry_crate() {
    let registry = Registry::new().await;
    let bytes = well_formed("demo-crate", "1.2.3");
    let cksum = registry.publish("demo-crate", "1.2.3", bytes, false).await;
    let (_dir, cache) = temp_cache();

    let fetched = fetch_crate(&cache, request(registry.spec(), "demo-crate", "1.2.3"))
        .await
        .unwrap();
    assert_eq!(fetched.digest, cksum);
    assert_eq!(fetched.provenance, robigus::Provenance::Verified);
    assert_eq!(fetched.tree.file_name().unwrap(), "demo-crate-1.2.3");
    assert!(
        fetched
            .tree
            .ends_with(Path::new("crate").join(&cksum).join("demo-crate-1.2.3"))
    );
    assert!(fetched.tree.join("Cargo.toml.orig").is_file());
    assert_eq!(
        fetched.kind,
        SourceKind::CargoRegistry {
            index_url: registry.spec().index_url
        }
    );
    assert_eq!(fetched.source_id().precise.as_deref(), Some(cksum.as_str()));
    let info = fetched.registry_crate.clone().unwrap();
    assert_eq!(
        (info.name.as_str(), info.version.as_str(), info.yanked),
        ("demo-crate", "1.2.3", Some(false))
    );
    // The registry was consulted config-first.
    let paths: Vec<String> = registry
        .requests()
        .await
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect();
    assert_eq!(paths[0], "/index/config.json", "{paths:?}");

    // With the checksum pinned, a second fetch is a cache hit with no
    // requests, online or offline.
    let before = registry.requests().await.len();
    let mut pinned = request(registry.spec(), "demo-crate", "1.2.3");
    pinned.digest = Some(cksum.to_uppercase());
    let hit = fetch_crate(&cache, pinned.clone()).await.unwrap();
    assert_eq!(hit.tree, fetched.tree);
    let offline = fetch_offline(SourceInput::Registry(pinned), &cache)
        .await
        .unwrap();
    assert_eq!(offline.tree, fetched.tree);
    let offline_info = offline.registry_crate.unwrap();
    assert_eq!(
        offline_info.yanked, None,
        "offline cannot know the yanked state"
    );
    assert_eq!(registry.requests().await.len(), before);
}

/// Regression: pinning one crate's checksum while requesting another used
/// to return the cached crate under the requested identity.
#[tokio::test]
async fn a_pinned_checksum_for_a_different_crate_is_refused() {
    let registry = Registry::new().await;
    let cksum = registry
        .publish(
            "cached-crate",
            "1.0.0",
            well_formed("cached-crate", "1.0.0"),
            false,
        )
        .await;
    let (_dir, cache) = temp_cache();
    fetch_crate(&cache, request(registry.spec(), "cached-crate", "1.0.0"))
        .await
        .unwrap();
    let before = registry.requests().await.len();
    for (name, version) in [
        ("other-crate", "1.0.0"),
        ("cached-crate", "2.0.0"),
        ("cached_crate", "1.0.0"),
        ("cached-crate", "1.0.0-rc.1"),
    ] {
        let mut wrong = request(registry.spec(), name, version);
        wrong.digest = Some(cksum.clone());
        for result in [
            fetch_crate(&cache, wrong.clone()).await,
            fetch_offline(SourceInput::Registry(wrong), &cache).await,
        ] {
            let message = fetch_error(result).to_string();
            assert!(
                message.contains("belongs to 'cached-crate-1.0.0'"),
                "{name} {version}: {message}"
            );
        }
    }
    // Still correct for the right crate, matched case-insensitively and
    // ignoring build metadata, all without network access.
    for (name, version) in [("cached-crate", "1.0.0"), ("Cached-Crate", "1.0.0+meta")] {
        let mut right = request(registry.spec(), name, version);
        right.digest = Some(cksum.clone());
        let fetched = fetch_offline(SourceInput::Registry(right), &cache)
            .await
            .unwrap();
        let info = fetched.registry_crate.unwrap();
        assert_eq!(
            (info.name.as_str(), info.version.as_str()),
            ("cached-crate", "1.0.0")
        );
    }
    assert_eq!(
        registry.requests().await.len(),
        before,
        "a cache hit used the network"
    );
}

#[tokio::test]
async fn offline_registry_fetches_need_a_pinned_cached_checksum() {
    let (_dir, cache) = temp_cache();
    let spec = RegistrySpec::crates_io();
    for digest in [None, Some("a".repeat(64))] {
        let mut source = request(spec.clone(), "itoa", "1.0.11");
        source.digest = digest;
        match fetch_offline(SourceInput::Registry(source), &cache).await {
            Err(RobigusError::Fetch(FetchError::OfflineCacheMiss(_))) => {}
            other => panic!("expected an offline cache miss, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn download_urls_honour_dl_markers_and_names_are_matched_like_the_index() {
    let registry = Registry::new().await;
    let bytes = well_formed("My_Crate", "0.1.0");
    let cksum = sha256(&bytes);
    registry
        .config(
            &format!(
                "{}/files/{{lowerprefix}}/{{crate}}-{{version}}.crate?sum={{sha256-checksum}}",
                registry.uri()
            ),
            false,
        )
        .await;
    registry
        .index(
            "my_crate",
            &[
                "this line is not json".into(),
                r#"{"name":"My_Crate","vers":"0.0.9","cksum":"short"}"#.into(),
                r#"{"name":"My_Crate","vers":"9.0.0","cksum":"x","v":3}"#.into(),
                index_line("My_Crate", "0.1.0", &cksum, false),
            ],
        )
        .await;
    Mock::given(method("GET"))
        .and(path("/files/my/_c/My_Crate-0.1.0.crate"))
        .and(wiremock::matchers::query_param("sum", cksum.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(&registry.server)
        .await;
    let (_dir, cache) = temp_cache();
    // Requested in a different case: matched case-insensitively and reported
    // as the index spells it.
    let fetched = fetch_crate(&cache, request(registry.spec(), "my_crate", "0.1.0"))
        .await
        .unwrap();
    assert_eq!(fetched.registry_crate.unwrap().name, "My_Crate");
    assert_eq!(fetched.tree.file_name().unwrap(), "My_Crate-0.1.0");

    // `-` and `_` are distinct; the error suggests the other spelling.
    let error =
        fetch_error(fetch_crate(&cache, request(registry.spec(), "my-crate", "0.1.0")).await);
    let message = error.to_string();
    assert!(
        message.contains("not found") && message.contains("my_crate"),
        "{message}"
    );
}

#[tokio::test]
async fn versions_match_ignoring_build_metadata_but_not_pre_releases() {
    let registry = Registry::new().await;
    let bytes = well_formed("meta-crate", "1.0.0+build.7");
    let cksum = sha256(&bytes);
    registry
        .config(&format!("{}/dl", registry.uri()), false)
        .await;
    registry
        .index(
            "meta-crate",
            &[index_line("meta-crate", "1.0.0+build.7", &cksum, false)],
        )
        .await;
    registry
        .serve("/dl/meta-crate/1.0.0%2Bbuild.7/download", bytes)
        .await;
    let (_dir, cache) = temp_cache();
    let fetched = fetch_crate(&cache, request(registry.spec(), "meta-crate", "1.0.0"))
        .await
        .unwrap();
    assert_eq!(fetched.registry_crate.unwrap().version, "1.0.0+build.7");
    let error = fetch_error(
        fetch_crate(&cache, request(registry.spec(), "meta-crate", "1.0.0-rc.1")).await,
    );
    assert!(error.to_string().contains("not found"), "{error}");
}

#[tokio::test]
async fn missing_yanked_mismatched_and_malformed_crates_fail_clearly() {
    let registry = Registry::new().await;
    let good = well_formed("ok-crate", "1.0.0");
    let cksum = registry
        .publish("ok-crate", "1.0.0", good.clone(), false)
        .await;
    let (_dir, cache) = temp_cache();

    // Crate absent from the index: 404 on the index file.
    let error = fetch_error(fetch_crate(&cache, request(registry.spec(), "absent", "1.0.0")).await);
    assert!(error.to_string().contains("not found"), "{error}");

    // Caller-supplied digest that disagrees with the index.
    let mut wrong = request(registry.spec(), "ok-crate", "1.0.0");
    wrong.digest = Some("b".repeat(64));
    assert!(matches!(
        fetch_error(fetch_crate(&cache, wrong).await),
        FetchError::Checksum { .. }
    ));

    // Yanked: refused by default, allowed explicitly and reported.
    let yanked = Registry::new().await;
    yanked
        .publish(
            "old-crate",
            "0.9.0",
            well_formed("old-crate", "0.9.0"),
            true,
        )
        .await;
    let error =
        fetch_error(fetch_crate(&cache, request(yanked.spec(), "old-crate", "0.9.0")).await);
    assert!(error.to_string().contains("--allow-yanked"), "{error}");
    let mut allowed = request(yanked.spec(), "old-crate", "0.9.0");
    allowed.allow_yanked = true;
    let fetched = fetch_crate(&cache, allowed).await.unwrap();
    assert_eq!(fetched.registry_crate.unwrap().yanked, Some(true));

    // Corrupted download: rejected against the index checksum.
    let corrupt = Registry::new().await;
    corrupt
        .config(&format!("{}/dl", corrupt.uri()), false)
        .await;
    corrupt
        .index(
            "bad-crate",
            &[index_line("bad-crate", "1.0.0", &cksum, false)],
        )
        .await;
    corrupt
        .serve("/dl/bad-crate/1.0.0/download", b"tampered".to_vec())
        .await;
    assert!(matches!(
        fetch_error(fetch_crate(&cache, request(corrupt.spec(), "bad-crate", "1.0.0")).await),
        FetchError::Checksum { .. }
    ));

    // Duplicate record (differs only in build metadata) for the version.
    let duplicate = Registry::new().await;
    duplicate
        .config(&format!("{}/dl", duplicate.uri()), false)
        .await;
    duplicate
        .index(
            "dup-crate",
            &[
                index_line("dup-crate", "1.0.0", &cksum, false),
                index_line("dup-crate", "1.0.0+x", &cksum, false),
            ],
        )
        .await;
    let error =
        fetch_error(fetch_crate(&cache, request(duplicate.spec(), "dup-crate", "1.0.0")).await);
    assert!(error.to_string().contains("more than once"), "{error}");
}

#[tokio::test]
async fn crate_archives_must_have_one_matching_top_level_directory() {
    let cases: [(&str, Vec<u8>, &str); 5] = [
        (
            "missing",
            crate_bytes(&[("Cargo.toml", b"[package]\n")]),
            "directory",
        ),
        (
            "extra",
            crate_bytes(&[("shape-1.0.0/Cargo.toml", b"x"), ("other/file", b"y")]),
            "exactly one",
        ),
        (
            "misnamed",
            crate_bytes(&[("shape-9.9.9/Cargo.toml", b"x")]),
            "shape-1.0.0",
        ),
        ("traversal", hostile_crate("shape-1.0.0/../../escape"), ""),
        ("not-gzip", b"plain bytes, not an archive".to_vec(), "gzip"),
    ];
    for (label, bytes, expected) in cases {
        let registry = Registry::new().await;
        registry.publish("shape", "1.0.0", bytes, false).await;
        let (dir, cache) = temp_cache();
        let error =
            fetch_error(fetch_crate(&cache, request(registry.spec(), "shape", "1.0.0")).await);
        assert!(
            matches!(error, FetchError::Extraction(_)),
            "{label}: expected an extraction error, got {error}"
        );
        assert!(error.to_string().contains(expected), "{label}: {error}");
        // Nothing was installed, and nothing escaped the cache.
        let crate_dir = dir.path().join("cache").join("crate");
        assert!(
            !crate_dir.exists() || std::fs::read_dir(&crate_dir).unwrap().next().is_none(),
            "{label}"
        );
        assert!(!dir.path().join("escape").exists(), "{label}");
    }
}

#[tokio::test]
async fn http_status_codes_map_to_specific_errors() {
    for (status, expected) in [(410, "not found"), (451, "not found"), (500, "HTTP 500")] {
        let registry = Registry::new().await;
        registry
            .config(&format!("{}/dl", registry.uri()), false)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/index{}", index_path("gone-crate"))))
            .respond_with(ResponseTemplate::new(status))
            .mount(&registry.server)
            .await;
        let (_dir, cache) = temp_cache();
        let error =
            fetch_error(fetch_crate(&cache, request(registry.spec(), "gone-crate", "1.0.0")).await);
        assert!(error.to_string().contains(expected), "{status}: {error}");
    }
}

#[tokio::test]
async fn identical_crates_from_two_registries_share_one_cache_entry() {
    let bytes = well_formed("shared-crate", "1.0.0");
    let first = Registry::new().await;
    let second = Registry::new().await;
    let cksum = first
        .publish("shared-crate", "1.0.0", bytes.clone(), false)
        .await;
    second.publish("shared-crate", "1.0.0", bytes, false).await;
    let (_dir, cache) = temp_cache();
    let a = fetch_crate(&cache, request(first.spec(), "shared-crate", "1.0.0"))
        .await
        .unwrap();
    let b = fetch_crate(&cache, request(second.spec(), "shared-crate", "1.0.0"))
        .await
        .unwrap();
    assert_eq!(a.tree, b.tree);
    assert_eq!(
        (a.digest.as_str(), b.digest.as_str()),
        (cksum.as_str(), cksum.as_str())
    );
    assert_ne!(a.kind, b.kind, "each fetch keeps its own registry identity");
    assert_ne!(a.source_id(), b.source_id());
}

#[tokio::test]
async fn index_and_crate_bodies_are_held_to_the_download_cap() {
    let registry = Registry::new().await;
    let bytes = well_formed("big-crate", "1.0.0");
    let size = bytes.len() as u64;
    registry.publish("big-crate", "1.0.0", bytes, false).await;
    let (_dir, cache) = temp_cache();
    let options = FetchOptions {
        download: robigus::DownloadLimits {
            max_bytes: size - 1,
            ..robigus::DownloadLimits::default()
        },
        ..FetchOptions::default()
    };
    let error = match fetch(
        SourceInput::Registry(request(registry.spec(), "big-crate", "1.0.0")),
        &cache,
        &options,
    )
    .await
    {
        Err(RobigusError::Fetch(error)) => error,
        other => panic!("expected a size-cap error, got {other:?}"),
    };
    assert!(error.to_string().contains("download limit"), "{error}");
}

// Redirects

#[tokio::test]
async fn plain_http_registries_need_the_test_only_policy() {
    // The HTTPS-to-HTTP redirect rule is unit-tested in `fetch::tests`,
    // because these mock servers speak only HTTP.
    let error = RegistrySpec::direct("sparse+http://127.0.0.1:1/index/").unwrap_err();
    assert!(error.to_string().contains("https"), "{error}");
}

#[tokio::test]
async fn redirects_are_bounded_and_strip_credentials_across_hosts() {
    // A registry whose downloads redirect to a second ("CDN") server.
    let cdn = MockServer::start().await;
    let bytes = well_formed("cdn-crate", "1.0.0");
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
        .mount(&cdn)
        .await;
    let registry = Registry::new().await;
    let cksum = sha256(&bytes);
    registry
        .config(&format!("{}/dl", registry.uri()), true)
        .await;
    registry
        .index(
            "cdn-crate",
            &[index_line("cdn-crate", "1.0.0", &cksum, false)],
        )
        .await;
    Mock::given(method("GET"))
        .and(path("/dl/cdn-crate/1.0.0/download"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{}/blob", cdn.uri())),
        )
        .mount(&registry.server)
        .await;
    let token_file = private_token_file();
    let spec = RegistrySpec::named_with_policy(
        "internal",
        &format!("sparse+{}/index/", registry.uri()),
        CredentialSource::File {
            path: token_file.1.clone(),
        },
        IndexUrlPolicy::InsecureHttpWithCredentialsForTests,
    )
    .unwrap();
    let (_dir, cache) = temp_cache();
    fetch_crate(&cache, request(spec, "cdn-crate", "1.0.0"))
        .await
        .unwrap();
    for received in cdn.received_requests().await.unwrap() {
        assert!(
            received.headers.get("authorization").is_none(),
            "token followed a redirect"
        );
    }
    // config.json declares auth-required and is readable without a token;
    // every later registry request carries it.
    let after_config: Vec<_> = registry
        .requests()
        .await
        .into_iter()
        .filter(|r| r.url.path() != "/index/config.json")
        .collect();
    assert!(!after_config.is_empty());
    assert!(
        after_config
            .iter()
            .all(|r| r.headers.get("authorization").is_some_and(|v| v == CANARY)),
        "a registry request after config.json lacked the token"
    );

    // More than five redirects are refused.
    let looping = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/loop"))
        .mount(&looping)
        .await;
    let tarball = SourceInput::Tarball {
        url: format!("{}/loop", looping.uri()).parse().unwrap(),
        digest: None,
    };
    let error = match fetch(tarball, &cache, &FetchOptions::default()).await {
        Err(error) => error.to_string(),
        Ok(_) => panic!("redirect loop succeeded"),
    };
    assert!(error.contains("redirect"), "{error}");
    let hops = looping.received_requests().await.unwrap().len();
    assert!(hops <= 6, "followed {hops} requests");
}

// Authentication

/// A `0600` token file containing the canary.
fn private_token_file() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, format!("{CANARY}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path)
}

/// An auth-required registry that only answers requests carrying the
/// canary token; unauthenticated config.json gets 401.
async fn authenticated_registry(name: &str, version: &str) -> (Registry, String) {
    let registry = Registry::new().await;
    let bytes = well_formed(name, version);
    let cksum = sha256(&bytes);
    Mock::given(method("GET"))
        .and(header("authorization", CANARY))
        .and(path("/index/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"dl": format!("{}/dl", registry.uri()), "auth-required": true}),
        ))
        .mount(&registry.server)
        .await;
    Mock::given(method("GET"))
        .and(header("authorization", CANARY))
        .and(path(format!("/index{}", index_path(name))))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(index_line(name, version, &cksum, false)),
        )
        .mount(&registry.server)
        .await;
    Mock::given(method("GET"))
        .and(header("authorization", CANARY))
        .and(path(format!("/dl/{name}/{version}/download")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(&registry.server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            r#"Cargo login_url="https://registry.example/me""#,
        ))
        .with_priority(10)
        .mount(&registry.server)
        .await;
    (registry, cksum)
}

fn named(registry: &Registry, credentials: CredentialSource) -> RegistrySpec {
    RegistrySpec::named_with_policy(
        "internal",
        &format!("sparse+{}/index/", registry.uri()),
        credentials,
        IndexUrlPolicy::InsecureHttpWithCredentialsForTests,
    )
    .unwrap()
}

#[tokio::test]
async fn a_401_triggers_token_retrieval_and_a_retried_request() {
    let (registry, cksum) = authenticated_registry("auth-crate", "1.0.0").await;
    let (_keep, token_file) = private_token_file();
    let (_dir, cache) = temp_cache();
    let fetched = fetch_crate(
        &cache,
        request(
            named(&registry, CredentialSource::File { path: token_file }),
            "auth-crate",
            "1.0.0",
        ),
    )
    .await
    .unwrap();
    assert_eq!(fetched.digest, cksum);
    let requests = registry.requests().await;
    // The first config.json request is unauthenticated (Cargo's discovery),
    // then every request carries the token.
    assert!(requests[0].headers.get("authorization").is_none());
    assert!(
        requests[1..]
            .iter()
            .all(|r| r.headers.get("authorization").is_some_and(|v| v == CANARY))
    );
    // The token is nowhere in what robigus returns.
    assert!(!format!("{fetched:?}").contains(CANARY));
}

#[tokio::test]
async fn tokens_come_from_the_environment_or_a_credential_process() {
    // Environment variable.
    let (registry, _) = authenticated_registry("env-crate", "1.0.0").await;
    let variable = CredentialSource::env_var("env-test-registry");
    // SAFETY: integration tests in this file do not read this variable
    // concurrently from other threads, and it is unique to this test.
    unsafe { std::env::set_var(&variable, CANARY) };
    let spec = RegistrySpec::named_with_policy(
        "env-test-registry",
        &format!("sparse+{}/index/", registry.uri()),
        CredentialSource::Env {
            registry: "env-test-registry".into(),
        },
        IndexUrlPolicy::InsecureHttpWithCredentialsForTests,
    )
    .unwrap();
    let (_dir, cache) = temp_cache();
    fetch_crate(&cache, request(spec, "env-crate", "1.0.0"))
        .await
        .unwrap();
    unsafe { std::env::remove_var(&variable) };

    // Cargo-protocol credential process.
    let (registry, _) = authenticated_registry("proc-crate", "1.0.0").await;
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("provider");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\necho '{{\"v\":[1]}}'\nread request\necho '{{\"Ok\":{{\"kind\":\"get\",\"token\":\"{CANARY}\",\"cache\":\"session\",\"operation_independent\":true}}}}'\n"
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let spec = named(
        &registry,
        CredentialSource::Process {
            program,
            args: vec![],
        },
    );
    // A concurrently forking test thread may briefly hold the new script
    // open for writing, which makes exec fail with ETXTBSY; retry that.
    for attempt in 0.. {
        match fetch_crate(&cache, request(spec.clone(), "proc-crate", "1.0.0")).await {
            Err(error) if attempt < 50 && error.to_string().contains("Text file busy") => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            result => {
                result.unwrap();
                break;
            }
        }
    }
}

#[tokio::test]
async fn credentialed_registries_are_refused_over_plain_http() {
    let (_keep, token_file) = private_token_file();
    let credentials = CredentialSource::File { path: token_file };
    let limits = robigus::DownloadLimits::default();
    // Through every public construction path: the named constructor with
    // the ordinary insecure policy, a spec whose fields are set directly,
    // and a spec retargeted from https to http after construction.
    let named_http = RegistrySpec::named_with_policy(
        "internal",
        "sparse+http://127.0.0.1:1/index/",
        credentials.clone(),
        IndexUrlPolicy::AllowInsecureHttp,
    )
    .unwrap();
    let direct_fields = RegistrySpec::new(
        "http://127.0.0.1:1/index/".parse().unwrap(),
        Some("internal".into()),
        credentials.clone(),
    );
    let mut retargeted = RegistrySpec::named(
        "internal",
        "sparse+https://registry.example/index/",
        credentials,
    )
    .unwrap();
    retargeted.index_url = "http://registry.example/index/".parse().unwrap();
    for spec in [named_http, direct_fields, retargeted] {
        let error = robigus::RegistryClient::new(spec.clone(), limits).unwrap_err();
        assert!(
            matches!(error, FetchError::InvalidRegistry(_)),
            "{spec:?}: {error}"
        );
        assert!(error.to_string().contains("https"), "{error}");
        // The fetch path refuses it too, before any request.
        let (_dir, cache) = temp_cache();
        assert!(matches!(
            fetch_error(fetch_crate(&cache, request(spec, "any-crate", "1.0.0")).await),
            FetchError::InvalidRegistry(_)
        ));
    }
    // Unnormalized URLs set directly are refused as well.
    for url in [
        "https://registry.example/index",
        "https://user:pw@registry.example/index/",
        "https://registry.example/index/?x=1",
        "file:///tmp/index/",
    ] {
        let spec = RegistrySpec::new(url.parse().unwrap(), None, CredentialSource::None);
        assert!(robigus::RegistryClient::new(spec, limits).is_err(), "{url}");
    }
    // A public registry may still be tested over http.
    let public = RegistrySpec::direct_with_policy(
        "sparse+http://127.0.0.1:1/index/",
        IndexUrlPolicy::AllowInsecureHttp,
    )
    .unwrap();
    assert!(robigus::RegistryClient::new(public, limits).is_ok());
}

/// Regression: the `WWW-Authenticate` login URL is registry-controlled and
/// was included unredacted in authentication errors.
#[tokio::test]
async fn a_login_url_that_echoes_the_token_is_redacted() {
    let registry = Registry::new().await;
    Mock::given(method("GET"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(403).insert_header(
            "www-authenticate",
            format!(r#"Cargo login_url="https://registry.example/login?token={CANARY}""#),
        ))
        .mount(&registry.server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            format!(r#"Cargo login_url="https://registry.example/{CANARY}""#),
        ))
        .with_priority(10)
        .mount(&registry.server)
        .await;
    let (_keep, token_file) = private_token_file();
    let (_dir, cache) = temp_cache();
    let error = fetch_error(
        fetch_crate(
            &cache,
            request(
                named(&registry, CredentialSource::File { path: token_file }),
                "any-crate",
                "1.0.0",
            ),
        )
        .await,
    );
    let message = error.to_string();
    assert!(matches!(error, FetchError::Credential(_)), "{message}");
    assert!(message.contains("rejected"), "{message}");
    assert!(
        message.contains("https://registry.example/login"),
        "{message}"
    );
    assert!(message.contains("<redacted>"), "{message}");
    assert!(!message.contains(CANARY), "{message}");
    assert!(!format!("{error:?}").contains(CANARY));
}

#[tokio::test]
async fn authentication_failures_are_specific_and_never_leak_the_token() {
    // No credential source (as for --index): a clear error, no token sent.
    let (registry, _) = authenticated_registry("needs-auth", "1.0.0").await;
    let (_dir, cache) = temp_cache();
    let error =
        fetch_error(fetch_crate(&cache, request(registry.spec(), "needs-auth", "1.0.0")).await);
    let message = error.to_string();
    assert!(matches!(error, FetchError::Credential(_)), "{message}");
    assert!(message.contains("requires authentication"), "{message}");
    assert!(
        registry
            .requests()
            .await
            .iter()
            .all(|r| r.headers.get("authorization").is_none())
    );

    // A rejected token: 403, with the login hint; the server echoes the
    // token in its body, which must not reach the error.
    let rejecting = Registry::new().await;
    Mock::given(method("GET"))
        .and(header_exists("authorization"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_string(format!("token {CANARY} is revoked"))
                .insert_header(
                    "www-authenticate",
                    r#"Cargo login_url="https://registry.example/me""#,
                ),
        )
        .mount(&rejecting.server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(10)
        .mount(&rejecting.server)
        .await;
    let (_keep, token_file) = private_token_file();
    let error = fetch_error(
        fetch_crate(
            &cache,
            request(
                named(&rejecting, CredentialSource::File { path: token_file }),
                "any-crate",
                "1.0.0",
            ),
        )
        .await,
    );
    let message = error.to_string();
    assert!(message.contains("rejected"), "{message}");
    assert!(message.contains("https://registry.example/me"), "{message}");
    assert!(message.contains("token file"), "{message}");
    assert!(!message.contains(CANARY), "{message}");
    assert!(!format!("{error:?}").contains(CANARY));

    // A missing environment variable names the variable, not a value.
    let (registry, _) = authenticated_registry("no-env", "1.0.0").await;
    let spec = named(
        &registry,
        CredentialSource::Env {
            registry: "unset-registry-name".into(),
        },
    );
    let message =
        fetch_error(fetch_crate(&cache, request(spec, "no-env", "1.0.0")).await).to_string();
    assert!(
        message.contains("ROBIGUS_REGISTRY_UNSET_REGISTRY_NAME_TOKEN"),
        "{message}"
    );
}

#[tokio::test]
async fn public_registries_never_receive_a_token_and_cargo_credentials_are_ignored() {
    let registry = Registry::new().await;
    registry
        .publish(
            "public-crate",
            "1.0.0",
            well_formed("public-crate", "1.0.0"),
            false,
        )
        .await;
    let (_keep, token_file) = private_token_file();
    let spec = named(&registry, CredentialSource::File { path: token_file });
    // Cargo's own credential sources are present but must be ignored.
    let cargo_home = tempfile::tempdir().unwrap();
    std::fs::write(
        cargo_home.path().join("credentials.toml"),
        format!("[registries.internal]\ntoken = \"{CANARY}-cargo\"\n"),
    )
    .unwrap();
    let (_dir, cache) = temp_cache();
    fetch_crate(&cache, request(spec, "public-crate", "1.0.0"))
        .await
        .unwrap();
    for received in registry.requests().await {
        assert!(
            received.headers.get("authorization").is_none(),
            "a public registry received a token"
        );
    }
}

#[tokio::test]
async fn a_token_is_never_sent_to_a_dl_host_outside_the_registry() {
    // config.json points downloads at another server; that server is the
    // registry's configured dl host, so it is in scope -- but a redirect
    // from it to a third host is not.
    let third = MockServer::start().await;
    let bytes = well_formed("scope-crate", "1.0.0");
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
        .mount(&third)
        .await;
    let dl_host = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{}/x", third.uri())),
        )
        .mount(&dl_host)
        .await;
    let registry = Registry::new().await;
    let cksum = sha256(&bytes);
    registry
        .config(&format!("{}/dl", dl_host.uri()), true)
        .await;
    registry
        .index(
            "scope-crate",
            &[index_line("scope-crate", "1.0.0", &cksum, false)],
        )
        .await;
    let (_keep, token_file) = private_token_file();
    let (_dir, cache) = temp_cache();
    fetch_crate(
        &cache,
        request(
            named(&registry, CredentialSource::File { path: token_file }),
            "scope-crate",
            "1.0.0",
        ),
    )
    .await
    .unwrap();
    assert!(
        dl_host
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.headers.get("authorization").is_some())
    );
    assert!(
        third
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.headers.get("authorization").is_none())
    );
}

// Store identity

#[tokio::test]
async fn a_fetched_registry_root_round_trips_through_the_store() {
    let registry = Registry::new().await;
    registry
        .publish(
            "store-crate",
            "2.0.0",
            well_formed("store-crate", "2.0.0"),
            false,
        )
        .await;
    let (dir, cache) = temp_cache();
    let fetched = fetch_crate(&cache, request(registry.spec(), "store-crate", "2.0.0"))
        .await
        .unwrap();
    let id = PackageId {
        name: "store-crate".into(),
        version: PackageVersion::SemVer(semver::Version::new(2, 0, 0)),
        source_id: fetched.source_id(),
        ecosystem: Ecosystem::Rust,
    };
    let store = Store::open(&dir.path().join("analysis.db")).await.unwrap();
    store
        .write_metadata(&AnalysisMetadata {
            robigus_version: "test".into(),
            project_name: "store-crate".into(),
            project_version: "2.0.0".into(),
            source_kind: "cargo-registry".into(),
            source_uri: registry.spec().index_url.to_string(),
            source_digest: fetched.digest.clone(),
            configuration: Configuration::default(),
            toolchain: Default::default(),
            network_mode: "offline".into(),
            sandbox_mode: "bwrap".into(),
            options: serde_json::json!({}),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: String::new(),
        })
        .await
        .unwrap();
    store.upsert_node(&Node::new(id.clone())).await.unwrap();
    let loaded = store.load().await.unwrap();
    assert!(
        loaded.graph.node(&id).is_some(),
        "registry root did not round-trip"
    );
}

// Live

/// Fetches `itoa 1.0.11` from crates.io; needs internet access, so it runs
/// only with `ROB_NETWORK_TESTS=1`.
#[tokio::test]
async fn live_crates_io_fetch_matches_the_index_checksum() {
    if std::env::var_os("ROB_NETWORK_TESTS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        eprintln!(
            "SKIPPED live_crates_io_fetch_matches_the_index_checksum: set ROB_NETWORK_TESTS=1"
        );
        return;
    }
    let (_dir, cache) = temp_cache();
    let fetched = fetch_crate(&cache, request(RegistrySpec::crates_io(), "itoa", "1.0.11"))
        .await
        .unwrap();
    assert_eq!(
        fetched.digest,
        "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b"
    );
    assert!(fetched.tree.join("Cargo.toml").is_file());
    assert_eq!(
        fetched.kind,
        SourceKind::CargoRegistry {
            index_url: robigus::CRATES_IO_INDEX.parse().unwrap()
        }
    );
}
