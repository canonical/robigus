//! WP-2.6: registry tokens never appear in `tracing` output (spec §7.2.2).
//!
//! A separate test binary, because `tracing` caches whether each callsite
//! is enabled process-wide: with other tests running first, a test-local
//! subscriber may miss events. Here the capturing subscriber is the global
//! default before anything else runs, and this is the only test.

use std::io::Write;
use std::sync::{Arc, Mutex};

use flate2::Compression;
use flate2::write::GzEncoder;
use robigus::fetch::{RegistrySource, SourceInput, fetch};
use robigus::registry::{IndexUrlPolicy, RegistrySpec, parse_exact_version};
use robigus::{Cache, CredentialSource, FetchOptions};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CANARY: &str = "robigus-canary-token-7e21b4";

/// A `tracing` writer that keeps everything written to it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn crate_archive(name: &str, version: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let manifest = format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n");
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            format!("{name}-{version}/Cargo.toml"),
            manifest.as_bytes(),
        )
        .unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&builder.into_inner().unwrap()).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn tokens_never_appear_in_trace_logs() {
    let captured = Captured::default();
    let writer = captured.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    let server = MockServer::start().await;
    let (name, version) = ("traced-crate", "1.0.0");
    let bytes = crate_archive(name, version);
    let cksum: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let authorized = || header("authorization", CANARY);
    Mock::given(method("GET"))
        .and(authorized())
        .and(path("/index/config.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"dl": format!("{}/dl", server.uri()), "auth-required": true}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(authorized())
        .and(path("/index/tr/ac/traced-crate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"name":"{name}","vers":"{version}","cksum":"{cksum}"}}"#
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(authorized())
        .and(path(format!("/dl/{name}/{version}/download")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(10)
        .mount(&server)
        .await;

    let token_dir = tempfile::tempdir().unwrap();
    let token_file = token_dir.path().join("token");
    std::fs::write(&token_file, CANARY).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let registry = RegistrySpec::named_with_policy(
        "internal",
        &format!("sparse+{}/index/", server.uri()),
        CredentialSource::File { path: token_file },
        IndexUrlPolicy::InsecureHttpWithCredentialsForTests,
    )
    .unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let fetched = fetch(
        SourceInput::Registry(RegistrySource {
            registry,
            name: name.into(),
            version: parse_exact_version(version).unwrap(),
            digest: None,
            allow_yanked: false,
        }),
        &Cache::new(cache_dir.path()),
        &FetchOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(fetched.digest, cksum);

    let log = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    // robigus traces every registry request with its headers, including the
    // authenticated ones, so this check is meaningful.
    assert!(
        log.contains(r#"headers={"authorization": Sensitive} authenticated=true"#),
        "no authenticated request was traced:\n{log}"
    );
    assert!(!log.contains(CANARY), "token in trace output:\n{log}");
}
