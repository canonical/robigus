//! Request parsing, validation, upstream connection, relaying and logging.

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::policy::{HostName, ProxyPolicy, is_public};
use super::tls;

/// Largest request head (request line and headers) the proxy reads.
const MAX_REQUEST_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
/// Longest client-supplied text copied into a log record.
const MAX_LOGGED_TEXT: usize = 512;
/// Headers never forwarded on plain HTTP requests (RFC 9110 §7.6.1), in
/// addition to `Host`, `Proxy-*`, and any header named by `Connection`.
const HOP_BY_HOP: [&str; 6] = [
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Append-only JSON-lines request log for one execution.
#[derive(Debug)]
pub(crate) struct ProxyLog {
    path: PathBuf,
    file: std::sync::Mutex<std::fs::File>,
}

impl ProxyLog {
    /// Creates the log; fails if `path` already exists.
    pub(crate) fn create(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        Ok(Self {
            path: path.to_owned(),
            file: std::sync::Mutex::new(file),
        })
    }

    fn write(&self, record: &Record) {
        match record.decision {
            Some(Decision::Allowed) | None => tracing::info!(
                target: "robigus::proxy",
                connection = record.connection,
                event = record.event,
                method = record.method.as_deref(),
                host = record.host.as_deref(),
                port = record.port,
                upstream = record.upstream.as_deref(),
                bytes_to_upstream = record.bytes_to_upstream,
                bytes_from_upstream = record.bytes_from_upstream,
                "proxy request"
            ),
            Some(decision) => tracing::warn!(
                target: "robigus::proxy",
                connection = record.connection,
                method = record.method.as_deref(),
                target_uri = record.target.as_deref(),
                host = record.host.as_deref(),
                port = record.port,
                decision = decision.as_str(),
                reason = record.reason.as_deref(),
                "proxy request refused"
            ),
        }
        let result = serde_json::to_string(record)
            .map_err(std::io::Error::other)
            .and_then(|line| match self.file.lock() {
                Ok(mut file) => writeln!(file, "{line}"),
                Err(_) => Err(std::io::Error::other("proxy log lock poisoned")),
            });
        if let Err(error) = result {
            tracing::error!(
                target: "robigus::proxy",
                %error,
                path = %self.path.display(),
                "cannot write proxy log"
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    /// Forwarded upstream.
    Allowed,
    /// Refused by policy.
    Denied,
    /// Refused because the request was malformed or unsupported.
    Rejected,
    /// Permitted, but the upstream could not be reached.
    Failed,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
}

/// One proxy log line. `event` is `request` for the decision and `close`
/// when a forwarded connection ends.
#[derive(Debug, Default, Serialize)]
struct Record {
    time: String,
    connection: u64,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_to_upstream: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_from_upstream: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

/// Bounds client-supplied text and replaces control characters, so log
/// records and responses cannot be forged or flooded.
fn bounded(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(MAX_LOGGED_TEXT)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();
    if text.chars().nth(MAX_LOGGED_TEXT).is_some() {
        out.push('…');
    }
    out
}

/// Accepts and serves connections until `shutdown` fires (or its sender is
/// dropped), then stops accepting and waits for the connections in progress,
/// so their `close` records are written. Dropping the future instead aborts
/// every connection at once.
pub(crate) async fn serve(
    listener: TcpListener,
    policy: Arc<ProxyPolicy>,
    log: Arc<ProxyLog>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    let permits = Arc::new(Semaphore::new(policy.max_connections.max(1)));
    let mut connections = JoinSet::new();
    let mut next_id = 0_u64;
    loop {
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit,
            _ = &mut shutdown => break,
        };
        let Ok(permit) = permit else {
            break;
        };
        while connections.try_join_next().is_some() {}
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = &mut shutdown => break,
        };
        match accepted {
            Ok((stream, _)) => {
                next_id += 1;
                let connection = Connection {
                    id: next_id,
                    started: Instant::now(),
                    policy: policy.clone(),
                    log: log.clone(),
                };
                connections.spawn(async move {
                    connection.handle(stream).await;
                    drop(permit);
                });
            }
            Err(error) => {
                // For example EMFILE: back off rather than spin.
                tracing::warn!(target: "robigus::proxy", %error, "proxy accept failed");
                drop(permit);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
}

/// A refused request: the response status, the decision, and why.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    status: u16,
    decision: Decision,
    reason: String,
}

impl Refusal {
    fn rejected(status: u16, reason: impl Into<String>) -> Self {
        Self {
            status,
            decision: Decision::Rejected,
            reason: reason.into(),
        }
    }

    fn denied(reason: impl Into<String>) -> Self {
        Self {
            status: 403,
            decision: Decision::Denied,
            reason: reason.into(),
        }
    }

    fn failed(status: u16, reason: impl Into<String>) -> Self {
        Self {
            status,
            decision: Decision::Failed,
            reason: reason.into(),
        }
    }
}

/// What the client asked for.
#[derive(Debug, PartialEq, Eq)]
enum Kind {
    /// `CONNECT host:port`.
    Tunnel,
    /// Absolute-form `http://` request, forwarded with this origin-form target.
    Http { origin: String },
}

/// Whatever could be parsed from a request head, for logging.
#[derive(Debug, Default, PartialEq, Eq)]
struct Summary {
    method: Option<String>,
    target: Option<String>,
    host: Option<String>,
    port: Option<u16>,
}

/// A parsed, syntactically valid request head.
#[derive(Debug)]
struct Request {
    method: String,
    target: String,
    kind: Kind,
    host: HostName,
    port: u16,
    /// Headers forwarded on plain HTTP, in order.
    headers: Vec<(String, Vec<u8>)>,
    /// Bytes received after the request head.
    rest: Vec<u8>,
}

impl Request {
    fn summary(&self) -> Summary {
        Summary {
            method: Some(self.method.clone()),
            target: Some(self.target.clone()),
            host: Some(self.host.to_string()),
            port: Some(self.port),
        }
    }
}

struct Connection {
    id: u64,
    started: Instant,
    policy: Arc<ProxyPolicy>,
    log: Arc<ProxyLog>,
}

impl Connection {
    fn record(&self, event: &'static str, summary: &Summary) -> Record {
        Record {
            time: chrono::Utc::now().to_rfc3339(),
            connection: self.id,
            event,
            method: summary.method.as_deref().map(bounded),
            target: summary.target.as_deref().map(bounded),
            host: summary.host.as_deref().map(bounded),
            port: summary.port,
            ..Record::default()
        }
    }

    fn log_refusal(&self, summary: &Summary, refusal: &Refusal) {
        let mut record = self.record("request", summary);
        record.decision = Some(refusal.decision);
        record.status = Some(refusal.status);
        record.reason = Some(bounded(&refusal.reason));
        self.log.write(&record);
    }

    fn log_allowed(&self, request: &Request, upstream: SocketAddr) {
        let mut record = self.record("request", &request.summary());
        record.decision = Some(Decision::Allowed);
        record.upstream = Some(upstream.to_string());
        self.log.write(&record);
    }

    fn log_close(&self, request: &Request, upstream: SocketAddr, to: u64, from: u64) {
        let mut summary = request.summary();
        summary.target = None;
        let mut record = self.record("close", &summary);
        record.upstream = Some(upstream.to_string());
        record.bytes_to_upstream = Some(to);
        record.bytes_from_upstream = Some(from);
        record.duration_ms =
            Some(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX));
        self.log.write(&record);
    }

    async fn handle(&self, mut client: TcpStream) {
        let parsed = tokio::time::timeout(self.policy.header_timeout, read_request(&mut client))
            .await
            .unwrap_or_else(|_| {
                Err((
                    Summary::default(),
                    Refusal::rejected(408, "timed out waiting for the request head"),
                ))
            });
        let checked = parsed.and_then(|request| match authorize(&request, &self.policy) {
            Ok(()) => Ok(request),
            Err(refusal) => Err((request.summary(), refusal)),
        });
        let request = match checked {
            Ok(request) => request,
            Err((summary, refusal)) => {
                self.log_refusal(&summary, &refusal);
                respond(&mut client, refusal.status).await;
                return;
            }
        };
        let (mut upstream, address) = match connect(&self.policy, &request.host, request.port).await
        {
            Ok(connected) => connected,
            Err(refusal) => {
                self.log_refusal(&request.summary(), &refusal);
                respond(&mut client, refusal.status).await;
                return;
            }
        };
        match &request.kind {
            Kind::Tunnel => self.tunnel(client, upstream, address, &request).await,
            Kind::Http { origin } => {
                self.log_allowed(&request, address);
                let head = origin_request(&request, origin);
                if upstream.write_all(&head).await.is_err() {
                    respond(&mut client, 502).await;
                    self.log_close(&request, address, 0, 0);
                    return;
                }
                let from = tokio::io::copy(&mut upstream, &mut client)
                    .await
                    .unwrap_or(0);
                let _ = client.shutdown().await;
                self.log_close(&request, address, head.len() as u64, from);
            }
        }
    }

    async fn tunnel(
        &self,
        mut client: TcpStream,
        mut upstream: TcpStream,
        address: SocketAddr,
        request: &Request,
    ) {
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        let hello = tokio::time::timeout(
            self.policy.header_timeout,
            read_client_hello(&mut client, request.rest.clone()),
        )
        .await
        .unwrap_or_else(|_| {
            Err(Refusal::rejected(
                408,
                "timed out waiting for the TLS ClientHello",
            ))
        })
        .and_then(|(hello, server_name)| {
            check_server_name(server_name.as_deref(), &request.host).map(|()| hello)
        });
        let hello = match hello {
            Ok(hello) => hello,
            Err(refusal) => {
                // The 200 was already sent; refusing means closing the
                // tunnel. No client byte has reached the upstream.
                self.log_refusal(&request.summary(), &refusal);
                return;
            }
        };
        self.log_allowed(request, address);
        if upstream.write_all(&hello).await.is_err() {
            self.log_close(request, address, 0, 0);
            return;
        }
        let (to, from) = tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .unwrap_or((0, 0));
        self.log_close(request, address, hello.len() as u64 + to, from);
    }
}

async fn respond(client: &mut TcpStream, status: u16) {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    };
    let body = format!("robigus proxy: {status} {reason}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = client.write_all(response.as_bytes()).await;
    let _ = client.shutdown().await;
}

/// Reads and parses one request head.
async fn read_request(client: &mut TcpStream) -> Result<Request, (Summary, Refusal)> {
    let mut buffer = Vec::with_capacity(4096);
    loop {
        match parse_request(&buffer) {
            Ok(Some(request)) => return Ok(request),
            Ok(None) if buffer.len() >= MAX_REQUEST_HEAD => {
                return Err((
                    Summary::default(),
                    Refusal::rejected(431, "request head exceeds 16 KiB"),
                ));
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        let mut chunk = [0_u8; 4096];
        let limit = (MAX_REQUEST_HEAD + 1 - buffer.len()).min(chunk.len());
        match client.read(&mut chunk[..limit]).await {
            Ok(0) => {
                return Err((
                    Summary::default(),
                    Refusal::rejected(400, "connection closed before a complete request head"),
                ));
            }
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
            Err(error) => {
                return Err((
                    Summary::default(),
                    Refusal::rejected(400, format!("cannot read request: {error}")),
                ));
            }
        }
    }
}

/// Parses a complete request head, `Ok(None)` if more bytes are needed.
fn parse_request(buffer: &[u8]) -> Result<Option<Request>, (Summary, Refusal)> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    let length = match parsed.parse(buffer) {
        Ok(httparse::Status::Complete(length)) => length,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => {
            return Err((
                Summary::default(),
                Refusal::rejected(431, "too many request headers"),
            ));
        }
        Err(error) => {
            return Err((
                Summary::default(),
                Refusal::rejected(400, format!("malformed request: {error}")),
            ));
        }
    };
    let method = parsed.method.unwrap_or_default().to_owned();
    let target = parsed.path.unwrap_or_default().to_owned();
    let mut summary = Summary {
        method: Some(method.clone()),
        target: Some(target.clone()),
        ..Summary::default()
    };
    let fail = |summary: Summary, status, reason: String| {
        Err((summary, Refusal::rejected(status, reason)))
    };
    if parsed.version != Some(1) && parsed.version != Some(0) {
        return fail(summary, 505, "only HTTP/1.x is supported".into());
    }

    let (kind, authority) = if method == "CONNECT" {
        (Kind::Tunnel, target.clone())
    } else if method == "GET" || method == "HEAD" {
        let Some(rest) = strip_prefix_ignore_case(&target, "http://") else {
            let reason = if strip_prefix_ignore_case(&target, "https://").is_some() {
                "https:// requests must use CONNECT"
            } else {
                "request target must be an absolute http:// URL"
            };
            return fail(summary, 400, reason.into());
        };
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(index) => rest.split_at(index),
            None => (rest, "/"),
        };
        if path.starts_with('#') || path.contains('#') {
            return fail(
                summary,
                400,
                "request target must not contain a fragment".into(),
            );
        }
        let origin = if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        if authority.contains('@') {
            return fail(
                summary,
                400,
                "request target must not contain user information".into(),
            );
        }
        (Kind::Http { origin }, authority.to_owned())
    } else {
        return fail(
            summary,
            405,
            format!("method {} is not supported", bounded(&method)),
        );
    };

    let default_port = match kind {
        Kind::Tunnel => None,
        Kind::Http { .. } => Some(80),
    };
    let (host_text, port) = match split_authority(&authority, default_port) {
        Ok(parts) => parts,
        Err(reason) => return fail(summary, 400, reason.into()),
    };
    summary.host = Some(host_text.to_owned());
    summary.port = Some(port);
    let host = match host_text.parse::<HostName>() {
        Ok(host) => host,
        Err(error) => {
            summary.port = Some(port);
            return Err((summary, Refusal::denied(error.to_string())));
        }
    };
    summary.host = Some(host.to_string());

    let mut host_headers = 0;
    let mut forwarded = Vec::new();
    let mut connection_tokens = Vec::new();
    for header in parsed.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        match name.as_str() {
            "host" => {
                host_headers += 1;
                let value = std::str::from_utf8(header.value).unwrap_or("").trim();
                let matches = split_authority(value, Some(port)).ok().is_some_and(
                    |(header_host, header_port)| {
                        header_port == port
                            && header_host
                                .parse::<HostName>()
                                .is_ok_and(|header_host| header_host == host)
                    },
                );
                if !matches {
                    return fail(
                        summary,
                        400,
                        format!(
                            "Host header {:?} does not match the request target",
                            bounded(value)
                        ),
                    );
                }
            }
            "content-length" => {
                if std::str::from_utf8(header.value).map(str::trim) != Ok("0") {
                    return fail(summary, 413, "request bodies are not supported".into());
                }
            }
            "transfer-encoding" => {
                return fail(summary, 411, "request bodies are not supported".into());
            }
            "connection" => connection_tokens.extend(
                String::from_utf8_lossy(header.value)
                    .split(',')
                    .map(|token| token.trim().to_ascii_lowercase()),
            ),
            _ => {}
        }
        if !name.starts_with("proxy-")
            && name != "host"
            && name != "content-length"
            && !HOP_BY_HOP.contains(&name.as_str())
        {
            forwarded.push((header.name.to_owned(), header.value.to_vec()));
        }
    }
    if host_headers > 1 {
        return fail(summary, 400, "more than one Host header".into());
    }
    if host_headers == 0 && matches!(kind, Kind::Http { .. }) {
        return fail(summary, 400, "Host header is required".into());
    }
    forwarded.retain(|(name, _)| !connection_tokens.contains(&name.to_ascii_lowercase()));

    Ok(Some(Request {
        method,
        target,
        kind,
        host,
        port,
        headers: forwarded,
        rest: buffer[length..].to_vec(),
    }))
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

/// Splits `host[:port]`. IPv6 literals in brackets are recognized only to be
/// refused later by [`HostName`]. Without `default_port`, a port is required.
fn split_authority(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(&str, u16), &'static str> {
    if authority.is_empty() {
        return Err("request target has no host");
    }
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let end = after.find(']').ok_or("unterminated IPv6 literal")?;
        let port = after[end + 1..].strip_prefix(':');
        if port.is_none() && end + 1 != after.len() {
            return Err("invalid authority after IPv6 literal");
        }
        (&authority[..end + 2], port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(text) => {
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid port");
            }
            match text.parse::<u16>() {
                Ok(port) if port != 0 => port,
                _ => return Err("invalid port"),
            }
        }
        None => default_port.ok_or("CONNECT target must be host:port")?,
    };
    if host.is_empty() {
        return Err("request target has no host");
    }
    Ok((host, port))
}

/// Applies the allowlist and port policy.
fn authorize(request: &Request, policy: &ProxyPolicy) -> Result<(), Refusal> {
    policy
        .allowlist
        .decide(&request.host)
        .map_err(Refusal::denied)?;
    if !policy.ports.contains(&request.port) {
        return Err(Refusal::denied(format!(
            "port {} is not allowed",
            request.port
        )));
    }
    Ok(())
}

/// Resolves the host (pinned addresses first) and connects to the first
/// reachable address. Refuses names that resolve to any non-public address.
async fn connect(
    policy: &ProxyPolicy,
    host: &HostName,
    port: u16,
) -> Result<(TcpStream, SocketAddr), Refusal> {
    let attempt = async {
        let addresses: Vec<SocketAddr> = match policy.resolve.get(host) {
            Some(pinned) => pinned.iter().map(|ip| SocketAddr::new(*ip, port)).collect(),
            None => {
                let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .map_err(|error| {
                        Refusal::failed(502, format!("cannot resolve {host}: {error}"))
                    })?
                    .collect();
                if let Some(address) = resolved.iter().find(|address| !is_public(address.ip())) {
                    return Err(Refusal::denied(format!(
                        "{host} resolves to non-public address {}",
                        address.ip()
                    )));
                }
                resolved
            }
        };
        let mut last_error = None;
        for address in &addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok((stream, *address)),
                Err(error) => last_error = Some(format!("{address}: {error}")),
            }
        }
        Err(Refusal::failed(
            502,
            format!(
                "cannot connect to {host}:{port}: {}",
                last_error.unwrap_or_else(|| "no addresses".into())
            ),
        ))
    };
    tokio::time::timeout(policy.connect_timeout, attempt)
        .await
        .unwrap_or_else(|_| {
            Err(Refusal::failed(
                504,
                format!("timed out connecting to {host}:{port}"),
            ))
        })
}

/// Reads until a complete ClientHello is buffered. Returns the buffered bytes
/// and the SNI host name, if present.
async fn read_client_hello(
    client: &mut TcpStream,
    mut buffer: Vec<u8>,
) -> Result<(Vec<u8>, Option<String>), Refusal> {
    loop {
        match tls::inspect(&buffer) {
            Ok(tls::Inspection::ClientHello { server_name }) => return Ok((buffer, server_name)),
            Ok(tls::Inspection::Incomplete) => {}
            Err(tls::Malformed(reason)) => return Err(Refusal::rejected(400, reason)),
        }
        // Records add 5 bytes per 16 KiB fragment; stop well past the bound.
        if buffer.len() > tls::MAX_CLIENT_HELLO + 1024 {
            return Err(Refusal::rejected(400, "ClientHello is too large"));
        }
        let mut chunk = [0_u8; 4096];
        match client.read(&mut chunk).await {
            Ok(0) => {
                return Err(Refusal::rejected(
                    400,
                    "tunnel closed before a complete TLS ClientHello",
                ));
            }
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
            Err(error) => {
                return Err(Refusal::rejected(
                    400,
                    format!("cannot read tunnel: {error}"),
                ));
            }
        }
    }
}

fn check_server_name(server_name: Option<&str>, host: &HostName) -> Result<(), Refusal> {
    let Some(name) = server_name else {
        return Err(Refusal::denied("TLS ClientHello has no server name (SNI)"));
    };
    match name.parse::<HostName>() {
        Ok(sni) if &sni == host => Ok(()),
        Ok(sni) => Err(Refusal::denied(format!(
            "TLS server name {sni} does not match CONNECT host {host}"
        ))),
        Err(error) => Err(Refusal::denied(format!("invalid TLS server name: {error}"))),
    }
}

/// Builds the origin-form request forwarded upstream for plain HTTP.
fn origin_request(request: &Request, origin: &str) -> Vec<u8> {
    let mut head = format!(
        "{} {origin} HTTP/1.1\r\nHost: {}",
        request.method, request.host
    );
    if request.port != 80 {
        head.push_str(&format!(":{}", request.port));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    for (name, value) in &request.headers {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"Connection: close\r\n\r\n");
    bytes
}

/// Address-family check used by the bootstrap hand-off: the received socket
/// must be a listening IPv4 TCP socket bound to the sandbox proxy address.
pub(crate) fn check_listener(address: SocketAddr, expected: SocketAddr) -> Result<(), String> {
    if address != expected {
        return Err(format!(
            "sandbox proxy listener is bound to {address}, expected {expected}"
        ));
    }
    if !matches!(address.ip(), IpAddr::V4(ip) if ip.is_loopback()) {
        return Err("sandbox proxy listener must be bound to IPv4 loopback".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Request {
        parse_request(text.as_bytes())
            .unwrap_or_else(|(_, refusal)| panic!("refused: {refusal:?}"))
            .expect("complete request")
    }

    fn refused(text: &str) -> (Summary, Refusal) {
        match parse_request(text.as_bytes()) {
            Err(refusal) => refusal,
            Ok(other) => panic!("accepted {text:?}: {other:?}"),
        }
    }

    #[test]
    fn parses_connect_and_absolute_http_requests() {
        let connect =
            parse("CONNECT index.crates.io:443 HTTP/1.1\r\nHost: index.crates.io:443\r\n\r\nEXTRA");
        assert_eq!(connect.kind, Kind::Tunnel);
        assert_eq!(connect.host.as_str(), "index.crates.io");
        assert_eq!(connect.port, 443);
        assert_eq!(connect.rest, b"EXTRA");

        let get = parse(
            "GET HTTP://Archive.Ubuntu.com/ubuntu/dists?x=1 HTTP/1.1\r\nhost: archive.ubuntu.com\r\nAccept: */*\r\nProxy-Authorization: secret\r\nConnection: keep-alive, X-Drop\r\nX-Drop: 1\r\nKeep-Alive: 5\r\n\r\n",
        );
        assert_eq!(
            get.kind,
            Kind::Http {
                origin: "/ubuntu/dists?x=1".into()
            }
        );
        assert_eq!(get.port, 80);
        let forwarded = String::from_utf8(origin_request(&get, "/ubuntu/dists?x=1")).unwrap();
        assert_eq!(
            forwarded,
            "GET /ubuntu/dists?x=1 HTTP/1.1\r\nHost: archive.ubuntu.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );

        let query =
            parse("HEAD http://example.org:8080?q HTTP/1.0\r\nHost: example.org:8080\r\n\r\n");
        assert_eq!(
            query.kind,
            Kind::Http {
                origin: "/?q".into()
            }
        );
        assert!(
            String::from_utf8(origin_request(&query, "/?q"))
                .unwrap()
                .starts_with("HEAD /?q HTTP/1.1\r\nHost: example.org:8080\r\n")
        );
        assert!(
            parse_request(b"CONNECT a.example:443 HTTP/1.1\r\n")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_malformed_and_unsupported_requests() {
        for (text, status) in [
            ("GET /index HTTP/1.1\r\nHost: a.example\r\n\r\n", 400),
            (
                "GET https://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                400,
            ),
            (
                "GET ftp://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                400,
            ),
            (
                "POST http://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                405,
            ),
            (
                "DELETE http://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                405,
            ),
            ("CONNECT a.example HTTP/1.1\r\n\r\n", 400),
            ("CONNECT a.example:0 HTTP/1.1\r\n\r\n", 400),
            ("CONNECT a.example:99999 HTTP/1.1\r\n\r\n", 400),
            ("CONNECT a.example:+443 HTTP/1.1\r\n\r\n", 400),
            ("CONNECT :443 HTTP/1.1\r\n\r\n", 400),
            ("CONNECT [::1 HTTP/1.1\r\n\r\n", 400),
            (
                "GET http://user@a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                400,
            ),
            (
                "GET http://a.example/#frag HTTP/1.1\r\nHost: a.example\r\n\r\n",
                400,
            ),
            ("GET http://a.example/ HTTP/1.1\r\n\r\n", 400),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n",
                400,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example:81\r\n\r\n",
                400,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nHost: a.example\r\n\r\n",
                400,
            ),
            (
                "CONNECT a.example:443 HTTP/1.1\r\nHost: b.example:443\r\n\r\n",
                400,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n\r\nhello",
                413,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n",
                411,
            ),
            (
                "GET http://a.example/ HTTP/2.0\r\nHost: a.example\r\n\r\n",
                400,
            ),
            ("GET http://a.example/ HTTP/1.1\r\nBad Header\r\n\r\n", 400),
            ("\x16\x03\x01\x00\x05hello", 400),
        ] {
            let (_, refusal) = refused(text);
            assert_eq!(refusal.status, status, "{text:?}: {refusal:?}");
            assert_eq!(refusal.decision, Decision::Rejected, "{text:?}");
        }
        let headers: String = (0..=MAX_HEADERS).map(|i| format!("X-{i}: 1\r\n")).collect();
        let (_, refusal) = refused(&format!("CONNECT a.example:443 HTTP/1.1\r\n{headers}\r\n"));
        assert_eq!(refusal.status, 431);
    }

    #[test]
    fn ip_literals_and_numeric_names_are_denied() {
        for target in [
            "127.0.0.1:443",
            "[::1]:443",
            "169.254.169.254:80",
            "2130706433:443",
            "0x7f000001:443",
            "localhost.123:443",
        ] {
            let (summary, refusal) = refused(&format!("CONNECT {target} HTTP/1.1\r\n\r\n"));
            assert_eq!(refusal.decision, Decision::Denied, "{target}");
            assert_eq!(refusal.status, 403, "{target}");
            assert!(summary.host.is_some(), "{target}");
        }
        let (_, refusal) = refused("GET http://10.0.0.1/ HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n");
        assert_eq!(refusal.decision, Decision::Denied);
    }

    #[test]
    fn authorization_applies_allowlist_and_ports() {
        let policy = ProxyPolicy::default();
        let request = |text: &str| parse(text);
        assert!(
            authorize(
                &request("CONNECT static.crates.io:443 HTTP/1.1\r\n\r\n"),
                &policy
            )
            .is_ok()
        );
        assert!(
            authorize(
                &request(
                    "GET http://archive.ubuntu.com/ HTTP/1.1\r\nHost: archive.ubuntu.com\r\n\r\n"
                ),
                &policy
            )
            .is_ok()
        );
        for text in [
            "CONNECT example.org:443 HTTP/1.1\r\n\r\n",
            "CONNECT evilcrates.io:443 HTTP/1.1\r\n\r\n",
            "CONNECT crates.io.evil.example:443 HTTP/1.1\r\n\r\n",
            "CONNECT crates.io:22 HTTP/1.1\r\n\r\n",
            "CONNECT crates.io:8443 HTTP/1.1\r\n\r\n",
        ] {
            let refusal = authorize(&request(text), &policy).unwrap_err();
            assert_eq!(refusal.decision, Decision::Denied, "{text}");
        }
    }

    #[test]
    fn server_name_must_match_connect_host() {
        let host: HostName = "index.crates.io".parse().unwrap();
        assert!(check_server_name(Some("index.crates.io"), &host).is_ok());
        assert!(check_server_name(Some("INDEX.crates.io."), &host).is_ok());
        for sni in [
            None,
            Some("static.crates.io"),
            Some("example.org"),
            Some("127.0.0.1"),
            Some("bad_name"),
        ] {
            let refusal = check_server_name(sni, &host).unwrap_err();
            assert_eq!(refusal.decision, Decision::Denied, "{sni:?}");
        }
    }

    #[test]
    fn logged_text_is_bounded_and_control_free() {
        assert_eq!(bounded("a\r\nb\u{1b}"), "a\u{fffd}\u{fffd}b\u{fffd}");
        let long = "x".repeat(MAX_LOGGED_TEXT + 10);
        let out = bounded(&long);
        assert_eq!(out.chars().count(), MAX_LOGGED_TEXT + 1);
        assert!(out.ends_with('…'));
        assert_eq!(
            bounded(&"y".repeat(MAX_LOGGED_TEXT)).chars().count(),
            MAX_LOGGED_TEXT
        );
    }

    /// A proxy on an ephemeral host port with `policy`, logging to a temp file.
    struct Harness {
        _dir: tempfile::TempDir,
        address: SocketAddr,
        log_path: PathBuf,
        task: tokio::task::JoinHandle<()>,
        _shutdown: tokio::sync::oneshot::Sender<()>,
    }

    impl Harness {
        async fn start(policy: ProxyPolicy) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log_path = dir.path().join("proxy.jsonl");
            let log = Arc::new(ProxyLog::create(&log_path).unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (shutdown, receiver) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(serve(listener, Arc::new(policy), log, receiver));
            Self {
                _dir: dir,
                address,
                log_path,
                task,
                _shutdown: shutdown,
            }
        }

        /// Sends `request` and returns everything the proxy sends back.
        async fn exchange(&self, request: &[u8]) -> Vec<u8> {
            let mut stream = TcpStream::connect(self.address).await.unwrap();
            stream.write_all(request).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
                .await
                .expect("proxy response timed out")
                .unwrap();
            response
        }

        fn records(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(&self.log_path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }

        /// Waits until `count` records are logged (close records follow the
        /// response).
        async fn wait_for_records(&self, count: usize) -> Vec<serde_json::Value> {
            for _ in 0..200 {
                let records = self.records();
                if records.len() >= count {
                    return records;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("expected {count} proxy records, got {:?}", self.records());
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// Allowlists `name` (only) and pins it to `127.0.0.1`.
    fn pinned(name: &str, ports: &[u16]) -> ProxyPolicy {
        let host: HostName = name.parse().unwrap();
        let mut allowlist = super::super::Allowlist::empty();
        allowlist.allow(host.clone());
        ProxyPolicy {
            allowlist,
            ports: ports.iter().copied().collect(),
            header_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(2),
            resolve: [(host, vec![IpAddr::from([127, 0, 0, 1])])].into(),
            ..ProxyPolicy::default()
        }
    }

    fn status_of(response: &[u8]) -> u16 {
        let text = String::from_utf8_lossy(response);
        text.split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn forwards_allowed_http_and_logs_it() {
        use wiremock::matchers::{header, header_exists, method, path};
        let origin = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/ubuntu/dists/resolute/Release"))
            .and(header(
                "host",
                format!("archive.ubuntu.com:{}", origin.address().port()),
            ))
            .and(header("connection", "close"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("release-body"))
            .expect(1)
            .mount(&origin)
            .await;
        // Hop-by-hop and proxy credentials must not reach the origin.
        wiremock::Mock::given(header_exists("proxy-authorization"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .expect(0)
            .mount(&origin)
            .await;
        let port = origin.address().port();
        let proxy = Harness::start(pinned("archive.ubuntu.com", &[port])).await;
        let response = proxy
            .exchange(
                format!(
                    "GET http://archive.ubuntu.com:{port}/ubuntu/dists/resolute/Release HTTP/1.1\r\n\
                     Host: archive.ubuntu.com:{port}\r\nProxy-Authorization: Basic c2VjcmV0\r\n\
                     Proxy-Connection: keep-alive\r\n\r\n"
                )
                .as_bytes(),
            )
            .await;
        assert_eq!(
            status_of(&response),
            200,
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"release-body"));
        let records = proxy.wait_for_records(2).await;
        assert_eq!(records[0]["event"], "request");
        assert_eq!(records[0]["decision"], "allowed");
        assert_eq!(records[0]["method"], "GET");
        assert_eq!(records[0]["host"], "archive.ubuntu.com");
        assert_eq!(records[0]["port"], port);
        assert_eq!(records[0]["upstream"], format!("127.0.0.1:{port}"));
        assert_eq!(records[1]["event"], "close");
        assert!(records[1]["bytes_from_upstream"].as_u64().unwrap() > 0);
        assert!(
            !std::fs::read_to_string(&proxy.log_path)
                .unwrap()
                .contains("c2VjcmV0")
        );
    }

    #[tokio::test]
    async fn denies_unlisted_hosts_ports_and_addresses_without_connecting() {
        let origin = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(0)
            .mount(&origin)
            .await;
        let port = origin.address().port();
        let mut policy = pinned("archive.ubuntu.com", &[port]);
        // Pinned but not allowlisted: pinning never grants access.
        policy.resolve.insert(
            "evil.example".parse().unwrap(),
            vec![IpAddr::from([127, 0, 0, 1])],
        );
        let proxy = Harness::start(policy).await;
        let cases = [
            (
                format!(
                    "GET http://evil.example:{port}/ HTTP/1.1\r\nHost: evil.example:{port}\r\n\r\n"
                ),
                403,
                "denied",
            ),
            (
                format!(
                    "GET http://archive.ubuntu.com:{}/ HTTP/1.1\r\nHost: archive.ubuntu.com:{}\r\n\r\n",
                    port + 1,
                    port + 1
                ),
                403,
                "denied",
            ),
            (
                format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
                403,
                "denied",
            ),
            (
                format!("CONNECT evil.example:{port} HTTP/1.1\r\n\r\n"),
                403,
                "denied",
            ),
            (
                format!(
                    "GET http://archive.ubuntu.com:{port}/ HTTP/1.1\r\nHost: evil.example:{port}\r\n\r\n"
                ),
                400,
                "rejected",
            ),
            (
                format!("GET /direct HTTP/1.1\r\nHost: archive.ubuntu.com:{port}\r\n\r\n"),
                400,
                "rejected",
            ),
            ("NOT HTTP AT ALL\r\n\r\n".to_owned(), 400, "rejected"),
        ];
        for (request, status, _) in &cases {
            let response = proxy.exchange(request.as_bytes()).await;
            assert_eq!(status_of(&response), *status, "{request:?}");
        }
        let records = proxy.wait_for_records(cases.len()).await;
        for (record, (request, status, decision)) in records.iter().zip(&cases) {
            assert_eq!(record["decision"], *decision, "{request:?}: {record}");
            assert_eq!(record["status"], *status, "{request:?}");
            assert!(record["reason"].as_str().is_some_and(|r| !r.is_empty()));
            assert!(record.get("upstream").is_none());
        }
    }

    #[tokio::test]
    async fn refuses_names_that_resolve_to_non_public_addresses() {
        let mut allowlist = super::super::Allowlist::empty();
        allowlist.allow("localhost".parse().unwrap());
        let policy = ProxyPolicy {
            allowlist,
            header_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(2),
            ..ProxyPolicy::default()
        };
        let proxy = Harness::start(policy).await;
        let response = proxy
            .exchange(b"CONNECT localhost:443 HTTP/1.1\r\n\r\n")
            .await;
        let records = proxy.wait_for_records(1).await;
        assert_eq!(status_of(&response), 403, "{records:?}");
        assert_eq!(records[0]["decision"], "denied");
        assert!(
            records[0]["reason"]
                .as_str()
                .unwrap()
                .contains("non-public"),
            "{records:?}"
        );
    }

    /// A fake TLS origin: echoes what it receives so the test can see
    /// exactly which bytes were forwarded.
    async fn echo_origin() -> (SocketAddr, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut received = Vec::new();
            while let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_secs(3), listener.accept()).await
            {
                let mut bytes = Vec::new();
                let mut chunk = [0_u8; 4096];
                while let Ok(Ok(count)) =
                    tokio::time::timeout(Duration::from_millis(300), stream.read(&mut chunk)).await
                {
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    let _ = stream.write_all(&chunk[..count]).await;
                }
                received.push(bytes);
            }
            received
        });
        (address, task)
    }

    #[tokio::test]
    async fn tunnels_only_after_a_matching_client_hello() {
        let (origin, received) = echo_origin().await;
        let proxy = Harness::start(pinned("index.crates.io", &[origin.port()])).await;
        let connect = format!(
            "CONNECT index.crates.io:{0} HTTP/1.1\r\nHost: index.crates.io:{0}\r\n\r\n",
            origin.port()
        );

        // Allowed: the ClientHello is forwarded unchanged, then bytes flow
        // both ways without inspection.
        let hello = tls::build::hello_for("index.crates.io");
        let mut stream = TcpStream::connect(proxy.address).await.unwrap();
        stream.write_all(connect.as_bytes()).await.unwrap();
        let mut established = [0_u8; 39];
        stream.read_exact(&mut established).await.unwrap();
        assert!(established.starts_with(b"HTTP/1.1 200"));
        stream.write_all(&hello).await.unwrap();
        stream.write_all(b"opaque-application-data").await.unwrap();
        let mut echoed = vec![0_u8; hello.len() + 23];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed[..hello.len()], &hello[..]);
        drop(stream);

        // Refused: missing SNI, different SNI, and non-TLS bytes. The tunnel
        // is closed without forwarding a single client byte.
        let refused: [Vec<u8>; 3] = [
            tls::build::records(&tls::build::hello_body(None), 1),
            tls::build::hello_for("evil.example"),
            b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
        ];
        for opening in &refused {
            let mut stream = TcpStream::connect(proxy.address).await.unwrap();
            stream.write_all(connect.as_bytes()).await.unwrap();
            stream.write_all(opening).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"));
            assert_eq!(response.len(), 39, "tunnel relayed data: {response:?}");
        }

        // The first tunnel's close record is written when its relay ends,
        // which may be after later connections are refused; order by
        // connection id.
        let mut records = proxy.wait_for_records(5).await;
        records.sort_by_key(|record| record["connection"].as_u64());
        let decisions: Vec<_> = records
            .iter()
            .map(|record| {
                (
                    record["event"].as_str().unwrap(),
                    record["decision"].as_str(),
                )
            })
            .collect();
        assert_eq!(
            decisions,
            [
                ("request", Some("allowed")),
                ("close", None),
                ("request", Some("denied")),
                ("request", Some("denied")),
                ("request", Some("rejected")),
            ]
        );
        assert!(
            records[2]["reason"]
                .as_str()
                .unwrap()
                .contains("no server name")
        );
        assert!(
            records[3]["reason"]
                .as_str()
                .unwrap()
                .contains("evil.example")
        );
        let received = received.await.unwrap();
        assert_eq!(
            received[0],
            [&hello[..], b"opaque-application-data"].concat()
        );
        assert!(
            received[1..].iter().all(Vec::is_empty),
            "refused tunnels forwarded bytes: {received:?}"
        );
    }

    #[tokio::test]
    async fn reports_unreachable_upstreams_and_slow_clients() {
        // A port with no listener: allowed, but the connection fails.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let proxy = Harness::start(pinned("index.crates.io", &[port])).await;
        let response = proxy
            .exchange(format!("CONNECT index.crates.io:{port} HTTP/1.1\r\n\r\n").as_bytes())
            .await;
        assert_eq!(status_of(&response), 502);

        // A client that never finishes its request head.
        let mut slow = TcpStream::connect(proxy.address).await.unwrap();
        slow.write_all(b"CONNECT index.crates.io").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status_of(&response), 408);
        let records = proxy.wait_for_records(2).await;
        assert_eq!(records[0]["decision"], "failed");
        assert_eq!(records[1]["decision"], "rejected");
    }

    #[test]
    fn listener_check_requires_the_sandbox_address() {
        let expected: SocketAddr = "127.0.0.1:3128".parse().unwrap();
        assert!(check_listener(expected, expected).is_ok());
        assert!(check_listener("0.0.0.0:3128".parse().unwrap(), expected).is_err());
        assert!(check_listener("127.0.0.1:3129".parse().unwrap(), expected).is_err());
    }
}
