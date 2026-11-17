//! Allowlisting forward proxy for sandboxed network access (spec §10.2;
//! WP-2.1).
//!
//! # Transport
//!
//! A network-enabled sandbox still runs in its own network namespace, which
//! contains only a loopback interface: nothing on the host or the internet is
//! routable from it. Before the workload starts, a fixed bootstrap
//! (`/usr/bin/python3 -I -S`, from the read-only host runtime) binds a TCP
//! listener on [`SANDBOX_PROXY_ADDR`] *inside* that namespace, sends the
//! listening socket to robigus over a private Unix socketpair and exits. The
//! sandbox shell then closes its end of the socketpair and `exec`s the
//! workload, so the workload never holds the control channel or the listener.
//! robigus accepts connections on the received socket and opens upstream
//! connections from the host only after validating each request. The workload
//! finds the proxy through `http_proxy`, `https_proxy`, their uppercase forms
//! and `CARGO_HTTP_PROXY`; connecting anywhere else still fails, because the
//! namespace has no route off the host.
//!
//! # Request policy
//!
//! - Only HTTP/1.x forward-proxy requests are served: `CONNECT host:port`
//!   tunnels, and absolute-form `GET`/`HEAD` requests for `http://` URLs.
//!   Origin-form requests, `https://` URLs sent without `CONNECT`, other
//!   methods, request bodies, and malformed requests are refused with a `4xx`
//!   response.
//! - Targets must be literal DNS names ([`HostName`]); IP address literals and
//!   numeric names are refused (`403`). The host must be permitted by the
//!   [`Allowlist`] and the port must be in [`ProxyPolicy::ports`].
//! - The `Host` header must name the request target's host and port. It is
//!   required for `http://` requests and checked whenever it is present on
//!   `CONNECT`; more than one `Host` header is refused.
//! - Names are resolved by robigus on the host. If any resolved address is not
//!   a public unicast address — loopback, unspecified, private, shared,
//!   link-local (including cloud metadata endpoints), unique-local, multicast
//!   or broadcast — the request is refused, so an allowlisted name cannot be
//!   pointed at services on the host or its network. Addresses pinned in
//!   [`ProxyPolicy::resolve`] are trusted and used as given.
//! - For `CONNECT`, robigus connects upstream before answering `200`, so
//!   connection failures are reported as `502`/`504`. The tunnel must then
//!   begin with a well-formed TLS ClientHello whose server name (SNI) is the
//!   `CONNECT` host. A ClientHello without a host-name SNI, with a different
//!   SNI, or bytes that are not a ClientHello close the tunnel before any
//!   client byte is forwarded. TLS is never intercepted: after the check the
//!   bytes are relayed unchanged, so the client verifies the server's
//!   certificate end to end.
//! - Plain HTTP requests are forwarded in origin form with a rebuilt `Host`
//!   header, `Connection: close`, and without hop-by-hop or `Proxy-*`
//!   headers. Exactly one request is served per connection; anything else the
//!   client sends on it is discarded.
//!
//! Every request is recorded as JSON lines in `proxy.jsonl` in the
//! invocation's log directory — a `request` record with the decision and
//! reason, and for forwarded requests a `close` record with byte counts — and
//! is emitted as a `tracing` event with target `robigus::proxy`.
//!
//! Residual risk: inside a TLS tunnel the HTTP `Host` header is encrypted and
//! cannot be checked without interception, so a client could address another
//! site served by the same allowlisted endpoint (domain fronting). Encrypted
//! ClientHello works only if its outer server name is the `CONNECT` host.

mod policy;
mod server;
mod tls;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

pub use policy::{Allowlist, DEFAULT_ALLOWLIST, HostName, ProxyPolicy};
pub(crate) use server::{ProxyLog, check_listener, serve};

/// A running proxy for one execution. Dropping it aborts every connection;
/// [`ProxyTask::finish`] lets connections in progress complete first.
#[derive(Debug)]
pub(crate) struct ProxyTask {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl ProxyTask {
    /// Starts serving `listener` on the current runtime.
    pub(crate) fn spawn(
        listener: tokio::net::TcpListener,
        policy: std::sync::Arc<ProxyPolicy>,
        log: std::sync::Arc<ProxyLog>,
    ) -> Self {
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        Self {
            shutdown: Some(shutdown),
            handle: tokio::spawn(serve(listener, policy, log, receiver)),
        }
    }

    /// Stops accepting and waits up to `grace` for connections in progress
    /// (normally ending as soon as the sandbox's sockets close), then aborts
    /// the rest.
    pub(crate) async fn finish(mut self, grace: std::time::Duration) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = tokio::time::timeout(grace, &mut self.handle).await;
    }
}

impl Drop for ProxyTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Address of the proxy inside every network-enabled sandbox.
pub const SANDBOX_PROXY_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3128));

/// Proxy URL placed in the sandbox's proxy environment variables.
pub const SANDBOX_PROXY_URL: &str = "http://127.0.0.1:3128";
