//! Host names, the allowlist, and the per-execution proxy policy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use crate::error::InvalidHost;

/// Hosts allowed by default, each including all of its subdomains (spec
/// §10.2, decision 9).
pub const DEFAULT_ALLOWLIST: [&str; 5] = [
    "crates.io",
    "ubuntu.com",
    "github.com",
    "gitlab.com",
    "codeberg.org",
];

/// A literal DNS host name: ASCII letters, digits and hyphens in dot-separated
/// labels, normalized to lowercase without a trailing dot.
///
/// URLs, ports, wildcards and IP addresses are rejected. The last label must
/// start with a letter, which excludes every numeric form a resolver might
/// interpret as an IP address. Internationalized names must be given in their
/// ASCII (`xn--`) form.
///
/// # Examples
///
/// ```
/// use robigus::HostName;
///
/// let host: HostName = "Index.Crates.IO.".parse()?;
/// assert_eq!(host.as_str(), "index.crates.io");
/// assert!(host.is_within(&"crates.io".parse()?));
/// assert!(!host.is_within(&"rates.io".parse()?));
///
/// for invalid in ["https://crates.io", "*.crates.io", "crates.io:443", "127.0.0.1"] {
///     assert!(invalid.parse::<HostName>().is_err());
/// }
/// # Ok::<(), robigus::InvalidHost>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);

impl HostName {
    /// The normalized name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this name is `domain` itself or one of its subdomains.
    pub fn is_within(&self, domain: &HostName) -> bool {
        match self.0.strip_suffix(&domain.0) {
            Some("") => true,
            Some(prefix) => prefix.ends_with('.'),
            None => false,
        }
    }
}

impl FromStr for HostName {
    type Err = InvalidHost;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let invalid = |reason| InvalidHost {
            host: input.chars().take(256).collect(),
            reason,
        };
        let host = input.strip_suffix('.').unwrap_or(input);
        if host.is_empty() {
            return Err(invalid("is empty"));
        }
        if host.len() > 253 {
            return Err(invalid("is longer than 253 characters"));
        }
        for label in host.split('.') {
            if label.is_empty() {
                return Err(invalid("has an empty label"));
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(invalid(
                    "contains characters other than ASCII letters, digits, hyphens and dots",
                ));
            }
            if label.len() > 63 {
                return Err(invalid("has a label longer than 63 characters"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(invalid("has a label that starts or ends with a hyphen"));
            }
        }
        if !host
            .rsplit('.')
            .next()
            .is_some_and(|last| last.starts_with(|c: char| c.is_ascii_alphabetic()))
        {
            return Err(invalid(
                "is an IP address or numeric name (the last label must start with a letter)",
            ));
        }
        Ok(Self(host.to_ascii_lowercase()))
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which hosts sandboxed workloads may reach through the proxy.
///
/// Each entry covers the host and all of its subdomains. A host is permitted
/// when it is within an allowed entry and not within a denied one: denial
/// always wins. [`Allowlist::default`] allows [`DEFAULT_ALLOWLIST`].
///
/// # Examples
///
/// ```
/// use robigus::{Allowlist, HostName};
///
/// let mut allowlist = Allowlist::default();
/// allowlist.deny("gitlab.com".parse()?);
/// allowlist.allow("pypi.org".parse()?);
///
/// let permits = |host: &str| -> Result<bool, robigus::InvalidHost> {
///     Ok(allowlist.permits(&host.parse::<HostName>()?))
/// };
/// assert!(permits("index.crates.io")?);
/// assert!(permits("files.pypi.org")?);
/// assert!(!permits("gitlab.com")?);
/// assert!(!permits("example.org")?);
/// # Ok::<(), robigus::InvalidHost>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    allowed: BTreeSet<HostName>,
    denied: BTreeSet<HostName>,
}

impl Default for Allowlist {
    fn default() -> Self {
        Self {
            allowed: DEFAULT_ALLOWLIST
                .iter()
                .map(|host| HostName((*host).to_owned()))
                .collect(),
            denied: BTreeSet::new(),
        }
    }
}

impl Allowlist {
    /// An allowlist that permits nothing.
    pub fn empty() -> Self {
        Self {
            allowed: BTreeSet::new(),
            denied: BTreeSet::new(),
        }
    }

    /// Allows `host` and its subdomains (unless denied).
    pub fn allow(&mut self, host: HostName) {
        self.allowed.insert(host);
    }

    /// Denies `host` and its subdomains, overriding any allowed entry.
    pub fn deny(&mut self, host: HostName) {
        self.denied.insert(host);
    }

    /// The allowed entries.
    pub fn allowed(&self) -> &BTreeSet<HostName> {
        &self.allowed
    }

    /// The denied entries.
    pub fn denied(&self) -> &BTreeSet<HostName> {
        &self.denied
    }

    /// Whether requests to `host` may be forwarded.
    pub fn permits(&self, host: &HostName) -> bool {
        self.decide(host).is_ok()
    }

    pub(super) fn decide(&self, host: &HostName) -> Result<(), &'static str> {
        if self.denied.iter().any(|entry| host.is_within(entry)) {
            Err("host is denied by configuration")
        } else if self.allowed.iter().any(|entry| host.is_within(entry)) {
            Ok(())
        } else {
            Err("host is not on the allowlist")
        }
    }
}

/// Everything the proxy enforces for one sandboxed execution.
///
/// [`ProxyPolicy::default`] uses the default [`Allowlist`], ports 80 and 443,
/// 30-second header and connect timeouts, at most 64 concurrent connections,
/// and no pinned addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPolicy {
    /// Hosts that may be reached.
    pub allowlist: Allowlist,
    /// Upstream ports that may be reached; must be nonempty and exclude 0.
    pub ports: BTreeSet<u16>,
    /// Limit for receiving a request head and, for `CONNECT`, the TLS
    /// ClientHello; must be nonzero.
    pub header_timeout: Duration,
    /// Limit for resolving the host and connecting upstream; must be nonzero.
    pub connect_timeout: Duration,
    /// Most connections served at once; must be nonzero. Further connections
    /// wait to be accepted.
    pub max_connections: usize,
    /// Addresses to use instead of DNS for specific hosts, for example a
    /// pinned mirror or a test server. They are trusted: unlike resolved
    /// addresses they may be loopback or private. The port comes from the
    /// request. Pinning does not allow a host; it must still be allowlisted.
    pub resolve: BTreeMap<HostName, Vec<IpAddr>>,
}

impl Default for ProxyPolicy {
    fn default() -> Self {
        Self {
            allowlist: Allowlist::default(),
            ports: BTreeSet::from([80, 443]),
            header_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(30),
            max_connections: 64,
            resolve: BTreeMap::new(),
        }
    }
}

impl ProxyPolicy {
    /// Checks the limits documented on each field.
    pub fn validate(&self) -> Result<(), String> {
        if self.ports.is_empty() || self.ports.contains(&0) {
            return Err("proxy ports must be nonempty and exclude 0".into());
        }
        if self.header_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err("proxy timeouts must be nonzero".into());
        }
        if self.max_connections == 0 {
            return Err("proxy max_connections must be nonzero".into());
        }
        if let Some((host, _)) = self
            .resolve
            .iter()
            .find(|(_, addresses)| addresses.is_empty())
        {
            return Err(format!("proxy resolve entry for {host} has no addresses"));
        }
        Ok(())
    }
}

/// Whether `address` may be connected to after DNS resolution: only public
/// unicast addresses, so an allowlisted name cannot be pointed at the host,
/// its network, or cloud metadata services.
pub(super) fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || a >= 240
                // 100.64.0.0/10 shared address space (carrier-grade NAT).
                || (a == 100 && (64..128).contains(&b))
                // 192.0.0.0/24 IETF protocol assignments.
                || (a == 192 && b == 0 && v4.octets()[2] == 0)
                // 198.18.0.0/15 benchmarking.
                || (a == 198 && (b == 18 || b == 19)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                // fc00::/7 unique local, fe80::/10 link local, fec0::/10 site local.
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first & 0xffc0) == 0xfec0
                // 2001:db8::/32 documentation, 64:ff9b::/96 NAT64 (may embed a
                // private IPv4), ::/96 IPv4-compatible.
                || (first == 0x2001 && v6.segments()[1] == 0x0db8)
                || (first == 0x0064 && v6.segments()[1] == 0xff9b)
                || v6.segments()[..6] == [0; 6])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(text: &str) -> HostName {
        text.parse().unwrap()
    }

    #[test]
    fn host_names_are_literal_dns_names() {
        assert_eq!(host("CRATES.io.").as_str(), "crates.io");
        assert_eq!(host("a-1.b2.example").as_str(), "a-1.b2.example");
        assert_eq!(host("xn--caf-dma.example").as_str(), "xn--caf-dma.example");
        assert_eq!(host("localhost").as_str(), "localhost");
        let long_label = format!("{}.example", "a".repeat(64));
        let long_name = format!("{}.example", vec!["a".repeat(63); 4].join("."));
        for invalid in [
            "",
            ".",
            "a..b",
            ".example",
            "exa mple.org",
            "exa_mple.org",
            "café.example",
            "-a.example",
            "a-.example",
            "*.example",
            "example.org:443",
            "https://example.org",
            "user@example.org",
            "[::1]",
            "::1",
            "127.0.0.1",
            "127.1",
            "2130706433",
            "0x7f.1",
            "1.2.3.4.",
            "example.123",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(invalid.parse::<HostName>().is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn subdomain_matching_respects_label_boundaries() {
        let crates = host("crates.io");
        assert!(host("crates.io").is_within(&crates));
        assert!(host("index.crates.io").is_within(&crates));
        assert!(host("a.b.crates.io").is_within(&crates));
        assert!(!host("evilcrates.io").is_within(&crates));
        assert!(!host("crates.io.evil.example").is_within(&crates));
        assert!(!host("io").is_within(&crates));
    }

    #[test]
    fn denial_overrides_allowance() {
        let mut list = Allowlist::default();
        for allowed in [
            "crates.io",
            "static.crates.io",
            "archive.ubuntu.com",
            "codeload.github.com",
            "gitlab.com",
            "codeberg.org",
        ] {
            assert!(list.permits(&host(allowed)), "{allowed}");
        }
        for denied in [
            "example.org",
            "githubusercontent.com",
            "crates.io.evil.example",
        ] {
            assert!(!list.permits(&host(denied)), "{denied}");
        }
        list.deny(host("static.crates.io"));
        list.allow(host("cdn.static.crates.io"));
        assert!(list.permits(&host("index.crates.io")));
        assert!(!list.permits(&host("static.crates.io")));
        assert!(!list.permits(&host("cdn.static.crates.io")));
        assert!(!Allowlist::empty().permits(&host("crates.io")));
    }

    #[test]
    fn policy_validation() {
        assert!(ProxyPolicy::default().validate().is_ok());
        for change in [
            |p: &mut ProxyPolicy| p.ports.clear(),
            |p: &mut ProxyPolicy| {
                p.ports.insert(0);
            },
            |p: &mut ProxyPolicy| p.header_timeout = Duration::ZERO,
            |p: &mut ProxyPolicy| p.connect_timeout = Duration::ZERO,
            |p: &mut ProxyPolicy| p.max_connections = 0,
            |p: &mut ProxyPolicy| {
                p.resolve.insert("a.example".parse().unwrap(), Vec::new());
            },
        ] {
            let mut policy = ProxyPolicy::default();
            change(&mut policy);
            assert!(policy.validate().is_err());
        }
    }

    #[test]
    fn only_public_unicast_addresses_are_connectable() {
        for public in [
            "151.101.66.137",
            "1.1.1.1",
            "2a04:4e42::649",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for internal in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.0.8",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::a00:1",
        ] {
            assert!(!is_public(internal.parse().unwrap()), "{internal}");
        }
    }
}
