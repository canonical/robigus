//! Bounded inspection of the TLS ClientHello that opens a `CONNECT` tunnel.
//!
//! Only the record and handshake framing and the ClientHello extensions are
//! parsed; nothing is decrypted and no TLS state is kept. Every length is
//! checked against its enclosing structure, so malformed input is an error,
//! never a panic or an out-of-bounds read.

/// Largest ClientHello handshake body the proxy buffers before deciding.
pub(super) const MAX_CLIENT_HELLO: usize = 64 * 1024;
/// Largest TLS plaintext record fragment (RFC 8446 §5.1).
const MAX_FRAGMENT: usize = 1 << 14;
const RECORD_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: u16 = 0;
const NAME_TYPE_HOST: u8 = 0;

/// Result of feeding the bytes received so far.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Inspection {
    /// More bytes are needed to finish the ClientHello.
    Incomplete,
    /// A complete ClientHello; the SNI host name, if any, verbatim.
    ClientHello { server_name: Option<String> },
}

/// Why the opening bytes are not an acceptable ClientHello.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Malformed(pub(super) &'static str);

/// Inspects the opening bytes of a tunnel. `bytes` must start at the first
/// byte the client sent after the `CONNECT` exchange.
pub(super) fn inspect(bytes: &[u8]) -> Result<Inspection, Malformed> {
    // A ClientHello can span several records (RFC 8446 §5.1); concatenate
    // their fragments until the handshake message is complete.
    let mut handshake = Vec::new();
    let mut rest = bytes;
    loop {
        if let Some(body) = complete_handshake(&handshake)? {
            return client_hello(body).map(|server_name| Inspection::ClientHello { server_name });
        }
        if rest.len() < 5 {
            return Ok(Inspection::Incomplete);
        }
        if rest[0] != RECORD_HANDSHAKE {
            return Err(Malformed(
                "tunnel did not start with a TLS handshake record",
            ));
        }
        // Legacy record version: 0x0301..=0x0304 in practice; only the major
        // byte is fixed.
        if rest[1] != 3 {
            return Err(Malformed("unsupported TLS record version"));
        }
        let length = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        if length == 0 || length > MAX_FRAGMENT {
            return Err(Malformed("invalid TLS record length"));
        }
        if rest.len() < 5 + length {
            return Ok(Inspection::Incomplete);
        }
        handshake.extend_from_slice(&rest[5..5 + length]);
        rest = &rest[5 + length..];
    }
}

/// Returns the ClientHello body once the handshake header and body are
/// present.
fn complete_handshake(handshake: &[u8]) -> Result<Option<&[u8]>, Malformed> {
    if handshake.len() < 4 {
        return Ok(None);
    }
    if handshake[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(Malformed("first handshake message is not a ClientHello"));
    }
    let length = (usize::from(handshake[1]) << 16)
        | (usize::from(handshake[2]) << 8)
        | usize::from(handshake[3]);
    if length > MAX_CLIENT_HELLO {
        return Err(Malformed("ClientHello is too large"));
    }
    if handshake.len() < 4 + length {
        return Ok(None);
    }
    if handshake.len() > 4 + length {
        // The ClientHello must be the only message in its flight.
        return Err(Malformed("unexpected data after the ClientHello"));
    }
    Ok(Some(&handshake[4..]))
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Malformed> {
        if self.bytes.len() < count {
            return Err(Malformed("truncated ClientHello"));
        }
        let (head, tail) = self.bytes.split_at(count);
        self.bytes = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Malformed> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], Malformed> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    fn vec16(&mut self) -> Result<&'a [u8], Malformed> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

/// Parses a ClientHello body (RFC 8446 §4.1.2) and returns its SNI name.
fn client_hello(body: &[u8]) -> Result<Option<String>, Malformed> {
    let mut hello = Reader { bytes: body };
    hello.take(2)?; // legacy_version
    hello.take(32)?; // random
    let session_id = hello.vec8()?;
    if session_id.len() > 32 {
        return Err(Malformed("invalid ClientHello session id"));
    }
    let suites = hello.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(Malformed("invalid ClientHello cipher suites"));
    }
    if hello.vec8()?.is_empty() {
        return Err(Malformed("ClientHello has no compression methods"));
    }
    if hello.bytes.is_empty() {
        // Extensions are optional before TLS 1.3; without them there is no SNI.
        return Ok(None);
    }
    let mut extensions = Reader {
        bytes: hello.vec16()?,
    };
    if !hello.bytes.is_empty() {
        return Err(Malformed("unexpected data after ClientHello extensions"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut server_name = None;
    while !extensions.bytes.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        if !seen.insert(kind) {
            return Err(Malformed("duplicate ClientHello extension"));
        }
        if kind == EXTENSION_SERVER_NAME {
            server_name = Some(sni(data)?);
        }
    }
    Ok(server_name)
}

/// Parses a `server_name` extension (RFC 6066 §3), which must carry exactly
/// one host name.
fn sni(data: &[u8]) -> Result<String, Malformed> {
    let mut extension = Reader { bytes: data };
    let mut list = Reader {
        bytes: extension.vec16()?,
    };
    if !extension.bytes.is_empty() {
        return Err(Malformed("unexpected data after the server name list"));
    }
    let mut host = None;
    while !list.bytes.is_empty() {
        let kind = list.u8()?;
        let name = list.vec16()?;
        if kind != NAME_TYPE_HOST {
            return Err(Malformed("unsupported server name type"));
        }
        if host.is_some() {
            return Err(Malformed("more than one server name"));
        }
        let name = std::str::from_utf8(name)
            .ok()
            .filter(|name| !name.is_empty() && name.is_ascii())
            .ok_or(Malformed("server name is not an ASCII host name"))?;
        host = Some(name.to_owned());
    }
    host.ok_or(Malformed("empty server name list"))
}

/// Test helpers that build ClientHello records.
#[cfg(test)]
pub(super) mod build {
    fn vec16(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// The `server_name` extension body for the given names.
    pub(in crate::sandbox::proxy) fn sni_extension(names: &[&str]) -> Vec<u8> {
        let mut list = Vec::new();
        for name in names {
            list.push(0);
            list.extend(vec16(name.as_bytes()));
        }
        vec16(&list)
    }

    /// A ClientHello body with the given extensions (`None` omits the block).
    pub(in crate::sandbox::proxy) fn hello_body(extensions: Option<&[(u16, Vec<u8>)]>) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0x11; 32]);
        body.push(0); // empty session id
        body.extend(vec16(&[0x13, 0x01]));
        body.extend([1, 0]); // null compression
        if let Some(extensions) = extensions {
            let mut block = Vec::new();
            for (kind, data) in extensions {
                block.extend(kind.to_be_bytes());
                block.extend(vec16(data));
            }
            body.extend(vec16(&block));
        }
        body
    }

    /// Wraps a ClientHello body in a handshake header and `records` records.
    pub(in crate::sandbox::proxy) fn records(body: &[u8], records: usize) -> Vec<u8> {
        let mut handshake = vec![1];
        handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(body);
        let chunk = handshake.len().div_ceil(records.max(1));
        let mut out = Vec::new();
        for part in handshake.chunks(chunk) {
            out.extend([22, 3, 1]);
            out.extend(vec16(part));
        }
        out
    }

    /// A complete single-record ClientHello for `name`.
    pub(in crate::sandbox::proxy) fn hello_for(name: &str) -> Vec<u8> {
        records(&hello_body(Some(&[(0, sni_extension(&[name]))])), 1)
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    fn named(name: &str) -> Result<Inspection, Malformed> {
        Ok(Inspection::ClientHello {
            server_name: Some(name.into()),
        })
    }

    #[test]
    fn extracts_sni_from_complete_and_fragmented_hellos() {
        let hello = hello_for("index.crates.io");
        assert_eq!(inspect(&hello), named("index.crates.io"));
        for cut in [0, 1, 4, 5, 9, hello.len() - 1] {
            assert_eq!(inspect(&hello[..cut]), Ok(Inspection::Incomplete), "{cut}");
        }
        let body = hello_body(Some(&[
            (10, vec![0, 2, 0, 29]),
            (0, sni_extension(&["static.crates.io"])),
        ]));
        let split = records(&body, 3);
        assert_eq!(inspect(&split), named("static.crates.io"));
        assert_eq!(
            inspect(&split[..split.len() - 1]),
            Ok(Inspection::Incomplete)
        );
    }

    #[test]
    fn reports_missing_sni_without_failing() {
        let no_extensions = records(&hello_body(None), 1);
        let other_extensions = records(&hello_body(Some(&[(10, vec![0, 2, 0, 29])])), 1);
        for hello in [no_extensions, other_extensions] {
            assert_eq!(
                inspect(&hello),
                Ok(Inspection::ClientHello { server_name: None })
            );
        }
    }

    #[test]
    fn rejects_non_tls_and_malformed_hellos() {
        let mut cases: Vec<Vec<u8>> = vec![
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
            vec![23, 3, 3, 0, 1, 0], // application data
            vec![22, 2, 0, 0, 1, 1], // SSLv2-style version
            vec![22, 3, 1, 0, 0],    // empty record
            vec![22, 3, 1, 0x40, 1], // oversized record
        ];
        // A ServerHello instead of a ClientHello.
        let mut server_hello = hello_for("a.example");
        server_hello[5] = 2;
        cases.push(server_hello);
        // Two server names, a non-host name type, and an empty list.
        for extension in [
            sni_extension(&["a.example", "b.example"]),
            {
                let mut ext = sni_extension(&["a.example"]);
                ext[2] = 1;
                ext
            },
            vec![0, 0],
            sni_extension(&["caf\u{e9}.example"]),
        ] {
            cases.push(records(&hello_body(Some(&[(0, extension)])), 1));
        }
        // A duplicated extension, and an extension length past its block.
        cases.push(records(
            &hello_body(Some(&[(0, sni_extension(&["a.example"])), (0, vec![])])),
            1,
        ));
        let mut overrun = hello_for("a.example");
        let last = overrun.len() - 1;
        overrun[last - "a.example".len() - 2] = 0xff;
        cases.push(overrun);
        // Trailing data after the ClientHello in the same flight.
        let mut trailing = hello_body(Some(&[(0, sni_extension(&["a.example"]))]));
        let declared = trailing.len();
        trailing.extend([0, 0, 0, 0]);
        let mut message = vec![1];
        message.extend(&(declared as u32).to_be_bytes()[1..]);
        message.extend(&trailing);
        let mut record = vec![22, 3, 1];
        record.extend((message.len() as u16).to_be_bytes());
        record.extend(message);
        cases.push(record);
        for case in cases {
            assert!(inspect(&case).is_err(), "accepted {case:?}");
        }
    }

    #[test]
    fn bounds_the_handshake_size() {
        let mut header = vec![22, 3, 1, 0, 4, 1];
        header.extend(&((MAX_CLIENT_HELLO + 1) as u32).to_be_bytes()[1..]);
        assert!(inspect(&header).is_err());
    }

    #[test]
    fn never_panics_on_truncations_of_valid_input() {
        let body = hello_body(Some(&[
            (0, sni_extension(&["index.crates.io"])),
            (43, vec![2, 3, 4]),
        ]));
        let hello = records(&body, 2);
        for cut in 0..hello.len() {
            let _ = inspect(&hello[..cut]);
            let mut corrupted = hello.clone();
            corrupted[cut] ^= 0xff;
            let _ = inspect(&corrupted);
        }
    }
}
