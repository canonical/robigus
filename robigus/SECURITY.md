# robigus Security Policy

This policy covers the `robigus` crate and its `tsp-analyzer` command-line tool. The repository-wide [`SECURITY.md`](../SECURITY.md) covers the other crates in this workspace.

robigus fetches and analyzes untrusted upstream source code. Vulnerabilities in source acquisition and extraction, the analysis sandbox, the SQLite store, or exported analysis data are in scope.

## Supported Versions

| Version | Supported |
|---|---|
| `main` (unreleased) | ✅ |

## Reporting a Vulnerability

Please do not open public GitHub issues for security vulnerabilities.

Report privately through [GitHub Private Vulnerability Reporting for robigus](https://github.com/canonical/robigus/security/advisories/new).

Please include:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce it, including the `tsp-analyzer` command and source, if applicable.
3. A proof of concept, if available.
4. Relevant configuration: kernel version, bubblewrap version, and whether unprivileged user namespaces are enabled.

You can expect an acknowledgment within 48 hours. We follow coordinated disclosure and will agree a disclosure date with you.

## Sandbox Scope

Project code executed during analysis runs in a bubblewrap sandbox: unprivileged user, mount, PID, network, IPC and UTS namespaces; private read-only overlays of the source and system runtime; a seccomp socket policy; and closure of inherited descriptors. Bypasses of this boundary are security vulnerabilities.

Network-enabled runs stay in their own network namespace. Egress is possible only through robigus's allowlisting forward proxy, whose listener is created inside the namespace and handed to robigus. The proxy enforces the host allowlist, allowed ports, `Host`/`CONNECT`/TLS SNI agreement, and refuses names that resolve to non-public addresses; TLS is relayed without interception. Reaching a host the policy forbids, or anything on the host or its network, is a security vulnerability.

Known limitations that are **not** yet in scope:

- CPU, memory and process-count limits (planned for the native backend, WP-3.5).
- Domain fronting: inside a TLS tunnel the encrypted HTTP `Host` header cannot be checked, so a client can address another site served by the same allowlisted endpoint.
- Exfiltration *to* allowlisted hosts (for example a public repository on an allowlisted forge) is not prevented; narrow the allowlist for untrusted analyses.
- Network-enabled runs need `/usr/bin/python3` on the host to bind the proxy listener inside the sandbox; without it they fail closed.
- The tool refuses to run as root; running it under other privileged configurations is unsupported.
- bubblewrap 0.11 or newer (Ubuntu 26.04 or later) is required for the read-only overlays; older versions, such as Ubuntu 24.04's 0.9.0, are rejected and no sandbox is established.

Exported JSON includes recorded tool arguments and environments. Treat exports as potentially sensitive.

## Registry Credentials

robigus can fetch crates from authenticated private registries (spec §7.2.2). Any of the following is a security vulnerability:

- a registry token sent to a host other than its registry's index or download host, sent over `http`, or forwarded on a cross-host redirect;
- a token appearing in the database, exports, `tool_invocation` records, proxy logs, `tracing` output, error messages, the process list, a core dump, or the sandbox;
- a token being sent over plain `http`, including through the library API (a registry with a credential source is refused over `http`);
- a pinned `--sha256` checksum returning a cached crate other than the one requested;
- robigus writing a token to disk, or reading tokens from Cargo's credentials file, Cargo configuration, or `CARGO_REGISTRIES_*` variables.

robigus does not store tokens. Each registry's token comes from one source configured in robigus's own configuration: an environment variable (for CI secret stores), a credential process using Cargo's credential provider protocol, or a token file that must be owned by you and have mode `0600`. Prefer a credential process or a CI secret store over a token file, use read-only tokens with the least privilege your registry offers, and rotate or revoke them at the registry; robigus has no `login` or `logout` commands. Public registries, including crates.io, never receive a token.

Known limitation: zeroing token memory is best effort. robigus zeroes every buffer it owns that holds token bytes, but the HTTP stack may copy the `Authorization` header into its own buffers. Core dumps are disabled before any token is read and robigus refuses to read a token if they cannot be disabled, so such copies cannot reach a core dump; a process able to read robigus's memory directly is out of scope.
