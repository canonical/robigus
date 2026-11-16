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

Known limitations that are **not** yet in scope:

- CPU, memory and process-count limits (planned for the native backend, WP-3.5).
- Allowlisted network egress, which is unavailable until the proxy lands (WP-2.1).
- The tool refuses to run as root; running it under other privileged configurations is unsupported.
- bubblewrap 0.11 or newer (Ubuntu 26.04 or later) is required for the read-only overlays; older versions, such as Ubuntu 24.04's 0.9.0, are rejected and no sandbox is established.

Exported JSON includes recorded tool arguments and environments. Treat exports as potentially sensitive.
