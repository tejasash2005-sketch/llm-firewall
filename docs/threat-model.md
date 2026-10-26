# Threat model and deployment assumptions

## Security goal

`llm-firewall` scans supported HTTP request body content sent through the proxy and replaces
recognized values with per-session placeholders before forwarding the request. It restores
those values in supported JSON and server-sent-event response fields so the local client can
continue to use the original values.

This is a local mitigation for accidental prompt disclosure. It is not a guarantee that
sensitive information cannot leave a machine or reach a provider.

## Data flow and trust boundaries

1. A client is configured to use the explicit HTTP proxy, or its TCP/443 connect is redirected
   by the optional cgroup eBPF hooks for IPs present in the daemon's target maps.
2. The client TLS connection terminates at the proxy. The client must trust the local CA
   certificate. The CA private key can issue certificates accepted by those clients.
3. The proxy reads supported request bodies, applies built-in scanner rules and configured
   deny-terms, and replaces findings with placeholders held in session memory.
4. The proxy establishes upstream TLS using bundled Mozilla roots. It forwards the request body
   with placeholders. HTTP headers and URLs are not scanned; provider authentication headers are
   sent upstream unchanged.
5. The proxy restores known placeholders in supported JSON and SSE response fields, then returns
   the response to the client.

The proxy, its process account, local filesystem, CA key, client trust configuration, and the
provider connection are separate trust boundaries. Anyone who can read the CA private key can
impersonate sites to clients that trust that CA. Anyone with process-level access can inspect
request contents and in-memory restoration mappings while they are active.

## In scope

- Accidental exposure of recognized secrets and PII located in supported request body content.
- Correct handling of placeholders and restoration mappings within a proxy session.
- Local request/response handling, including supported streaming formats.
- Avoiding content values in normal application logs, as covered by current tests.

## Out of scope and limitations

- Unknown, changed, obfuscated, encoded, or unsupported secret formats; scanner detection is
  heuristic and can have false positives and false negatives.
- Secrets in headers, URLs, query parameters, unsupported or unscannable bodies when
  `--block-unscannable` is disabled, and data sent outside this proxy.
- Malicious or compromised proxy hosts, operating systems, users with local process privileges,
  clients that do not trust the expected CA, provider-side retention, or endpoint compromise.
- Generic HTTPS tunneling. The explicit proxy validates CONNECT/SNI hosts against its allow-list.
- Certificate pinning, HTTP versions other than HTTP/1.1, compressed request bodies, and complete
  semantic support for every provider response format.
- Complete prevention of direct egress in transparent mode. The eBPF hooks redirect only
  allow-listed IPs populated from daemon DNS resolution. Missing/stale map entries and DNS
  differences can allow bypass. The hooks return allow for missing configuration or target
  entries. A daemon or eBPF task failure can detach hooks and permit direct egress.
- Kernel attachment, cleanup, fail-closed enforcement, or audit completeness as verified
  guarantees. Userspace tests do not load privileged eBPF programs.

## Required deployment assumptions

- Keep `ca/llm-firewall-ca.key` readable only by the trusted service account; generated mode is
  0600. Do not distribute it with the public source or install it on clients that do not need
  interception.
- Protect the host and daemon process. Avoid untrusted local users who can read process memory,
  alter configuration, or access the CA key.
- Use a host firewall or other external egress control that denies direct provider egress when
  transparent-mode bypass must be prevented. The project's eBPF mode is fail-open and does not
  replace this control.
- Use explicit proxy mode only for clients that are configured to send traffic through it; it
  cannot control clients that ignore proxy settings.
- Treat synthetic scanner evaluation as regression evidence for the supplied corpus only. It is
  not a measure of real-world accuracy.
- Verify eBPF loading, attachment, cleanup, kernel support, and service restart policy on the
  intended privileged Linux host before relying on transparent mode. Current unit and CI tests
  do not establish those properties.
