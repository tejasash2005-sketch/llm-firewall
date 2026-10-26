# LLM Data Leakage Firewall

A local TLS-intercepting proxy that masks recognized secrets and PII in supported request
bodies sent to LLM APIs and restores them in responses. Detection is heuristic; headers and URLs
are not scanned, and this does not guarantee that sensitive data cannot reach a provider.

```
client ──TLS──▶ [ llm-firewall ] ──TLS──▶ api.openai.com / api.anthropic.com
                 │ mask request body        (webpki roots only, never the local CA)
                 │ [AWS_ACCESS_KEY_3fa9c1d2]
client ◀──TLS── │ de-tokenize SSE / JSON responses (placeholders split across events handled)
```

## Status

This is an early-stage implementation. The userspace suite has passed in Linux Docker (45 tests),
`cargo check --locked` has passed, and the release benchmark command has executed. The benchmark
prints machine-specific synthetic measurements, but no numeric run output is stored in this
repository. These checks do not verify privileged eBPF loading, attachment, cleanup, or enforcement.
The GitHub Actions workflow runs userspace tests and compilation checks; a passing CI badge should
only be added after an actual workflow run succeeds.

## Components

| File | Role |
|---|---|
| `firewall_kernel.bpf.c` | `cgroup/connect4` + `connect6` programs that redirect TCP/443 connections to allow-listed LLM IPs to the local proxy; `bpf_ringbuf` audit events; proxy PID exempt (no loops) |
| `src/kernel_loader.rs` | Aya loader: attaches hooks, seeds/refreshes target IP maps from DNS, drains the ring buffer asynchronously |
| `src/tls.rs` | Local root CA (key mode 0600) and per-host leaf certificate minting (cached) |
| `src/scanner.rs` | Aho-Corasick prefix prefilter + anchored regex confirmation, entropy rule, Luhn-checked cards, deny-terms; overlap resolution |
| `src/state.rs` | `dashmap` session registry; placeholders = truncated SHA-256(salt‖value); raw values zeroized on drop |
| `src/stream.rs` | SSE framing across arbitrary TCP fragments; per-field streaming detokenizer for OpenAI chat, Anthropic, Responses API deltas; JSON-escaped restoration for tool-call arguments |
| `src/proxy.rs` | tokio/hyper accept loop: transparent TLS + explicit `CONNECT`; request masking; response restoration |
| `src/main.rs` | CLI, wiring, graceful shutdown |

Why eBPF does **not** inspect payloads: `tc`/`sockops` hooks only see TLS ciphertext, and an
`SSL_write` uprobe can read but not safely rewrite plaintext. The kernel layer therefore does
transparent redirection and auditing; decryption and masking happen in the proxy.

## Build

Requirements: Linux, Rust 1.88+, clang with the BPF target, and libbpf headers (`libbpf-dev`) for
eBPF mode. The eBPF ring buffer requires Linux 5.8 or newer and the loader attaches cgroup socket
address hooks to a cgroup v2 directory. The Makefile maps x86_64 and aarch64 hosts to the
`x86` and `arm64` BPF target defines. The current binary uses Unix-specific signal,
file-permission, and async file-descriptor APIs, so Windows is not a supported build target. Root
or equivalent BPF and networking capabilities are needed only for eBPF mode.

```bash
cargo build --release --locked # explicit proxy binary; no eBPF object required
cargo test --locked         # userspace unit and local/mock integration tests
cargo check --locked
```

For eBPF mode, install clang/LLVM with a BPF target, libbpf headers, and `make` (for Debian or
Ubuntu, the packages are commonly `clang llvm libbpf-dev make`). Then run `make`, which compiles
`firewall_kernel.bpf.o` before building the release binary. The default Makefile target is
architecture-specific; use `__TARGET_ARCH_arm64` for AArch64 as documented in the Makefile.
Transparent mode additionally needs Linux, cgroup v2, kernel ring-buffer support (Linux 5.8+),
and sufficient BPF/networking privileges. These requirements do not apply to explicit proxy mode.

The Rust proxy integration test uses a locally generated CA and an in-process TLS mock upstream.
It uses synthetic values only and does not contact an LLM provider. It checks request masking,
response restoration, streaming restoration, and that benign JSON is forwarded unchanged.
Stream framing and interrupted/partial stream cases also have unit coverage. These tests require
no paid services or credentials; after dependencies are available they can run without provider
network access.

The GitHub Actions workflow at `.github/workflows/ci.yml` runs these userspace tests and
`cargo check --locked` on GitHub-hosted Linux runners. It does not load or attach eBPF programs.
The repository's Git metadata is not present in this checkout, so CI runs on pushes to all
branches rather than assuming a default branch name.

### Scanner evaluation

The labeled scanner corpus is `evaluation/scanner-corpus.csv`. Its columns are `id`, `text`, and
pipe-delimited `expected_kinds`; an empty label marks benign input. The synthetic fixtures exercise
all built-in detection kinds with positive, negative, boundary, code, environment-file, and log
examples. The one-character email suffix case records a regex boundary only; it does not assert
that such a domain is deliverable. Reports contain counts and false-positive/false-negative example
IDs, never input text. Per-kind counts use one binary decision per example and kind, so repeated
occurrences in one example do not increase corpus-level counts. The aggregate micro score sums
those decisions across kinds; macro precision and recall average defined per-kind rates and skip
undefined rates. These synthetic results describe this supplied test set only and do not imply
real-world accuracy. Evaluation is separate from `cargo test`. The checked-in generated report
records 87 examples across 17 detection kinds: micro TP=64, FP=0, FN=0, TN=1415, precision=1.0,
recall=1.0; macro precision and recall are also 1.0. These figures apply only to the supplied
synthetic corpus and its expected labels.

Run it from PowerShell with Docker Desktop's Linux engine available:

```powershell
docker run --rm -v "${PWD}:/work" -w /work rust:1.88-bookworm bash -lc "cargo run --locked -- --evaluate-csv evaluation/scanner-corpus.csv --evaluation-report evaluation/report.json"
```

The command prints the machine-readable JSON report and saves it to
`evaluation/report.json`. To run the ordinary Linux checks in Docker, use:

```powershell
docker run --rm -v "${PWD}:/work" -w /work rust:1.88-bookworm bash -lc "cargo test --locked && cargo check --locked"
```

### Local performance benchmark

The standalone benchmark uses only deterministic synthetic strings and the in-process scanner,
masking, JSON restoration, and SSE restoration code. It is separate from `cargo test` and makes
no network or provider calls. From PowerShell with Docker Desktop's Linux engine available, run:

```powershell
docker run --rm -v "${PWD}:/work" -w /work rust:1.88-bookworm bash -lc "cargo run --release --locked -- --benchmark"
```

The benchmark prints input bytes, iteration count, warm-up policy, aggregate elapsed time,
operations per second, input MiB per second, and mean microseconds per operation. Scanner and
masking workloads cover 128 B, 4 KiB, and 64 KiB inputs with no finding, one synthetic AWS key,
and two distinct synthetic keys. Restoration includes a JSON response with two placeholders and
SSE delta events whose placeholder is split across events and each event is split at a fixed
network-chunk boundary. Results are local baseline measurements for that machine and build; there
are no timing thresholds, percentile claims, or end-to-end TLS/proxy latency measurements. The
command does not save output automatically, and no numeric benchmark output is currently checked
in. To save exact output in PowerShell, pipe the Docker command through
`Tee-Object -FilePath "$env:TEMP\llm-firewall-benchmark.txt"`. Compare repeated runs in the same
release container rather than treating one noisy run as a regression.

Manual equivalent:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(uname -m)-linux-gnu \
      -c firewall_kernel.bpf.c -o firewall_kernel.bpf.o     # use __TARGET_ARCH_arm64 on ARM
cargo build --release --locked
```

## Run

### A. Explicit proxy (no root, most robust)

```bash
./target/release/llm-firewall --deny-term "Project Falcon"
```

In the shell that runs your tool:

```bash
export HTTPS_PROXY=http://127.0.0.1:8443
export NODE_EXTRA_CA_CERTS=$PWD/ca/llm-firewall-ca.pem   # Node / Claude Code / Codex CLIs
export SSL_CERT_FILE=$PWD/ca/llm-firewall-ca.pem         # Python (httpx), curl, Go, OpenSSL
export REQUESTS_CA_BUNDLE=$PWD/ca/llm-firewall-ca.pem    # Python requests
```

### B. Transparent mode (root; redirects matching connections under the cgroup)

```bash
sudo ./target/release/llm-firewall --bpf-object ./firewall_kernel.bpf.o
# optionally restrict to one cgroup:  --cgroup /sys/fs/cgroup/user.slice
```

Clients still need to trust the CA, but no proxy variables are required. This mode only redirects
TCP/443 connects to destination IPs currently present in the eBPF target maps; it does not cover
arbitrary hosts or prevent direct egress when a target is missing.

### Optional provider smoke test

This sends a real request to the provider and may incur provider charges. It is not part of CI or
the local/mock test suite. Use only a test account and synthetic prompt data.

```bash
curl -sS https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user",
       "content":"Repeat this exactly: AKIAIOSFODNN7EXAMPLE and postgres://u:p@db.local/x"}]}'
```

With `RUST_LOG=debug` the proxy logs counts only, never values. The model sees placeholders;
the reply you receive contains the originals.

## CLI

`--listen`, `--ca-dir`, `--allow-host` (repeatable), `--deny-term` (repeatable), `--max-body-mib`,
`--session-ttl-secs`, `--upstream-timeout-secs`, `--max-connections`, `--block-unscannable`,
`--bpf-object`, `--cgroup`, `--target-refresh-secs`. See `--help`.

## Security notes and limitations

See [the threat model](docs/threat-model.md) for data flow, trust boundaries, deployment
assumptions, and out-of-scope threats. For vulnerability reports, follow [SECURITY.md](SECURITY.md).

- Whoever holds `ca/llm-firewall-ca.key` can impersonate any site to clients that trust the CA.
  Keep it private, back it up only in protected storage, and rotate it by stopping the proxy,
  replacing the CA key and certificate, and reinstalling the new certificate in each client.
  `.gitignore` excludes `ca/`; this does not remove an already tracked key from Git history.
- Transparent mode redirects only IPs the proxy resolved itself. CDN-fronted hosts may resolve
  differently for clients, which means **bypass is possible** (fail-open). Use explicit proxy mode
  or a firewall rule that denies direct 443 egress when you need a guarantee.
- If the daemon crashes or its eBPF task returns an error or panics, cgroup hooks detach and
  traffic can flow directly (fail-open). The daemon monitors the task and stops proxy acceptance
  after detecting its exit, but that response cannot prevent direct egress after hook detachment.
  A hung task is not detected by a heartbeat, and stale or missing target-map entries also allow
  direct connections. A heartbeat map plus pinned links or an external egress-deny firewall
  policy is required for fail-closed enforcement; neither is implemented here. Do not use
  transparent mode where bypass must be impossible without that external enforcement.
- Redirect audit events use a bounded 1 MiB ring buffer. If a reservation fails, the BPF program
  increments a per-CPU drop counter and continues the redirect unchanged; the userspace loader
  periodically reports the observed count. This is not a complete audit guarantee: counter-read
  failures, malformed records, and events still queued when the process exits can make reported
  counts incomplete. Ring-buffer loss never changes the redirect decision.
- Transparent mode refuses non-allow-listed SNIs (the original destination is not preserved).
- The eBPF and daemon failure behavior, including unverified kernel-specific cases, is recorded in
  [the failure-mode matrix](docs/failure-mode-matrix.md).
- HTTP/1.1 only; compressed request bodies and malformed JSON declared as JSON are rejected.
  Request bodies are size-limited and must arrive within 30 seconds. Binary and unsupported
  content types pass through with a warning unless `--block-unscannable` is set. Enable that
  flag when every request body must be inspectable.
- Explicit proxy mode rejects non-allow-listed CONNECT targets. It does not create a generic
  tunnel. The allow-list applies to the TLS SNI (or CONNECT authority when SNI is absent).
- Only request bodies are scanned. Headers and URLs are untouched because they carry your real
  provider credentials.
- Detection is heuristic. API key prefixes and formats can change; entropy-based assignments,
  emails, phone numbers, SSNs, and Luhn-valid card numbers can have false positives and misses.
  Names and project terms are only caught via `--deny-term`; there is no ML NER. This is not a
  substitute for preventing secrets from entering prompts.
- Each client TLS session retains at most 8,192 distinct restoration mappings. Further detected
  values are sent as `[KIND_REDACTED]` and cannot be restored in the response; this bounds the
  session map rather than allowing it to grow without limit on a long-lived connection.
- Certificate-pinning clients will not work through the interception.

## Roadmap

1. Labeled secrets/PII corpus with precision/recall report (initial evaluation harness available).
2. p50/p99 added-latency and throughput benchmarks (publish only measured numbers).
3. Fail-safe mode: heartbeat map, pinned links, configurable fail-open/closed.
4. Optional detect-only `SSL_write` uprobe audit mode for clients that cannot be proxied.
5. Pluggable NER detector behind a trait.

## License

`Cargo.toml` declares Apache-2.0. This checkout does not contain a `LICENSE` file or a copyright
owner notice. Before public release, the rights holder should confirm the intended license and
add its license text and notices. The eBPF object also declares `GPL` in its BPF license section;
that kernel compatibility marker is not a repository-wide license statement. Third-party
dependency license metadata has not been audited into a notice file; see the release checklist
in [docs/release-readiness.md](docs/release-readiness.md).
