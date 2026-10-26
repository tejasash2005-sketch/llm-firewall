# Release readiness notes

This is a checklist for maintainers preparing a public release. It records repository facts and
items that cannot be resolved from the source checkout alone.

## Reproducible checks

- `Cargo.lock` is present; use `--locked` for tests, checks, evaluation, and benchmarks.
- `.github/workflows/ci.yml` runs `cargo test --locked` and `cargo check --locked` on pushes,
  pull requests, and manual dispatch, on a GitHub-hosted Linux runner.
- The workflow is userspace-only. It does not load BPF objects or exercise kernel attachment,
  cleanup, or fail-closed enforcement.
- No CI result is asserted by the workflow definition itself. Confirm a real run after pushing
  the workflow before adding a passing badge or claiming CI status.
- The repository has no Git metadata in this checkout, so the workflow uses an unfiltered push
  trigger rather than guessing the configured default branch.
- No formatting job is configured: the existing Rust source does not pass whole-project
  `cargo fmt --check` without unrelated formatting changes.

## Evaluation and benchmark artifacts

- Keep `evaluation/scanner-corpus.csv` and `evaluation/report.json` with the repository. The
  corpus is synthetic; the report records metrics and example IDs, not input text.
- Run scanner evaluation with the command in the README and review the report before changing
  detection rules.
- Run the release benchmark with `cargo run --release --locked -- --benchmark` on the same
  environment when comparing revisions. It prints local measurements but does not persist them.
  No numeric benchmark output is stored in this checkout; do not invent or infer measurements
  from the synthetic scanner evaluation report.
- Benchmark output covers scanner, body masking, JSON restoration, and SSE restoration. It is
  not end-to-end TLS, proxy, network, or eBPF performance.

## Licensing review still required

- `Cargo.toml` declares `Apache-2.0`, but this checkout has no `LICENSE` file or copyright owner
  notice. Obtain confirmation from the rights holder and add the appropriate license text and
  notices before publication. No copyright holder has been inferred here.
- `firewall_kernel.bpf.c` sets the BPF object license string to `GPL`, which is relevant to
  kernel helper availability. It does not by itself establish the repository's source license.
  Have the rights holder review the intended relationship between project licensing and this
  kernel-facing component before release.
- `Cargo.lock` pins the dependency graph. A complete third-party license inventory or notices
  file is not present. The local offline Cargo metadata command could not complete because
  `core-foundation v0.9.4` was not cached; no dependency license report was generated. Run a
  dependency license review in an environment with the complete lockfile graph available.
- No new dependency was added for CI or documentation work in this batch.

## Repository hygiene and security review

- `.gitignore` excludes `target/`, `ca/`, compiled BPF objects, the temporary toolchain directory,
  common environment files, and common private-key container extensions. `evaluation/report.json`
  remains eligible for tracking.
- The local `ca/` directory in this checkout contains a private CA key and certificate but is
  ignored. Verify with `git status` in the actual Git repository before publishing; never force-add
  the local CA key or private configuration.
- `step1-cargo-test.log` and `step1-make-test.log` are present at the workspace root. They were
  left untouched; decide in the actual repository whether they are useful evidence or should be
  excluded from the release commit.
- `SECURITY.md` gives private reporting guidance but no verified monitored contact is available
  in this checkout. Enable GitHub private vulnerability reporting or add a monitored contact
  before publication.
- Review README's optional provider smoke test carefully. It makes a real provider request and
  can incur charges; it is not part of CI or automated tests.

## Platform validation

Before relying on transparent mode, validate object loading, both cgroup attachments, partial
attachment cleanup, shutdown, restart, and direct-egress policy on the intended privileged Linux
kernel. Current user-provided verification covers 45 userspace tests, `cargo check --locked`, and
execution of the synthetic release benchmark only. It does not establish privileged eBPF
behavior.
