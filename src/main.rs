mod error;
mod benchmark;
mod kernel_loader;
mod proxy;
mod scanner;
mod state;
mod stream;
mod tls;

use std::{
    collections::HashSet, future::Future, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration,
};

use anyhow::{ensure, Context, Result};
use clap::Parser;
use tokio::{
    net::TcpListener,
    signal::unix::SignalKind,
    sync::{watch, Semaphore},
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    kernel_loader::{KernelConfig, KernelFirewall},
    proxy::{ProxyConfig, ProxyState},
    scanner::Scanner,
    state::SessionRegistry,
    tls::CertAuthority,
};

#[derive(Parser, Debug)]
#[command(
    name = "llm-firewall",
    version,
    about = "LLM Data Leakage Firewall: masks secrets/PII in prompts, restores them in responses"
)]
struct Cli {
    /// Run deterministic local scanner, masking, restoration, and streaming benchmarks.
    #[arg(long, conflicts_with_all = ["evaluate_csv", "evaluation_report"])]
    benchmark: bool,

    /// Evaluate the scanner against a labeled CSV corpus and write a JSON report.
    #[arg(long, value_name = "CSV")]
    evaluate_csv: Option<PathBuf>,

    /// Destination for the evaluation JSON report (required with --evaluate-csv).
    #[arg(long, value_name = "JSON")]
    evaluation_report: Option<PathBuf>,

    /// Address the interception proxy listens on.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,

    /// Directory holding (or receiving) the local root CA.
    #[arg(long, default_value = "./ca")]
    ca_dir: PathBuf,

    /// Hostnames to intercept (repeatable). Other CONNECT targets are refused.
    #[arg(
        long = "allow-host",
        default_values_t = ["api.openai.com".to_string(), "api.anthropic.com".to_string()]
    )]
    allow_host: Vec<String>,

    /// Literal terms to always mask, case-insensitive (names, code names). Repeatable.
    #[arg(long = "deny-term")]
    deny_term: Vec<String>,

    /// Maximum buffered request/response body size in MiB.
    #[arg(long, default_value_t = 32)]
    max_body_mib: usize,

    /// Idle time before a session's token map is discarded.
    #[arg(long, default_value_t = 900)]
    session_ttl_secs: u64,

    /// Timeout for upstream response headers.
    #[arg(long, default_value_t = 120)]
    upstream_timeout_secs: u64,

    #[arg(long, default_value_t = 1024)]
    max_connections: usize,

    /// Reject binary request bodies instead of forwarding them unscanned.
    #[arg(long)]
    block_unscannable: bool,

    /// Compiled eBPF object; enables transparent kernel-level redirection (requires root).
    #[arg(long)]
    bpf_object: Option<PathBuf>,

    /// cgroup v2 directory the eBPF programs attach to (all processes beneath it are covered).
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup: PathBuf,

    /// How often to re-resolve the allow-listed hosts into the kernel target maps.
    #[arg(long, default_value_t = 300)]
    target_refresh_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match (&cli.evaluate_csv, &cli.evaluation_report) {
        (Some(input), Some(output)) => return evaluate(input, output),
        (Some(_), None) | (None, Some(_)) => anyhow::bail!(
            "--evaluate-csv and --evaluation-report must be provided together"
        ),
        (None, None) => {}
    }
    if cli.benchmark {
        return benchmark::run();
    }

    ensure!(
        cli.max_connections > 0 && cli.max_connections <= Semaphore::MAX_PERMITS,
        "--max-connections must be between 1 and {}",
        Semaphore::MAX_PERMITS
    );
    ensure!(
        cli.bpf_object.is_none() || cli.target_refresh_secs > 0,
        "--target-refresh-secs must be greater than zero when --bpf-object is enabled"
    );

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = Arc::new(CertAuthority::load_or_create(&cli.ca_dir).context("initialising local CA")?);
    info!(
        ca = %ca.cert_path().display(),
        "trust this CA in the clients you protect, e.g. NODE_EXTRA_CA_CERTS / SSL_CERT_FILE / REQUESTS_CA_BUNDLE"
    );

    let scanner = Arc::new(Scanner::new(&cli.deny_term).context("building scanner")?);
    let registry = Arc::new(SessionRegistry::new());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _sweeper = registry.spawn_sweeper(
        Duration::from_secs(60),
        Duration::from_secs(cli.session_ttl_secs),
        shutdown_rx.clone(),
    );

    let allowed_hosts: HashSet<String> = cli
        .allow_host
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();

    let max_body = cli
        .max_body_mib
        .checked_mul(1024 * 1024)
        .context("--max-body-mib is too large")?;

    let state = Arc::new(ProxyState::new(
        scanner,
        registry,
        ca,
        ProxyConfig {
            allowed_hosts,
            max_body,
            block_unscannable: cli.block_unscannable,
            upstream_timeout: Duration::from_secs(cli.upstream_timeout_secs),
            max_connections: cli.max_connections,
        },
    ));

    // Bind first so redirected connections always have a listener.
    let listener = TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("binding {}", cli.listen))?;

    let kernel_task = match &cli.bpf_object {
        Some(object_path) => {
            let mut fw = KernelFirewall::load(KernelConfig {
                object_path: object_path.clone(),
                cgroup_path: cli.cgroup.clone(),
                proxy_addr: listener
                    .local_addr()
                    .context("reading bound proxy address")?,
                proxy_pid: std::process::id(),
                hosts: state_hosts(&cli),
                refresh_interval: Duration::from_secs(cli.target_refresh_secs),
            })
            .context("starting eBPF layer")?;
            fw.refresh().await.context("seeding eBPF target maps")?;
            let rx = shutdown_rx.clone();
            Some(tokio::spawn(async move { fw.run(rx).await }))
        }
        None => {
            info!("no --bpf-object given: running as an explicit proxy only (set HTTPS_PROXY)");
            None
        }
    };

    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    let tx = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        info!("shutdown signal received");
        let _ = tx.send(true);
    });

    let proxy_result = supervise_kernel(
        proxy::run(listener, state.clone(), shutdown_rx.clone()),
        kernel_task,
        shutdown_tx.clone(),
        shutdown_rx.clone(),
    )
    .await;
    let _ = shutdown_tx.send(true);

    use std::sync::atomic::Ordering::Relaxed;
    let m = &state.metrics;
    info!(
        requests = m.requests.load(Relaxed),
        requests_masked = m.requests_masked.load(Relaxed),
        findings = m.findings.load(Relaxed),
        unscanned_bodies = m.unscanned_bodies.load(Relaxed),
        "final counters"
    );

    if let Err(e) = proxy_result {
        warn!(error = %e, "proxy exited with error");
        return Err(e.into());
    }
    Ok(())
}

/// Monitors the eBPF task while the proxy is serving. A returned error or task panic stops proxy
/// acceptance promptly; this cannot prevent direct egress after the kernel links detach.
async fn supervise_kernel<P>(
    proxy_run: P,
    kernel_task: Option<tokio::task::JoinHandle<Result<()>>>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
) -> std::result::Result<(), crate::error::FirewallError>
where
    P: Future<Output = std::result::Result<(), crate::error::FirewallError>>,
{
    let mut proxy_run = Box::pin(proxy_run);
    let Some(mut kernel_task) = kernel_task else {
        return proxy_run.await;
    };

    tokio::select! {
        proxy_result = &mut proxy_run => {
            let _ = shutdown_tx.send(true);
            report_kernel_exit(kernel_task.await, *shutdown_rx.borrow());
            proxy_result
        }
        kernel_result = &mut kernel_task => {
            let shutting_down = *shutdown_rx.borrow();
            report_kernel_exit(kernel_result, shutting_down);
            if !shutting_down {
                let _ = shutdown_tx.send(true);
            }
            proxy_run.await
        }
    }
}

fn report_kernel_exit(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    shutting_down: bool,
) {
    match result {
        Ok(Ok(())) if !shutting_down => warn!("eBPF task exited unexpectedly; stopping proxy"),
        Ok(Err(error)) => error!(%error, "eBPF task failed; stopping proxy"),
        Err(error) => error!(%error, "eBPF task panicked or was cancelled; stopping proxy"),
        Ok(Ok(())) => {}
    }
}

/// CSV columns: id,text,expected_kinds. expected_kinds is pipe-delimited; blank means benign.
/// The JSON report intentionally contains identifiers and aggregate counts, never input text.
fn evaluate(input: &std::path::Path, output: &std::path::Path) -> Result<()> {
    let csv = std::fs::read_to_string(input)
        .with_context(|| format!("reading evaluation corpus {}", input.display()))?;
    let scanner = Scanner::new(&[]).context("building scanner")?;
    let report = evaluation_report(&csv, &scanner)?;
    let encoded = serde_json::to_string_pretty(&report)?;
    std::fs::write(output, format!("{encoded}\n"))
        .with_context(|| format!("writing evaluation report {}", output.display()))?;
    println!("{encoded}");
    Ok(())
}

#[derive(Default)]
struct KindMetrics {
    tp: usize,
    fp: usize,
    r#fn: usize,
    tn: usize,
    false_positive_ids: Vec<String>,
    false_negative_ids: Vec<String>,
}

impl KindMetrics {
    fn observe(&mut self, id: &str, expected: bool, detected: bool) {
        match (expected, detected) {
            (true, true) => self.tp += 1,
            (false, true) => {
                self.fp += 1;
                self.false_positive_ids.push(id.to_string());
            }
            (true, false) => {
                self.r#fn += 1;
                self.false_negative_ids.push(id.to_string());
            }
            (false, false) => self.tn += 1,
        }
    }

    fn precision(&self) -> Option<f64> {
        rate(self.tp, self.tp + self.fp)
    }

    fn recall(&self) -> Option<f64> {
        rate(self.tp, self.tp + self.r#fn)
    }

    fn value(&self) -> serde_json::Value {
        serde_json::json!({
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.r#fn,
            "tn": self.tn,
            "expected_positive_examples": self.tp + self.r#fn,
            "expected_negative_examples": self.fp + self.tn,
            "precision": self.precision(),
            "recall": self.recall(),
            "false_positive_ids": self.false_positive_ids,
            "false_negative_ids": self.false_negative_ids,
        })
    }
}

fn rate(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator > 0).then(|| numerator as f64 / denominator as f64)
}

fn evaluation_report(csv: &str, scanner: &Scanner) -> Result<serde_json::Value> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut records = csv_records(&csv)?;
    ensure!(records.first().is_some_and(|r| {
        r.len() == 3 && r[0] == "id" && r[1] == "text" && r[2] == "expected_kinds"
    }),
        "CSV header must be id,text,expected_kinds");
    records.remove(0);
    ensure!(!records.is_empty(), "evaluation corpus has no examples");

    let kinds: BTreeSet<&str> = scanner.detection_kinds().collect();
    let mut metrics: BTreeMap<&str, KindMetrics> = kinds
        .iter()
        .map(|kind| (*kind, KindMetrics::default()))
        .collect();
    let mut seen_ids = BTreeSet::new();
    for (line, row) in records.iter().enumerate() {
        ensure!(row.len() == 3, "CSV record {} must have exactly 3 columns", line + 2);
        let id = &row[0];
        ensure!(!id.trim().is_empty() && seen_ids.insert(id.clone()),
            "CSV record {} has a blank or duplicate id", line + 2);
        let expected: BTreeSet<&str> = row[2].split('|').map(str::trim).filter(|s| !s.is_empty()).collect();
        ensure!(
            expected.iter().all(|kind| kinds.contains(kind)),
            "CSV record {} contains an unsupported expected kind",
            line + 2
        );
        let detected: BTreeSet<&str> = scanner.scan(&row[1]).into_iter().map(|f| f.kind).collect();
        for &kind in &kinds {
            metrics
                .get_mut(kind)
                .expect("every built-in kind has a metric")
                .observe(id, expected.contains(kind), detected.contains(kind));
        }
    }

    let total = metrics.values().fold(KindMetrics::default(), |mut total, metric| {
        total.tp += metric.tp;
        total.fp += metric.fp;
        total.r#fn += metric.r#fn;
        total.tn += metric.tn;
        total
    });
    let mean = |values: Vec<f64>| {
        (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
    };
    let macro_precision = mean(metrics.values().filter_map(KindMetrics::precision).collect());
    let macro_recall = mean(metrics.values().filter_map(KindMetrics::recall).collect());
    let per_kind: serde_json::Map<String, serde_json::Value> = metrics
        .iter()
        .map(|(kind, metric)| ((*kind).to_string(), metric.value()))
        .collect();

    Ok(serde_json::json!({
        "corpus_examples": seen_ids.len(),
        "metrics_by_kind": per_kind,
        "aggregate": {
            "micro": {
                "tp": total.tp,
                "fp": total.fp,
                "fn": total.r#fn,
                "tn": total.tn,
                "precision": total.precision(),
                "recall": total.recall(),
            },
            "macro": {"precision": macro_precision, "recall": macro_recall},
            "aggregation_method": "micro sums per-kind/per-example decisions; macro averages defined per-kind precision and recall, skipping undefined rates"
        }
    }))
}

/// Small RFC 4180 reader sufficient for this corpus: quoted commas, escaped quotes, CRLF.
fn csv_records(input: &str) -> Result<Vec<Vec<String>>> {
    let mut records = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut chars = input.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '"' if chars.peek() == Some(&'"') => { chars.next(); field.push('"'); }
                '"' => quoted = false,
                _ => field.push(ch),
            }
        } else {
            match ch {
                '"' if field.is_empty() => quoted = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\n' => { row.push(std::mem::take(&mut field)); records.push(std::mem::take(&mut row)); }
                '\r' if chars.peek() == Some(&'\n') => { chars.next(); row.push(std::mem::take(&mut field)); records.push(std::mem::take(&mut row)); }
                _ => field.push(ch),
            }
        }
    }
    ensure!(!quoted, "unterminated quoted CSV field");
    if !field.is_empty() || !row.is_empty() { row.push(field); records.push(row); }
    Ok(records)
}

fn state_hosts(cli: &Cli) -> Vec<String> {
    cli.allow_host
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

#[cfg(test)]
mod evaluation_tests {
    use super::*;

    #[test]
    fn evaluation_reports_confusion_counts_and_zero_denominator_rates() {
        let scanner = Scanner::new(&[]).unwrap();
        let csv = concat!(
            "id,text,expected_kinds\n",
            "tp,AKIAABCDEFGHIJKLMNOP,AWS_ACCESS_KEY\n",
            "fp,AKIAABCDEFGHIJKLMNOP,\n",
            "fn,ordinary text,AWS_ACCESS_KEY\n",
            "tn,ordinary text,\n",
        );
        let report = evaluation_report(csv, &scanner).unwrap();
        let aws = &report["metrics_by_kind"]["AWS_ACCESS_KEY"];
        assert_eq!(aws["tp"], 1);
        assert_eq!(aws["fp"], 1);
        assert_eq!(aws["fn"], 1);
        assert_eq!(aws["tn"], 1);
        assert_eq!(aws["precision"], 0.5);
        assert_eq!(aws["recall"], 0.5);

        let no_hits = &report["metrics_by_kind"]["ANTHROPIC_KEY"];
        assert_eq!(no_hits["tp"], 0);
        assert_eq!(no_hits["fp"], 0);
        assert_eq!(no_hits["fn"], 0);
        assert_eq!(no_hits["tn"], 4);
        assert!(no_hits["precision"].is_null());
        assert!(no_hits["recall"].is_null());

        assert_eq!(
            report["aggregate"]["micro"]["tp"],
            1,
            "micro totals sum decisions over all kinds and examples"
        );
        assert_eq!(report["aggregate"]["micro"]["tn"], 65);
    }

    #[test]
    fn evaluation_report_is_deterministic_and_rejects_unknown_labels() {
        let scanner = Scanner::new(&[]).unwrap();
        let csv = "id,text,expected_kinds\nexample,ordinary text,\n";
        assert_eq!(
            evaluation_report(csv, &scanner).unwrap(),
            evaluation_report(csv, &scanner).unwrap()
        );
        assert!(evaluation_report(
            "id,text,expected_kinds\nexample,ordinary text,NOT_A_RULE\n",
            &scanner
        )
        .is_err());
    }

    #[test]
    fn expanded_synthetic_corpus_is_parseable_stable_and_covers_every_kind() {
        let scanner = Scanner::new(&[]).unwrap();
        let csv = include_str!("../evaluation/scanner-corpus.csv");
        let first = evaluation_report(csv, &scanner).unwrap();
        let second = evaluation_report(csv, &scanner).unwrap();
        assert_eq!(first, second);
        assert_eq!(first["corpus_examples"], 87);
        for kind in scanner.detection_kinds() {
            assert!(
                first["metrics_by_kind"][kind]["expected_positive_examples"]
                    .as_u64()
                    .unwrap()
                    >= 3,
                "{kind} needs multiple positive synthetic examples"
            );
        }
    }

    #[tokio::test]
    async fn kernel_error_stops_proxy_future() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let kernel_task = tokio::spawn(async {
            Err(anyhow::anyhow!("deterministic mock kernel failure"))
        });
        let mut proxy_shutdown = shutdown_rx.clone();
        let proxy = async move {
            if !*proxy_shutdown.borrow() {
                proxy_shutdown.changed().await.unwrap();
            }
            assert!(*proxy_shutdown.borrow());
            Ok(())
        };

        supervise_kernel(proxy, Some(kernel_task), shutdown_tx, shutdown_rx.clone())
            .await
            .unwrap();
        assert!(*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn kernel_task_panic_stops_proxy_future() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let kernel_task: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async {
            panic!("deterministic mock kernel task panic");
            #[allow(unreachable_code)]
            Ok(())
        });
        let mut proxy_shutdown = shutdown_rx.clone();
        let proxy = async move {
            if !*proxy_shutdown.borrow() {
                proxy_shutdown.changed().await.unwrap();
            }
            assert!(*proxy_shutdown.borrow());
            Ok(())
        };

        supervise_kernel(proxy, Some(kernel_task), shutdown_tx, shutdown_rx.clone())
            .await
            .unwrap();
        assert!(*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn proxy_shutdown_is_forwarded_to_kernel_task() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut kernel_shutdown = shutdown_rx.clone();
        let kernel_task = tokio::spawn(async move {
            kernel_shutdown.changed().await.unwrap();
            Ok(())
        });

        supervise_kernel(async { Ok(()) }, Some(kernel_task), shutdown_tx, shutdown_rx.clone())
            .await
            .unwrap();
        assert!(*shutdown_rx.borrow());
    }
}
