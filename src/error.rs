use thiserror::Error;

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate error: {0}")]
    Cert(#[from] rcgen::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("pattern automaton error: {0}")]
    Automaton(#[from] aho_corasick::BuildError),
    #[error("request body exceeds {limit} bytes")]
    BodyTooLarge { limit: usize },
    #[error("timed out while reading the request body")]
    RequestTimeout,
    #[error("unsupported content-encoding on request: {0}")]
    UnsupportedEncoding(String),
    #[error("request body is binary/unscannable and the policy is fail-closed")]
    UnscannableBody,
    #[error("host {0} is not in the interception allow-list")]
    HostNotAllowed(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("upstream error: {0}")]
    Upstream(String),
}
