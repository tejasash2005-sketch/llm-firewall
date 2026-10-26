//! The interception proxy.
//!
//! One listener accepts two kinds of clients:
//!   * transparent: a TLS ClientHello (first byte 0x16), typically redirected here by the eBPF
//!     connect hook; the SNI picks the upstream host,
//!   * explicit: plain HTTP `CONNECT host:443` (HTTPS_PROXY); allow-listed hosts are
//!     intercepted and all other targets are rejected.
//!
//! Outbound: the buffered request body is parsed (JSON-aware), masked, and forwarded upstream.
//! Inbound: SSE streams are de-tokenized incrementally; JSON bodies are restored in place.
//! Headers (including Authorization) are intentionally NOT masked: they are the client's own
//! credentials for the provider.

use std::{
    collections::HashSet,
    convert::Infallible,
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Empty, Full, Limited, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    header::{self, HeaderMap, HeaderValue},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode, Uri, Version,
};
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use rustls::server::Acceptor;
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
};
use tokio_rustls::LazyConfigAcceptor;
use tracing::{debug, info, warn};

use crate::{
    error::FirewallError,
    scanner::Scanner,
    state::{Session, SessionRegistry},
    stream::{restore_value, SseProcessor},
    tls::CertAuthority,
};

type RespBody = UnsyncBoxBody<Bytes, io::Error>;
pub type UpstreamClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCKING_SCAN_THRESHOLD: usize = 64 * 1024;
const HOP_BY_HOP: [&str; 10] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "expect",
];

#[derive(Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub requests_masked: AtomicU64,
    pub findings: AtomicU64,
    pub unscanned_bodies: AtomicU64,
}

pub struct ProxyConfig {
    pub allowed_hosts: HashSet<String>,
    pub max_body: usize,
    pub block_unscannable: bool,
    pub upstream_timeout: Duration,
    pub max_connections: usize,
}

pub struct ProxyState {
    pub scanner: Arc<Scanner>,
    pub registry: Arc<SessionRegistry>,
    pub ca: Arc<CertAuthority>,
    pub client: UpstreamClient,
    pub metrics: Metrics,
    cfg: ProxyConfig,
    conn_limit: Arc<Semaphore>,
    #[cfg(test)]
    test_upstream_authority: Option<String>,
}

impl ProxyState {
    pub fn new(
        scanner: Arc<Scanner>,
        registry: Arc<SessionRegistry>,
        ca: Arc<CertAuthority>,
        cfg: ProxyConfig,
    ) -> Self {
        let conn_limit = Arc::new(Semaphore::new(cfg.max_connections));
        Self {
            scanner,
            registry,
            ca,
            client: build_upstream_client(),
            metrics: Metrics::default(),
            cfg,
            conn_limit,
            #[cfg(test)]
            test_upstream_authority: None,
        }
    }

    fn is_allowed(&self, host: &str) -> bool {
        self.cfg.allowed_hosts.contains(host)
    }
}

/// Upstream TLS trusts the bundled Mozilla roots only (never the system store), so the
/// firewall's own CA can never be used to validate its upstream connections.
fn build_upstream_client() -> UpstreamClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build(https)
}

// ---------------------------------------------------------------------------
// Body helpers
// ---------------------------------------------------------------------------

fn full_body(b: impl Into<Bytes>) -> RespBody {
    Full::new(b.into())
        .map_err(|n: Infallible| -> io::Error { match n {} })
        .boxed_unsync()
}

fn empty_body() -> RespBody {
    Empty::<Bytes>::new()
        .map_err(|n: Infallible| -> io::Error { match n {} })
        .boxed_unsync()
}

fn error_response(status: StatusCode, msg: &str) -> Response<RespBody> {
    let body = serde_json::json!({
        "error": {"type": "llm_firewall_error", "message": msg}
    })
    .to_string();
    let mut r = Response::new(full_body(body));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

fn status_for(e: &FirewallError) -> StatusCode {
    match e {
        FirewallError::BodyTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        FirewallError::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
        FirewallError::UnsupportedEncoding(_) | FirewallError::UnscannableBody => {
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        }
        FirewallError::HostNotAllowed(_) => StatusCode::FORBIDDEN,
        FirewallError::Upstream(_) | FirewallError::Http(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn strip_hop_by_hop(h: &mut HeaderMap) {
    // RFC 9110 allows Connection to nominate additional hop-by-hop fields.
    let nominated: Vec<header::HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        h.remove(name);
    }
    for name in HOP_BY_HOP {
        h.remove(name);
    }
}

fn connect_target_allowed(allowed_hosts: &HashSet<String>, host: &str, port: u16) -> bool {
    port == 443 && allowed_hosts.contains(host)
}

fn lower_header(h: &HeaderMap, name: header::HeaderName) -> String {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

pub async fn run(
    listener: TcpListener,
    state: Arc<ProxyState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), FirewallError> {
    info!(addr = %listener.local_addr()?, "firewall proxy listening");
    loop {
        tokio::select! {
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = state.conn_limit.clone().try_acquire_owned() else {
                    warn!(%peer, "connection limit reached; dropping connection");
                    continue;
                };
                let st = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(stream, st).await {
                        debug!(%peer, error = %e, "connection ended with error");
                    }
                });
            }
        }
    }

    // Graceful drain.
    let max = state.cfg.max_connections;
    let drain = async {
        while state.conn_limit.available_permits() < max {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .is_err()
    {
        warn!("shutdown: some connections still active after 5s");
    }
    Ok(())
}

async fn handle_connection(stream: TcpStream, state: Arc<ProxyState>) -> Result<(), FirewallError> {
    stream.set_nodelay(true)?;
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(FIRST_BYTE_TIMEOUT, stream.peek(&mut first))
        .await
        .map_err(|_| FirewallError::Protocol("client sent no data".into()))??;
    if n == 0 {
        return Ok(());
    }
    if first[0] == 0x16 {
        serve_tls(stream, state, None).await
    } else {
        serve_plain_proxy(stream, state).await
    }
}

// ---------------------------------------------------------------------------
// Explicit proxy (CONNECT)
// ---------------------------------------------------------------------------

async fn serve_plain_proxy(stream: TcpStream, state: Arc<ProxyState>) -> Result<(), FirewallError> {
    let svc = service_fn(move |req: Request<Incoming>| handle_connect(state.clone(), req));
    http1::Builder::new()
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await?;
    Ok(())
}

async fn handle_connect(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<RespBody>, Infallible> {
    if req.method() != Method::CONNECT {
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "llm-firewall accepts CONNECT requests for allow-listed hosts only",
        ));
    }
    let Some(authority) = req.uri().authority().cloned() else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "CONNECT requires host:port",
        ));
    };
    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);

    if !connect_target_allowed(&state.cfg.allowed_hosts, &host, port) {
        return Ok(error_response(
            StatusCode::FORBIDDEN,
            "CONNECT target is not an allow-listed HTTPS host",
        ));
    }

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let result = serve_tls(io, state, Some(host.clone())).await;
                if let Err(e) = result {
                    debug!(%host, error = %e, "CONNECT session ended with error");
                }
            }
            Err(e) => warn!(error = %e, "CONNECT upgrade failed"),
        }
    });
    Ok(Response::new(empty_body()))
}

// ---------------------------------------------------------------------------
// TLS interception
// ---------------------------------------------------------------------------

async fn serve_tls<IO>(
    io: IO,
    state: Arc<ProxyState>,
    connect_host: Option<String>,
) -> Result<(), FirewallError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = async {
        let start = LazyConfigAcceptor::new(Acceptor::default(), io).await?;
        let sni = start
            .client_hello()
            .server_name()
            .map(|s| s.to_ascii_lowercase());
        let host = sni.or(connect_host).ok_or_else(|| {
            FirewallError::Protocol("no SNI and no CONNECT target to pick a certificate".into())
        })?;
        if !state.is_allowed(&host) {
            return Err(FirewallError::HostNotAllowed(host));
        }
        let config = state.ca.server_config_for(&host)?;
        let tls = start.into_stream(config).await?;
        Ok::<_, FirewallError>((tls, host))
    };
    let (tls, host) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| FirewallError::Protocol("TLS handshake timed out".into()))??;

    let session = state.registry.create();
    let (svc_state, svc_session, svc_host) = (state.clone(), session.clone(), host);
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = svc_state.clone();
        let session = svc_session.clone();
        let host = svc_host.clone();
        async move { handle_llm_request(state, session, host, req).await }
    });

    let result = http1::Builder::new()
        .serve_connection(TokioIo::new(tls), svc)
        .await;
    state.registry.remove(session.id());
    result?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Request / response pipeline
// ---------------------------------------------------------------------------

async fn handle_llm_request(
    state: Arc<ProxyState>,
    session: Arc<Session>,
    host: String,
    req: Request<Incoming>,
) -> Result<Response<RespBody>, Infallible> {
    match process_llm_request(&state, &session, &host, req).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!(%host, error = %e, "request failed");
            Ok(error_response(status_for(&e), &e.to_string()))
        }
    }
}

pub(crate) fn mask_body_sync(
    scanner: &Scanner,
    session: &Session,
    content_type: &str,
    body: Bytes,
    block_unscannable: bool,
) -> Result<(Bytes, usize, bool), FirewallError> {
    if body.is_empty() {
        return Ok((body, 0, false));
    }
    let looks_json = content_type.contains("json")
        || (content_type.is_empty() && matches!(body.first(), Some(b'{') | Some(b'[')));

    if looks_json {
        let mut v =
            serde_json::from_slice::<Value>(&body).map_err(|_| FirewallError::UnscannableBody)?;
        let n = scanner.mask_json(&mut v, session);
        if n == 0 {
            return Ok((body, 0, false)); // untouched: forward the original bytes
        }
        return Ok((Bytes::from(serde_json::to_vec(&v)?), n, false));
    }

    if looks_json
        || content_type.is_empty()
        || content_type.starts_with("text/")
        || content_type.contains("x-www-form-urlencoded")
    {
        if let Ok(text) = std::str::from_utf8(&body) {
            return Ok(match scanner.mask_text(text, session) {
                Some((masked, n)) => (Bytes::from(masked), n, false),
                None => (body, 0, false),
            });
        }
    }

    if block_unscannable {
        Err(FirewallError::UnscannableBody)
    } else {
        warn!(
            content_type,
            len = body.len(),
            "forwarding unscannable (binary) request body"
        );
        Ok((body, 0, true))
    }
}

async fn mask_request_body(
    state: &Arc<ProxyState>,
    session: &Arc<Session>,
    content_type: &str,
    body: Bytes,
) -> Result<(Bytes, usize, bool), FirewallError> {
    let block = state.cfg.block_unscannable;
    if body.len() >= BLOCKING_SCAN_THRESHOLD {
        let scanner = state.scanner.clone();
        let session = session.clone();
        let ct = content_type.to_string();
        let result = tokio::task::spawn_blocking(move || {
            mask_body_sync(&scanner, &session, &ct, body, block)
        })
        .await
        .map_err(|e| FirewallError::Upstream(format!("scan task failed: {e}")))?;
        result
    } else {
        mask_body_sync(&state.scanner, session, content_type, body, block)
    }
}

async fn process_llm_request(
    state: &Arc<ProxyState>,
    session: &Arc<Session>,
    host: &str,
    req: Request<Incoming>,
) -> Result<Response<RespBody>, FirewallError> {
    state.metrics.requests.fetch_add(1, Ordering::Relaxed);
    let (mut parts, body) = req.into_parts();

    // Fail closed on compressed request bodies: we cannot scan what we cannot read.
    let enc = lower_header(&parts.headers, header::CONTENT_ENCODING);
    if !enc.is_empty() && enc != "identity" {
        return Err(FirewallError::UnsupportedEncoding(enc));
    }

    let limit = state.cfg.max_body;
    let collected = tokio::time::timeout(REQUEST_BODY_TIMEOUT, Limited::new(body, limit).collect())
        .await
        .map_err(|_| FirewallError::RequestTimeout)?
        .map_err(|e| {
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                FirewallError::BodyTooLarge { limit }
            } else {
                FirewallError::Upstream(format!("reading client body: {e}"))
            }
        })?;
    let body_bytes = collected.to_bytes();

    let content_type = lower_header(&parts.headers, header::CONTENT_TYPE);
    let (masked, findings, unscanned) =
        mask_request_body(state, session, &content_type, body_bytes).await?;
    if unscanned {
        state
            .metrics
            .unscanned_bodies
            .fetch_add(1, Ordering::Relaxed);
    }
    if findings > 0 {
        state
            .metrics
            .requests_masked
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .findings
            .fetch_add(findings as u64, Ordering::Relaxed);
    }

    let path = parts.uri.path().to_string(); // never log the query string
    let method = parts.method.clone();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    #[cfg(test)]
    let upstream_authority = state.test_upstream_authority.as_deref().unwrap_or(host);
    #[cfg(not(test))]
    let upstream_authority = host;
    let uri: Uri = format!("https://{upstream_authority}{path_and_query}")
        .parse()
        .map_err(|e| FirewallError::Protocol(format!("invalid request target: {e}")))?;

    let mut headers = std::mem::take(&mut parts.headers);
    strip_hop_by_hop(&mut headers);
    headers.remove(header::HOST);
    headers.remove(header::CONTENT_LENGTH);
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    if !masked.is_empty() {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(masked.len()));
    }

    let mut upstream_req = Request::new(Full::new(masked));
    *upstream_req.method_mut() = parts.method;
    *upstream_req.uri_mut() = uri;
    *upstream_req.version_mut() = Version::HTTP_11;
    *upstream_req.headers_mut() = headers;

    let resp = tokio::time::timeout(
        state.cfg.upstream_timeout,
        state.client.request(upstream_req),
    )
    .await
    .map_err(|_| FirewallError::Upstream("timed out waiting for upstream response".into()))?
    .map_err(|e| FirewallError::Upstream(e.to_string()))?;

    info!(%host, %method, %path, findings, status = resp.status().as_u16(), "forwarded");

    let (mut rparts, rbody) = resp.into_parts();
    strip_hop_by_hop(&mut rparts.headers);

    let ctype = lower_header(&rparts.headers, header::CONTENT_TYPE);
    let cenc = lower_header(&rparts.headers, header::CONTENT_ENCODING);
    let encoded = !cenc.is_empty() && cenc != "identity";

    if !session.has_mappings() || encoded {
        if encoded && session.has_mappings() {
            warn!(%host, encoding = %cenc, "upstream compressed the response; cannot de-tokenize");
        }
        let body = rbody.map_err(io::Error::other).boxed_unsync();
        return Ok(Response::from_parts(rparts, body));
    }

    if ctype.contains("text/event-stream") {
        rparts.headers.remove(header::CONTENT_LENGTH);
        return Ok(Response::from_parts(
            rparts,
            sse_body(rbody, session.clone()),
        ));
    }

    if ctype.contains("json") {
        let collected = Limited::new(rbody, limit)
            .collect()
            .await
            .map_err(|e| FirewallError::Upstream(format!("reading upstream body: {e}")))?;
        let bytes = collected.to_bytes();
        let restored = match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut v) => {
                restore_value(&mut v, session);
                Bytes::from(serde_json::to_vec(&v)?)
            }
            Err(_) => bytes,
        };
        rparts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(restored.len()));
        return Ok(Response::from_parts(rparts, full_body(restored)));
    }

    let body = rbody.map_err(io::Error::other).boxed_unsync();
    Ok(Response::from_parts(rparts, body))
}

struct SseState {
    inner: std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, io::Error>> + Send>>,
    proc: SseProcessor,
    finished: bool,
}

fn sse_body(body: Incoming, session: Arc<Session>) -> RespBody {
    let inner = body
        .into_data_stream()
        .map(|chunk| chunk.map_err(io::Error::other));
    sse_body_from_stream(Box::pin(inner), session)
}

fn sse_body_from_stream(
    inner: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<Bytes, io::Error>> + Send>,
    >,
    session: Arc<Session>,
) -> RespBody {
    let state = SseState {
        inner,
        proc: SseProcessor::new(session),
        finished: false,
    };
    let stream = futures_util::stream::unfold(state, |mut st| async move {
        if st.finished {
            return None;
        }
        loop {
            match st.inner.next().await {
                Some(Ok(chunk)) => {
                    let out = st.proc.push(&chunk);
                    if out.is_empty() {
                        continue; // everything held back; wait for more input
                    }
                    return Some((Ok::<_, io::Error>(Frame::data(out)), st));
                }
                Some(Err(e)) => {
                    st.finished = true;
                    return Some((Err(e), st));
                }
                None => {
                    st.finished = true;
                    let out = st.proc.finish();
                    if out.is_empty() {
                        return None;
                    }
                    return Some((Ok(Frame::data(out)), st));
                }
            }
        }
    });
    StreamBody::new(stream).boxed_unsync()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scanner::Scanner, state::SessionRegistry};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::SocketAddr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::mpsc,
    };

    struct TestDirectory(std::path::PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_upstream_tls() -> (rustls::ServerConfig, CertificateDer<'static>) {
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params.signed_by(&leaf_key, &root, &root_key).unwrap();
        let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], server_key)
            .unwrap();

        (server, root.der().clone())
    }

    async fn tls_proxy_client(
        proxy_addr: SocketAddr,
        config: Arc<rustls::ClientConfig>,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut socket = TcpStream::connect(proxy_addr).await.unwrap();
        socket
            .write_all(b"CONNECT proxy.test:443 HTTP/1.1\r\nHost: proxy.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            socket.read_exact(&mut byte).await.unwrap();
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
        tokio_rustls::TlsConnector::from(config)
            .connect(
                rustls::pki_types::ServerName::try_from("proxy.test")
                    .unwrap()
                    .to_owned(),
                socket,
            )
            .await
            .unwrap()
    }

    async fn send_proxy_post(
        proxy_addr: SocketAddr,
        config: Arc<rustls::ClientConfig>,
        path: &str,
        extra_headers: &str,
        body: &[u8],
    ) -> Vec<u8> {
        let mut client = tls_proxy_client(proxy_addr, config).await;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: proxy.test\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        client.write_all(head.as_bytes()).await.unwrap();
        client.write_all(body).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        response
    }

    #[derive(Clone)]
    struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
        type Writer = LogBuffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_request_error_logs_do_not_include_request_secrets() {
        static NEXT_TEMP_ID: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let ca_dir = loop {
            let path = std::env::temp_dir().join(format!(
                "llm-firewall-log-test-{}-{}",
                std::process::id(),
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating temporary CA directory: {error}"),
            }
        };
        let _temp_dir = TestDirectory(ca_dir.clone());
        let state = Arc::new(ProxyState::new(
            Arc::new(Scanner::new(&[]).unwrap()),
            Arc::new(SessionRegistry::new()),
            Arc::new(CertAuthority::load_or_create(&ca_dir).unwrap()),
            ProxyConfig {
                allowed_hosts: HashSet::from(["proxy.test".to_string()]),
                max_body: 1024,
                block_unscannable: true,
                upstream_timeout: Duration::from_secs(1),
                max_connections: 1,
            },
        ));
        let session = state.registry.create();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let service = service_fn(move |req| {
            handle_llm_request(
                state.clone(),
                session.clone(),
                "proxy.test".to_string(),
                req,
            )
        });
        let server = async move {
            let (socket, _) = listener.accept().await.unwrap();
            http1::Builder::new()
                .serve_connection(TokioIo::new(socket), service)
                .await
                .unwrap();
        };

        const SYNTHETIC_SECRET: &str = "synthetic-log-secret-value";
        let client = async move {
            let mut socket = TcpStream::connect(addr).await.unwrap();
            let body = format!(r#"{{"password":"{SYNTHETIC_SECRET}""#);
            let request = format!(
                "POST /test HTTP/1.1\r\nHost: proxy.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            socket.read_to_end(&mut response).await.unwrap();
            response
        };

        let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(LogBuffer(logs.clone()))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let ((), response) = tokio::join!(server, client);
        drop(_guard);

        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 415"));
        let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("request failed"));
        assert!(!logs.contains(SYNTHETIC_SECRET));
    }

    #[tokio::test]
    async fn sse_body_propagates_upstream_transport_error() {
        let chunks: Vec<Result<Bytes, io::Error>> = vec![
            Ok(Bytes::from_static(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"unfinished",
            )),
            Err(io::Error::other("synthetic mock upstream body failure")),
        ];
        let session = SessionRegistry::new().create();
        let body = sse_body_from_stream(
            Box::pin(futures_util::stream::iter(chunks)),
            session,
        );
        let mut response = Response::new(body);
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));

        // Inject the I/O failure at the upstream body boundary, after valid response headers
        // exist. Hyper's server-side body error can otherwise abort HTTP parsing itself.
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .as_bytes(),
            b"text/event-stream"
        );

        let mut body = response.into_body();
        match body.frame().await {
            Some(Err(_)) => {}
            Some(Ok(_)) => panic!("incomplete SSE event was emitted as a body frame"),
            None => panic!("upstream body error was not propagated"),
        }
    }

    #[tokio::test]
    async fn proxy_sends_masked_json_to_tls_mock_upstream_and_restores_response() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        static NEXT_TEMP_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let (server_tls, upstream_root) = test_upstream_tls();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
        let (body_tx, mut body_rx) = mpsc::channel::<Bytes>(5);
        tokio::spawn(async move {
            for _ in 0..5 {
                let (socket, _) = upstream_listener.accept().await.unwrap();
                let tls = acceptor.accept(socket).await.unwrap();
                let body_tx = body_tx.clone();
                let service = service_fn(move |req: Request<Incoming>| {
                    let body_tx = body_tx.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        let stream_response = path.ends_with("/stream");
                        let error_response = path.ends_with("/upstream-error");
                        let malformed_response = path.ends_with("/malformed-response");
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        body_tx.send(body.clone()).await.unwrap();
                        let value: Value = serde_json::from_slice(&body).unwrap();
                        let token = value["messages"][0]["content"]
                            .as_str()
                            .unwrap()
                            .to_string();
                        let (response_body, content_type) = if stream_response {
                            let split = token.len() / 2;
                            let first = serde_json::json!({
                                "choices": [{"index": 0, "delta": {"content": format!("SSE {}", &token[..split])}, "finish_reason": null}]
                            });
                            let second = serde_json::json!({
                                "choices": [{"index": 0, "delta": {"content": format!("{} done", &token[split..])}, "finish_reason": null}]
                            });
                            let wire = format!("data: {first}\n\ndata: {second}\n\ndata: [DONE]\n\n");
                            let chunks = wire
                                .as_bytes()
                                .chunks(5)
                                .map(|chunk| {
                                    Ok::<_, io::Error>(Frame::data(Bytes::copy_from_slice(chunk)))
                                })
                                .collect::<Vec<_>>();
                            (
                                StreamBody::new(futures_util::stream::iter(chunks)).boxed_unsync(),
                                "text/event-stream",
                            )
                        } else if error_response {
                            let response = serde_json::json!({ "error": { "message": token } }).to_string();
                            (full_body(response), "application/json")
                        } else if malformed_response {
                            (full_body(format!("{{\"message\":\"{token}\"")), "application/json")
                        } else {
                            let response = serde_json::json!({ "echo": value }).to_string();
                            (full_body(response), "application/json")
                        };
                        let mut response = Response::new(response_body);
                        if error_response {
                            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                        }
                        response
                            .headers_mut()
                            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
                        Ok::<_, Infallible>(response)
                    }
                });
                http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await
                    .unwrap();
            }
        });

        let ca_dir = loop {
            let path = std::env::temp_dir().join(format!(
                "llm-firewall-proxy-test-{}-{}-{}",
                std::process::id(),
                upstream_addr.port(),
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating temporary CA directory: {error}"),
            }
        };
        let _temp_dir = TestDirectory(ca_dir.clone());
        let ca = Arc::new(CertAuthority::load_or_create(&ca_dir).unwrap());
        let ca_cert = ca.certificate_der();
        let registry = Arc::new(SessionRegistry::new());
        let scanner = Arc::new(Scanner::new(&["Project Falcon".to_string()]).unwrap());
        let mut state = ProxyState::new(
            scanner,
            registry.clone(),
            ca,
            ProxyConfig {
                allowed_hosts: HashSet::from(["proxy.test".to_string()]),
                max_body: 1024 * 1024,
                block_unscannable: true,
                upstream_timeout: Duration::from_secs(5),
                max_connections: 4,
            },
        );
        let mut upstream_roots = rustls::RootCertStore::empty();
        upstream_roots.add(upstream_root).unwrap();
        let upstream_tls = rustls::ClientConfig::builder()
            .with_root_certificates(upstream_roots)
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(upstream_tls)
            .https_only()
            .enable_http1()
            .build();
        state.client = Client::builder(TokioExecutor::new()).build(connector);
        state.test_upstream_authority = Some(format!("127.0.0.1:{}", upstream_addr.port()));
        let state = Arc::new(state);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy_task = tokio::spawn(run(proxy_listener, state, shutdown_rx));

        let mut denied = TcpStream::connect(proxy_addr).await.unwrap();
        denied
            .write_all(
                b"CONNECT not-allowed.example:443 HTTP/1.1\r\nHost: not-allowed.example:443\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut denied_response = Vec::new();
        denied.read_to_end(&mut denied_response).await.unwrap();
        assert!(denied_response.starts_with(b"HTTP/1.1 403"));

        let mut proxy_roots = rustls::RootCertStore::empty();
        proxy_roots.add(ca_cert).unwrap();
        let proxy_tls = rustls::ClientConfig::builder()
            .with_root_certificates(proxy_roots)
            .with_no_client_auth();
        let proxy_tls = Arc::new(proxy_tls);

        let malformed = send_proxy_post(
            proxy_addr,
            proxy_tls.clone(),
            "/v1/test",
            "Content-Type: application/json\r\n",
            br#"{"prompt":"AKIAIOSFODNN7EXAMPLE"#,
        )
        .await;
        assert!(malformed.starts_with(b"HTTP/1.1 415"));
        assert!(
            !String::from_utf8_lossy(&malformed).contains("AKIAIOSFODNN7EXAMPLE"),
            "error response reflected a synthetic credential"
        );

        let compressed = send_proxy_post(
            proxy_addr,
            proxy_tls.clone(),
            "/v1/test",
            "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
            br#"{"prompt":"Project Falcon"}"#,
        )
        .await;
        assert!(compressed.starts_with(b"HTTP/1.1 415"));

        let unscannable = send_proxy_post(
            proxy_addr,
            proxy_tls.clone(),
            "/v1/test",
            "Content-Type: application/octet-stream\r\n",
            &[0xff, 0],
        )
        .await;
        assert!(unscannable.starts_with(b"HTTP/1.1 415"));

        let oversized_body = vec![b'x'; 1024 * 1024 + 1];
        let oversized = send_proxy_post(
            proxy_addr,
            proxy_tls.clone(),
            "/v1/test",
            "Content-Type: text/plain\r\n",
            &oversized_body,
        )
        .await;
        assert!(
            oversized.starts_with(b"HTTP/1.1 413"),
            "oversized request returned status {:?}",
            String::from_utf8_lossy(&oversized)
                .lines()
                .next()
                .unwrap_or("<empty>")
        );

        // Synthetic values only. Keep them in constants so failed assertions can use
        // redacted messages and never dump a credential-like literal.
        const FAKE_AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
        const FAKE_OPENAI_KEY: &str = "sk-12345678901234567890";
        let request_body = Bytes::from_static(
            br#"{"model":"test-model","messages":[{"content":"Project Falcon AKIAIOSFODNN7EXAMPLE sk-12345678901234567890"}],"temperature":0.25}"#,
        );
        let response = send_proxy_post(
            proxy_addr,
            proxy_tls.clone(),
            "/v1/test",
            "Content-Type: application/json\r\n",
            &request_body,
        )
        .await;
        let streaming_response = send_proxy_post(
            proxy_addr,
            proxy_tls.clone(),
            "/v1/stream",
            "Content-Type: application/json\r\n",
            &request_body,
        )
        .await;
        let benign_body = br#"{"model":"test-model","messages":[{"content":"hello, nothing sensitive here"}],"temperature":0.25}"#;
        let benign_response = send_proxy_post(
            proxy_addr,
            proxy_tls.clone(),
            "/v1/benign",
            "Content-Type: application/json\r\n",
            benign_body,
        )
        .await;
        let upstream_error = send_proxy_post(
            proxy_addr,
            proxy_tls.clone(),
            "/v1/upstream-error",
            "Content-Type: application/json\r\n",
            &request_body,
        )
        .await;
        let malformed_response = send_proxy_post(
            proxy_addr,
            proxy_tls,
            "/v1/malformed-response",
            "Content-Type: application/json\r\n",
            &request_body,
        )
        .await;
        let _ = shutdown_tx.send(true);
        proxy_task.await.unwrap().unwrap();

        let upstream_body = tokio::time::timeout(Duration::from_secs(5), body_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let upstream_text = std::str::from_utf8(&upstream_body).unwrap();
        assert!(!upstream_text.contains("Project Falcon"));
        assert!(!upstream_text.contains(FAKE_AWS_KEY), "upstream body contained a synthetic credential");
        assert!(!upstream_text.contains(FAKE_OPENAI_KEY), "upstream body contained a synthetic credential");
        let upstream_json: Value = serde_json::from_slice(&upstream_body).unwrap();
        assert_eq!(upstream_json["model"], "test-model");
        assert_eq!(upstream_json["temperature"], 0.25);
        let masked = upstream_json["messages"][0]["content"].as_str().unwrap();
        assert!(masked.starts_with("[TERM_"));
        assert!(masked.contains("[AWS_ACCESS_KEY_"));
        assert!(masked.contains("[OPENAI_KEY_"));
        let placeholders: Vec<_> = masked
            .split_whitespace()
            .filter(|word| word.starts_with('[') && word.ends_with(']'))
            .collect();
        assert_eq!(placeholders.len(), 3, "expected three independent placeholders");
        assert_eq!(
            placeholders.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "distinct values must not share a placeholder"
        );

        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text.contains("Project Falcon"));
        assert!(response_text.contains(FAKE_AWS_KEY));
        assert!(response_text.contains(FAKE_OPENAI_KEY));
        assert!(!response_text.contains(masked));

        let streaming_upstream = tokio::time::timeout(Duration::from_secs(5), body_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!String::from_utf8_lossy(&streaming_upstream).contains("Project Falcon"));
        let streaming_upstream_text = String::from_utf8_lossy(&streaming_upstream);
        assert!(!streaming_upstream_text.contains(FAKE_AWS_KEY), "stream request exposed a synthetic credential");
        assert!(!streaming_upstream_text.contains(FAKE_OPENAI_KEY), "stream request exposed a synthetic credential");
        assert!(String::from_utf8_lossy(&streaming_response).contains("Project Falcon"));
        assert!(String::from_utf8_lossy(&streaming_response).contains(FAKE_AWS_KEY));
        assert!(String::from_utf8_lossy(&streaming_response).contains(FAKE_OPENAI_KEY));
        assert!(!String::from_utf8_lossy(&streaming_response).contains(masked));
        assert!(String::from_utf8_lossy(&streaming_response).contains("[DONE]"));
        let streaming_text = String::from_utf8_lossy(&streaming_response);
        let streaming_body = streaming_text.split_once("\r\n\r\n").unwrap().1;
        assert!(streaming_text
            .to_ascii_lowercase()
            .contains("content-type: text/event-stream"));
        assert_eq!(streaming_body.matches("\n\n").count(), 3, "SSE event framing changed");

        let benign_upstream = tokio::time::timeout(Duration::from_secs(5), body_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(benign_upstream.as_ref(), &benign_body[..]);
        let benign_text = String::from_utf8_lossy(&benign_response);
        assert!(benign_text.contains("hello, nothing sensitive here"));

        let upstream_error_text = String::from_utf8_lossy(&upstream_error);
        assert!(upstream_error_text.starts_with("HTTP/1.1 429"));
        assert!(upstream_error_text.contains("Project Falcon"));
        assert!(upstream_error_text.contains(FAKE_AWS_KEY));
        assert!(upstream_error_text.contains(FAKE_OPENAI_KEY));

        // Invalid JSON is forwarded unchanged; restoration must not corrupt its bytes.
        let malformed_response_text = String::from_utf8_lossy(&malformed_response);
        assert!(malformed_response_text.contains("HTTP/1.1 200"));
        assert!(malformed_response_text.contains("[TERM_"));
        assert!(!malformed_response_text.contains("Project Falcon"));

        // The remaining two mock requests also carried masked bodies on error paths.
        for _ in 0..2 {
            let upstream_body = tokio::time::timeout(Duration::from_secs(5), body_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(!String::from_utf8_lossy(&upstream_body).contains("Project Falcon"));
            assert!(!String::from_utf8_lossy(&upstream_body).contains(FAKE_AWS_KEY));
            assert!(!String::from_utf8_lossy(&upstream_body).contains(FAKE_OPENAI_KEY));
        }
    }

    #[test]
    fn json_masking_preserves_nested_unrelated_values() {
        let scanner = Scanner::new(&["Project Falcon".into()]).unwrap();
        let session = SessionRegistry::new().create();
        let input = Bytes::from_static(
            br#"{"model":"m","messages":[{"content":"Project Falcon"}],"temperature":0.2,"enabled":true}"#,
        );
        let (body, count, unscanned) =
            mask_body_sync(&scanner, &session, "application/json", input, true).unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(count, 1);
        assert!(!unscanned);
        assert_eq!(value["model"], "m");
        assert_eq!(value["temperature"], 0.2);
        assert_eq!(value["enabled"], true);
        assert!(value["messages"][0]["content"]
            .as_str()
            .unwrap()
            .starts_with("[TERM_"));
        assert!(!String::from_utf8_lossy(&body).contains("Project Falcon"));
    }

    #[test]
    fn malformed_declared_json_is_rejected() {
        let scanner = Scanner::new(&[]).unwrap();
        let session = SessionRegistry::new().create();
        let err = mask_body_sync(
            &scanner,
            &session,
            "application/json",
            Bytes::from_static(br#"{"prompt":"Project Falcon""#),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, FirewallError::UnscannableBody));
    }

    #[test]
    fn connection_nominated_headers_are_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("x-private, keep-alive"),
        );
        headers.insert("x-private", HeaderValue::from_static("secret"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key("x-private"));
        assert!(!headers.contains_key(header::CONNECTION));
        assert!(headers.contains_key(header::CONTENT_TYPE));
    }

    #[test]
    fn connect_target_requires_allowlisted_host_and_https_port() {
        let allowed = HashSet::from(["api.openai.com".to_string()]);
        assert!(connect_target_allowed(&allowed, "api.openai.com", 443));
        assert!(!connect_target_allowed(&allowed, "example.com", 443));
        assert!(!connect_target_allowed(&allowed, "api.openai.com", 8443));
    }

    #[test]
    fn blocking_policy_rejects_unscannable_binary_and_bad_json() {
        let scanner = Scanner::new(&[]).unwrap();
        let session = SessionRegistry::new().create();
        let (forwarded, findings, unscanned) = mask_body_sync(
            &scanner,
            &session,
            "application/octet-stream",
            Bytes::from_static(b"\xff\x00"),
            false,
        )
        .unwrap();
        assert_eq!(forwarded, Bytes::from_static(b"\xff\x00"));
        assert_eq!(findings, 0);
        assert!(unscanned);

        for (content_type, body) in [
            ("application/octet-stream", Bytes::from_static(b"\xff\x00")),
            ("application/json", Bytes::from_static(b"{broken")),
        ] {
            assert!(matches!(
                mask_body_sync(&scanner, &session, content_type, body, true),
                Err(FirewallError::UnscannableBody)
            ));
        }
    }
}
