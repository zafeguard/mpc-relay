//! HTTP surface: the WebSocket endpoint, `/healthz`, `/readyz`, `/metrics`,
//! optional TLS, and the relay's start/shutdown lifecycle.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::serve::{IncomingStream, Listener};
use axum::Router;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::auth::Authenticator;
use crate::bridge::{self, Shared};
use crate::broker::{redact_amqp_url, Broker};
use crate::config::{Config, TlsFiles};
use crate::metrics::Metrics;

/// Subprotocols accepted, matched against the client's list in the
/// client's order.
pub const SUBPROTOCOLS: &[&str] = &["v12.stomp", "v11.stomp", "stomp"];

/// Slack above the STOMP frame limit for the WebSocket message limit, so a
/// slightly oversized frame is answered with a STOMP ERROR rather than a bare
/// WebSocket close. Anything larger is refused by the WebSocket layer before
/// it is buffered.
const WS_MESSAGE_SLACK: usize = 64 * 1024;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Install the process-wide rustls crypto provider. Both `ring` (pulled in
/// by lapin's TLS connector) and `aws-lc-rs` are compiled in, and rustls
/// refuses to guess between them. Idempotent.
pub fn init_crypto() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Remote address of a connection, for any listener whose address type is
/// a socket address (plain TCP and the TLS listener below).
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

impl Connected<IncomingStream<'_, TcpListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for PeerAddr {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}

/// A TLS listener whose handshakes run in their own tasks, so one slow or
/// hostile handshake cannot stall `accept` for everyone else.
pub struct TlsListener {
    rx: mpsc::Receiver<(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    fn new(tcp: TcpListener, config: Arc<rustls::ServerConfig>) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, rx) = mpsc::channel(256);
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        tokio::spawn(async move {
            loop {
                let (stream, addr) = match tcp.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if tx.is_closed() {
                    return;
                }
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, addr)).await;
                        }
                        Ok(Err(e)) => tracing::debug!(%addr, error = %e, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%addr, "TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(TlsListener { rx, local })
    }
}

impl Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(v) => v,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

fn load_tls(files: &TlsFiles) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(&files.cert)
        .map_err(|e| anyhow::anyhow!("MPC_RELAY_TLS_CERT {}: {e}", files.cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("MPC_RELAY_TLS_CERT {}: {e}", files.cert.display()))?;
    if certs.is_empty() {
        anyhow::bail!(
            "MPC_RELAY_TLS_CERT {}: no certificates found",
            files.cert.display()
        );
    }
    let key = PrivateKeyDer::from_pem_file(&files.key)
        .map_err(|e| anyhow::anyhow!("MPC_RELAY_TLS_KEY {}: {e}", files.key.display()))?;
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // WebSocket upgrades are HTTP/1.1.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// The relay's HTTP application. `/metrics` is served here only when no
/// separate metrics listener is configured.
pub fn router(shared: Arc<Shared>, with_metrics: bool) -> Router {
    let mut r = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(&shared.config.ws_path, get(ws_handler));
    if with_metrics {
        r = r.route("/metrics", get(metrics));
    }
    r.with_state(shared)
}

fn metrics_router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .with_state(shared)
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(shared): State<Arc<Shared>>) -> Response {
    let state = shared.broker.state();
    let broker = state
        .connection
        .as_ref()
        .is_some_and(|c| c.status().connected());
    let exchange = broker && state.exchange_ok;
    let keys = shared.auth.is_ready();
    let draining = shared.draining.load(Ordering::Acquire);
    let ready = broker && exchange && keys && !draining;
    let body = serde_json::json!({
        "ready": ready,
        "broker": broker,
        "exchange": exchange,
        "keys": keys,
        "draining": draining,
    });
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn metrics(State(shared): State<Arc<Shared>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        shared.metrics.render(),
    )
        .into_response()
}

/// The first subprotocol the client offers that this relay speaks, in the
/// client's order of preference.
pub fn select_subprotocol<'a>(offered: impl Iterator<Item = &'a str>) -> Option<&'static str> {
    offered
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .find_map(|p| SUBPROTOCOLS.iter().find(|s| **s == p).copied())
}

async fn ws_handler(
    State(shared): State<Arc<Shared>>,
    ConnectInfo(PeerAddr(peer)): ConnectInfo<PeerAddr>,
    mut ws: WebSocketUpgrade,
) -> Response {
    if shared.draining.load(Ordering::Acquire) {
        shared.metrics.error("draining");
        return (StatusCode::SERVICE_UNAVAILABLE, "draining\n").into_response();
    }
    let Some(slot) = shared.try_acquire() else {
        shared.metrics.error("too_many_connections");
        return (StatusCode::SERVICE_UNAVAILABLE, "too many connections\n").into_response();
    };
    let chosen = select_subprotocol(ws.requested_protocols().filter_map(|v| v.to_str().ok()));
    if let Some(p) = chosen {
        ws.set_selected_protocol(HeaderValue::from_static(p));
    }
    let limit = shared.config.limits.max_frame_bytes + WS_MESSAGE_SLACK;
    let metrics = shared.metrics.clone();
    ws.max_message_size(limit)
        .max_frame_size(limit)
        .on_failed_upgrade(move |e| {
            metrics.error("upgrade_failed");
            tracing::debug!(error = %e, "websocket upgrade failed");
        })
        .on_upgrade(move |socket| bridge::serve(socket, shared, slot, peer))
}

/// A running relay.
pub struct Relay {
    pub local_addr: SocketAddr,
    pub metrics_addr: Option<SocketAddr>,
    pub shared: Arc<Shared>,
    drain: CancellationToken,
    stop_broker: CancellationToken,
    servers: Vec<tokio::task::JoinHandle<()>>,
}

/// Bind the listeners and start the broker supervisor. Returns once the
/// listeners are bound; the broker connects in the background.
pub async fn start(config: Config) -> anyhow::Result<Relay> {
    init_crypto();
    let config = Arc::new(config);
    let metrics = Arc::new(Metrics::new());
    let stop_broker = CancellationToken::new();
    let drain = CancellationToken::new();
    let tls = config.tls.as_ref().map(load_tls).transpose()?;

    let auth = Authenticator::new(config.auth.clone(), stop_broker.clone())?;
    let broker = Broker::start(
        config.amqp_url.clone(),
        config.amqp_connection_name.clone(),
        config.exchange.clone(),
        metrics.clone(),
        stop_broker.clone(),
    );
    let shared = Arc::new(Shared::new(config.clone(), auth, broker, metrics));

    let mut servers = Vec::new();
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let app = router(shared.clone(), config.metrics_listen.is_none())
        .into_make_service_with_connect_info::<PeerAddr>();
    let d = drain.clone();
    if let Some(tls) = tls {
        let tls_listener = TlsListener::new(listener, tls)?;
        servers.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(tls_listener, app)
                .with_graceful_shutdown(d.cancelled_owned())
                .await
            {
                tracing::error!(error = %e, "server failed");
            }
        }));
    } else {
        servers.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(d.cancelled_owned())
                .await
            {
                tracing::error!(error = %e, "server failed");
            }
        }));
    }

    let mut metrics_addr = None;
    if let Some(addr) = config.metrics_listen {
        let ml = TcpListener::bind(addr).await?;
        metrics_addr = Some(ml.local_addr()?);
        let app = metrics_router(shared.clone());
        let d = drain.clone();
        servers.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(ml, app)
                .with_graceful_shutdown(d.cancelled_owned())
                .await
            {
                tracing::error!(error = %e, "metrics server failed");
            }
        }));
    }

    tracing::info!(
        listen = %local_addr,
        metrics = ?metrics_addr,
        tls = config.tls.is_some(),
        ws_path = %config.ws_path,
        exchange = %config.exchange,
        broker = %redact_amqp_url(&config.amqp_url),
        auth = ?config.auth.source,
        "mpc-relay {} listening",
        env!("CARGO_PKG_VERSION"),
    );
    Ok(Relay {
        local_addr,
        metrics_addr,
        shared,
        drain,
        stop_broker,
        servers,
    })
}

impl Relay {
    /// Stop accepting, give clients `shutdown_grace` to leave on their own,
    /// end the rest with ERROR "server shutting down", clean up their queues,
    /// then close the broker connection.
    pub async fn shutdown(self) {
        let grace = self.shared.config.shutdown_grace;
        self.shared.draining.store(true, Ordering::Release);
        self.drain.cancel();
        tracing::info!(
            active = self.shared.active_connections(),
            ?grace,
            "draining"
        );
        wait_for_idle(&self.shared, grace).await;
        self.shared.shutdown.cancel();
        wait_for_idle(&self.shared, Duration::from_secs(15)).await;
        self.stop_broker.cancel();
        for s in self.servers {
            let _ = tokio::time::timeout(Duration::from_secs(5), s).await;
        }
        // Give the supervisor a moment to close the AMQP connection cleanly.
        let mut rx = self.shared.broker.watch();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while rx.borrow_and_update().connection.is_some() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        tracing::info!("stopped");
    }
}

async fn wait_for_idle(shared: &Shared, max: Duration) {
    let deadline = tokio::time::Instant::now() + max;
    while shared.active_connections() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
