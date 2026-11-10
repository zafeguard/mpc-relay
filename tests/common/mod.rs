//! Shared harness for the integration tests: an in-process relay, a
//! STOMP-over-WebSocket client, raw AMQP helpers, and an optional
//! RabbitMQ management API client.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use lapin::options::{BasicPublishOptions, ExchangeDeclareOptions, ExchangeDeleteOptions};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Connection, ConnectionProperties, ExchangeKind};
use mpc_relay::auth::unix_now;
use mpc_relay::codec::{Decoder, Frame};
use mpc_relay::config::{Config, KeySource};
use mpc_relay::server::Relay;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub const SECRET: &[u8] = b"integration-test-secret-0123456789abcdef";
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// The broker these tests run against, or `None` to skip.
pub fn amqp_url() -> Option<String> {
    std::env::var("MPC_RELAY_TEST_AMQP_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// Skip the calling test unless `MPC_RELAY_TEST_AMQP_URL` is set. Once it is
/// set, an unreachable broker fails the test instead of skipping it.
#[macro_export]
macro_rules! require_broker {
    () => {
        match common::amqp_url() {
            Some(u) => u,
            None => {
                eprintln!(
                    "SKIPPED: set MPC_RELAY_TEST_AMQP_URL to run this test against a real broker"
                );
                return;
            }
        }
    };
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn unique(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}-{}",
        std::process::id(),
        unix_now(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

pub fn session() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}

pub fn token_with(claims: Value) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap()
}

pub fn token(sub: &str) -> String {
    let now = unix_now();
    token_with(json!({"sub": sub, "iat": now, "exp": now + 600}))
}

pub async fn amqp(url: &str) -> Connection {
    mpc_relay::server::init_crypto();
    Connection::connect(
        url,
        ConnectionProperties::default()
            .with_executor(tokio_executor_trait::Tokio::current())
            .with_reactor(tokio_reactor_trait::Tokio),
    )
    .await
    .expect("MPC_RELAY_TEST_AMQP_URL is set but the broker is unreachable")
}

/// Declare the exchange the way the agents do: a durable topic exchange.
pub async fn declare_exchange(conn: &Connection, name: &str) {
    let ch = conn.create_channel().await.unwrap();
    ch.exchange_declare(
        name,
        ExchangeKind::Topic,
        ExchangeDeclareOptions {
            durable: true,
            ..Default::default()
        },
        FieldTable::default(),
    )
    .await
    .unwrap();
    ch.close(200, "ok").await.unwrap();
}

pub async fn delete_exchange(conn: &Connection, name: &str) {
    if let Ok(ch) = conn.create_channel().await {
        let _ = ch
            .exchange_delete(name, ExchangeDeleteOptions::default())
            .await;
        let _ = ch.close(200, "ok").await;
    }
}

pub async fn publish(
    ch: &lapin::Channel,
    exchange: &str,
    key: &str,
    body: &[u8],
    content_type: Option<&str>,
) {
    let mut props = BasicProperties::default();
    if let Some(ct) = content_type {
        props = props.with_content_type(ct.into());
    }
    ch.basic_publish(exchange, key, BasicPublishOptions::default(), body, props)
        .await
        .unwrap()
        .await
        .unwrap();
}

pub fn config(amqp_url: &str, exchange: &str) -> Config {
    let mut c = Config::new(amqp_url, exchange, KeySource::Hmac(SECRET.to_vec()));
    c.listen = "127.0.0.1:0".parse().unwrap();
    c.amqp_connection_name = unique("mpc-relay-test");
    c.shutdown_grace = Duration::ZERO;
    c.drain_delay = Duration::ZERO;
    c
}

/// `MPC_RELAY_TEST_LOG=debug` (any filter) prints the relay's logs.
pub fn init_logs() {
    if let Ok(filter) = std::env::var("MPC_RELAY_TEST_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_test_writer()
            .try_init();
    }
}

/// Start a relay and wait until it reports ready.
pub async fn start(cfg: Config) -> Relay {
    init_logs();
    let relay = mpc_relay::server::start(cfg).await.unwrap();
    for _ in 0..200 {
        if relay.shared.pool.is_ready() {
            return relay;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("relay did not become ready");
}

/// A broker test fixture: a fresh exchange, a raw AMQP connection playing
/// the agents, and a relay in front of it.
pub struct Fixture {
    pub url: String,
    pub exchange: String,
    pub amqp: Connection,
    pub relay: Option<Relay>,
    pub addr: SocketAddr,
}

impl Fixture {
    pub async fn new(url: String) -> Self {
        Self::with_config(url, |_| {}).await
    }

    pub async fn with_config(url: String, tweak: impl FnOnce(&mut Config)) -> Self {
        let exchange = unique("mpc.test");
        let amqp = amqp(&url).await;
        declare_exchange(&amqp, &exchange).await;
        let mut cfg = config(&url, &exchange);
        tweak(&mut cfg);
        let relay = start(cfg).await;
        let addr = relay.local_addr;
        Fixture {
            url,
            exchange,
            amqp,
            relay: Some(relay),
            addr,
        }
    }

    pub fn dest(&self, key: &str) -> String {
        format!("/exchange/{}/{}", self.exchange, key)
    }

    pub async fn connect(&self, sub: &str) -> Stomp {
        Stomp::connect(self.addr, &token(sub))
            .await
            .expect("CONNECTED")
    }

    pub async fn channel(&self) -> lapin::Channel {
        self.amqp.create_channel().await.unwrap()
    }

    pub async fn teardown(mut self) {
        if let Some(r) = self.relay.take() {
            r.shutdown().await;
        }
        delete_exchange(&self.amqp, &self.exchange).await;
        let _ = self.amqp.close(200, "test done").await;
    }
}

/// Probe a queue from an unrelated connection: `Exclusive` if it exists
/// and is exclusive to another connection (RESOURCE_LOCKED), `Gone` if it
/// does not exist (NOT_FOUND), `Open` if a passive declare succeeds.
#[derive(Debug, PartialEq, Eq)]
pub enum QueueProbe {
    Exclusive,
    Gone,
    Open,
}

pub async fn probe_queue(url: &str, queue: &str) -> QueueProbe {
    let conn = amqp(url).await;
    let ch = conn.create_channel().await.unwrap();
    let r = ch
        .queue_declare(
            queue,
            lapin::options::QueueDeclareOptions {
                passive: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await;
    let out = match r {
        Ok(_) => QueueProbe::Open,
        Err(lapin::Error::ProtocolError(e)) => match e.get_id() {
            405 => QueueProbe::Exclusive,
            404 => QueueProbe::Gone,
            other => panic!("unexpected AMQP error {other}: {e}"),
        },
        Err(e) => panic!("unexpected error {e}"),
    };
    let _ = conn.close(200, "probe").await;
    out
}

/// Poll until the queue is gone, or panic.
pub async fn wait_queue_gone(url: &str, queue: &str) {
    for _ in 0..100 {
        if probe_queue(url, queue).await == QueueProbe::Gone {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("queue {queue} still exists");
}

// ---- STOMP client ---------------------------------------------------------

pub struct Stomp {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    dec: Decoder,
    pending: std::collections::VecDeque<Frame>,
    pub protocol: Option<String>,
}

impl Stomp {
    pub async fn open(addr: SocketAddr, protocols: Option<&str>) -> Self {
        let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
        if let Some(p) = protocols {
            req.headers_mut()
                .insert("Sec-WebSocket-Protocol", p.parse().unwrap());
        }
        let (ws, resp) = tokio_tungstenite::connect_async(req)
            .await
            .expect("websocket");
        let protocol = resp
            .headers()
            .get("sec-websocket-protocol")
            .map(|v| v.to_str().unwrap().to_owned());
        Stomp {
            ws,
            dec: Decoder::new(64 * 1024 * 1024),
            pending: Default::default(),
            protocol,
        }
    }

    /// Open and CONNECT; `Err` carries the ERROR frame.
    pub async fn connect(addr: SocketAddr, token: &str) -> Result<Self, Frame> {
        let mut s = Stomp::open(addr, Some("v12.stomp, v11.stomp")).await;
        s.send(
            Frame::new("CONNECT")
                .with_header("accept-version", "1.2")
                .with_header("host", "/")
                .with_header("login", "ignored")
                .with_header("passcode", token)
                .with_header("heart-beat", "10000,10000"),
        )
        .await;
        let f = s.recv().await.expect("a reply to CONNECT");
        match f.command.as_str() {
            "CONNECTED" => Ok(s),
            "ERROR" => Err(f),
            other => panic!("unexpected {other}"),
        }
    }

    pub async fn send(&mut self, frame: Frame) {
        self.send_raw(frame.encode()).await;
    }

    pub async fn send_raw(&mut self, bytes: Vec<u8>) {
        let msg = match String::from_utf8(bytes) {
            Ok(s) => Message::text(s),
            Err(e) => Message::binary(e.into_bytes()),
        };
        self.ws.send(msg).await.unwrap();
    }

    pub async fn send_binary(&mut self, bytes: &[u8]) {
        self.ws.send(Message::binary(bytes.to_vec())).await.unwrap();
    }

    pub async fn send_text(&mut self, text: &str) {
        self.ws.send(Message::text(text.to_owned())).await.unwrap();
    }

    /// Next frame within `TIMEOUT`, `None` if the socket closed first.
    pub async fn recv(&mut self) -> Option<Frame> {
        self.recv_within(TIMEOUT)
            .await
            .expect("timed out waiting for a frame")
    }

    /// `Err(())` on timeout, `Ok(None)` on close.
    pub async fn recv_within(&mut self, t: Duration) -> Result<Option<Frame>, ()> {
        if let Some(f) = self.pending.pop_front() {
            return Ok(Some(f));
        }
        let deadline = tokio::time::Instant::now() + t;
        loop {
            let msg = match tokio::time::timeout_at(deadline, self.ws.next()).await {
                Err(_) => return Err(()),
                Ok(None) | Ok(Some(Err(_))) => return Ok(None),
                Ok(Some(Ok(m))) => m,
            };
            let data = match msg {
                Message::Text(t) => t.as_bytes().to_vec(),
                Message::Binary(b) => b.to_vec(),
                Message::Close(_) => return Ok(None),
                _ => continue,
            };
            self.dec.extend(&data);
            while let Some(f) = self.dec.decode().unwrap() {
                self.pending.push_back(f);
            }
            if let Some(f) = self.pending.pop_front() {
                return Ok(Some(f));
            }
        }
    }

    pub async fn expect(&mut self, command: &str) -> Frame {
        let f = self
            .recv()
            .await
            .unwrap_or_else(|| panic!("socket closed while waiting for {command}"));
        assert_eq!(f.command, command, "expected {command}, got {f:?}");
        f
    }

    /// Expect ERROR with this `message`, then the socket closing.
    pub async fn expect_error(&mut self, message: &str) -> Frame {
        let f = self.expect("ERROR").await;
        assert_eq!(
            f.header("message"),
            Some(message),
            "ERROR body: {:?}",
            String::from_utf8_lossy(&f.body)
        );
        self.expect_closed().await;
        f
    }

    pub async fn expect_closed(&mut self) {
        match self.recv_within(TIMEOUT).await {
            Ok(None) => {}
            Ok(Some(f)) => panic!("expected close, got {f:?}"),
            Err(()) => panic!("socket not closed"),
        }
    }

    /// Nothing arrives within `t`.
    pub async fn expect_silence(&mut self, t: Duration) {
        if let Ok(f) = self.recv_within(t).await {
            panic!("expected nothing, got {f:?}");
        }
    }

    pub async fn subscribe(
        &mut self,
        id: &str,
        destination: &str,
        queue: &str,
        receipt: Option<&str>,
    ) {
        let mut f = Frame::new("SUBSCRIBE")
            .with_header("id", id)
            .with_header("destination", destination)
            .with_header("ack", "auto")
            .with_header("x-queue-name", queue);
        if let Some(r) = receipt {
            f = f.with_header("receipt", r);
        }
        self.send(f).await;
        if let Some(r) = receipt {
            let got = self.expect("RECEIPT").await;
            assert_eq!(got.header("receipt-id"), Some(r));
        }
    }

    pub async fn unsubscribe(&mut self, id: &str, receipt: Option<&str>) {
        let mut f = Frame::new("UNSUBSCRIBE").with_header("id", id);
        if let Some(r) = receipt {
            f = f.with_header("receipt", r);
        }
        self.send(f).await;
        if let Some(r) = receipt {
            let got = self.expect("RECEIPT").await;
            assert_eq!(got.header("receipt-id"), Some(r));
        }
    }

    pub async fn publish(
        &mut self,
        destination: &str,
        body: &[u8],
        content_type: Option<&str>,
        receipt: Option<&str>,
    ) {
        let mut f = Frame::new("SEND")
            .with_header("destination", destination)
            .with_header("content-length", body.len().to_string());
        if let Some(ct) = content_type {
            f = f.with_header("content-type", ct);
        }
        if let Some(r) = receipt {
            f = f.with_header("receipt", r);
        }
        self.send(f.with_body(body.to_vec())).await;
        if let Some(r) = receipt {
            let got = self.expect("RECEIPT").await;
            assert_eq!(got.header("receipt-id"), Some(r));
        }
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}

// ---- management API ---------------------------------------------------------

/// RabbitMQ management API, when `MPC_RELAY_TEST_MGMT_URL` is set
/// (e.g. `http://mpc:mpc@127.0.0.1:15681`). Used to assert queue flags and
/// bindings, which AMQP alone cannot list.
pub struct Mgmt {
    base: String,
    user: String,
    pass: String,
    http: reqwest::Client,
}

pub fn mgmt() -> Option<Mgmt> {
    let raw = std::env::var("MPC_RELAY_TEST_MGMT_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    let url = reqwest::Url::parse(&raw).expect("MPC_RELAY_TEST_MGMT_URL");
    let user = url.username().to_owned();
    let pass = url.password().unwrap_or_default().to_owned();
    let mut base = url.clone();
    base.set_username("").unwrap();
    base.set_password(None).unwrap();
    mpc_relay::server::init_crypto();
    Some(Mgmt {
        base: base.as_str().trim_end_matches('/').to_owned(),
        user,
        pass,
        http: reqwest::Client::new(),
    })
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

impl Mgmt {
    async fn get(&self, path: &str) -> (u16, Value) {
        let r = self
            .http
            .get(format!("{}{}", self.base, path))
            .basic_auth(&self.user, Some(&self.pass))
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let body = r.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    pub async fn queue(&self, vhost: &str, name: &str) -> Option<Value> {
        let (status, v) = self
            .get(&format!("/api/queues/{}/{}", enc(vhost), enc(name)))
            .await;
        (status == 200).then_some(v)
    }

    /// Routing keys binding `queue` to `exchange`, sorted.
    pub async fn binding_keys(&self, vhost: &str, queue: &str, exchange: &str) -> Vec<String> {
        let (_, v) = self
            .get(&format!(
                "/api/queues/{}/{}/bindings",
                enc(vhost),
                enc(queue)
            ))
            .await;
        let mut keys: Vec<String> = v
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|b| b["source"] == exchange)
            .map(|b| b["routing_key"].as_str().unwrap().to_owned())
            .collect();
        keys.sort();
        keys
    }

    /// Consumers on a queue, or `None` when the broker has management
    /// statistics disabled (RabbitMQ 4 can run that way, and then neither
    /// `/api/consumers` nor a queue's consumer count is available).
    pub async fn consumer_count(&self, vhost: &str, queue: &str) -> Option<usize> {
        let (status, v) = self.get(&format!("/api/consumers/{}", enc(vhost))).await;
        if status != 200 {
            return None;
        }
        Some(
            v.as_array()?
                .iter()
                .filter(|c| c["queue"]["name"] == queue)
                .count(),
        )
    }

    /// Poll until the queue has `want` consumers (the count is
    /// statistics-based and lags by up to an emission interval). `None` if
    /// the broker has statistics disabled.
    pub async fn wait_consumer_count(
        &self,
        vhost: &str,
        queue: &str,
        want: usize,
    ) -> Option<usize> {
        let mut n = self.consumer_count(vhost, queue).await;
        for _ in 0..120 {
            if n.is_none_or(|n| n == want) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            n = self.consumer_count(vhost, queue).await;
        }
        n
    }

    async fn send(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> u16 {
        let mut req = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .basic_auth(&self.user, Some(&self.pass));
        if let Some(b) = body {
            req = req.json(&b);
        }
        req.send().await.unwrap().status().as_u16()
    }

    /// A broker user with full permissions on `vhost`, so a test can own
    /// (and later force-close) exactly the connections made as it.
    pub async fn create_user(&self, vhost: &str, name: &str, password: &str) {
        let s = self
            .send(
                reqwest::Method::PUT,
                &format!("/api/users/{}", enc(name)),
                Some(json!({"password": password, "tags": ""})),
            )
            .await;
        assert!(s == 201 || s == 204, "create user: HTTP {s}");
        let s = self
            .send(
                reqwest::Method::PUT,
                &format!("/api/permissions/{}/{}", enc(vhost), enc(name)),
                Some(json!({"configure": ".*", "write": ".*", "read": ".*"})),
            )
            .await;
        assert!(s == 201 || s == 204, "set permissions: HTTP {s}");
    }

    pub async fn delete_user(&self, name: &str) {
        self.send(
            reqwest::Method::DELETE,
            &format!("/api/users/{}", enc(name)),
            None,
        )
        .await;
    }

    /// Force-close every connection made as `user`. Works with management
    /// statistics disabled, unlike listing `/api/connections`.
    pub async fn close_user_connections(&self, user: &str) -> bool {
        for _ in 0..50 {
            let (_, v) = self
                .get(&format!("/api/connections/username/{}", enc(user)))
                .await;
            if v.as_array().is_some_and(|a| !a.is_empty()) {
                let s = self
                    .send(
                        reqwest::Method::DELETE,
                        &format!("/api/connections/username/{}", enc(user)),
                        None,
                    )
                    .await;
                return s == 204 || s == 200;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
}

impl Mgmt {
    /// Broker-side names of the connections made as `user`. Works with
    /// management statistics disabled.
    pub async fn connection_names_of(&self, user: &str) -> Vec<String> {
        let (_, v) = self
            .get(&format!("/api/connections/username/{}", enc(user)))
            .await;
        let mut names: Vec<String> = v
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|c| c["name"].as_str().map(str::to_owned))
            .collect();
        names.sort();
        names
    }

    /// Force-close one connection by its broker-side name. `Err` carries
    /// the request, status and body of the last attempt, so a failure says
    /// why.
    ///
    /// Retries on 404. The names come from `/api/connections/username/..`,
    /// which reads the broker's connection-tracking table and lists a
    /// connection the moment it opens. With management statistics enabled
    /// (the default), `DELETE /api/connections/{name}` instead looks the
    /// connection up in the statistics database, which learns of it only at
    /// the next statistics emission (`collect_statistics_interval`, 5 s by
    /// default). Until then the DELETE answers 404 for a connection that
    /// exists. With statistics disabled both read the tracking table, which
    /// is why this only showed on a stats-enabled broker.
    pub async fn close_connection(&self, name: &str) -> Result<(), String> {
        let path = format!("/api/connections/{}", enc(name));
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(15);
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let r = self
                .http
                .delete(format!("{}{}", self.base, path))
                .basic_auth(&self.user, Some(&self.pass))
                .header("X-Reason", "test: simulated loss of one pooled connection")
                .send()
                .await
                .map_err(|e| format!("DELETE {path}: {e}"))?;
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            if status.is_success() {
                return Ok(());
            }
            if status != reqwest::StatusCode::NOT_FOUND || tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "DELETE {path} (connection {name:?}) -> {status}: {body} \
                     (attempt {attempts}, {:?} after the first)",
                    started.elapsed()
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Wait until `user` has exactly `n` connections; returns their names.
    pub async fn wait_connections_of(&self, user: &str, n: usize) -> Vec<String> {
        let mut names = Vec::new();
        for _ in 0..100 {
            names = self.connection_names_of(user).await;
            if names.len() == n {
                return names;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("expected {n} connections for {user}, saw {names:?}");
    }
}

/// `url` with its credentials replaced.
pub fn with_credentials(url: &str, user: &str, pass: &str) -> String {
    let mut u = url::Url::parse(url).unwrap();
    u.set_username(user).unwrap();
    u.set_password(Some(pass)).unwrap();
    u.to_string()
}

/// The vhost in an AMQP URL (`%2f` -> `/`).
pub fn vhost(amqp_url: &str) -> String {
    amqp_url
        .parse::<lapin::uri::AMQPUri>()
        .map(|u| u.vhost)
        .unwrap_or_else(|_| "/".into())
}

// ---- the relay as a separate process ----------------------------------------

/// The real `mpc-relay` binary, as a child process: its own AMQP
/// connections, its own exclusivity registry, real signals.
pub struct RelayProcess {
    child: std::process::Child,
    pub addr: SocketAddr,
}

impl RelayProcess {
    /// Start the binary with a clean environment plus `extra`, and wait
    /// for `/readyz`.
    pub async fn spawn(amqp_url: &str, exchange: &str, extra: &[(&str, &str)]) -> Self {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_mpc-relay"));
        cmd.env_clear()
            .env("MPC_RELAY_LISTEN", addr.to_string())
            .env("MPC_RELAY_AMQP_URL", amqp_url)
            .env("MPC_RELAY_EXCHANGE", exchange)
            .env("MPC_RELAY_JWT_SECRET", std::str::from_utf8(SECRET).unwrap())
            .env("MPC_RELAY_AMQP_CONNECTION_NAME", unique("mpc-relay-proc"));
        for (k, v) in extra {
            cmd.env(k, v);
        }
        match std::env::var("MPC_RELAY_TEST_LOG") {
            Ok(filter) => {
                cmd.env("RUST_LOG", filter);
            }
            Err(_) => {
                cmd.stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
        }
        let child = cmd.spawn().expect("spawn mpc-relay");
        let mut p = RelayProcess { child, addr };
        let http = reqwest::Client::new();
        for _ in 0..200 {
            if let Ok(r) = http.get(format!("http://{addr}/readyz")).send().await {
                if r.status() == 200 {
                    return p;
                }
            }
            if let Ok(Some(status)) = p.child.try_wait() {
                panic!("mpc-relay exited during startup: {status}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("mpc-relay process did not become ready");
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn sigterm(&self) {
        let ok = std::process::Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()
            .expect("run kill")
            .success();
        assert!(ok, "kill -TERM failed");
    }

    /// Wait for the process to exit, up to `max`.
    pub async fn wait_exit(&mut self, max: Duration) -> Option<std::process::ExitStatus> {
        let deadline = tokio::time::Instant::now() + max;
        loop {
            if let Ok(Some(s)) = self.child.try_wait() {
                return Some(s);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
