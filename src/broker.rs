//! The one long-lived AMQP connection, and its supervision.
//!
//! A supervisor task connects, checks with a passive declare that the
//! exchange exists (the agents own its declaration; the relay never declares
//! it), publishes the state on a `watch` channel, and reconnects with capped
//! exponential backoff when the connection is lost. Every client session
//! watches that channel: a lost connection, or a new one replacing it, ends
//! the session with ERROR "broker unavailable", because the channel and the
//! exclusive queues it had lived on the old connection.

use std::sync::Arc;
use std::time::Duration;

use lapin::options::ExchangeDeclareOptions;
use lapin::types::FieldTable;
use lapin::{Connection, ConnectionProperties, ExchangeKind};
use tokio::sync::{watch, Notify};
use tokio_util::sync::CancellationToken;

use crate::metrics::Metrics;

const BACKOFF_INITIAL: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const OP_TIMEOUT: Duration = Duration::from_secs(10);
/// How often to re-check the exchange while it is missing, and while it is
/// present.
const EXCHANGE_RECHECK_MISSING: Duration = Duration::from_secs(2);
const EXCHANGE_RECHECK_PRESENT: Duration = Duration::from_secs(30);

#[derive(Clone, Default)]
pub struct BrokerState {
    pub connection: Option<Arc<Connection>>,
    /// Incremented on every successful connect.
    pub generation: u64,
    pub exchange_ok: bool,
}

impl BrokerState {
    pub fn ready(&self) -> bool {
        self.exchange_ok
            && self
                .connection
                .as_ref()
                .is_some_and(|c| c.status().connected())
    }
}

pub struct Broker {
    state: watch::Sender<BrokerState>,
}

/// `host:port/vhost` with credentials removed, for logs.
pub fn redact_amqp_url(url: &str) -> String {
    match url.parse::<lapin::uri::AMQPUri>() {
        Ok(u) => format!(
            "{}://{}:{}/{}",
            match u.scheme {
                lapin::uri::AMQPScheme::AMQP => "amqp",
                lapin::uri::AMQPScheme::AMQPS => "amqps",
            },
            u.authority.host,
            u.authority.port,
            u.vhost
        ),
        Err(_) => "<unparseable AMQP URL>".into(),
    }
}

impl Broker {
    /// Start the supervisor. It runs until `stop` is cancelled, then closes
    /// the connection.
    pub fn start(
        amqp_url: String,
        connection_name: String,
        exchange: String,
        metrics: Arc<Metrics>,
        stop: CancellationToken,
    ) -> Arc<Self> {
        let (tx, _) = watch::channel(BrokerState::default());
        let broker = Arc::new(Broker { state: tx });
        tokio::spawn(
            broker
                .clone()
                .supervise(amqp_url, connection_name, exchange, metrics, stop),
        );
        broker
    }

    pub fn watch(&self) -> watch::Receiver<BrokerState> {
        self.state.subscribe()
    }

    pub fn state(&self) -> BrokerState {
        self.state.borrow().clone()
    }

    pub fn is_ready(&self) -> bool {
        self.state.borrow().ready()
    }

    /// The connection and its generation, if the broker is ready for
    /// clients.
    pub fn ready_connection(&self) -> Option<(Arc<Connection>, u64)> {
        let s = self.state.borrow();
        if s.ready() {
            s.connection.clone().map(|c| (c, s.generation))
        } else {
            None
        }
    }

    async fn supervise(
        self: Arc<Self>,
        url: String,
        connection_name: String,
        exchange: String,
        metrics: Arc<Metrics>,
        stop: CancellationToken,
    ) {
        let target = redact_amqp_url(&url);
        let mut backoff = BACKOFF_INITIAL;
        let mut generation = 0u64;
        loop {
            if stop.is_cancelled() {
                return;
            }
            let props = ConnectionProperties::default()
                .with_connection_name(connection_name.clone().into())
                .with_executor(tokio_executor_trait::Tokio::current())
                .with_reactor(tokio_reactor_trait::Tokio);
            let attempt = tokio::select! {
                r = tokio::time::timeout(CONNECT_TIMEOUT, Connection::connect(&url, props)) => r,
                _ = stop.cancelled() => return,
            };
            match attempt {
                Ok(Ok(conn)) => {
                    backoff = BACKOFF_INITIAL;
                    generation += 1;
                    let conn = Arc::new(conn);
                    let lost = Arc::new(Notify::new());
                    {
                        let lost = lost.clone();
                        conn.on_error(move |e| {
                            tracing::warn!(error = %e, "AMQP connection error");
                            lost.notify_one();
                        });
                    }
                    let channel_max = conn.configuration().channel_max();
                    tracing::info!(broker = %target, generation, channel_max, "connected to broker");
                    metrics.broker_connected.set(1);
                    self.state.send_replace(BrokerState {
                        connection: Some(conn.clone()),
                        generation,
                        exchange_ok: false,
                    });
                    let stopped = self.hold(&conn, &exchange, &lost, &stop).await;
                    if stopped {
                        let _ = tokio::time::timeout(OP_TIMEOUT, conn.close(200, "mpc-relay shutting down")).await;
                    }
                    metrics.broker_connected.set(0);
                    self.state.send_replace(BrokerState {
                        connection: None,
                        generation,
                        exchange_ok: false,
                    });
                    if stopped {
                        tracing::info!("broker connection closed");
                        return;
                    }
                    tracing::warn!(broker = %target, "lost broker connection; reconnecting");
                }
                Ok(Err(e)) => {
                    tracing::warn!(broker = %target, error = %e, retry_in = ?backoff, "broker connection failed")
                }
                Err(_) => {
                    tracing::warn!(broker = %target, retry_in = ?backoff, "broker connection attempt timed out")
                }
            }
            let jittered = jitter(backoff);
            tokio::select! {
                _ = tokio::time::sleep(jittered) => {}
                _ = stop.cancelled() => return,
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    /// Hold a live connection: keep the exchange check current, return when
    /// the connection is lost (`false`) or the relay stops (`true`).
    async fn hold(
        &self,
        conn: &Connection,
        exchange: &str,
        lost: &Notify,
        stop: &CancellationToken,
    ) -> bool {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut next_check = tokio::time::Instant::now();
        loop {
            if tokio::time::Instant::now() >= next_check {
                let ok = exchange_exists(conn, exchange).await;
                let changed = self.state.send_if_modified(|s| {
                    let changed = s.exchange_ok != ok;
                    s.exchange_ok = ok;
                    changed
                });
                if changed {
                    if ok {
                        tracing::info!(exchange, "exchange exists; ready");
                    } else {
                        tracing::warn!(exchange, "exchange does not exist (the agents declare it); not ready");
                    }
                }
                next_check = tokio::time::Instant::now()
                    + if ok {
                        EXCHANGE_RECHECK_PRESENT
                    } else {
                        EXCHANGE_RECHECK_MISSING
                    };
            }
            tokio::select! {
                _ = lost.notified() => return false,
                _ = stop.cancelled() => return true,
                _ = tick.tick() => {
                    if !conn.status().connected() {
                        return false;
                    }
                }
            }
        }
    }
}

/// Passive declare on a throwaway channel: the broker closes that channel
/// with 404 if the exchange is missing, which is why it is not a client's.
pub async fn exchange_exists(conn: &Connection, exchange: &str) -> bool {
    let check = async {
        let ch = conn.create_channel().await?;
        let r = ch
            .exchange_declare(
                exchange,
                ExchangeKind::Topic,
                ExchangeDeclareOptions {
                    passive: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await;
        if r.is_ok() {
            let _ = ch.close(200, "exchange check done").await;
        }
        r
    };
    match tokio::time::timeout(OP_TIMEOUT, check).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::debug!(exchange, error = %e, "passive exchange declare failed");
            false
        }
        Err(_) => false,
    }
}

/// Up to +/-20% so a fleet of relays does not reconnect in lockstep.
fn jitter(d: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.subsec_nanos())
        .unwrap_or(0);
    let factor = 0.8 + (nanos % 1000) as f64 / 2500.0;
    d.mul_f64(factor)
}
