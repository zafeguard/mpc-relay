//! The AMQP connection pool.
//!
//! Every client session needs one AMQP channel, and one connection carries
//! at most `channel_max` channels (RabbitMQ's default is 2047). So the relay
//! keeps a pool of connections ("slots"):
//!
//! * Slot 0 is opened at startup; the others are opened lazily, when every
//!   live connection is full.
//! * A session is placed on the first live connection with a free channel,
//!   leaving [`CHANNEL_MARGIN`] channels per connection for the relay's own
//!   short-lived channels (the exchange check, cleanup).
//! * The pool is capped so its total capacity matches
//!   `MPC_RELAY_MAX_CONNECTIONS`: `ceil(max clients / per-connection
//!   capacity)` connections, unless `MPC_RELAY_AMQP_MAX_CONNECTIONS`
//!   overrides it.
//! * Each slot is supervised on its own: it checks the exchange with a
//!   passive declare (the agents own its declaration; the relay never
//!   declares it), and when its connection is lost it publishes that on its
//!   own `watch` channel - which ends exactly the sessions placed on it - and
//!   reconnects with capped exponential backoff, independently of the
//!   others.
//!
//! The pool is ready while at least one connection is up and sees the
//! exchange.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lapin::options::ExchangeDeclareOptions;
use lapin::protocol::{AMQPErrorKind, AMQPSoftError};
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
/// Channels per connection kept back from sessions, for the relay's own
/// short-lived channels: the periodic exchange check, and the fallback
/// channel cleanup opens when a session's own channel has died.
pub const CHANNEL_MARGIN: usize = 2;
/// Default cap on sessions per pooled connection: none beyond the
/// broker's `channel_max` minus [`CHANNEL_MARGIN`].
///
/// Measured, one relay with 10 000 sessions (README, Scaling): capping at
/// 512, 256 or 64 sessions per connection did not lower CPU per message, and
/// each extra connection costs ~8 MiB, because lapin allocates two zeroed
/// buffers of 32 x `frame_max` per connection. The cap is still useful to
/// bound how many sessions one AMQP connection's loss can drop.
pub const DEFAULT_CHANNELS_PER_CONNECTION: usize = u16::MAX as usize;

/// Longest a CONNECT waits for a pooled connection that is still
/// connecting.
const ACQUIRE_WAIT: Duration = Duration::from_secs(10);

/// The state of one pooled connection.
#[derive(Clone, Default)]
pub struct SlotState {
    pub connection: Option<Arc<Connection>>,
    /// Incremented on every successful connect of this slot.
    pub generation: u64,
    pub exchange_ok: bool,
    /// Sessions this connection may carry: negotiated `channel_max` minus
    /// [`CHANNEL_MARGIN`].
    pub capacity: usize,
    /// Failed connection attempts since the slot was last connected.
    pub failures: u64,
}

impl SlotState {
    pub fn connected(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|c| c.status().connected())
    }

    pub fn ready(&self) -> bool {
        self.exchange_ok && self.connected()
    }
}

pub struct Slot {
    pub index: usize,
    state: watch::Sender<SlotState>,
    in_use: AtomicUsize,
}

impl Slot {
    pub fn state(&self) -> SlotState {
        self.state.borrow().clone()
    }

    pub fn watch(&self) -> watch::Receiver<SlotState> {
        self.state.subscribe()
    }

    /// Sessions currently placed on this connection.
    pub fn sessions(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }

    fn try_reserve(&self, capacity: usize) -> bool {
        let mut cur = self.in_use.load(Ordering::Acquire);
        loop {
            if cur >= capacity {
                return false;
            }
            match self
                .in_use
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// A session's place on a pooled connection. Dropping it frees the place.
pub struct Lease {
    slot: Arc<Slot>,
    metrics: Arc<Metrics>,
    pub connection: Arc<Connection>,
    pub generation: u64,
}

impl Lease {
    pub fn slot(&self) -> &Arc<Slot> {
        &self.slot
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.slot.in_use.fetch_sub(1, Ordering::AcqRel);
        self.metrics.amqp_channels_in_use.dec();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// No pooled connection is up with the exchange present.
    Unavailable,
    /// Every connection the pool may open is full.
    Full,
}

/// A point-in-time view of one slot, for diagnostics and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotInfo {
    pub index: usize,
    pub connected: bool,
    pub exchange_ok: bool,
    pub generation: u64,
    pub capacity: usize,
    pub sessions: usize,
}

#[derive(Clone, Debug)]
pub struct PoolSettings {
    pub amqp_url: String,
    pub connection_name: String,
    pub exchange: String,
    /// `MPC_RELAY_MAX_CONNECTIONS`: the client count the pool must carry.
    pub max_clients: usize,
    /// `MPC_RELAY_AMQP_MAX_CONNECTIONS`: overrides the derived cap.
    pub max_connections: Option<usize>,
    /// `MPC_RELAY_AMQP_CHANNELS_PER_CONNECTION`: sessions per connection,
    /// at most (and never more than `channel_max` minus the margin).
    pub channels_per_connection: usize,
}

pub struct Pool {
    settings: PoolSettings,
    slots: Mutex<Vec<Arc<Slot>>>,
    metrics: Arc<Metrics>,
    stop: CancellationToken,
    /// Capacity of the most recently connected slot: what the derived cap
    /// divides by. Zero until a connection has been negotiated.
    known_capacity: AtomicUsize,
    connected: AtomicUsize,
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

impl Pool {
    /// Start the pool with its first connection. Slots run until `stop` is
    /// cancelled, then close their connections.
    pub fn start(
        settings: PoolSettings,
        metrics: Arc<Metrics>,
        stop: CancellationToken,
    ) -> Arc<Self> {
        let pool = Arc::new(Pool {
            settings,
            slots: Mutex::new(Vec::new()),
            metrics,
            stop,
            known_capacity: AtomicUsize::new(0),
            connected: AtomicUsize::new(0),
        });
        {
            let mut slots = pool.slots.lock().expect("pool lock");
            pool.spawn_slot(&mut slots);
        }
        pool
    }

    fn spawn_slot(self: &Arc<Self>, slots: &mut Vec<Arc<Slot>>) -> Arc<Slot> {
        let (tx, _) = watch::channel(SlotState::default());
        let slot = Arc::new(Slot {
            index: slots.len(),
            state: tx,
            in_use: AtomicUsize::new(0),
        });
        slots.push(slot.clone());
        self.metrics.amqp_pool_size.set(slots.len() as i64);
        if slot.index > 0 {
            tracing::info!(
                slot = slot.index,
                "every pooled AMQP connection is full; opening another"
            );
        }
        tokio::spawn(self.clone().supervise(slot.clone()));
        slot
    }

    /// Most connections this pool will open.
    pub fn cap(&self) -> usize {
        if let Some(n) = self.settings.max_connections {
            return n;
        }
        match self.known_capacity.load(Ordering::Acquire) {
            0 => 1,
            per => self.settings.max_clients.div_ceil(per).max(1),
        }
    }

    /// Ready while at least one connection is up and sees the exchange.
    pub fn is_ready(&self) -> bool {
        self.slots
            .lock()
            .expect("pool lock")
            .iter()
            .any(|s| s.state.borrow().ready())
    }

    /// Open connections right now.
    pub fn connected_count(&self) -> usize {
        self.connected.load(Ordering::Acquire)
    }

    pub fn snapshot(&self) -> Vec<SlotInfo> {
        self.slots
            .lock()
            .expect("pool lock")
            .iter()
            .map(|s| {
                let st = s.state.borrow();
                SlotInfo {
                    index: s.index,
                    connected: st.connected(),
                    exchange_ok: st.exchange_ok,
                    generation: st.generation,
                    capacity: st.capacity,
                    sessions: s.sessions(),
                }
            })
            .collect()
    }

    /// Place a session on a pooled connection with a free channel, opening
    /// another connection if every live one is full and the cap allows.
    pub async fn acquire(self: &Arc<Self>) -> Result<Lease, AcquireError> {
        enum Next {
            Wait(watch::Receiver<SlotState>),
            Fail(AcquireError),
        }
        let deadline = tokio::time::Instant::now() + ACQUIRE_WAIT;
        loop {
            let next = {
                let mut slots = self.slots.lock().expect("pool lock");
                let mut any_ready = false;
                let mut pending: Option<watch::Receiver<SlotState>> = None;
                for s in slots.iter() {
                    // Subscribe before reading, so a change after this read
                    // is never missed by the wait below.
                    let rx = s.watch();
                    let st = rx.borrow().clone();
                    if st.ready() {
                        any_ready = true;
                        if s.try_reserve(st.capacity) {
                            self.metrics.amqp_channels_in_use.inc();
                            return Ok(Lease {
                                slot: s.clone(),
                                metrics: self.metrics.clone(),
                                connection: st.connection.clone().expect("ready implies connected"),
                                generation: st.generation,
                            });
                        }
                    } else if pending.is_none() {
                        pending = Some(rx);
                    }
                }
                if !any_ready {
                    // The broker is down (or the exchange is missing) for
                    // every connection: no point waiting or opening more.
                    Next::Fail(AcquireError::Unavailable)
                } else if let Some(rx) = pending {
                    // A connection that is still (re)connecting will have
                    // room once it is up; opening yet another would not help.
                    Next::Wait(rx)
                } else if slots.len() < self.cap() {
                    let slot = self.spawn_slot(&mut slots);
                    Next::Wait(slot.watch())
                } else {
                    Next::Fail(AcquireError::Full)
                }
            };
            match next {
                Next::Fail(e) => return Err(e),
                Next::Wait(mut rx) => {
                    if tokio::time::timeout_at(deadline, rx.changed())
                        .await
                        .is_err()
                    {
                        return Err(AcquireError::Full);
                    }
                }
            }
        }
    }

    /// Wait until every slot has closed its connection (after `stop`).
    pub async fn wait_closed(&self, max: Duration) {
        let deadline = tokio::time::Instant::now() + max;
        while self.connected_count() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn set_connected(&self, delta: isize) {
        let now = if delta > 0 {
            self.connected.fetch_add(1, Ordering::AcqRel) + 1
        } else {
            self.connected.fetch_sub(1, Ordering::AcqRel) - 1
        };
        self.metrics.amqp_connections.set(now as i64);
        self.metrics.broker_connected.set(i64::from(now > 0));
    }

    async fn supervise(self: Arc<Self>, slot: Arc<Slot>) {
        let url = &self.settings.amqp_url;
        let target = redact_amqp_url(url);
        let name = format!("{}#{}", self.settings.connection_name, slot.index);
        let index = slot.index;
        let mut backoff = BACKOFF_INITIAL;
        let mut generation = 0u64;
        loop {
            if self.stop.is_cancelled() {
                return;
            }
            let props = ConnectionProperties::default()
                .with_connection_name(name.clone().into())
                .with_executor(tokio_executor_trait::Tokio::current())
                .with_reactor(tokio_reactor_trait::Tokio);
            let attempt = tokio::select! {
                r = tokio::time::timeout(CONNECT_TIMEOUT, Connection::connect(url, props)) => r,
                _ = self.stop.cancelled() => return,
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
                            tracing::warn!(slot = index, error = %e, "AMQP connection error");
                            lost.notify_one();
                        });
                    }
                    let channel_max = match conn.configuration().channel_max() {
                        0 => usize::from(u16::MAX),
                        n => usize::from(n),
                    };
                    let capacity = channel_max
                        .saturating_sub(CHANNEL_MARGIN)
                        .min(self.settings.channels_per_connection)
                        .max(1);
                    self.known_capacity.store(capacity, Ordering::Release);
                    tracing::info!(broker = %target, slot = index, generation, channel_max, capacity, cap = self.cap(), "connected to broker");
                    self.set_connected(1);
                    slot.state.send_replace(SlotState {
                        connection: Some(conn.clone()),
                        generation,
                        exchange_ok: false,
                        capacity,
                        failures: 0,
                    });
                    let stopped = self.hold(&slot, &conn, &lost).await;
                    if stopped {
                        let _ = tokio::time::timeout(
                            OP_TIMEOUT,
                            conn.close(200, "mpc-relay shutting down"),
                        )
                        .await;
                    }
                    slot.state.send_replace(SlotState {
                        connection: None,
                        generation,
                        exchange_ok: false,
                        capacity,
                        failures: 0,
                    });
                    self.set_connected(-1);
                    if stopped {
                        tracing::info!(slot = index, "broker connection closed");
                        return;
                    }
                    tracing::warn!(broker = %target, slot = index, "lost broker connection; reconnecting");
                }
                Ok(Err(e)) => {
                    tracing::warn!(broker = %target, slot = index, error = %e, retry_in = ?backoff, "broker connection failed");
                    slot.state.send_modify(|s| s.failures += 1);
                }
                Err(_) => {
                    tracing::warn!(broker = %target, slot = index, retry_in = ?backoff, "broker connection attempt timed out");
                    slot.state.send_modify(|s| s.failures += 1);
                }
            }
            let jittered = jitter(backoff);
            tokio::select! {
                _ = tokio::time::sleep(jittered) => {}
                _ = self.stop.cancelled() => return,
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    /// Hold a live connection: keep its exchange check current, return when
    /// it is lost (`false`) or the relay stops (`true`).
    async fn hold(&self, slot: &Slot, conn: &Connection, lost: &Notify) -> bool {
        let exchange = &self.settings.exchange;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut next_check = tokio::time::Instant::now();
        loop {
            if tokio::time::Instant::now() >= next_check {
                let ok = match exchange_exists(conn, exchange).await {
                    ExchangeCheck::Exists => true,
                    ExchangeCheck::Missing => false,
                    ExchangeCheck::Inconclusive(why) => {
                        // Keep what we knew; ask again soon.
                        tracing::warn!(slot = slot.index, exchange, why, "exchange check inconclusive (broker slow?); keeping the previous state");
                        next_check = tokio::time::Instant::now() + EXCHANGE_RECHECK_MISSING;
                        slot.state.borrow().exchange_ok
                    }
                };
                let changed = slot.state.send_if_modified(|s| {
                    let changed = s.exchange_ok != ok;
                    s.exchange_ok = ok;
                    changed
                });
                if changed {
                    if ok {
                        tracing::info!(slot = slot.index, exchange, "exchange exists; ready");
                    } else {
                        tracing::warn!(
                            slot = slot.index,
                            exchange,
                            "exchange does not exist (the agents declare it); not ready"
                        );
                    }
                }
                let at_least = tokio::time::Instant::now()
                    + if ok {
                        EXCHANGE_RECHECK_PRESENT
                    } else {
                        EXCHANGE_RECHECK_MISSING
                    };
                if next_check < tokio::time::Instant::now() {
                    next_check = at_least;
                }
            }
            tokio::select! {
                _ = lost.notified() => return false,
                _ = self.stop.cancelled() => return true,
                _ = tick.tick() => {
                    if !conn.status().connected() {
                        return false;
                    }
                }
            }
        }
    }
}

/// What a passive exchange declare established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeCheck {
    Exists,
    /// The broker answered 404 NOT_FOUND.
    Missing,
    /// No definite answer: a timeout, or some other error. A slow, busy
    /// broker produces these, and treating them as "missing" flips
    /// `/readyz` off on every relay at the worst moment.
    Inconclusive(String),
}

/// Classify the outcome of a passive declare (`None`: it timed out).
pub fn classify_exchange_check(outcome: Option<lapin::Result<()>>) -> ExchangeCheck {
    match outcome {
        Some(Ok(())) => ExchangeCheck::Exists,
        Some(Err(lapin::Error::ProtocolError(e)))
            if *e.kind() == AMQPErrorKind::Soft(AMQPSoftError::NOTFOUND) =>
        {
            ExchangeCheck::Missing
        }
        Some(Err(e)) => ExchangeCheck::Inconclusive(e.to_string()),
        None => ExchangeCheck::Inconclusive("timed out".into()),
    }
}

/// Passive declare on a throwaway channel: the broker closes that channel
/// with 404 if the exchange is missing, which is why it is not a client's.
pub async fn exchange_exists(conn: &Connection, exchange: &str) -> ExchangeCheck {
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
    classify_exchange_check(tokio::time::timeout(OP_TIMEOUT, check).await.ok())
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
