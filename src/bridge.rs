//! One client connection: a STOMP session bridged onto one AMQP channel.
//!
//! Three tasks per connection:
//!
//! * the **reader** (this module's `Session`) decodes frames and acts on them
//!   strictly in order. Each frame's broker-side effects (queue declared,
//!   binding made, consumer started or cancelled, publish sent) complete
//!   before the next frame is looked at, so a RECEIPT vouches for every
//!   earlier frame on the connection as well as its own.
//! * the **dispatcher** owns the AMQP consumers - one per subscription id,
//!   as RabbitMQ Web-STOMP creates them - and merges their deliveries back
//!   into channel order (see [`Dispatcher`]).
//! * the **writer** owns the WebSocket sink. It writes frames, acks each
//!   delivery after its MESSAGE frame is written (so the broker's prefetch
//!   window is the backpressure towards a slow client), and sends pings.

use std::collections::{HashMap, HashSet};
use std::future::{pending, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, Stream, StreamExt};
use lapin::message::Delivery;
use lapin::options::{
    BasicAckOptions, BasicCancelOptions, BasicConsumeOptions, BasicPublishOptions, BasicQosOptions,
    ConfirmSelectOptions, QueueBindOptions, QueueDeclareOptions, QueueDeleteOptions,
};
use lapin::protocol::{AMQPErrorKind, AMQPSoftError};
use lapin::publisher_confirm::Confirmation;
use lapin::types::FieldTable;
use lapin::{acker::Acker, BasicProperties, Channel, Connection};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::acl;
use crate::auth::{Authenticator, Identity};
use crate::broker::Broker;
use crate::codec::{CodecError, Decoder, Frame};
use crate::config::Config;
use crate::metrics::Metrics;

/// Frames queued towards the writer before producers wait.
const OUTBOUND_QUEUE: usize = 64;
/// Bound on any single broker operation made for a client.
const OP_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on each broker operation during cleanup.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for the client's Close after sending ours.
const CLOSE_LINGER: Duration = Duration::from_secs(3);

pub const SERVER_NAME: &str = concat!("mpc-relay/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Which client connection holds each session queue.
///
/// All clients share the relay's one AMQP connection, so the broker's
/// exclusive-queue check cannot tell them apart. This registry is that check:
/// a second connection subscribing with a queue name another connection
/// holds is refused, as RabbitMQ refuses it with RESOURCE_LOCKED across
/// connections. A queue is released only after its deletion has been
/// attempted, so a new holder never inherits a queue that is about to be
/// deleted under it.
#[derive(Default)]
pub struct QueueRegistry(Mutex<HashMap<String, u64>>);

#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    New,
    AlreadyOurs,
    Locked,
}

impl QueueRegistry {
    pub fn claim(&self, queue: &str, conn: u64) -> Claim {
        let mut m = self.0.lock().expect("registry lock");
        match m.get(queue) {
            Some(owner) if *owner == conn => Claim::AlreadyOurs,
            Some(_) => Claim::Locked,
            None => {
                m.insert(queue.to_owned(), conn);
                Claim::New
            }
        }
    }

    pub fn release(&self, queue: &str, conn: u64) {
        let mut m = self.0.lock().expect("registry lock");
        if m.get(queue) == Some(&conn) {
            m.remove(queue);
        }
    }

    pub fn len(&self) -> usize {
        self.0.lock().expect("registry lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct Shared {
    pub config: Arc<Config>,
    pub auth: Arc<Authenticator>,
    pub broker: Arc<Broker>,
    pub metrics: Arc<Metrics>,
    pub registry: QueueRegistry,
    /// Cancelled to end every client session ("server shutting down").
    pub shutdown: CancellationToken,
    pub draining: AtomicBool,
    next_conn_id: AtomicU64,
    active: AtomicUsize,
}

impl Shared {
    pub fn new(
        config: Arc<Config>,
        auth: Arc<Authenticator>,
        broker: Arc<Broker>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Shared {
            config,
            auth,
            broker,
            metrics,
            registry: QueueRegistry::default(),
            shutdown: CancellationToken::new(),
            draining: AtomicBool::new(false),
            next_conn_id: AtomicU64::new(1),
            active: AtomicUsize::new(0),
        }
    }

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Reserve a connection slot, or `None` at the configured maximum.
    pub fn try_acquire(self: &Arc<Self>) -> Option<ConnectionSlot> {
        let max = self.config.limits.max_connections;
        let mut cur = self.active.load(Ordering::Acquire);
        loop {
            if cur >= max {
                return None;
            }
            match self
                .active
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        self.metrics.connections_active.inc();
        self.metrics.connections_total.inc();
        Some(ConnectionSlot {
            shared: self.clone(),
            id: self.next_conn_id.fetch_add(1, Ordering::Relaxed),
        })
    }
}

/// A reserved connection slot; released on drop.
pub struct ConnectionSlot {
    shared: Arc<Shared>,
    pub id: u64,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.shared.active.fetch_sub(1, Ordering::AcqRel);
        self.shared.metrics.connections_active.dec();
    }
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Why a session ended.
enum End {
    /// Send ERROR, then close.
    Error(StompError),
    /// DISCONNECT (any RECEIPT already queued): close.
    Graceful,
    /// The client is gone or unwritable: nothing to tell it.
    Silent(&'static str),
}

struct StompError {
    /// Label for `mpc_relay_errors_total`.
    reason: &'static str,
    /// The ERROR frame's `message` header.
    message: String,
    /// The ERROR frame's body.
    detail: String,
    receipt: Option<String>,
}

fn fail(
    reason: &'static str,
    message: impl Into<String>,
    detail: impl Into<String>,
    receipt: &Option<String>,
) -> Option<End> {
    Some(End::Error(StompError {
        reason,
        message: message.into(),
        detail: detail.into(),
        receipt: receipt.clone(),
    }))
}

/// Map a broker-side failure to what the client is told. Every one of these
/// ends the session: a channel-level AMQP error closes the channel.
fn broker_failure(err: BrokerOpError, receipt: &Option<String>) -> Option<End> {
    match err {
        BrokerOpError::Timeout => fail(
            "broker_error",
            "broker error",
            "the broker did not answer in time",
            receipt,
        ),
        BrokerOpError::Amqp(lapin::Error::ProtocolError(e)) => match e.kind() {
            AMQPErrorKind::Soft(AMQPSoftError::RESOURCELOCKED) => fail(
                "resource_locked",
                "resource locked",
                e.get_message().to_string(),
                receipt,
            ),
            AMQPErrorKind::Soft(AMQPSoftError::ACCESSREFUSED) => fail(
                "broker_error",
                "access refused",
                e.get_message().to_string(),
                receipt,
            ),
            AMQPErrorKind::Soft(AMQPSoftError::NOTFOUND) => fail(
                "broker_error",
                "not found",
                e.get_message().to_string(),
                receipt,
            ),
            _ => fail(
                "broker_error",
                "broker error",
                e.get_message().to_string(),
                receipt,
            ),
        },
        BrokerOpError::Amqp(lapin::Error::ChannelsLimitReached) => fail(
            "channel_limit",
            "too many connections",
            "the relay's broker connection has no free channels",
            receipt,
        ),
        BrokerOpError::Amqp(e) => {
            tracing::debug!(error = %e, "broker operation failed");
            fail("broker_unavailable", "broker unavailable", "", receipt)
        }
    }
}

enum BrokerOpError {
    Amqp(lapin::Error),
    Timeout,
}

async fn op<T>(
    fut: impl std::future::Future<Output = lapin::Result<T>>,
) -> Result<T, BrokerOpError> {
    match tokio::time::timeout(OP_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(BrokerOpError::Amqp(e)),
        Err(_) => Err(BrokerOpError::Timeout),
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

enum Outbound {
    Frame {
        bytes: Vec<u8>,
        command: &'static str,
    },
    Delivery {
        bytes: Vec<u8>,
        acker: Acker,
    },
    Close,
}

/// RabbitMQ Web-STOMP sends text WebSocket messages. A frame whose bytes are
/// valid UTF-8 goes out the same way; one that is not (a binary body) goes
/// out as a binary message, which a browser accepts and an invalid text
/// message it would not.
fn ws_message(bytes: Vec<u8>) -> Message {
    match String::from_utf8(bytes) {
        Ok(s) => Message::Text(s.into()),
        Err(e) => Message::Binary(Bytes::from(e.into_bytes())),
    }
}

async fn write_loop(
    mut sink: SplitSink<WebSocket, Message>,
    mut rx: mpsc::Receiver<Outbound>,
    ping_every: Duration,
    write_timeout: Duration,
    metrics: Arc<Metrics>,
) {
    let mut ping = tokio::time::interval_at(Instant::now() + ping_every, ping_every);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            item = rx.recv() => match item {
                None => break,
                Some(Outbound::Frame { bytes, command }) => {
                    if !send(&mut sink, ws_message(bytes), write_timeout).await {
                        break;
                    }
                    metrics.frame_out(command);
                }
                Some(Outbound::Delivery { bytes, acker }) => {
                    if !send(&mut sink, ws_message(bytes), write_timeout).await {
                        break;
                    }
                    metrics.frame_out("MESSAGE");
                    metrics.deliveries.inc();
                    // Acked after the write, so the prefetch window, not the
                    // relay's memory, absorbs a slow client.
                    let _ = acker.ack(BasicAckOptions::default()).await;
                }
                Some(Outbound::Close) => {
                    let close = Message::Close(Some(CloseFrame { code: 1000, reason: "".into() }));
                    let _ = send(&mut sink, close, write_timeout).await;
                    let _ = tokio::time::timeout(write_timeout, sink.close()).await;
                    break;
                }
            },
            _ = ping.tick() => {
                if !send(&mut sink, Message::Ping(Bytes::new()), write_timeout).await {
                    break;
                }
            }
        }
    }
}

async fn send(
    sink: &mut SplitSink<WebSocket, Message>,
    msg: Message,
    write_timeout: Duration,
) -> bool {
    matches!(
        tokio::time::timeout(write_timeout, sink.send(msg)).await,
        Ok(Ok(()))
    )
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

enum DispatchCmd {
    Consume {
        sub_id: String,
        queue: String,
        reply: oneshot::Sender<Result<String, BrokerOpError>>,
    },
    Cancel {
        sub_id: String,
        reply: oneshot::Sender<Result<(), BrokerOpError>>,
    },
}

enum DispatchEvent {
    /// The broker cancelled a consumer the client had not unsubscribed
    /// (its queue was deleted from outside).
    ConsumerCancelled,
    /// A consumer reported an error: the channel is gone.
    ChannelFailed(String),
}

struct Slot {
    sub_id: String,
    tag: String,
    consumer: lapin::Consumer,
    head: Option<Delivery>,
    cancelling: bool,
}

enum Step {
    Deliver(usize),
    Ended(usize),
    Failed(String),
}

/// Owns this connection's consumers and forwards their deliveries in
/// channel order.
///
/// RabbitMQ dispatches one queue's messages round-robin across its
/// consumers, and the consumers of a connection all share one channel, so
/// the order the client must see is the channel's delivery order - which
/// `delivery_tag` records, increasing by one per delivery on the channel.
/// lapin hands each consumer its own stream, filled by a single IO loop in
/// frame order; reading two streams from two tasks would reorder messages
/// whenever both have something buffered.
///
/// So a single task reads every stream and only ever emits the
/// lowest-tagged delivery it holds, and only after a full pass over every
/// stream it holds nothing from came back empty. Because the IO loop fills
/// the streams in tag order, a delivery visible in one stream means every
/// lower-tagged delivery is already visible in its own; that pass is what
/// makes "lowest held" equal to "next in channel order".
///
/// Consumers are created here too (`DispatchCmd::Consume`), not by the
/// reader: deliveries to a new consumer can start the moment the broker
/// answers `basic.consume`, and if the dispatcher kept emitting while the
/// new stream was still on its way to it, a later delivery to an older
/// consumer could overtake them. While this task awaits `basic.consume` it
/// emits nothing, and the new stream is in the set before it emits again.
struct Dispatcher {
    channel: Channel,
    out: mpsc::Sender<Outbound>,
    events: mpsc::Sender<DispatchEvent>,
    conn_id: u64,
    slots: Vec<Slot>,
}

impl Dispatcher {
    async fn run(mut self, mut cmds: mpsc::Receiver<DispatchCmd>) {
        loop {
            tokio::select! {
                biased;
                cmd = cmds.recv() => match cmd {
                    None => return,
                    Some(cmd) => self.command(cmd).await,
                },
                step = poll_fn(|cx| poll_step(&mut self.slots, cx)) => match step {
                    Step::Deliver(i) => {
                        let slot = &mut self.slots[i];
                        let d = slot.head.take().expect("Deliver names a held delivery");
                        let bytes = message_frame(&slot.sub_id, self.conn_id, &d);
                        let acker = d.acker.clone();
                        if self.out.send(Outbound::Delivery { bytes, acker }).await.is_err() {
                            return;
                        }
                    }
                    Step::Ended(i) => {
                        let slot = self.slots.remove(i);
                        if !slot.cancelling {
                            let _ = self.events.send(DispatchEvent::ConsumerCancelled).await;
                            return;
                        }
                    }
                    Step::Failed(e) => {
                        let _ = self.events.send(DispatchEvent::ChannelFailed(e)).await;
                        return;
                    }
                },
            }
        }
    }

    async fn command(&mut self, cmd: DispatchCmd) {
        match cmd {
            DispatchCmd::Consume {
                sub_id,
                queue,
                reply,
            } => {
                // Empty tag: the broker generates one, unique on the channel
                // whatever the client's subscription ids look like.
                let r = op(self.channel.basic_consume(
                    &queue,
                    "",
                    BasicConsumeOptions::default(),
                    FieldTable::default(),
                ))
                .await;
                let r = r.map(|consumer| {
                    let tag = consumer.tag().to_string();
                    self.slots.push(Slot {
                        sub_id,
                        tag: tag.clone(),
                        consumer,
                        head: None,
                        cancelling: false,
                    });
                    tag
                });
                let _ = reply.send(r);
            }
            DispatchCmd::Cancel { sub_id, reply } => {
                let Some(slot) = self
                    .slots
                    .iter_mut()
                    .find(|s| s.sub_id == sub_id && !s.cancelling)
                else {
                    let _ = reply.send(Ok(()));
                    return;
                };
                slot.cancelling = true;
                let tag = slot.tag.clone();
                // Returns once basic.cancel-ok has arrived: the broker will
                // deliver nothing more to this consumer. What it delivered
                // before that is still in the stream and is forwarded.
                let r = op(self
                    .channel
                    .basic_cancel(&tag, BasicCancelOptions::default()))
                .await;
                let _ = reply.send(r);
            }
        }
    }
}

fn poll_step(slots: &mut [Slot], cx: &mut Context<'_>) -> Poll<Step> {
    loop {
        let mut progressed = false;
        for (i, slot) in slots.iter_mut().enumerate() {
            if slot.head.is_some() {
                continue;
            }
            match Pin::new(&mut slot.consumer).poll_next(cx) {
                Poll::Ready(Some(Ok(d))) => {
                    slot.head = Some(d);
                    progressed = true;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Step::Failed(e.to_string())),
                Poll::Ready(None) => return Poll::Ready(Step::Ended(i)),
                Poll::Pending => {}
            }
        }
        if !progressed {
            break;
        }
    }
    slots
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.head.as_ref().map(|d| (d.delivery_tag, i)))
        .min()
        .map_or(Poll::Pending, |(_, i)| Poll::Ready(Step::Deliver(i)))
}

fn message_frame(sub_id: &str, conn_id: u64, d: &Delivery) -> Vec<u8> {
    let mut f = Frame::new("MESSAGE")
        .with_header("subscription", sub_id)
        .with_header(
            "destination",
            format!(
                "/exchange/{}/{}",
                d.exchange.as_str(),
                d.routing_key.as_str()
            ),
        )
        .with_header(
            "message-id",
            format!("T_{sub_id}@@relay-{conn_id}@@{}", d.delivery_tag),
        )
        .with_header("redelivered", if d.redelivered { "true" } else { "false" });
    if let Some(ct) = d.properties.content_type() {
        f = f.with_header("content-type", ct.as_str());
    }
    f.with_header("content-length", d.data.len().to_string())
        .with_body(d.data.clone())
        .encode()
}

// ---------------------------------------------------------------------------
// Session (reader)
// ---------------------------------------------------------------------------

struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: f64, burst: u32) -> Self {
        TokenBucket {
            capacity: burst as f64,
            tokens: burst as f64,
            rate,
            last: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Subscription {
    queue: String,
    tag: String,
}

struct Connected {
    identity: Identity,
    connection: Arc<Connection>,
    channel: Channel,
    generation: u64,
    expiry: Option<Instant>,
    dispatcher: mpsc::Sender<DispatchCmd>,
    dispatcher_task: tokio::task::JoinHandle<()>,
    subs: HashMap<String, Subscription>,
    /// Queues declared by this connection, with the subscription ids on each.
    queues: HashMap<String, HashSet<String>>,
}

struct Session {
    shared: Arc<Shared>,
    conn_id: u64,
    peer: SocketAddr,
    out: mpsc::Sender<Outbound>,
    bucket: TokenBucket,
    connected: Option<Connected>,
    /// Handed to the read loop once CONNECT succeeds.
    new_events: Option<mpsc::Receiver<DispatchEvent>>,
}

/// Serve one upgraded WebSocket until it ends.
pub async fn serve(ws: WebSocket, shared: Arc<Shared>, slot: ConnectionSlot, peer: SocketAddr) {
    let conn_id = slot.id;
    let limits = shared.config.limits.clone();
    let (sink, stream) = ws.split();
    let (out_tx, out_rx) = mpsc::channel(OUTBOUND_QUEUE);
    let writer = tokio::spawn(write_loop(
        sink,
        out_rx,
        limits.ping_interval,
        limits.write_timeout,
        shared.metrics.clone(),
    ));
    tracing::debug!(conn = conn_id, %peer, "websocket open");
    let mut session = Session {
        shared: shared.clone(),
        conn_id,
        peer,
        out: out_tx,
        bucket: TokenBucket::new(limits.send_rate, limits.send_burst),
        connected: None,
        new_events: None,
    };
    let mut stream = stream;
    let end = session.read_loop(&mut stream).await;
    session.finish(end).await;
    drop(session);
    // Lingering close. The writer has queued ERROR (if any) and a Close
    // frame; keep reading until the client answers with its own Close. If
    // the socket were dropped now, a client still sending (a pong, a frame
    // in flight) would get a TCP reset, and a reset lets the client's stack
    // discard the ERROR frame it has not read yet.
    let _ = tokio::time::timeout(CLOSE_LINGER, async {
        while let Some(Ok(msg)) = stream.next().await {
            if let Message::Close(_) = msg {
                break;
            }
        }
    })
    .await;
    let _ = tokio::time::timeout(limits.write_timeout + Duration::from_secs(1), writer).await;
    drop(slot);
}

fn negotiate_version(accept: Option<&str>) -> Option<&'static str> {
    let offered: Vec<&str> = accept?.split(',').map(str::trim).collect();
    if offered.contains(&"1.2") {
        Some("1.2")
    } else if offered.contains(&"1.1") {
        Some("1.1")
    } else {
        None
    }
}

/// `exp` (+ leeway) as a monotonic deadline. Far-future values are capped
/// rather than overflowing `Instant`.
fn expiry_deadline(exp: u64, leeway: Duration) -> Instant {
    const CAP: Duration = Duration::from_secs(10 * 365 * 24 * 3600);
    let remaining = UNIX_EPOCH
        .checked_add(Duration::from_secs(exp))
        .and_then(|t| t.checked_add(leeway))
        .and_then(|t| t.duration_since(SystemTime::now()).ok())
        .unwrap_or(Duration::ZERO)
        .min(CAP);
    Instant::now() + remaining
}

async fn sleep_until_opt(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => pending().await,
    }
}

async fn recv_opt(rx: &mut Option<mpsc::Receiver<DispatchEvent>>) -> Option<DispatchEvent> {
    match rx {
        Some(rx) => rx.recv().await,
        None => pending().await,
    }
}

impl Session {
    async fn read_loop(&mut self, stream: &mut SplitStream<WebSocket>) -> End {
        let limits = self.shared.config.limits.clone();
        let shutdown = self.shared.shutdown.clone();
        let out = self.out.clone();
        let mut broker = self.shared.broker.watch();
        let mut events: Option<mpsc::Receiver<DispatchEvent>> = None;
        let connect_deadline = Instant::now() + limits.connect_timeout;
        let idle = tokio::time::sleep(limits.idle_timeout);
        tokio::pin!(idle);
        let mut decoder = Decoder::new(limits.max_frame_bytes);

        loop {
            let generation = self.connected.as_ref().map(|c| c.generation);
            let expiry = self.connected.as_ref().and_then(|c| c.expiry);
            let connected = generation.is_some();
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    return End::Error(StompError {
                        reason: "shutdown",
                        message: "server shutting down".into(),
                        detail: "reconnect to another relay instance".into(),
                        receipt: None,
                    });
                }
                _ = out.closed() => return End::Silent("websocket write side closed"),
                changed = broker.changed(), if connected => {
                    let lost = changed.is_err() || {
                        let s = broker.borrow_and_update();
                        Some(s.generation) != generation
                            || !s.connection.as_ref().is_some_and(|c| c.status().connected())
                    };
                    if lost {
                        return broker_unavailable();
                    }
                }
                ev = recv_opt(&mut events), if connected => {
                    return match ev {
                        Some(DispatchEvent::ConsumerCancelled) => End::Error(StompError {
                            reason: "broker_error",
                            message: "subscription cancelled by broker".into(),
                            detail: "the subscription's queue was deleted".into(),
                            receipt: None,
                        }),
                        Some(DispatchEvent::ChannelFailed(e)) => {
                            tracing::warn!(conn = self.conn_id, error = %e, "client channel failed");
                            broker_unavailable()
                        }
                        None => broker_unavailable(),
                    };
                }
                _ = tokio::time::sleep_until(connect_deadline), if !connected => {
                    return End::Error(StompError {
                        reason: "connect_timeout",
                        message: "connect timeout".into(),
                        detail: format!("no CONNECT frame within {:?}", limits.connect_timeout),
                        receipt: None,
                    });
                }
                _ = &mut idle => {
                    return End::Error(StompError {
                        reason: "idle_timeout",
                        message: "idle timeout".into(),
                        detail: format!("nothing received for {:?}", limits.idle_timeout),
                        receipt: None,
                    });
                }
                _ = sleep_until_opt(expiry), if expiry.is_some() => {
                    return End::Error(StompError {
                        reason: "token_expired",
                        message: "token expired".into(),
                        detail: "reconnect with a fresh token".into(),
                        receipt: None,
                    });
                }
                msg = stream.next() => {
                    let data: Bytes = match msg {
                        None | Some(Err(_)) => return End::Silent("client went away"),
                        Some(Ok(Message::Close(_))) => return End::Silent("client closed"),
                        Some(Ok(Message::Text(t))) => Bytes::from(t),
                        Some(Ok(Message::Binary(b))) => b,
                        // Any inbound traffic, a pong to our ping included,
                        // counts as activity.
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                            idle.as_mut().reset(Instant::now() + limits.idle_timeout);
                            continue;
                        }
                    };
                    idle.as_mut().reset(Instant::now() + limits.idle_timeout);
                    decoder.extend(&data);
                    loop {
                        match decoder.decode() {
                            Ok(None) => break,
                            Ok(Some(frame)) => {
                                self.shared.metrics.frame_in(&frame.command);
                                if let Some(end) = self.handle(frame).await {
                                    return end;
                                }
                                if events.is_none() {
                                    events = self.new_events.take();
                                }
                            }
                            Err(e @ CodecError::FrameTooLarge { .. }) => {
                                return End::Error(StompError {
                                    reason: "frame_too_large",
                                    message: "frame too large".into(),
                                    detail: e.to_string(),
                                    receipt: None,
                                });
                            }
                            Err(e) => {
                                return End::Error(StompError {
                                    reason: "protocol",
                                    message: "malformed frame".into(),
                                    detail: e.to_string(),
                                    receipt: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    async fn emit(&self, frame: Frame) {
        let command = crate::metrics::command_label(&frame.command);
        let _ = self
            .out
            .send(Outbound::Frame {
                bytes: frame.encode(),
                command,
            })
            .await;
    }

    async fn receipt(&self, receipt: Option<String>) {
        if let Some(r) = receipt {
            self.emit(Frame::new("RECEIPT").with_header("receipt-id", r))
                .await;
        }
    }

    async fn handle(&mut self, frame: Frame) -> Option<End> {
        let receipt = frame.header("receipt").map(str::to_owned);
        let command = frame.command.clone();
        if self.connected.is_none() {
            return match command.as_str() {
                "CONNECT" | "STOMP" => self.on_connect(frame).await,
                _ => fail(
                    "protocol",
                    "not connected",
                    "the first frame must be CONNECT or STOMP",
                    &receipt,
                ),
            };
        }
        match command.as_str() {
            "CONNECT" | "STOMP" => fail("protocol", "already connected", "", &receipt),
            "SUBSCRIBE" => self.on_subscribe(frame, receipt).await,
            "UNSUBSCRIBE" => self.on_unsubscribe(frame, receipt).await,
            "SEND" => self.on_send(frame, receipt).await,
            "DISCONNECT" => {
                self.receipt(receipt).await;
                Some(End::Graceful)
            }
            other => fail(
                "not_supported",
                "not supported",
                format!("{other} is not supported by mpc-relay"),
                &receipt,
            ),
        }
    }

    async fn on_connect(&mut self, frame: Frame) -> Option<End> {
        let none = None;
        let Some(version) = negotiate_version(frame.header("accept-version")) else {
            return fail(
                "protocol",
                "unsupported protocol version",
                "mpc-relay speaks STOMP 1.1 and 1.2 (accept-version must include one)",
                &none,
            );
        };
        let identity = match self
            .shared
            .auth
            .authenticate(frame.header("login"), frame.header("passcode"))
            .await
        {
            Ok(i) => i,
            Err(e) => {
                self.shared.metrics.auth_failure(e.reason());
                tracing::info!(conn = self.conn_id, peer = %self.peer, reason = e.reason(), detail = %e, "authentication failed");
                return fail(
                    "auth",
                    "authentication failed",
                    "authentication failed",
                    &none,
                );
            }
        };
        if self.shared.auth.is_disabled() {
            tracing::warn!(
                conn = self.conn_id,
                peer = %self.peer,
                sub = %identity.principal.sub,
                "MPC_RELAY_AUTH=none: connection accepted WITHOUT authentication - never run this in production"
            );
        }
        let Some((connection, generation)) = self.shared.broker.ready_connection() else {
            return broker_unavailable_opt();
        };
        let prefetch = self.shared.config.limits.prefetch;
        let channel = match open_channel(&connection, prefetch).await {
            Ok(ch) => ch,
            Err(e) => return broker_failure(e, &none),
        };
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (ev_tx, ev_rx) = mpsc::channel(4);
        {
            // The broker closes a channel asynchronously, e.g. after a
            // publish to an exchange that has since been deleted. Without
            // this a client with no consumers would only find out on its
            // next frame.
            let ev_tx = ev_tx.clone();
            channel.on_error(move |e| {
                let _ = ev_tx.try_send(DispatchEvent::ChannelFailed(e.to_string()));
            });
        }
        let dispatcher = Dispatcher {
            channel: channel.clone(),
            out: self.out.clone(),
            events: ev_tx,
            conn_id: self.conn_id,
            slots: Vec::new(),
        };
        let dispatcher_task = tokio::spawn(dispatcher.run(cmd_rx));
        let leeway = self.shared.config.auth.leeway;
        let expiry = identity.expires_at.map(|exp| expiry_deadline(exp, leeway));
        tracing::info!(conn = self.conn_id, peer = %self.peer, sub = %identity.principal.sub, version, "connected");
        self.connected = Some(Connected {
            identity,
            connection,
            channel,
            generation,
            expiry,
            dispatcher: cmd_tx,
            dispatcher_task,
            subs: HashMap::new(),
            queues: HashMap::new(),
        });
        self.new_events = Some(ev_rx);
        self.emit(
            Frame::new("CONNECTED")
                .with_header("version", version)
                .with_header("server", SERVER_NAME)
                .with_header("heart-beat", "0,0"),
        )
        .await;
        None
    }

    async fn on_subscribe(&mut self, frame: Frame, receipt: Option<String>) -> Option<End> {
        let limits = &self.shared.config.limits;
        let exchange = &self.shared.config.exchange;
        let c = self.connected.as_mut().expect("connected");
        let Some(id) = frame.header("id").filter(|v| !v.is_empty()) else {
            return fail(
                "protocol",
                "missing header",
                "SUBSCRIBE requires an id header",
                &receipt,
            );
        };
        if id.len() > 255 {
            return fail(
                "protocol",
                "invalid header",
                "subscription id longer than 255 bytes",
                &receipt,
            );
        }
        let Some(destination) = frame.header("destination") else {
            return fail(
                "protocol",
                "missing header",
                "SUBSCRIBE requires a destination header",
                &receipt,
            );
        };
        match frame.header("ack") {
            None | Some("auto") => {}
            Some(other) => {
                return fail(
                    "not_supported",
                    "not supported",
                    format!("ack mode {other} is not supported; use ack:auto"),
                    &receipt,
                )
            }
        }
        if c.subs.contains_key(id) {
            return fail(
                "protocol",
                "duplicate subscription id",
                format!("subscription {id} already exists"),
                &receipt,
            );
        }
        if c.subs.len() >= limits.max_subscriptions {
            return fail(
                "too_many_subscriptions",
                "too many subscriptions",
                format!(
                    "at most {} subscriptions per connection",
                    limits.max_subscriptions
                ),
                &receipt,
            );
        }
        if !self.bucket.take() {
            return rate_limited(&receipt);
        }
        let grant = match acl::authorize_subscribe(
            &c.identity.principal,
            exchange,
            destination,
            frame.header("x-queue-name"),
        ) {
            Ok(g) => g,
            Err(e) => {
                tracing::info!(conn = self.conn_id, sub = %c.identity.principal.sub, destination, error = %e, "subscribe refused");
                return fail("acl", "access refused", e.to_string(), &receipt);
            }
        };
        let fresh = match self.shared.registry.claim(&grant.queue, self.conn_id) {
            Claim::Locked => {
                return fail(
                    "resource_locked",
                    "resource locked",
                    format!("queue {} is held by another connection", grant.queue),
                    &receipt,
                )
            }
            Claim::New => true,
            Claim::AlreadyOurs => false,
        };
        if !c.queues.contains_key(&grant.queue) {
            let declared = op(c.channel.queue_declare(
                &grant.queue,
                QueueDeclareOptions {
                    passive: false,
                    durable: false,
                    exclusive: true,
                    auto_delete: true,
                    nowait: false,
                },
                FieldTable::default(),
            ))
            .await;
            if let Err(e) = declared {
                if fresh {
                    self.shared.registry.release(&grant.queue, self.conn_id);
                }
                return broker_failure(e, &receipt);
            }
            c.queues.insert(grant.queue.clone(), HashSet::new());
        }
        if let Err(e) = op(c.channel.queue_bind(
            &grant.queue,
            exchange,
            &grant.routing_key,
            QueueBindOptions::default(),
            FieldTable::default(),
        ))
        .await
        {
            return broker_failure(e, &receipt);
        }
        let (tx, rx) = oneshot::channel();
        let sent = c
            .dispatcher
            .send(DispatchCmd::Consume {
                sub_id: id.to_owned(),
                queue: grant.queue.clone(),
                reply: tx,
            })
            .await;
        let tag = match (sent, rx.await) {
            (Ok(()), Ok(Ok(tag))) => tag,
            (Ok(()), Ok(Err(e))) => return broker_failure(e, &receipt),
            _ => return broker_unavailable_opt(),
        };
        c.subs.insert(
            id.to_owned(),
            Subscription {
                queue: grant.queue.clone(),
                tag,
            },
        );
        c.queues
            .get_mut(&grant.queue)
            .expect("declared above")
            .insert(id.to_owned());
        tracing::debug!(conn = self.conn_id, id, queue = %grant.queue, routing_key = %grant.routing_key, "subscribed");
        // Queue declared, binding made, consumer started: only now.
        self.receipt(receipt).await;
        None
    }

    async fn on_unsubscribe(&mut self, frame: Frame, receipt: Option<String>) -> Option<End> {
        let c = self.connected.as_mut().expect("connected");
        let Some(id) = frame.header("id").filter(|v| !v.is_empty()) else {
            return fail(
                "protocol",
                "missing header",
                "UNSUBSCRIBE requires an id header",
                &receipt,
            );
        };
        if !c.subs.contains_key(id) {
            return fail(
                "protocol",
                "subscription not found",
                format!("no subscription {id}"),
                &receipt,
            );
        }
        if !self.bucket.take() {
            return rate_limited(&receipt);
        }
        let (tx, rx) = oneshot::channel();
        let sent = c
            .dispatcher
            .send(DispatchCmd::Cancel {
                sub_id: id.to_owned(),
                reply: tx,
            })
            .await;
        match (sent, rx.await) {
            (Ok(()), Ok(Ok(()))) => {}
            (Ok(()), Ok(Err(e))) => return broker_failure(e, &receipt),
            _ => return broker_unavailable_opt(),
        }
        let sub = c.subs.remove(id).expect("checked above");
        if let Some(ids) = c.queues.get_mut(&sub.queue) {
            ids.remove(id);
            if ids.is_empty() {
                // Its last consumer is gone, so the broker has auto-deleted
                // it, exactly as with RabbitMQ Web-STOMP. Deleting it again
                // here could race that and is not needed.
                c.queues.remove(&sub.queue);
                self.shared.registry.release(&sub.queue, self.conn_id);
            }
        }
        // Consumer cancelled (basic.cancel-ok received): only now.
        self.receipt(receipt).await;
        None
    }

    async fn on_send(&mut self, frame: Frame, receipt: Option<String>) -> Option<End> {
        let exchange = &self.shared.config.exchange;
        let c = self.connected.as_mut().expect("connected");
        let Some(destination) = frame.header("destination") else {
            return fail(
                "protocol",
                "missing header",
                "SEND requires a destination header",
                &receipt,
            );
        };
        if !self.bucket.take() {
            return rate_limited(&receipt);
        }
        let grant = match acl::authorize_send(&c.identity.principal, exchange, destination) {
            Ok(g) => g,
            Err(e) => {
                tracing::info!(conn = self.conn_id, sub = %c.identity.principal.sub, destination, error = %e, "send refused");
                return fail("acl", "access refused", e.to_string(), &receipt);
            }
        };
        let mut props = BasicProperties::default();
        if let Some(ct) = frame.header("content-type") {
            props = props.with_content_type(ct.into());
        }
        let confirm = match op(c.channel.basic_publish(
            exchange,
            &grant.routing_key,
            BasicPublishOptions::default(),
            &frame.body,
            props,
        ))
        .await
        {
            Ok(confirm) => confirm,
            Err(e) => return broker_failure(e, &receipt),
        };
        self.shared.metrics.publishes.inc();
        if receipt.is_some() {
            // As RabbitMQ Web-STOMP does: the RECEIPT for a SEND waits for
            // the broker's publisher confirm.
            match tokio::time::timeout(OP_TIMEOUT, confirm).await {
                Ok(Ok(Confirmation::Nack(_))) => {
                    return fail(
                        "broker_error",
                        "publish rejected",
                        "the broker refused the message",
                        &receipt,
                    )
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return broker_failure(BrokerOpError::Amqp(e), &receipt),
                Err(_) => return broker_failure(BrokerOpError::Timeout, &receipt),
            }
            self.receipt(receipt).await;
        } else {
            let metrics = self.shared.metrics.clone();
            let conn = self.conn_id;
            tokio::spawn(async move {
                if let Ok(Ok(Confirmation::Nack(_))) =
                    tokio::time::timeout(OP_TIMEOUT, confirm).await
                {
                    metrics.error("publish_nack");
                    tracing::warn!(conn, "broker nacked a publish sent without receipt");
                }
            });
        }
        None
    }

    async fn finish(&mut self, end: End) {
        match end {
            End::Error(e) => {
                self.shared.metrics.error(e.reason);
                tracing::info!(conn = self.conn_id, peer = %self.peer, reason = e.reason, message = %e.message, detail = %e.detail, "closing with ERROR");
                let mut f = Frame::new("ERROR").with_header("message", e.message);
                if let Some(r) = e.receipt {
                    f = f.with_header("receipt-id", r);
                }
                f = f
                    .with_header("content-type", "text/plain")
                    .with_header("content-length", e.detail.len().to_string())
                    .with_body(e.detail);
                // Stop deliveries first so the ERROR is not queued behind them.
                if let Some(c) = &self.connected {
                    c.dispatcher_task.abort();
                }
                self.emit(f).await;
            }
            End::Graceful => tracing::debug!(conn = self.conn_id, "client disconnected"),
            End::Silent(why) => tracing::debug!(conn = self.conn_id, why, "connection ended"),
        }
        let _ = self.out.send(Outbound::Close).await;
        if let Some(c) = self.connected.take() {
            cleanup(&self.shared, self.conn_id, c).await;
        }
    }
}

fn rate_limited(receipt: &Option<String>) -> Option<End> {
    fail(
        "rate_limited",
        "rate limit exceeded",
        "too many frames per second on this connection",
        receipt,
    )
}

fn broker_unavailable() -> End {
    End::Error(StompError {
        reason: "broker_unavailable",
        message: "broker unavailable".into(),
        detail: String::new(),
        receipt: None,
    })
}

fn broker_unavailable_opt() -> Option<End> {
    Some(broker_unavailable())
}

async fn open_channel(conn: &Connection, prefetch: u16) -> Result<Channel, BrokerOpError> {
    let ch = op(conn.create_channel()).await?;
    op(ch.basic_qos(prefetch, BasicQosOptions { global: false })).await?;
    op(ch.confirm_select(ConfirmSelectOptions::default())).await?;
    Ok(ch)
}

/// Cancel the client's consumers, delete its queues, close its channel, and
/// only then release the queue names.
///
/// The explicit delete matters: the AMQP connection the queues are exclusive
/// to is shared and outlives the client, and auto-delete fires only when a
/// queue's last consumer goes - a queue that was declared but whose consumer
/// never started would otherwise live as long as the relay.
async fn cleanup(shared: &Shared, conn_id: u64, c: Connected) {
    c.dispatcher_task.abort();
    let queues: Vec<String> = c.queues.keys().cloned().collect();
    let same_connection = shared
        .broker
        .state()
        .connection
        .as_ref()
        .is_some_and(|live| Arc::ptr_eq(live, &c.connection) && live.status().connected());
    if same_connection {
        if c.channel.status().connected() {
            for sub in c.subs.values() {
                let _ = tokio::time::timeout(
                    CLEANUP_TIMEOUT,
                    c.channel
                        .basic_cancel(&sub.tag, BasicCancelOptions::default()),
                )
                .await;
            }
        }
        if !queues.is_empty() {
            // The client's channel may be the reason we are here; fall back
            // to a short-lived one on the same connection.
            let ch = if c.channel.status().connected() {
                Some(c.channel.clone())
            } else {
                tokio::time::timeout(CLEANUP_TIMEOUT, c.connection.create_channel())
                    .await
                    .ok()
                    .and_then(Result::ok)
            };
            if let Some(ch) = &ch {
                for q in &queues {
                    match tokio::time::timeout(
                        CLEANUP_TIMEOUT,
                        ch.queue_delete(q, QueueDeleteOptions::default()),
                    )
                    .await
                    {
                        Ok(Ok(_)) => tracing::debug!(conn = conn_id, queue = %q, "queue deleted"),
                        Ok(Err(e)) => {
                            tracing::warn!(conn = conn_id, queue = %q, error = %e, "queue delete failed")
                        }
                        Err(_) => {
                            tracing::warn!(conn = conn_id, queue = %q, "queue delete timed out")
                        }
                    }
                    if !ch.status().connected() {
                        break;
                    }
                }
                if ch.id() != c.channel.id() {
                    let _ =
                        tokio::time::timeout(CLEANUP_TIMEOUT, ch.close(200, "cleanup done")).await;
                }
            }
        }
        if c.channel.status().connected() {
            let _ =
                tokio::time::timeout(CLEANUP_TIMEOUT, c.channel.close(200, "client disconnected"))
                    .await;
        }
    }
    // With the connection gone, the broker already dropped its exclusive
    // queues; either way the names are free now.
    for q in &queues {
        shared.registry.release(q, conn_id);
    }
}
