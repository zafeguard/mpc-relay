//! Load generator for measuring one relay instance.
//!
//! ```text
//! cargo run --release --example load -- \
//!   --relay ws://127.0.0.1:8080/ws --amqp amqp://mpc:mpc@127.0.0.1:5672/%2f \
//!   --exchange mpc.load --secret <MPC_RELAY_JWT_SECRET> \
//!   --sessions 5000 --messages 50000 --size 1024 [--relay-pid 1]
//! ```
//!
//! Phases, each reported:
//!
//! 1. **connect**: `--sessions` devices, each a WebSocket that CONNECTs with
//!    its own token and SUBSCRIBEs twice with one shared `x-queue-name`, as
//!    an MPC device does, waiting for the RECEIPT. At most `--ramp`
//!    handshakes in flight.
//! 2. **idle**: all held open for `--hold` seconds.
//! 3. **deliver**: `--messages` raw AMQP publishes of `--size` bytes,
//!    round-robin over the devices' unicast keys; ends when every MESSAGE
//!    frame has arrived.
//! 4. **publish**: the devices SEND `--messages` frames in total to an
//!    unbound key (the broker drops them); ends when each device's last
//!    SEND, sent with a receipt, is confirmed.
//!
//! With `--relay-pid` (Linux, e.g. run in a container sharing the relay's
//! PID namespace), the relay's CPU time and resident memory are read from
//! /proc before and after each phase, giving memory per idle connection and
//! CPU per message.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, Connection, ConnectionProperties};
use mpc_relay::codec::{Decoder, Frame};
use tokio::sync::{mpsc, Semaphore};
use tokio_tungstenite::tungstenite::Message;

struct Args(HashMap<String, String>);

impl Args {
    fn parse() -> Self {
        let mut m = HashMap::new();
        let mut it = std::env::args().skip(1);
        while let Some(k) = it.next() {
            let k = k.trim_start_matches("--").to_owned();
            let v = it.next().unwrap_or_else(|| panic!("--{k} needs a value"));
            m.insert(k, v);
        }
        Args(m)
    }
    fn get(&self, k: &str) -> String {
        self.0
            .get(k)
            .cloned()
            .unwrap_or_else(|| panic!("--{k} is required"))
    }
    fn num(&self, k: &str, default: u64) -> u64 {
        self.0
            .get(k)
            .map(|v| v.parse().expect("number"))
            .unwrap_or(default)
    }
}

/// CPU seconds (user + system) and resident bytes of a Linux process.
fn proc_sample(pid: Option<u64>) -> Option<(f64, u64)> {
    let pid = pid?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = after.split_whitespace().collect();
    // Fields 14 and 15 (utime, stime) are 11 and 12 after the comm field.
    let ticks: f64 = f[11].parse::<f64>().ok()? + f[12].parse::<f64>().ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kb: u64 = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    // USER_HZ is 100 on every Linux this runs on.
    Some((ticks / 100.0, rss_kb * 1024))
}

fn pct(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

enum Cmd {
    Send {
        count: u64,
        size: usize,
        done: tokio::sync::oneshot::Sender<()>,
    },
    Close,
}

struct Device {
    session: String,
    sub: String,
    cmd: mpsc::Sender<Cmd>,
}

#[tokio::main]
async fn main() {
    let a = Args::parse();
    let relay = a.get("relay");
    let amqp_url = a.get("amqp");
    let exchange = a.get("exchange");
    let secret = a.get("secret");
    let sessions = a.num("sessions", 1000) as usize;
    let ramp = a.num("ramp", 200) as usize;
    let hold = a.num("hold", 10);
    let messages = a.num("messages", 20000);
    let size = a.num("size", 1024) as usize;
    let pid = a.0.get("relay-pid").map(|p| p.parse().unwrap());
    let prefix = a.0.get("prefix").cloned().unwrap_or_else(|| "load".into());
    // Token lifetime: keep it within the relay's MPC_RELAY_JWT_MAX_TTL.
    let ttl = a.num("ttl", 600);

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let amqp = Connection::connect(
        &amqp_url,
        ConnectionProperties::default()
            .with_executor(tokio_executor_trait::Tokio::current())
            .with_reactor(tokio_reactor_trait::Tokio),
    )
    .await
    .expect("broker");
    let ch = amqp.create_channel().await.unwrap();
    ch.exchange_declare(
        &exchange,
        lapin::ExchangeKind::Topic,
        lapin::options::ExchangeDeclareOptions {
            durable: true,
            ..Default::default()
        },
        lapin::types::FieldTable::default(),
    )
    .await
    .unwrap();

    let base = proc_sample(pid);
    println!("relay at start: {}", fmt_sample(base));

    // ---- connect ----
    let received = Arc::new(AtomicU64::new(0));
    let gate = Arc::new(Semaphore::new(ramp));
    let started = Instant::now();
    let mut joins = Vec::with_capacity(sessions);
    for i in 0..sessions {
        let gate = gate.clone();
        let relay = relay.clone();
        let exchange = exchange.clone();
        let received = received.clone();
        let sub = format!("{prefix}-{i}");
        let token = {
            let now = mpc_relay::auth::unix_now();
            encode(
                &Header::new(Algorithm::HS256),
                &serde_json::json!({"sub": sub, "iat": now, "exp": now + ttl}),
                &EncodingKey::from_secret(secret.as_bytes()),
            )
            .unwrap()
        };
        joins.push(tokio::spawn(async move {
            let permit = gate.acquire_owned().await.unwrap();
            let t = Instant::now();
            let r = device(relay, exchange, sub, token, received).await;
            drop(permit);
            r.map(|d| (d, t.elapsed()))
        }));
    }
    let mut devices = Vec::with_capacity(sessions);
    let mut times = Vec::with_capacity(sessions);
    let mut failures: HashMap<String, usize> = HashMap::new();
    for j in joins {
        match j.await.unwrap() {
            Ok((d, t)) => {
                devices.push(d);
                times.push(t);
            }
            Err(e) => *failures.entry(e).or_default() += 1,
        }
    }
    times.sort();
    let connect_secs = started.elapsed().as_secs_f64();
    println!(
        "connect: {} of {sessions} sessions up in {connect_secs:.1}s ({:.0}/s); handshake p50 {:?} p99 {:?} max {:?}; failures {failures:?}",
        devices.len(),
        devices.len() as f64 / connect_secs,
        pct(&times, 0.5),
        pct(&times, 0.99),
        times.last().copied().unwrap_or_default(),
    );

    // ---- idle ----
    let before_idle = proc_sample(pid);
    tokio::time::sleep(Duration::from_secs(hold)).await;
    let idle = proc_sample(pid);
    println!(
        "idle with {} sessions for {hold}s: {}",
        devices.len(),
        fmt_sample(idle)
    );
    if let (Some((_, rss0)), Some((cpu1, rss1)), Some((cpu0, _))) = (base, idle, before_idle) {
        let n = devices.len().max(1) as f64;
        println!(
            "  memory per idle session: {:.1} KiB (RSS {:.1} MiB -> {:.1} MiB); idle CPU {:.3}% of a core",
            (rss1 as f64 - rss0 as f64) / n / 1024.0,
            rss0 as f64 / 1048576.0,
            rss1 as f64 / 1048576.0,
            (cpu1 - cpu0) / hold as f64 * 100.0
        );
    }
    if devices.is_empty() {
        return;
    }

    // ---- deliver ----
    let body = vec![b'x'; size];
    let s0 = proc_sample(pid);
    let t0 = Instant::now();
    for i in 0..messages as usize {
        let d = &devices[i % devices.len()];
        ch.basic_publish(
            &exchange,
            &format!("session.{}.node.{}", d.session, d.sub),
            BasicPublishOptions::default(),
            &body,
            BasicProperties::default(),
        )
        .await
        .unwrap();
    }
    let published = t0.elapsed();
    while received.load(Ordering::Relaxed) < messages {
        if t0.elapsed() > Duration::from_secs(300) {
            println!(
                "deliver: timed out with {} of {messages}",
                received.load(Ordering::Relaxed)
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let delivered = t0.elapsed();
    let s1 = proc_sample(pid);
    println!(
        "deliver: {messages} x {size} B to {} sessions in {:.2}s ({:.0} msg/s; publisher done at {:.2}s)",
        devices.len(),
        delivered.as_secs_f64(),
        messages as f64 / delivered.as_secs_f64(),
        published.as_secs_f64()
    );
    print_cpu("deliver", s0, s1, messages, delivered);

    // ---- publish ----
    let per = (messages / devices.len() as u64).max(1);
    let total = per * devices.len() as u64;
    let s0 = proc_sample(pid);
    let t0 = Instant::now();
    let mut waits = Vec::new();
    for d in &devices {
        let (tx, rx) = tokio::sync::oneshot::channel();
        d.cmd
            .send(Cmd::Send {
                count: per,
                size,
                done: tx,
            })
            .await
            .unwrap();
        waits.push(rx);
    }
    for w in waits {
        let _ = w.await;
    }
    let elapsed = t0.elapsed();
    let s1 = proc_sample(pid);
    println!(
        "publish: {total} SENDs x {size} B from {} sessions in {:.2}s ({:.0} msg/s)",
        devices.len(),
        elapsed.as_secs_f64(),
        total as f64 / elapsed.as_secs_f64()
    );
    print_cpu("publish", s0, s1, total, elapsed);

    for d in &devices {
        let _ = d.cmd.send(Cmd::Close).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("relay at end: {}", fmt_sample(proc_sample(pid)));
}

fn fmt_sample(s: Option<(f64, u64)>) -> String {
    match s {
        Some((cpu, rss)) => format!("cpu {cpu:.2}s, rss {:.1} MiB", rss as f64 / 1048576.0),
        None => "(no /proc sample; pass --relay-pid on Linux)".into(),
    }
}

fn print_cpu(phase: &str, s0: Option<(f64, u64)>, s1: Option<(f64, u64)>, n: u64, wall: Duration) {
    if let (Some((c0, _)), Some((c1, _))) = (s0, s1) {
        let cpu = c1 - c0;
        println!(
            "  {phase}: relay CPU {cpu:.2}s = {:.1} us per message; {:.0}% of a core on average",
            cpu / n as f64 * 1e6,
            cpu / wall.as_secs_f64() * 100.0
        );
    }
}

/// One device: connect, subscribe like an MPC device, then count MESSAGEs
/// and act on commands.
async fn device(
    relay: String,
    exchange: String,
    sub: String,
    token: String,
    received: Arc<AtomicU64>,
) -> Result<Device, String> {
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(30),
        tokio_tungstenite::connect_async(&relay),
    )
    .await
    .map_err(|_| "ws timeout".to_string())?
    .map_err(|e| format!("ws: {e}"))?;
    let (mut tx, mut rx) = ws.split();
    let session = uuid::Uuid::new_v4().hyphenated().to_string();
    let queue = format!("mpc.session.{sub}.{session}");
    let send = |f: Frame| Message::binary(f.encode());
    tx.send(send(
        Frame::new("CONNECT")
            .with_header("accept-version", "1.2")
            .with_header("host", "/")
            .with_header("passcode", token),
    ))
    .await
    .map_err(|e| format!("send: {e}"))?;
    tx.send(send(
        Frame::new("SUBSCRIBE")
            .with_header("id", "b")
            .with_header(
                "destination",
                format!("/exchange/{exchange}/session.{session}.broadcast"),
            )
            .with_header("x-queue-name", queue.clone()),
    ))
    .await
    .map_err(|e| format!("send: {e}"))?;
    tx.send(send(
        Frame::new("SUBSCRIBE")
            .with_header("id", "n")
            .with_header(
                "destination",
                format!("/exchange/{exchange}/session.{session}.node.{sub}"),
            )
            .with_header("x-queue-name", queue)
            .with_header("receipt", "ready"),
    ))
    .await
    .map_err(|e| format!("send: {e}"))?;
    let mut dec = Decoder::new(64 << 20);
    // Wait for CONNECTED and the RECEIPT.
    let ready = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match rx.next().await {
                Some(Ok(m)) => {
                    dec.extend(&m.into_data());
                    while let Some(f) = dec.decode().map_err(|e| e.to_string())? {
                        match f.command.as_str() {
                            "RECEIPT" => return Ok(()),
                            "ERROR" => {
                                return Err(format!("ERROR {}", f.header("message").unwrap_or("")))
                            }
                            _ => {}
                        }
                    }
                }
                _ => return Err("closed before ready".to_string()),
            }
        }
    })
    .await
    .map_err(|_| "subscribe timeout".to_string())?;
    ready?;

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(4);
    let sink_key = format!("/exchange/{exchange}/session.{session}.node.load-sink");
    tokio::spawn(async move {
        let mut pending_done: Option<tokio::sync::oneshot::Sender<()>> = None;
        loop {
            tokio::select! {
                m = rx.next() => match m {
                    Some(Ok(m)) => {
                        if m.is_ping() || m.is_pong() { continue; }
                        dec.extend(&m.into_data());
                        while let Ok(Some(f)) = dec.decode() {
                            match f.command.as_str() {
                                "MESSAGE" => { received.fetch_add(1, Ordering::Relaxed); }
                                "RECEIPT" => { if let Some(d) = pending_done.take() { let _ = d.send(()); } }
                                _ => {}
                            }
                        }
                    }
                    _ => return,
                },
                c = cmd_rx.recv() => match c {
                    Some(Cmd::Send { count, size, done }) => {
                        let body = vec![b'y'; size];
                        for i in 0..count {
                            let mut f = Frame::new("SEND")
                                .with_header("destination", sink_key.clone())
                                .with_header("content-length", size.to_string());
                            if i + 1 == count {
                                f = f.with_header("receipt", "last");
                            }
                            if tx.send(Message::binary(f.with_body(body.clone()).encode())).await.is_err() {
                                return;
                            }
                        }
                        pending_done = Some(done);
                    }
                    Some(Cmd::Close) | None => {
                        let _ = tx.send(Message::binary(Frame::new("DISCONNECT").encode())).await;
                        let _ = tx.close().await;
                        return;
                    }
                },
            }
        }
    });
    Ok(Device {
        session,
        sub,
        cmd: cmd_tx,
    })
}
