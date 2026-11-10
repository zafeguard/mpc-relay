//! Several relay processes against one real broker. Skips unless
//! MPC_RELAY_TEST_AMQP_URL is set.
//!
//! Each relay process has its own AMQP connections and its own in-process
//! exclusivity registry, so across instances it is the broker's
//! exclusive-queue lock that keeps a session queue to one holder. These
//! tests run the real binary, which also lets them send a real SIGTERM.

mod common;

use std::time::{Duration, Instant};

use common::*;
use mpc_relay::codec::Frame;

fn keys(s: &str, me: &str) -> (String, String) {
    (
        format!("session.{s}.broadcast"),
        format!("session.{s}.node.{me}"),
    )
}

fn qname(me: &str, s: &str) -> String {
    format!("mpc.session.{me}.{s}")
}

fn dest(exchange: &str, key: &str) -> String {
    format!("/exchange/{exchange}/{key}")
}

struct Broker {
    exchange: String,
    amqp: lapin::Connection,
}

impl Broker {
    async fn new(url: String) -> Self {
        let exchange = unique("mpc.inst");
        let amqp = amqp(&url).await;
        declare_exchange(&amqp, &exchange).await;
        Broker { exchange, amqp }
    }

    async fn publish(&self, key: &str, body: &[u8]) {
        let ch = self.amqp.create_channel().await.unwrap();
        publish(&ch, &self.exchange, key, body, None).await;
        let _ = ch.close(200, "ok").await;
    }

    async fn done(self) {
        delete_exchange(&self.amqp, &self.exchange).await;
        let _ = self.amqp.close(200, "done").await;
    }
}

async fn subscribe_session(c: &mut Stomp, exchange: &str, me: &str, s: &str) {
    let (bcast, node) = keys(s, me);
    c.subscribe("b", &dest(exchange, &bcast), &qname(me, s), None)
        .await;
    c.subscribe("n", &dest(exchange, &node), &qname(me, s), Some("bound"))
        .await;
}

/// The same node's session queue, asked for through a second relay
/// instance while the first holds it: refused with ERROR, never a silent
/// second consumer stealing half the messages.
#[tokio::test]
async fn second_instance_cannot_take_a_held_session_queue() {
    let url = require_broker!();
    let br = Broker::new(url.clone()).await;
    let a = RelayProcess::spawn(&url, &br.exchange, &[]).await;
    let b = RelayProcess::spawn(&url, &br.exchange, &[]).await;
    let (s, me) = (session(), "device-x");
    let (bcast, node) = keys(&s, me);
    let q = qname(me, &s);

    let mut holder = Stomp::connect(a.addr, &token(me)).await.unwrap();
    subscribe_session(&mut holder, &br.exchange, me, &s).await;

    // Through instance B, with either key and the same queue name.
    for key in [&node, &bcast] {
        let mut intruder = Stomp::connect(b.addr, &token(me)).await.unwrap();
        intruder
            .send(
                Frame::new("SUBSCRIBE")
                    .with_header("id", "x")
                    .with_header("destination", dest(&br.exchange, key))
                    .with_header("x-queue-name", q.clone())
                    .with_header("receipt", "r"),
            )
            .await;
        let f = intruder.expect_error("resource locked").await;
        let detail = String::from_utf8_lossy(&f.body).into_owned();
        assert!(
            detail.contains("RESOURCE_LOCKED"),
            "the broker's own lock: {detail}"
        );
    }

    // Every message still reaches the holder, in order: nothing was split
    // off to a second consumer.
    for i in 0..30 {
        let key = if i % 2 == 0 { &bcast } else { &node };
        br.publish(key, format!("m{i}").as_bytes()).await;
    }
    for i in 0..30 {
        let f = holder.expect("MESSAGE").await;
        assert_eq!(String::from_utf8_lossy(&f.body), format!("m{i}"));
    }
    holder.expect_silence(Duration::from_millis(300)).await;
    if let Some(m) = mgmt() {
        if let Some(n) = m.wait_consumer_count(&vhost(&url), &q, 2).await {
            assert_eq!(n, 2, "only the holder's two consumers");
        }
    }

    // Instance B itself is unharmed: its other sessions work.
    let mut other = Stomp::connect(b.addr, &token("device-y")).await.unwrap();
    let s2 = session();
    subscribe_session(&mut other, &br.exchange, "device-y", &s2).await;
    br.publish(&format!("session.{s2}.broadcast"), b"b is fine")
        .await;
    assert_eq!(&other.expect("MESSAGE").await.body[..], b"b is fine");

    // Once the holder leaves, instance B can take the queue.
    holder.close().await;
    wait_queue_gone(&url, &q).await;
    let mut taker = Stomp::connect(b.addr, &token(me)).await.unwrap();
    subscribe_session(&mut taker, &br.exchange, me, &s).await;
    br.publish(&node, b"moved").await;
    assert_eq!(&taker.expect("MESSAGE").await.body[..], b"moved");

    drop((a, b));
    br.done().await;
}

/// SIGTERM, with a 2 s drain delay and a 4 s grace:
///
/// * `/readyz` is 503 at once, liveness stays 200;
/// * during the delay ("lame duck") a NEW connection is still accepted and
///   works, so connections the load balancer routes before it deregisters
///   the instance do not fail;
/// * after the delay new WebSockets are refused with HTTP 503;
/// * open sessions keep working throughout, those that leave in time leave
///   cleanly, and the rest get ERROR when the grace runs out.
#[tokio::test]
async fn sigterm_drains_gracefully() {
    let url = require_broker!();
    let br = Broker::new(url.clone()).await;
    let mut p = RelayProcess::spawn(
        &url,
        &br.exchange,
        &[
            ("MPC_RELAY_DRAIN_DELAY", "2s"),
            ("MPC_RELAY_SHUTDOWN_GRACE", "4s"),
        ],
    )
    .await;
    let http = reqwest::Client::new();
    let (s1, s2) = (session(), session());
    let mut stays = Stomp::connect(p.addr, &token("stays")).await.unwrap();
    subscribe_session(&mut stays, &br.exchange, "stays", &s1).await;
    let mut leaves = Stomp::connect(p.addr, &token("leaves")).await.unwrap();
    subscribe_session(&mut leaves, &br.exchange, "leaves", &s2).await;

    let t0 = Instant::now();
    p.sigterm();

    // /readyz turns 503 at once; liveness stays up.
    let mut unready_after = None;
    for _ in 0..100 {
        let r = http
            .get(format!("http://{}/readyz", p.addr))
            .send()
            .await
            .unwrap();
        if r.status() == 503 {
            let body: serde_json::Value = r.json().await.unwrap();
            assert_eq!(body["draining"], true);
            assert_eq!(
                body["accepting"], true,
                "still accepting during the drain delay"
            );
            unready_after = Some(t0.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let unready_after = unready_after.expect("/readyz never went 503");
    assert!(
        unready_after < Duration::from_millis(500),
        "{unready_after:?}"
    );
    let h = http
        .get(format!("http://{}/healthz", p.addr))
        .send()
        .await
        .unwrap();
    assert_eq!(h.status(), 200, "liveness stays up while draining");

    // Lame duck: a brand-new device connecting now is accepted and works.
    let s4 = session();
    let mut late = Stomp::connect(p.addr, &token("late"))
        .await
        .expect("a new connection during the drain delay is accepted");
    subscribe_session(&mut late, &br.exchange, "late", &s4).await;
    br.publish(&format!("session.{s4}.node.late"), b"welcome")
        .await;
    assert_eq!(&late.expect("MESSAGE").await.body[..], b"welcome");
    let accepted_late_at = t0.elapsed();
    assert!(
        accepted_late_at < Duration::from_secs(2),
        "{accepted_late_at:?}"
    );

    // After the delay, new WebSockets are refused (HTTP 503).
    while t0.elapsed() < Duration::from_millis(2300) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    match tokio_tungstenite::connect_async(format!("ws://{}/ws", p.addr)).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 503),
        other => panic!("expected HTTP 503 after the drain delay, got {other:?}"),
    }
    let r = http
        .get(format!("http://{}/readyz", p.addr))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["accepting"], false);

    // Open sessions, including the one accepted during the delay, keep
    // working in both directions.
    for (c, me, s) in [
        (&mut stays, "stays", &s1),
        (&mut leaves, "leaves", &s2),
        (&mut late, "late", &s4),
    ] {
        br.publish(&format!("session.{s}.node.{me}"), b"during drain")
            .await;
        assert_eq!(&c.expect("MESSAGE").await.body[..], b"during drain");
        c.publish(
            &dest(&br.exchange, &format!("session.{s}.node.agent-0")),
            b"reply",
            None,
            Some("sent"),
        )
        .await;
    }

    // One client finishes and leaves cleanly within the grace.
    leaves
        .send(Frame::new("DISCONNECT").with_header("receipt", "bye"))
        .await;
    assert_eq!(
        leaves.expect("RECEIPT").await.header("receipt-id"),
        Some("bye")
    );
    leaves.expect_closed().await;
    wait_queue_gone(&url, &qname("leaves", &s2)).await;

    // The others are told when delay + grace has run out, then closed.
    let mut told = Vec::new();
    for c in [&mut stays, &mut late] {
        let f = c
            .recv_within(Duration::from_secs(12))
            .await
            .expect("ERROR before the timeout")
            .expect("ERROR, not a bare close");
        told.push(t0.elapsed());
        assert_eq!(f.command, "ERROR");
        assert_eq!(f.header("message"), Some("server shutting down"));
        c.expect_closed().await;
    }
    for t in &told {
        assert!(
            *t >= Duration::from_millis(5800) && *t < Duration::from_secs(9),
            "ERROR at {t:?}; delay 2s + grace 4s"
        );
    }
    wait_queue_gone(&url, &qname("stays", &s1)).await;
    wait_queue_gone(&url, &qname("late", &s4)).await;

    let status = p
        .wait_exit(Duration::from_secs(20))
        .await
        .expect("process exits");
    assert!(status.success(), "{status}");
    eprintln!(
        "readyz 503 after {unready_after:?}; new connection accepted and served at {accepted_late_at:?}; refused after 2.3s; remaining told at {told:?}; exited after {:?}",
        t0.elapsed()
    );
    br.done().await;
}

/// The drain ends as soon as the last client has left, not when the grace
/// runs out.
#[tokio::test]
async fn sigterm_exits_early_once_clients_are_gone() {
    let url = require_broker!();
    let br = Broker::new(url.clone()).await;
    let mut p = RelayProcess::spawn(
        &url,
        &br.exchange,
        &[
            ("MPC_RELAY_DRAIN_DELAY", "0s"),
            ("MPC_RELAY_SHUTDOWN_GRACE", "30s"),
        ],
    )
    .await;
    let s = session();
    let mut c = Stomp::connect(p.addr, &token("d")).await.unwrap();
    subscribe_session(&mut c, &br.exchange, "d", &s).await;
    p.sigterm();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let left = Instant::now();
    c.send(Frame::new("DISCONNECT").with_header("receipt", "bye"))
        .await;
    assert_eq!(c.expect("RECEIPT").await.header("receipt-id"), Some("bye"));
    drop(c);
    let status = p
        .wait_exit(Duration::from_secs(10))
        .await
        .expect("exits well before the 30 s grace");
    assert!(status.success());
    let after = left.elapsed();
    assert!(
        after < Duration::from_secs(2),
        "exited {after:?} after the last client left"
    );
    eprintln!("exited {after:?} after the last client left (grace 30s)");
    br.done().await;
}
