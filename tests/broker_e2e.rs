//! Against a real RabbitMQ. Every test skips unless MPC_RELAY_TEST_AMQP_URL
//! is set; with MPC_RELAY_TEST_MGMT_URL also set, queue flags, bindings and
//! consumer counts are asserted through the management API too.
//!
//! The behaviour asserted here is RabbitMQ Web-STOMP's, as the device client
//! relies on it: two SUBSCRIBEs sharing one `x-queue-name` make one
//! exclusive, auto-delete, non-durable queue bound to both keys; messages
//! arrive in publish order; the queue goes away with the connection.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::*;
use futures_util::StreamExt;
use lapin::options::{BasicConsumeOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use mpc_relay::auth::unix_now;
use mpc_relay::codec::Frame;
use serde_json::json;

fn keys(s: &str, me: &str) -> (String, String) {
    (
        format!("session.{s}.broadcast"),
        format!("session.{s}.node.{me}"),
    )
}

fn qname(me: &str, s: &str) -> String {
    format!("mpc.session.{me}.{s}")
}

#[tokio::test]
async fn two_subscribes_share_one_exclusive_queue_in_publish_order() {
    let url = require_broker!();
    let fx = Fixture::new(url.clone()).await;
    let (s, me) = (session(), "device-a");
    let (bcast, node) = keys(&s, me);
    let q = qname(me, &s);

    let mut c = fx.connect(me).await;
    c.subscribe("sub-0", &fx.dest(&bcast), &q, None).await;
    c.subscribe("sub-1", &fx.dest(&node), &q, Some("ready"))
        .await;

    // One queue, exclusive to the relay's AMQP connection.
    assert_eq!(probe_queue(&url, &q).await, QueueProbe::Exclusive);
    if let Some(m) = mgmt() {
        let vh = vhost(&url);
        let info = m.queue(&vh, &q).await.expect("queue exists");
        assert_eq!(info["exclusive"], true);
        assert_eq!(info["auto_delete"], true);
        assert_eq!(info["durable"], false);
        let mut want = vec![bcast.clone(), node.clone()];
        want.sort();
        assert_eq!(
            m.binding_keys(&vh, &q, &fx.exchange).await,
            want,
            "bound to exactly those two keys"
        );
        // One consumer per subscription id, as Web-STOMP creates them -
        // when the broker exposes consumer statistics at all. (Without
        // them, the rotating subscription header below shows the same.)
        let mut consumers = m.consumer_count(&vh, &q).await;
        for _ in 0..100 {
            if consumers.is_none_or(|n| n == 2) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            consumers = m.consumer_count(&vh, &q).await;
        }
        match consumers {
            Some(n) => assert_eq!(n, 2, "two consumers on the one queue"),
            None => eprintln!(
                "note: management statistics disabled on this broker; consumer count not asserted"
            ),
        }
    } else {
        eprintln!("note: MPC_RELAY_TEST_MGMT_URL not set; queue flags and bindings checked behaviourally only");
    }

    // Interleave the two keys, with unicasts to another node mixed in.
    let ch = fx.channel().await;
    let n = 60;
    for i in 0..n {
        let key = if i % 3 == 0 { &bcast } else { &node };
        publish(
            &ch,
            &fx.exchange,
            key,
            format!("m{i}").as_bytes(),
            Some("text/plain"),
        )
        .await;
        if i % 10 == 0 {
            publish(
                &ch,
                &fx.exchange,
                &format!("session.{s}.node.device-b"),
                b"not for me",
                None,
            )
            .await;
        }
    }
    let mut subs = HashSet::new();
    for i in 0..n {
        let f = c.expect("MESSAGE").await;
        assert_eq!(
            String::from_utf8_lossy(&f.body),
            format!("m{i}"),
            "publish order preserved"
        );
        let key = if i % 3 == 0 { &bcast } else { &node };
        assert_eq!(f.header("destination").unwrap(), fx.dest(key));
        assert_eq!(f.header("content-type"), Some("text/plain"));
        assert_eq!(
            f.header("content-length"),
            Some(format!("m{i}").len().to_string().as_str())
        );
        assert!(f.header("message-id").is_some());
        subs.insert(f.header("subscription").unwrap().to_owned());
    }
    assert_eq!(
        subs,
        HashSet::from(["sub-0".to_owned(), "sub-1".to_owned()]),
        "one queue, two consumers: the subscription header rotates between both ids"
    );
    c.expect_silence(Duration::from_millis(500)).await;

    c.close().await;
    wait_queue_gone(&url, &q).await;
    fx.teardown().await;
}

#[tokio::test]
async fn relay_send_reaches_a_raw_amqp_consumer() {
    let url = require_broker!();
    let fx = Fixture::new(url.clone()).await;
    let s = session();
    // The agent side: bound the way the AMQP carrier binds its own queue.
    let agent = "agent-0";
    let (bcast, agent_key) = keys(&s, agent);
    let ch = fx.channel().await;
    let aq = qname(agent, &s);
    ch.queue_declare(
        &aq,
        QueueDeclareOptions {
            exclusive: true,
            auto_delete: true,
            ..Default::default()
        },
        FieldTable::default(),
    )
    .await
    .unwrap();
    for k in [&bcast, &agent_key] {
        ch.queue_bind(
            &aq,
            &fx.exchange,
            k,
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .unwrap();
    }
    let mut consumer = ch
        .basic_consume(
            &aq,
            "",
            BasicConsumeOptions {
                no_ack: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .unwrap();

    let mut c = fx.connect("device-a").await;
    let binary: Vec<u8> = vec![0, 1, 2, 0xff, 0, b'\n', 0, 0xfe];
    c.publish(
        &fx.dest(&agent_key),
        &binary,
        Some("application/octet-stream"),
        Some("p1"),
    )
    .await;
    c.publish(
        &fx.dest(&bcast),
        br#"{"round":1}"#,
        Some("application/json"),
        None,
    )
    .await;
    c.publish(
        &fx.dest(&format!("session.{s}.node.agent-1")),
        b"elsewhere",
        None,
        Some("p2"),
    )
    .await;
    c.publish(&fx.dest(&bcast), b"no content type", None, Some("p3"))
        .await;

    macro_rules! next {
        () => {
            tokio::time::timeout(TIMEOUT, consumer.next())
                .await
                .expect("delivery")
                .unwrap()
                .unwrap()
        };
    }
    let d1 = next!();
    assert_eq!(d1.routing_key.as_str(), agent_key);
    assert_eq!(d1.data, binary, "body bytes unchanged");
    assert_eq!(
        d1.properties.content_type().as_ref().map(|c| c.as_str()),
        Some("application/octet-stream")
    );
    let d2 = next!();
    assert_eq!(d2.routing_key.as_str(), bcast);
    assert_eq!(d2.data, br#"{"round":1}"#);
    assert_eq!(
        d2.properties.content_type().as_ref().map(|c| c.as_str()),
        Some("application/json")
    );
    let d3 = next!();
    assert_eq!(
        d3.data, b"no content type",
        "the agent-1 unicast was not routed here"
    );
    assert!(d3.properties.content_type().is_none());

    let metrics = fx.relay.as_ref().unwrap().shared.metrics.render();
    assert!(metrics.contains("mpc_relay_publishes_total 4"), "{metrics}");
    c.close().await;
    fx.teardown().await;
}

#[tokio::test]
async fn raw_amqp_publish_reaches_a_relay_client() {
    let url = require_broker!();
    let fx = Fixture::new(url.clone()).await;
    let (s, me) = (session(), "device-a");
    let (bcast, node) = keys(&s, me);
    let q = qname(me, &s);
    let mut c = fx.connect(me).await;
    c.subscribe("b", &fx.dest(&bcast), &q, None).await;
    c.subscribe("n", &fx.dest(&node), &q, Some("r")).await;

    let ch = fx.channel().await;
    // Not UTF-8, with NULs: must arrive byte for byte, length-delimited.
    let binary: Vec<u8> = vec![0xc3, 0x28, 0, 0, 0xff, b'a', 0];
    publish(
        &ch,
        &fx.exchange,
        &node,
        &binary,
        Some("application/octet-stream"),
    )
    .await;
    publish(&ch, &fx.exchange, &bcast, b"plain", None).await;
    let big = vec![b'x'; 256 * 1024];
    publish(&ch, &fx.exchange, &bcast, &big, Some("text/plain")).await;

    let f = c.expect("MESSAGE").await;
    assert_eq!(&f.body[..], &binary[..]);
    assert_eq!(f.header("content-type"), Some("application/octet-stream"));
    assert_eq!(f.header("content-length"), Some("7"));
    let f = c.expect("MESSAGE").await;
    assert_eq!(&f.body[..], b"plain");
    assert_eq!(
        f.header("content-type"),
        None,
        "no content-type when the AMQP message had none"
    );
    let f = c.expect("MESSAGE").await;
    assert_eq!(f.body.len(), big.len());
    c.close().await;
    fx.teardown().await;
}

#[tokio::test]
async fn device_to_device_through_the_relay() {
    let url = require_broker!();
    let fx = Fixture::new(url).await;
    let s = session();
    let mut a = fx.connect("dev-a").await;
    let mut b = fx.connect("dev-b").await;
    for (c, me) in [(&mut a, "dev-a"), (&mut b, "dev-b")] {
        let (bcast, node) = keys(&s, me);
        c.subscribe("0", &fx.dest(&bcast), &qname(me, &s), None)
            .await;
        c.subscribe("1", &fx.dest(&node), &qname(me, &s), Some("r"))
            .await;
    }
    a.publish(
        &fx.dest(&format!("session.{s}.node.dev-b")),
        b"hello b",
        Some("text/plain"),
        Some("x"),
    )
    .await;
    // No receipt here: the sender is subscribed to the broadcast key too,
    // and its own MESSAGE may overtake the RECEIPT (which waits for the
    // publisher confirm). STOMP does not order the two.
    a.publish(
        &fx.dest(&format!("session.{s}.broadcast")),
        b"hello all",
        None,
        None,
    )
    .await;
    assert_eq!(&b.expect("MESSAGE").await.body[..], b"hello b");
    assert_eq!(&b.expect("MESSAGE").await.body[..], b"hello all");
    // A broadcast reaches its sender too, as on Web-STOMP.
    assert_eq!(&a.expect("MESSAGE").await.body[..], b"hello all");
    a.expect_silence(Duration::from_millis(300)).await;
    a.close().await;
    b.close().await;
    fx.teardown().await;
}

/// Addenda to the spec: a SUBSCRIBE RECEIPT is sent only once the queue is
/// declared, the binding exists and the consumer has started; frames are
/// processed in order, so a RECEIPT on the second SUBSCRIBE vouches for the
/// first one's binding too; an UNSUBSCRIBE RECEIPT follows the cancel.
#[tokio::test]
async fn receipts_vouch_for_bindings_and_cancels() {
    let url = require_broker!();
    let fx = Fixture::new(url.clone()).await;
    let ch = fx.channel().await;
    let me = "device-r";
    let mut c = fx.connect(me).await;

    for i in 0..40 {
        let s = session();
        let (bcast, node) = keys(&s, me);
        let q = qname(me, &s);
        // Receipt on the SECOND subscribe only.
        c.subscribe(&format!("b{i}"), &fx.dest(&bcast), &q, None)
            .await;
        c.subscribe(
            &format!("n{i}"),
            &fx.dest(&node),
            &q,
            Some(&format!("r{i}")),
        )
        .await;
        // Immediately publish to the FIRST key, then the second.
        publish(
            &ch,
            &fx.exchange,
            &bcast,
            format!("first-{i}").as_bytes(),
            None,
        )
        .await;
        publish(
            &ch,
            &fx.exchange,
            &node,
            format!("second-{i}").as_bytes(),
            None,
        )
        .await;
        assert_eq!(
            String::from_utf8_lossy(&c.expect("MESSAGE").await.body),
            format!("first-{i}")
        );
        assert_eq!(
            String::from_utf8_lossy(&c.expect("MESSAGE").await.body),
            format!("second-{i}")
        );

        // After the UNSUBSCRIBE RECEIPT the cancelled consumer gets nothing:
        // every message now goes to the remaining subscription.
        c.unsubscribe(&format!("b{i}"), Some(&format!("u{i}")))
            .await;
        for j in 0..4 {
            publish(
                &ch,
                &fx.exchange,
                &bcast,
                format!("after-{i}-{j}").as_bytes(),
                None,
            )
            .await;
        }
        for j in 0..4 {
            let f = c.expect("MESSAGE").await;
            assert_eq!(String::from_utf8_lossy(&f.body), format!("after-{i}-{j}"));
            assert_eq!(
                f.header("subscription"),
                Some(format!("n{i}").as_str()),
                "cancelled before RECEIPT"
            );
        }
        // Last consumer cancelled: the broker auto-deletes the queue.
        c.unsubscribe(&format!("n{i}"), Some(&format!("v{i}")))
            .await;
        wait_queue_gone(&url, &q).await;
    }

    // And on fresh connections, where the race against the first frames of
    // a connection would show.
    for i in 0..20 {
        let s = session();
        let (bcast, node) = keys(&s, me);
        let q = qname(me, &s);
        let mut c2 = fx.connect(&format!("fresh-{i}")).await;
        let me2 = format!("fresh-{i}");
        let (bcast2, node2) = keys(&s, &me2);
        let q2 = qname(&me2, &s);
        let _ = (&node, &q, &bcast);
        c2.subscribe("a", &fx.dest(&bcast2), &q2, None).await;
        c2.subscribe("b", &fx.dest(&node2), &q2, Some("go")).await;
        publish(&ch, &fx.exchange, &bcast2, b"first", None).await;
        assert_eq!(&c2.expect("MESSAGE").await.body[..], b"first");
        c2.close().await;
    }
    c.close().await;
    fx.teardown().await;
}

#[tokio::test]
async fn several_sessions_on_one_connection() {
    let url = require_broker!();
    let fx = Fixture::new(url.clone()).await;
    let me = "device-m";
    let (s1, s2) = (session(), session());
    let mut c = fx.connect(me).await;
    for (i, s) in [&s1, &s2].iter().enumerate() {
        let (bcast, node) = keys(s, me);
        c.subscribe(&format!("{i}b"), &fx.dest(&bcast), &qname(me, s), None)
            .await;
        c.subscribe(&format!("{i}n"), &fx.dest(&node), &qname(me, s), Some("ok"))
            .await;
    }
    let ch = fx.channel().await;
    publish(
        &ch,
        &fx.exchange,
        &format!("session.{s2}.broadcast"),
        b"to s2",
        None,
    )
    .await;
    publish(
        &ch,
        &fx.exchange,
        &format!("session.{s1}.node.{me}"),
        b"to s1",
        None,
    )
    .await;
    let mut got: Vec<String> = Vec::new();
    for _ in 0..2 {
        got.push(String::from_utf8_lossy(&c.expect("MESSAGE").await.body).into_owned());
    }
    got.sort();
    assert_eq!(got, vec!["to s1", "to s2"]);
    assert_eq!(
        probe_queue(&url, &qname(me, &s1)).await,
        QueueProbe::Exclusive
    );
    assert_eq!(
        probe_queue(&url, &qname(me, &s2)).await,
        QueueProbe::Exclusive
    );
    // DISCONNECT with a receipt: RECEIPT, close, and both queues deleted.
    c.send(Frame::new("DISCONNECT").with_header("receipt", "bye"))
        .await;
    assert_eq!(c.expect("RECEIPT").await.header("receipt-id"), Some("bye"));
    c.expect_closed().await;
    wait_queue_gone(&url, &qname(me, &s1)).await;
    wait_queue_gone(&url, &qname(me, &s2)).await;
    fx.teardown().await;
}

#[tokio::test]
async fn acl_rejections() {
    let url = require_broker!();
    let fx = Fixture::new(url.clone()).await;
    let (s, me) = (session(), "device-a");
    let (bcast, _) = keys(&s, me);
    let q = qname(me, &s);
    let other_s = session();

    let subscribe_cases: Vec<(String, Option<String>)> = vec![
        // another node's unicast key
        (
            fx.dest(&format!("session.{s}.node.device-b")),
            Some(q.clone()),
        ),
        // another node's queue name
        (fx.dest(&bcast), Some(qname("device-b", &s))),
        // queue name for a different session
        (fx.dest(&bcast), Some(qname(me, &other_s))),
        // no x-queue-name
        (fx.dest(&bcast), None),
        // another exchange
        (format!("/exchange/amq.topic/{bcast}"), Some(q.clone())),
        // other destination types
        (format!("/queue/{q}"), Some(q.clone())),
        (format!("/topic/{bcast}"), Some(q.clone())),
        (format!("/amq/queue/{q}"), Some(q.clone())),
        (format!("/temp-queue/{q}"), Some(q.clone())),
        // wildcards
        (fx.dest(&format!("session.{s}.#")), Some(q.clone())),
        (fx.dest("session.*.broadcast"), Some(q.clone())),
        // not a session key
        (fx.dest("anything"), Some(q.clone())),
    ];
    for (dest, queue) in subscribe_cases {
        let mut c = fx.connect(me).await;
        let mut f = Frame::new("SUBSCRIBE")
            .with_header("id", "x")
            .with_header("destination", dest.clone());
        if let Some(q) = &queue {
            f = f.with_header("x-queue-name", q.clone());
        }
        c.send(f).await;
        c.expect_error("access refused").await;
    }
    // None of those created a queue.
    assert_eq!(probe_queue(&url, &q).await, QueueProbe::Gone);

    let send_cases = vec![
        fx.dest(&format!("session.{s}.*")),
        format!("/exchange/amq.topic/{bcast}"),
        format!("/queue/{q}"),
        fx.dest("not.a.session.key"),
        fx.dest(&format!("session.{s}.node.has space")),
    ];
    for dest in send_cases {
        let mut c = fx.connect(me).await;
        c.send(
            Frame::new("SEND")
                .with_header("destination", dest.clone())
                .with_body(&b"x"[..]),
        )
        .await;
        c.expect_error("access refused").await;
    }

    // `sessions` claim: only the listed session.
    let now = unix_now();
    let limited = token_with(json!({"sub": me, "exp": now + 600, "sessions": [other_s]}));
    let mut c = Stomp::connect(fx.addr, &limited).await.unwrap();
    c.subscribe(
        "ok",
        &fx.dest(&format!("session.{other_s}.broadcast")),
        &qname(me, &other_s),
        Some("r"),
    )
    .await;
    c.send(
        Frame::new("SUBSCRIBE")
            .with_header("id", "no")
            .with_header("destination", fx.dest(&bcast))
            .with_header("x-queue-name", q.clone()),
    )
    .await;
    c.expect_error("access refused").await;
    let mut c = Stomp::connect(fx.addr, &limited).await.unwrap();
    c.send(Frame::new("SEND").with_header("destination", fx.dest(&bcast)))
        .await;
    c.expect_error("access refused").await;

    // ack modes other than auto, and unsupported commands.
    for ack in ["client", "client-individual"] {
        let mut c = fx.connect(me).await;
        c.send(
            Frame::new("SUBSCRIBE")
                .with_header("id", "x")
                .with_header("destination", fx.dest(&bcast))
                .with_header("ack", ack)
                .with_header("x-queue-name", q.clone()),
        )
        .await;
        c.expect_error("not supported").await;
    }
    for cmd in ["ACK", "NACK", "BEGIN", "COMMIT", "ABORT", "FROBNICATE"] {
        let mut c = fx.connect(me).await;
        c.send(
            Frame::new(cmd)
                .with_header("id", "1")
                .with_header("transaction", "t"),
        )
        .await;
        c.expect_error("not supported").await;
    }
    let metrics = fx.relay.as_ref().unwrap().shared.metrics.render();
    assert!(
        metrics.contains(r#"mpc_relay_errors_total{reason="acl"}"#),
        "{metrics}"
    );
    fx.teardown().await;
}

#[tokio::test]
async fn bad_tokens_are_refused_without_detail() {
    let url = require_broker!();
    let fx = Fixture::new(url).await;
    let now = unix_now();
    let expired = token_with(json!({"sub": "d", "exp": now - 3600}));
    let wrong_key = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &json!({"sub": "d", "exp": now + 600}),
        &jsonwebtoken::EncodingKey::from_secret(b"not-the-relay-secret-not-the-relay-secret"),
    )
    .unwrap();
    let b64 = |v: serde_json::Value| {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let alg_none = format!(
        "{}.{}.",
        b64(json!({"alg": "none"})),
        b64(json!({"sub": "d", "exp": now + 600}))
    );
    let not_yet = token_with(json!({"sub": "d", "exp": now + 600, "nbf": now + 3600}));
    for (t, reason) in [
        (expired.as_str(), "expired"),
        (wrong_key.as_str(), "bad_signature"),
        ("garbage", "malformed"),
        (alg_none.as_str(), "bad_algorithm"),
        (not_yet.as_str(), "not_yet_valid"),
        ("", "missing_token"),
    ] {
        let err = match Stomp::connect(fx.addr, t).await {
            Err(f) => f,
            Ok(_) => panic!("{reason}: accepted"),
        };
        assert_eq!(
            err.header("message"),
            Some("authentication failed"),
            "{reason}"
        );
        assert_eq!(
            &err.body[..],
            b"authentication failed",
            "{reason}: no detail on the wire"
        );
        let metrics = fx.relay.as_ref().unwrap().shared.metrics.render();
        assert!(
            metrics.contains(&format!(
                r#"mpc_relay_auth_failures_total{{reason="{reason}"}} 1"#
            )),
            "{reason}: {metrics}"
        );
    }
    fx.teardown().await;
}

#[tokio::test]
async fn second_connection_on_a_held_queue_is_refused() {
    let url = require_broker!();
    let fx = Fixture::new(url.clone()).await;
    let (s, me) = (session(), "device-a");
    let (bcast, node) = keys(&s, me);
    let q = qname(me, &s);
    let mut a = fx.connect(me).await;
    a.subscribe("0", &fx.dest(&bcast), &q, None).await;
    a.subscribe("1", &fx.dest(&node), &q, Some("r")).await;

    // Same node, second connection, same queue name: RESOURCE_LOCKED.
    let mut b = fx.connect(me).await;
    b.send(
        Frame::new("SUBSCRIBE")
            .with_header("id", "0")
            .with_header("destination", fx.dest(&bcast))
            .with_header("x-queue-name", q.clone()),
    )
    .await;
    b.expect_error("resource locked").await;

    // The holder is undisturbed.
    let ch = fx.channel().await;
    publish(&ch, &fx.exchange, &node, b"still mine", None).await;
    assert_eq!(&a.expect("MESSAGE").await.body[..], b"still mine");

    // Once the holder leaves, the name is free again.
    a.close().await;
    wait_queue_gone(&url, &q).await;
    let mut c = None;
    for _ in 0..50 {
        let mut attempt = fx.connect(me).await;
        attempt
            .send(
                Frame::new("SUBSCRIBE")
                    .with_header("id", "0")
                    .with_header("destination", fx.dest(&bcast))
                    .with_header("x-queue-name", q.clone())
                    .with_header("receipt", "r"),
            )
            .await;
        let f = attempt.recv().await.unwrap();
        if f.command == "RECEIPT" {
            c = Some(attempt);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut c = c.expect("queue name released after the holder disconnected");
    publish(&ch, &fx.exchange, &bcast, b"new holder", None).await;
    assert_eq!(&c.expect("MESSAGE").await.body[..], b"new holder");
    c.close().await;
    fx.teardown().await;
}

#[tokio::test]
async fn token_expiry_mid_connection_closes_it() {
    let url = require_broker!();
    let fx = Fixture::with_config(url, |c| c.auth.leeway = Duration::ZERO).await;
    let now = unix_now();
    let t = token_with(json!({"sub": "d", "exp": now + 2}));
    let mut c = Stomp::connect(fx.addr, &t).await.unwrap();
    let f = c
        .recv_within(Duration::from_secs(5))
        .await
        .expect("closed in time")
        .expect("ERROR frame");
    assert_eq!(f.command, "ERROR");
    assert_eq!(f.header("message"), Some("token expired"));
    c.expect_closed().await;
    fx.teardown().await;
}

#[tokio::test]
async fn send_rate_limit() {
    let url = require_broker!();
    let fx = Fixture::with_config(url, |c| {
        c.limits.send_rate = 5.0;
        c.limits.send_burst = 5;
    })
    .await;
    let s = session();
    let mut c = fx.connect("d").await;
    for _ in 0..5 {
        c.send(
            Frame::new("SEND")
                .with_header("destination", fx.dest(&format!("session.{s}.broadcast"))),
        )
        .await;
    }
    c.send(
        Frame::new("SEND").with_header("destination", fx.dest(&format!("session.{s}.broadcast"))),
    )
    .await;
    c.expect_error("rate limit exceeded").await;
    fx.teardown().await;
}

#[tokio::test]
async fn subscription_limit() {
    let url = require_broker!();
    let fx = Fixture::with_config(url, |c| c.limits.max_subscriptions = 2).await;
    let me = "d";
    let mut c = fx.connect(me).await;
    for i in 0..2 {
        let s = session();
        c.subscribe(
            &i.to_string(),
            &fx.dest(&format!("session.{s}.broadcast")),
            &qname(me, &s),
            Some("r"),
        )
        .await;
    }
    let s = session();
    c.send(
        Frame::new("SUBSCRIBE")
            .with_header("id", "2")
            .with_header("destination", fx.dest(&format!("session.{s}.broadcast")))
            .with_header("x-queue-name", qname(me, &s)),
    )
    .await;
    c.expect_error("too many subscriptions").await;
    fx.teardown().await;
}

#[tokio::test]
async fn protocol_errors_after_connect() {
    let url = require_broker!();
    let fx = Fixture::with_config(url, |c| c.limits.max_frame_bytes = 2048).await;
    let (s, me) = (session(), "d");
    let (bcast, _) = keys(&s, me);

    let mut c = fx.connect(me).await;
    c.publish(&fx.dest(&bcast), &vec![b'z'; 4096], None, None)
        .await;
    c.expect_error("frame too large").await;

    let mut c = fx.connect(me).await;
    c.subscribe("dup", &fx.dest(&bcast), &qname(me, &s), Some("r"))
        .await;
    c.send(
        Frame::new("SUBSCRIBE")
            .with_header("id", "dup")
            .with_header("destination", fx.dest(&bcast))
            .with_header("x-queue-name", qname(me, &s)),
    )
    .await;
    c.expect_error("duplicate subscription id").await;

    let mut c = fx.connect(me).await;
    c.send(Frame::new("UNSUBSCRIBE").with_header("id", "nope"))
        .await;
    c.expect_error("subscription not found").await;

    let mut c = fx.connect(me).await;
    c.send(Frame::new("CONNECT").with_header("accept-version", "1.2"))
        .await;
    c.expect_error("already connected").await;

    let mut c = fx.connect(me).await;
    c.send(Frame::new("SUBSCRIBE").with_header("destination", fx.dest(&bcast)))
        .await;
    c.expect_error("missing header").await;
    fx.teardown().await;
}

#[tokio::test]
async fn idle_timeout_spares_a_client_that_answers_pings() {
    let url = require_broker!();
    let fx = Fixture::with_config(url, |c| {
        c.limits.idle_timeout = Duration::from_millis(1200);
        c.limits.ping_interval = Duration::from_millis(300);
    })
    .await;
    let mut c = fx.connect("d").await;
    // Reading lets the client answer pings: well past the idle timeout and
    // still connected.
    c.expect_silence(Duration::from_millis(3000)).await;
    // Stop reading (no pongs) and the relay gives up on it.
    tokio::time::sleep(Duration::from_millis(2000)).await;
    c.expect_error("idle timeout").await;
    fx.teardown().await;
}

#[tokio::test]
async fn broker_loss_ends_sessions_and_the_relay_recovers() {
    let url = require_broker!();
    let Some(m) = mgmt() else {
        eprintln!(
            "SKIPPED: needs MPC_RELAY_TEST_MGMT_URL to force-close the relay's broker connection"
        );
        return;
    };
    // The relay connects as its own broker user, so closing that user's
    // connections hits the relay and nothing else running in parallel.
    let vh = vhost(&url);
    let user = unique("relay-loss");
    m.create_user(&vh, &user, "loss-test").await;
    let relay_url = with_credentials(&url, &user, "loss-test");
    let fx = Fixture::with_config(url.clone(), |c| c.amqp_url = relay_url.clone()).await;
    let relay = fx.relay.as_ref().unwrap();
    let http = reqwest::Client::new();
    let readyz = format!("http://{}/readyz", fx.addr);
    assert_eq!(http.get(&readyz).send().await.unwrap().status(), 200);

    let (s, me) = (session(), "d");
    let mut c = fx.connect(me).await;
    c.subscribe(
        "0",
        &fx.dest(&format!("session.{s}.broadcast")),
        &qname(me, &s),
        Some("r"),
    )
    .await;

    assert!(
        m.close_user_connections(&user).await,
        "closed the relay's broker connection"
    );
    c.expect_error("broker unavailable").await;

    // Not ready while down; ready again after the reconnect.
    let mut saw_unready = false;
    let mut ready_again = false;
    for _ in 0..400 {
        let status = http.get(&readyz).send().await.unwrap().status();
        if status == 503 {
            saw_unready = true;
        } else if saw_unready && status == 200 {
            ready_again = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(saw_unready, "readyz reported 503 while disconnected");
    assert!(ready_again, "readyz recovered after reconnect");
    let metrics = relay.shared.metrics.render();
    assert!(
        metrics.contains("mpc_relay_broker_connected 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains(r#"mpc_relay_errors_total{reason="broker_unavailable"} 1"#),
        "{metrics}"
    );

    // The old exclusive queue died with the old connection; a new session
    // works end to end.
    let mut c = fx.connect(me).await;
    c.subscribe(
        "0",
        &fx.dest(&format!("session.{s}.broadcast")),
        &qname(me, &s),
        Some("r"),
    )
    .await;
    let ch = fx.channel().await;
    publish(
        &ch,
        &fx.exchange,
        &format!("session.{s}.broadcast"),
        b"back",
        None,
    )
    .await;
    assert_eq!(&c.expect("MESSAGE").await.body[..], b"back");
    c.close().await;
    fx.teardown().await;
    m.delete_user(&user).await;
}

#[tokio::test]
async fn readiness_follows_the_exchange() {
    let url = require_broker!();
    let exchange = unique("mpc.late");
    let mut cfg = config(&url, &exchange);
    cfg.amqp_connection_name = unique("mpc-relay-late");
    let relay = mpc_relay::server::start(cfg).await.unwrap();
    let http = reqwest::Client::new();
    let readyz = format!("http://{}/readyz", relay.local_addr);
    // Connected, but the agents have not declared the exchange yet.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let r = http.get(&readyz).send().await.unwrap();
    assert_eq!(r.status(), 503);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["broker"], true);
    assert_eq!(body["exchange"], false);
    let err = Stomp::connect(relay.local_addr, &token("d"))
        .await
        .err()
        .expect("refused");
    assert_eq!(err.header("message"), Some("broker unavailable"));

    let amqp = amqp(&url).await;
    declare_exchange(&amqp, &exchange).await;
    let mut ready = false;
    for _ in 0..100 {
        if http.get(&readyz).send().await.unwrap().status() == 200 {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "ready once the exchange exists");
    assert!(Stomp::connect(relay.local_addr, &token("d")).await.is_ok());
    relay.shutdown().await;
    delete_exchange(&amqp, &exchange).await;
}

#[tokio::test]
async fn shutdown_tells_clients_and_deletes_their_queues() {
    let url = require_broker!();
    let fx = Fixture::new(url.clone()).await;
    let (s, me) = (session(), "d");
    let q = qname(me, &s);
    let mut c = fx.connect(me).await;
    c.subscribe(
        "0",
        &fx.dest(&format!("session.{s}.broadcast")),
        &q,
        Some("r"),
    )
    .await;
    let Fixture {
        relay,
        amqp,
        exchange,
        ..
    } = fx;
    let stop = tokio::spawn(relay.unwrap().shutdown());
    c.expect_error("server shutting down").await;
    stop.await.unwrap();
    wait_queue_gone(&url, &q).await;
    delete_exchange(&amqp, &exchange).await;
}

#[tokio::test]
async fn a_channel_closed_by_the_broker_ends_the_session_promptly() {
    let url = require_broker!();
    let fx = Fixture::new(url).await;
    let s = session();
    let mut c = fx.connect("d").await;
    // The agents' exchange disappears; a publish to it makes the broker
    // close the client's channel (404) asynchronously. The client has no
    // consumers and sends nothing more, and must still be told.
    delete_exchange(&fx.amqp, &fx.exchange).await;
    c.publish(
        &fx.dest(&format!("session.{s}.broadcast")),
        b"x",
        None,
        None,
    )
    .await;
    c.expect_error("broker unavailable").await;
    fx.teardown().await;
}

/// A connection with `channel_max=3` carries one session (two channels
/// are kept back), so every further session needs another connection.
fn tiny_channel_max(url: &str) -> String {
    format!("{url}?channel_max=3")
}

/// Subscribe `c` (node `me`) to a fresh session and prove a raw publish to
/// its broadcast key reaches it.
async fn prove_session_works(fx: &Fixture, c: &mut Stomp, me: &str) {
    let s = session();
    let (bcast, node) = keys(&s, me);
    c.subscribe("b", &fx.dest(&bcast), &qname(me, &s), None)
        .await;
    c.subscribe("n", &fx.dest(&node), &qname(me, &s), Some("ok"))
        .await;
    let ch = fx.channel().await;
    publish(
        &ch,
        &fx.exchange,
        &bcast,
        format!("to {me}").as_bytes(),
        None,
    )
    .await;
    assert_eq!(
        String::from_utf8_lossy(&c.expect("MESSAGE").await.body),
        format!("to {me}")
    );
    let _ = ch.close(200, "ok").await;
}

/// The pool opens connections only when the live ones are full, places
/// sessions beyond one connection's channel_max on the next, and reuses
/// freed places before opening more.
#[tokio::test]
async fn pool_opens_connections_lazily_and_spreads_sessions() {
    let url = require_broker!();
    let capped = tiny_channel_max(&url);
    let fx = Fixture::with_config(url.clone(), |c| {
        c.amqp_url = capped.clone();
        c.limits.max_connections = 3; // => pool cap ceil(3 / 1) = 3
    })
    .await;
    let pool = fx.relay.as_ref().unwrap().shared.pool.clone();
    let snap = pool.snapshot();
    assert_eq!(
        snap.len(),
        1,
        "only the first connection is opened at startup: {snap:?}"
    );
    assert_eq!(snap[0].capacity, 1, "channel_max 3 minus the margin of 2");
    assert_eq!(pool.cap(), 3);

    let mut clients = Vec::new();
    for i in 0..3 {
        let me = format!("d{i}");
        let mut c = fx.connect(&me).await;
        prove_session_works(&fx, &mut c, &me).await;
        clients.push(c);
        assert_eq!(
            pool.snapshot().len(),
            i + 1,
            "a connection per session once each is full"
        );
    }
    let snap = pool.snapshot();
    assert!(
        snap.iter().all(|s| s.connected && s.sessions == 1),
        "{snap:?}"
    );
    let metrics = fx.relay.as_ref().unwrap().shared.metrics.render();
    assert!(
        metrics.contains("mpc_relay_amqp_connections 3"),
        "{metrics}"
    );
    assert!(
        metrics.contains("mpc_relay_amqp_channels_in_use 3"),
        "{metrics}"
    );

    // The client limit still applies on top: a fourth WebSocket is refused.
    match tokio_tungstenite::connect_async(format!("ws://{}/ws", fx.addr)).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 503),
        other => panic!("expected HTTP 503, got {other:?}"),
    }

    // A freed place is reused: no fourth connection.
    clients.pop().unwrap().close().await;
    let mut freed = false;
    for _ in 0..50 {
        if pool.snapshot().iter().any(|s| s.sessions == 0) {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(freed, "the departed session's place was released");
    let mut c = fx.connect("d9").await;
    prove_session_works(&fx, &mut c, "d9").await;
    assert_eq!(pool.snapshot().len(), 3);
    fx.teardown().await;
}

/// MPC_RELAY_AMQP_MAX_CONNECTIONS overrides the derived cap; past it,
/// CONNECT gets a clear ERROR.
#[tokio::test]
async fn pool_cap_override_refuses_beyond_capacity() {
    let url = require_broker!();
    let capped = tiny_channel_max(&url);
    let fx = Fixture::with_config(url.clone(), |c| {
        c.amqp_url = capped.clone();
        c.limits.max_connections = 50;
        c.amqp_max_connections = Some(2);
    })
    .await;
    let pool = fx.relay.as_ref().unwrap().shared.pool.clone();
    let mut held = Vec::new();
    for i in 0..2 {
        let me = format!("d{i}");
        let mut c = fx.connect(&me).await;
        prove_session_works(&fx, &mut c, &me).await;
        held.push(c);
    }
    assert_eq!(pool.cap(), 2);
    let err = Stomp::connect(fx.addr, &token("d2"))
        .await
        .err()
        .expect("refused");
    assert_eq!(err.header("message"), Some("too many connections"));
    assert_eq!(pool.snapshot().len(), 2, "no connection beyond the cap");
    let metrics = fx.relay.as_ref().unwrap().shared.metrics.render();
    assert!(
        metrics.contains(r#"mpc_relay_errors_total{reason="pool_full"} 1"#),
        "{metrics}"
    );
    fx.teardown().await;
}

/// One pooled connection dropping ends exactly the sessions on it; the
/// others carry on, the relay stays ready, and the lost connection comes
/// back on its own.
#[tokio::test]
async fn losing_one_pooled_connection_drops_only_its_sessions() {
    let url = require_broker!();
    let Some(m) = mgmt() else {
        eprintln!("SKIPPED: needs MPC_RELAY_TEST_MGMT_URL to close one of the relay's connections");
        return;
    };
    let vh = vhost(&url);
    let user = unique("relay-pool");
    m.create_user(&vh, &user, "pool-test").await;
    let relay_url = tiny_channel_max(&with_credentials(&url, &user, "pool-test"));
    let fx = Fixture::with_config(url.clone(), |c| c.amqp_url = relay_url.clone()).await;
    let pool = fx.relay.as_ref().unwrap().shared.pool.clone();
    m.wait_connections_of(&user, 1).await;

    // Two sessions; with one place per connection they sit on two
    // connections.
    let mut a = fx.connect("dev-a").await;
    prove_session_works(&fx, &mut a, "dev-a").await;
    let mut b = fx.connect("dev-b").await;
    prove_session_works(&fx, &mut b, "dev-b").await;
    let names = m.wait_connections_of(&user, 2).await;
    let before = pool.snapshot();
    assert_eq!(before.len(), 2);
    assert!(
        before.iter().all(|s| s.sessions == 1 && s.generation == 1),
        "{before:?}"
    );

    // Kill one of them, from the broker side.
    assert!(m.close_connection(&names[0]).await);
    let http = reqwest::Client::new();
    let readyz = format!("http://{}/readyz", fx.addr);
    let ra = a.recv_within(Duration::from_secs(3)).await;
    let rb = b.recv_within(Duration::from_millis(500)).await;
    let is_err = |r: &Result<Option<Frame>, ()>| matches!(r, Ok(Some(f)) if f.command == "ERROR" && f.header("message") == Some("broker unavailable"));
    let (mut survivor, survivor_name) = match (is_err(&ra), is_err(&rb)) {
        (true, false) => {
            assert!(rb.is_err(), "the other session saw nothing: {rb:?}");
            (b, "dev-b")
        }
        (false, true) => {
            assert!(ra.is_err(), "the other session saw nothing: {ra:?}");
            (a, "dev-a")
        }
        other => panic!("exactly one session must be dropped, got {other:?} ({ra:?}, {rb:?})"),
    };
    // Still ready: the other connection is up.
    assert_eq!(http.get(&readyz).send().await.unwrap().status(), 200);
    // The survivor's session still works end to end.
    let s = session();
    let (bcast, node) = keys(&s, survivor_name);
    survivor
        .subscribe("b2", &fx.dest(&bcast), &qname(survivor_name, &s), None)
        .await;
    survivor
        .subscribe("n2", &fx.dest(&node), &qname(survivor_name, &s), Some("ok"))
        .await;
    let ch = fx.channel().await;
    publish(&ch, &fx.exchange, &bcast, b"still here", None).await;
    assert_eq!(&survivor.expect("MESSAGE").await.body[..], b"still here");

    // The killed connection reconnects by itself; the survivor's never
    // reconnected.
    let mut after = pool.snapshot();
    for _ in 0..100 {
        after = pool.snapshot();
        if after.iter().all(|s| s.connected) && after.iter().any(|s| s.generation == 2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut generations: Vec<u64> = after.iter().map(|s| s.generation).collect();
    generations.sort();
    assert_eq!(
        generations,
        vec![1, 2],
        "only the killed connection reconnected: {after:?}"
    );
    let reconnected = after.iter().find(|s| s.generation == 2).unwrap();
    assert_eq!(reconnected.sessions, 0, "its session was dropped with it");
    m.wait_connections_of(&user, 2).await;
    let metrics = fx.relay.as_ref().unwrap().shared.metrics.render();
    assert!(
        metrics.contains(r#"mpc_relay_errors_total{reason="broker_unavailable"} 1"#),
        "{metrics}"
    );

    // And it takes new sessions again.
    let mut c = fx.connect("dev-c").await;
    prove_session_works(&fx, &mut c, "dev-c").await;
    assert_eq!(
        pool.snapshot().len(),
        2,
        "placed on the reconnected connection, not a new one"
    );
    fx.teardown().await;
    m.delete_user(&user).await;
}
