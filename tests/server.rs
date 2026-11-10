//! WebSocket and HTTP behaviour that needs no broker: the relay is started
//! against an AMQP port nothing listens on.

mod common;

use std::time::Duration;

use common::*;
use mpc_relay::codec::Frame;
use mpc_relay::config::Config;
use mpc_relay::server::{select_subprotocol, Relay};

const DEAD_BROKER: &str = "amqp://guest:guest@127.0.0.1:9/%2f";

async fn relay(tweak: impl FnOnce(&mut Config)) -> Relay {
    init_logs();
    let mut cfg = config(DEAD_BROKER, "mpc.cohort");
    tweak(&mut cfg);
    mpc_relay::server::start(cfg).await.unwrap()
}

fn connect_frame(token: &str) -> Frame {
    Frame::new("CONNECT")
        .with_header("accept-version", "1.1,1.2")
        .with_header("host", "/")
        .with_header("passcode", token)
}

#[tokio::test]
async fn health_and_readiness_without_a_broker() {
    let r = relay(|_| {}).await;
    let http = reqwest::Client::new();
    let h = http
        .get(format!("http://{}/healthz", r.local_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(h.status(), 200);
    let rd = http
        .get(format!("http://{}/readyz", r.local_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(rd.status(), 503);
    let body: serde_json::Value = rd.json().await.unwrap();
    assert_eq!(body["broker"], false);
    assert_eq!(body["ready"], false);
    let m = http
        .get(format!("http://{}/metrics", r.local_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(m.status(), 200);
    let text = m.text().await.unwrap();
    for name in [
        "mpc_relay_connections_active",
        "mpc_relay_connections_total",
        "mpc_relay_publishes_total",
        "mpc_relay_deliveries_total",
        "mpc_relay_broker_connected 0",
    ] {
        assert!(text.contains(name), "{name} missing:\n{text}");
    }
    assert_eq!(
        http.get(format!("http://{}/nope", r.local_addr))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    r.shutdown().await;
}

#[tokio::test]
async fn separate_metrics_listener() {
    let r = relay(|c| c.metrics_listen = Some("127.0.0.1:0".parse().unwrap())).await;
    let http = reqwest::Client::new();
    let main = http
        .get(format!("http://{}/metrics", r.local_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(
        main.status(),
        404,
        "metrics are not served on the public listener"
    );
    let side = http
        .get(format!("http://{}/metrics", r.metrics_addr.unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(side.status(), 200);
    assert!(side
        .text()
        .await
        .unwrap()
        .contains("mpc_relay_connections_total"));
    r.shutdown().await;
}

#[tokio::test]
async fn auth_is_checked_before_the_broker() {
    let r = relay(|_| {}).await;
    let err = Stomp::connect(r.local_addr, "not-a-token")
        .await
        .err()
        .unwrap();
    assert_eq!(err.header("message"), Some("authentication failed"));
    let err = Stomp::connect(r.local_addr, &token("d"))
        .await
        .err()
        .unwrap();
    assert_eq!(err.header("message"), Some("broker unavailable"));
    r.shutdown().await;
}

#[tokio::test]
async fn connect_timeout() {
    let r = relay(|c| c.limits.connect_timeout = Duration::from_millis(300)).await;
    let mut s = Stomp::open(r.local_addr, None).await;
    // Heart-beat EOLs do not count as a CONNECT.
    s.send_text("\n\n").await;
    s.expect_error("connect timeout").await;
    r.shutdown().await;
}

#[tokio::test]
async fn frames_before_connect_are_refused() {
    let r = relay(|_| {}).await;
    for cmd in ["SEND", "SUBSCRIBE", "DISCONNECT", "ACK"] {
        let mut s = Stomp::open(r.local_addr, None).await;
        s.send(Frame::new(cmd).with_header("destination", "/x"))
            .await;
        s.expect_error("not connected").await;
    }
    r.shutdown().await;
}

#[tokio::test]
async fn oversize_and_malformed_frames() {
    let r = relay(|c| c.limits.max_frame_bytes = 1024).await;
    let mut s = Stomp::open(r.local_addr, None).await;
    let mut big = b"CONNECT\naccept-version:1.2\npasscode:".to_vec();
    big.extend(vec![b'a'; 2000]);
    big.extend(b"\n\n\0");
    s.send_raw(big).await;
    s.expect_error("frame too large").await;

    // Declared length over the limit: refused before the body arrives.
    let mut s = Stomp::open(r.local_addr, None).await;
    s.send_text("SEND\ncontent-length:999999\n\n").await;
    s.expect_error("frame too large").await;

    // Far beyond the WebSocket message limit: the WebSocket layer closes.
    let mut s = Stomp::open(r.local_addr, None).await;
    s.send_raw(vec![b'A'; 512 * 1024]).await;
    let _ = s.recv_within(TIMEOUT).await;

    let mut s = Stomp::open(r.local_addr, None).await;
    s.send_text("connect\n\n\0").await;
    s.expect_error("malformed frame").await;

    let mut s = Stomp::open(r.local_addr, None).await;
    s.send_text("SEND\nbad\\escape:x\n\n\0").await;
    s.expect_error("malformed frame").await;
    r.shutdown().await;
}

#[tokio::test]
async fn unsupported_versions() {
    let r = relay(|_| {}).await;
    for accept in [None, Some("1.0"), Some("2.0")] {
        let mut s = Stomp::open(r.local_addr, None).await;
        let mut f = Frame::new("CONNECT").with_header("passcode", token("d"));
        if let Some(a) = accept {
            f = f.with_header("accept-version", a);
        }
        s.send(f).await;
        s.expect_error("unsupported protocol version").await;
    }
    r.shutdown().await;
}

#[tokio::test]
async fn frames_split_and_merged_across_websocket_messages() {
    let r = relay(|_| {}).await;
    // One frame in three messages, as binary: still parsed (and answered).
    let mut s = Stomp::open(r.local_addr, None).await;
    let wire = connect_frame("garbage").encode();
    let (a, rest) = wire.split_at(5);
    let (b, c) = rest.split_at(10);
    for part in [a, b, c] {
        s.send_binary(part).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    s.expect_error("authentication failed").await;

    // Heart-beats and a frame in one message.
    let mut s = Stomp::open(r.local_addr, None).await;
    let mut wire = b"\n\r\n\n".to_vec();
    wire.extend(connect_frame("garbage").encode());
    s.send_raw(wire).await;
    s.expect_error("authentication failed").await;
    r.shutdown().await;
}

#[test]
fn subprotocol_is_the_first_the_client_offers() {
    assert_eq!(
        select_subprotocol(["v11.stomp, v12.stomp"].into_iter()),
        Some("v11.stomp")
    );
    assert_eq!(
        select_subprotocol(["v12.stomp,v11.stomp"].into_iter()),
        Some("v12.stomp")
    );
    assert_eq!(
        select_subprotocol(["mqtt, stomp"].into_iter()),
        Some("stomp")
    );
    assert_eq!(
        select_subprotocol(["mqtt", "v10.stomp", "v11.stomp"].into_iter()),
        Some("v11.stomp")
    );
    assert_eq!(select_subprotocol(["mqtt"].into_iter()), None);
    assert_eq!(select_subprotocol(std::iter::empty()), None);
}

#[tokio::test]
async fn subprotocol_negotiation_over_the_wire() {
    let r = relay(|_| {}).await;
    let s = Stomp::open(r.local_addr, Some("v11.stomp, v12.stomp")).await;
    assert_eq!(s.protocol.as_deref(), Some("v11.stomp"));
    let s = Stomp::open(r.local_addr, Some("stomp")).await;
    assert_eq!(s.protocol.as_deref(), Some("stomp"));
    // No subprotocol offered: accepted, none selected.
    let mut s = Stomp::open(r.local_addr, None).await;
    assert_eq!(s.protocol, None);
    s.send(connect_frame("garbage")).await;
    s.expect_error("authentication failed").await;
    r.shutdown().await;
}

#[tokio::test]
async fn connection_limit() {
    let r = relay(|c| c.limits.max_connections = 2).await;
    let _a = Stomp::open(r.local_addr, None).await;
    let _b = Stomp::open(r.local_addr, None).await;
    let third = tokio_tungstenite::connect_async(format!("ws://{}/ws", r.local_addr)).await;
    match third {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 503),
        other => panic!("expected HTTP 503, got {other:?}"),
    }
    let metrics = r.shared.metrics.render();
    assert!(
        metrics.contains(r#"mpc_relay_errors_total{reason="too_many_connections"} 1"#),
        "{metrics}"
    );
    assert!(
        metrics.contains("mpc_relay_connections_active 2"),
        "{metrics}"
    );
    r.shutdown().await;
}

#[tokio::test]
async fn custom_ws_path() {
    let r = relay(|c| c.ws_path = "/stomp".into()).await;
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{}/ws", r.local_addr))
            .await
            .is_err()
    );
    assert!(
        tokio_tungstenite::connect_async(format!("ws://{}/stomp", r.local_addr))
            .await
            .is_ok()
    );
    r.shutdown().await;
}

#[tokio::test]
async fn tls_listener() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = std::env::temp_dir().join(unique("mpc-relay-tls"));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let r = relay(|c| {
        c.tls = Some(mpc_relay::config::TlsFiles {
            cert: cert_path.clone(),
            key: key_path.clone(),
        })
    })
    .await;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));

    // A plaintext client on the TLS port gets nothing useful, and does not
    // stall the listener for the TLS client after it.
    let mut plain = tokio::net::TcpStream::connect(r.local_addr).await.unwrap();
    plain
        .write_all(b"GET /healthz HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();

    let tcp = tokio::net::TcpStream::connect(r.local_addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, tcp).await.expect("TLS handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), None);
    tls.write_all(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("ok\n"), "{resp}");
    r.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
