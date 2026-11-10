//! Prometheus metrics. Every label takes values from a fixed set chosen by
//! the relay, never from client input, so cardinality is bounded.

use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

pub struct Metrics {
    registry: Registry,
    pub connections_active: IntGauge,
    pub connections_total: IntCounter,
    pub auth_failures: IntCounterVec,
    pub frames: IntCounterVec,
    pub publishes: IntCounter,
    pub deliveries: IntCounter,
    pub errors: IntCounterVec,
    pub broker_connected: IntGauge,
}

/// STOMP commands that get their own `command` label value; anything else
/// is counted as `OTHER`.
const COMMANDS: &[&str] = &[
    "CONNECT",
    "STOMP",
    "CONNECTED",
    "SEND",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "ACK",
    "NACK",
    "BEGIN",
    "COMMIT",
    "ABORT",
    "DISCONNECT",
    "MESSAGE",
    "RECEIPT",
    "ERROR",
];

pub fn command_label(command: &str) -> &'static str {
    COMMANDS
        .iter()
        .find(|c| **c == command)
        .copied()
        .unwrap_or("OTHER")
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let connections_active = IntGauge::new(
            "mpc_relay_connections_active",
            "WebSocket connections currently open",
        )
        .expect("metric");
        let connections_total = IntCounter::new(
            "mpc_relay_connections_total",
            "WebSocket connections accepted since start",
        )
        .expect("metric");
        let auth_failures = IntCounterVec::new(
            Opts::new(
                "mpc_relay_auth_failures_total",
                "CONNECT frames rejected by authentication, by reason",
            ),
            &["reason"],
        )
        .expect("metric");
        let frames = IntCounterVec::new(
            Opts::new("mpc_relay_frames_total", "STOMP frames by direction and command"),
            &["direction", "command"],
        )
        .expect("metric");
        let publishes = IntCounter::new(
            "mpc_relay_publishes_total",
            "Messages published to the broker on behalf of clients",
        )
        .expect("metric");
        let deliveries = IntCounter::new(
            "mpc_relay_deliveries_total",
            "Broker messages delivered to clients as MESSAGE frames",
        )
        .expect("metric");
        let errors = IntCounterVec::new(
            Opts::new(
                "mpc_relay_errors_total",
                "Connections ended with an ERROR frame or refused, by reason",
            ),
            &["reason"],
        )
        .expect("metric");
        let broker_connected = IntGauge::new(
            "mpc_relay_broker_connected",
            "1 while the AMQP connection is up, else 0",
        )
        .expect("metric");
        for c in [
            Box::new(connections_active.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(connections_total.clone()),
            Box::new(auth_failures.clone()),
            Box::new(frames.clone()),
            Box::new(publishes.clone()),
            Box::new(deliveries.clone()),
            Box::new(errors.clone()),
            Box::new(broker_connected.clone()),
        ] {
            registry.register(c).expect("unique metric names");
        }
        Metrics {
            registry,
            connections_active,
            connections_total,
            auth_failures,
            frames,
            publishes,
            deliveries,
            errors,
            broker_connected,
        }
    }

    pub fn frame_in(&self, command: &str) {
        self.frames
            .with_label_values(&["in", command_label(command)])
            .inc();
    }

    pub fn frame_out(&self, command: &str) {
        self.frames
            .with_label_values(&["out", command_label(command)])
            .inc();
    }

    pub fn error(&self, reason: &'static str) {
        self.errors.with_label_values(&[reason]).inc();
    }

    pub fn auth_failure(&self, reason: &'static str) {
        self.auth_failures.with_label_values(&[reason]).inc();
    }

    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buf)
            .expect("text encoding cannot fail");
        String::from_utf8(buf).expect("prometheus text is UTF-8")
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
