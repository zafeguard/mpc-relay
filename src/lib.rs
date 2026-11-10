//! mpc-relay: an authenticated, topology-aware STOMP-over-WebSocket to
//! AMQP 0-9-1 bridge that reproduces the subset of RabbitMQ Web-STOMP
//! behaviour MPC devices rely on.
//!
//! * [`codec`] - STOMP 1.2 frame decoding and encoding.
//! * [`auth`] - JWT verification of the CONNECT passcode.
//! * [`acl`] - which destinations a token may subscribe and send to.
//! * [`bridge`] - one client session bridged onto one AMQP channel.
//! * [`broker`] - the shared AMQP connection and its supervision.
//! * [`server`] - HTTP endpoints, WebSocket upgrade, TLS, lifecycle.
//! * [`config`] - `MPC_RELAY_*` environment configuration.
//! * [`metrics`] - Prometheus metrics.

pub mod acl;
pub mod auth;
pub mod bridge;
pub mod broker;
pub mod codec;
pub mod config;
pub mod metrics;
pub mod server;
