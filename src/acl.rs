//! Which destinations an authenticated client may SUBSCRIBE to and SEND to.
//!
//! Destinations are `/exchange/<EXCHANGE>/<routing-key>` with `<EXCHANGE>`
//! the configured exchange, and routing keys are one of:
//!
//! ```text
//! session.<S>.broadcast
//! session.<S>.node.<node-id>
//! ```
//!
//! where `<S>` is a canonical (lowercase, hyphenated) UUID. A client may
//! subscribe only to the broadcast key and to the unicast key naming its own
//! `sub`, through the queue `mpc.session.<sub>.<S>`; it may send to the
//! broadcast key or to any node. A `sessions` claim narrows both to the
//! listed sessions.

use std::collections::HashSet;

/// Longest AMQP short string (queue names, routing keys).
pub const MAX_SHORTSTR: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AclError {
    #[error("unsupported destination; use /exchange/<exchange>/<routing-key>")]
    UnsupportedDestination,
    #[error("destination names an exchange other than the one this relay serves")]
    ForeignExchange,
    #[error("routing keys must not contain wildcards (* or #)")]
    Wildcard,
    #[error("routing key must be session.<uuid>.broadcast or session.<uuid>.node.<node-id>")]
    BadRoutingKey,
    #[error("session id must be a lowercase hyphenated UUID")]
    BadSession,
    #[error("invalid node id: {0}")]
    BadNodeId(&'static str),
    #[error("a client may subscribe only to the broadcast key and to its own node key")]
    NotOwnNode,
    #[error("x-queue-name header is required")]
    MissingQueueName,
    #[error("x-queue-name must be mpc.session.<sub>.<session> for the subscribed session")]
    QueueNameMismatch,
    #[error("this token is not valid for that session")]
    SessionNotAllowed,
    #[error("queue name or routing key would exceed 255 bytes")]
    TooLong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Broadcast,
    Node(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingKey {
    /// Canonical lowercase hyphenated UUID.
    pub session: String,
    pub target: Target,
}

/// The authorisation-relevant part of an authenticated identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub sub: String,
    /// `None`: any session. `Some`: only these (canonical form).
    pub sessions: Option<HashSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeGrant {
    pub routing_key: String,
    pub queue: String,
    pub session: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendGrant {
    pub routing_key: String,
    pub session: String,
}

/// A node id (a token's `sub`, or a unicast target) is 1..=255 bytes and
/// contains no `*`, `#`, `/`, whitespace or control characters.
pub fn validate_node_id(id: &str) -> Result<(), AclError> {
    if id.is_empty() {
        return Err(AclError::BadNodeId("empty"));
    }
    if id.len() > 255 {
        return Err(AclError::BadNodeId("longer than 255 bytes"));
    }
    for c in id.chars() {
        if c == '*' || c == '#' {
            return Err(AclError::BadNodeId("contains a wildcard"));
        }
        if c == '/' {
            return Err(AclError::BadNodeId("contains '/'"));
        }
        if c.is_whitespace() {
            return Err(AclError::BadNodeId("contains whitespace"));
        }
        if c.is_control() {
            return Err(AclError::BadNodeId("contains a control character"));
        }
    }
    Ok(())
}

/// Lowercase hyphenated 8-4-4-4-12 hex, exactly.
pub fn is_canonical_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

pub fn queue_name(sub: &str, session: &str) -> String {
    format!("mpc.session.{sub}.{session}")
}

/// Strip `/exchange/<exchange>/` and return the routing key.
pub fn parse_destination<'a>(destination: &'a str, exchange: &str) -> Result<&'a str, AclError> {
    let rest = destination
        .strip_prefix("/exchange/")
        .ok_or(AclError::UnsupportedDestination)?;
    let (ex, key) = rest
        .split_once('/')
        .ok_or(AclError::UnsupportedDestination)?;
    if ex != exchange {
        return Err(AclError::ForeignExchange);
    }
    if key.is_empty() {
        return Err(AclError::UnsupportedDestination);
    }
    Ok(key)
}

pub fn parse_routing_key(key: &str) -> Result<RoutingKey, AclError> {
    if key.contains(['*', '#']) {
        return Err(AclError::Wildcard);
    }
    if key.len() > MAX_SHORTSTR {
        return Err(AclError::TooLong);
    }
    let rest = key.strip_prefix("session.").ok_or(AclError::BadRoutingKey)?;
    if rest.len() < 37 || !rest.is_char_boundary(36) || rest.as_bytes()[36] != b'.' {
        return Err(AclError::BadRoutingKey);
    }
    let (session, tail) = (&rest[..36], &rest[37..]);
    if !is_canonical_uuid(session) {
        return Err(AclError::BadSession);
    }
    let target = if tail == "broadcast" {
        Target::Broadcast
    } else if let Some(node) = tail.strip_prefix("node.") {
        validate_node_id(node)?;
        Target::Node(node.to_owned())
    } else {
        return Err(AclError::BadRoutingKey);
    };
    Ok(RoutingKey {
        session: session.to_owned(),
        target,
    })
}

fn check_session(principal: &Principal, session: &str) -> Result<(), AclError> {
    match &principal.sessions {
        Some(allowed) if !allowed.contains(session) => Err(AclError::SessionNotAllowed),
        _ => Ok(()),
    }
}

pub fn authorize_subscribe(
    principal: &Principal,
    exchange: &str,
    destination: &str,
    x_queue_name: Option<&str>,
) -> Result<SubscribeGrant, AclError> {
    let key = parse_destination(destination, exchange)?;
    let rk = parse_routing_key(key)?;
    match &rk.target {
        Target::Broadcast => {}
        Target::Node(node) if *node == principal.sub => {}
        Target::Node(_) => return Err(AclError::NotOwnNode),
    }
    let expected = queue_name(&principal.sub, &rk.session);
    if expected.len() > MAX_SHORTSTR {
        return Err(AclError::TooLong);
    }
    match x_queue_name {
        None => return Err(AclError::MissingQueueName),
        Some(q) if q != expected => return Err(AclError::QueueNameMismatch),
        Some(_) => {}
    }
    check_session(principal, &rk.session)?;
    Ok(SubscribeGrant {
        routing_key: key.to_owned(),
        queue: expected,
        session: rk.session,
    })
}

pub fn authorize_send(
    principal: &Principal,
    exchange: &str,
    destination: &str,
) -> Result<SendGrant, AclError> {
    let key = parse_destination(destination, exchange)?;
    let rk = parse_routing_key(key)?;
    check_session(principal, &rk.session)?;
    Ok(SendGrant {
        routing_key: key.to_owned(),
        session: rk.session,
    })
}
