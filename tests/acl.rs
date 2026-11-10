use std::collections::HashSet;

use mpc_relay::acl::{
    authorize_send, authorize_subscribe, is_canonical_uuid, parse_routing_key, queue_name,
    validate_node_id, AclError, Principal, Target,
};

const EX: &str = "mpc.cohort";
const S: &str = "0b9f4c1e-6d2a-4f6b-9e0c-3a5d7b8c9d0e";
const S2: &str = "11111111-2222-4333-8444-555555555555";
const ME: &str = "device-1";

fn me() -> Principal {
    Principal {
        sub: ME.into(),
        sessions: None,
    }
}

fn me_limited(sessions: &[&str]) -> Principal {
    Principal {
        sub: ME.into(),
        sessions: Some(
            sessions
                .iter()
                .map(|s| s.to_string())
                .collect::<HashSet<_>>(),
        ),
    }
}

fn dest(key: &str) -> String {
    format!("/exchange/{EX}/{key}")
}

fn q(sub: &str, s: &str) -> String {
    queue_name(sub, s)
}

// ---- SUBSCRIBE: allowed -------------------------------------------------

#[test]
fn subscribe_broadcast() {
    let g = authorize_subscribe(
        &me(),
        EX,
        &dest(&format!("session.{S}.broadcast")),
        Some(&q(ME, S)),
    )
    .unwrap();
    assert_eq!(g.routing_key, format!("session.{S}.broadcast"));
    assert_eq!(g.queue, format!("mpc.session.{ME}.{S}"));
    assert_eq!(g.session, S);
}

#[test]
fn subscribe_own_unicast() {
    let g = authorize_subscribe(
        &me(),
        EX,
        &dest(&format!("session.{S}.node.{ME}")),
        Some(&q(ME, S)),
    )
    .unwrap();
    assert_eq!(g.routing_key, format!("session.{S}.node.{ME}"));
    assert_eq!(g.queue, format!("mpc.session.{ME}.{S}"));
}

#[test]
fn subscribe_within_sessions_claim() {
    let p = me_limited(&[S, S2]);
    assert!(authorize_subscribe(
        &p,
        EX,
        &dest(&format!("session.{S}.broadcast")),
        Some(&q(ME, S))
    )
    .is_ok());
    assert!(authorize_subscribe(
        &p,
        EX,
        &dest(&format!("session.{S2}.node.{ME}")),
        Some(&q(ME, S2))
    )
    .is_ok());
}

// ---- SUBSCRIBE: rejected ------------------------------------------------

fn sub_err(p: &Principal, destination: &str, queue: Option<&str>) -> AclError {
    authorize_subscribe(p, EX, destination, queue).expect_err("must be refused")
}

#[test]
fn subscribe_rejects_other_destination_types() {
    let queue = q(ME, S);
    for d in [
        format!("/queue/mpc.session.{ME}.{S}"),
        format!("/topic/session.{S}.broadcast"),
        format!("/amq/queue/mpc.session.{ME}.{S}"),
        format!("/temp-queue/session.{S}.broadcast"),
        format!("session.{S}.broadcast"),
        "".to_string(),
        format!("/exchange/{EX}"),
        format!("/exchange/{EX}/"),
    ] {
        assert_eq!(
            sub_err(&me(), &d, Some(&queue)),
            AclError::UnsupportedDestination,
            "{d}"
        );
    }
}

#[test]
fn subscribe_rejects_other_exchange() {
    for ex in ["amq.topic", "other", "mpc.cohort2", ""] {
        let d = format!("/exchange/{ex}/session.{S}.broadcast");
        assert_eq!(
            sub_err(&me(), &d, Some(&q(ME, S))),
            AclError::ForeignExchange,
            "{d}"
        );
    }
}

#[test]
fn subscribe_rejects_wildcards() {
    for key in [
        format!("session.{S}.*"),
        format!("session.{S}.#"),
        "session.*.broadcast".to_string(),
        "#".to_string(),
        format!("session.{S}.node.*"),
        format!("session.{S}.node.dev#"),
    ] {
        assert_eq!(
            sub_err(&me(), &dest(&key), Some(&q(ME, S))),
            AclError::Wildcard,
            "{key}"
        );
    }
}

#[test]
fn subscribe_rejects_bad_routing_keys() {
    let queue = q(ME, S);
    for key in [
        format!("sessions.{S}.broadcast"),
        format!("session.{S}"),
        format!("session.{S}."),
        format!("session.{S}.broadcast.extra"),
        format!("session.{S}.unicast.{ME}"),
        format!("session.{S}.nodes.{ME}"),
        format!("session.{S}broadcast"),
        "session..broadcast".to_string(),
    ] {
        let e = sub_err(&me(), &dest(&key), Some(&queue));
        assert!(
            matches!(e, AclError::BadRoutingKey | AclError::BadSession),
            "{key}: {e:?}"
        );
    }
}

#[test]
fn subscribe_rejects_non_canonical_session_ids() {
    for s in [
        "0B9F4C1E-6D2A-4F6B-9E0C-3A5D7B8C9D0E",
        "0b9f4c1e6d2a4f6b9e0c3a5d7b8c9d0e0000",
        "{b9f4c1e-6d2a-4f6b-9e0c-3a5d7b8c9d0}",
        "0b9f4c1e-6d2a-4f6b-9e0c-3a5d7b8c9d0g",
        "0b9f4c1e_6d2a_4f6b_9e0c_3a5d7b8c9d0e",
    ] {
        let key = format!("session.{s}.broadcast");
        assert_eq!(
            sub_err(&me(), &dest(&key), Some(&q(ME, s))),
            AclError::BadSession,
            "{s}"
        );
    }
}

#[test]
fn subscribe_rejects_other_nodes_unicast() {
    for other in ["device-2", "agent-0", "device-10", "Device-1"] {
        let key = format!("session.{S}.node.{other}");
        assert_eq!(
            sub_err(&me(), &dest(&key), Some(&q(ME, S))),
            AclError::NotOwnNode,
            "{other}"
        );
    }
}

#[test]
fn subscribe_requires_matching_queue_name() {
    let d = dest(&format!("session.{S}.broadcast"));
    assert_eq!(sub_err(&me(), &d, None), AclError::MissingQueueName);
    for bad in [
        q("device-2", S),
        q(ME, S2),
        format!("{}x", q(ME, S)),
        format!("mpc.session.{S}.{ME}"),
        "".to_string(),
        format!("amq.gen-{S}"),
    ] {
        assert_eq!(
            sub_err(&me(), &d, Some(&bad)),
            AclError::QueueNameMismatch,
            "{bad}"
        );
    }
    // The node key must use the queue for ITS session too.
    let d = dest(&format!("session.{S}.node.{ME}"));
    assert_eq!(
        sub_err(&me(), &d, Some(&q(ME, S2))),
        AclError::QueueNameMismatch
    );
}

#[test]
fn subscribe_outside_sessions_claim() {
    let p = me_limited(&[S2]);
    let d = dest(&format!("session.{S}.broadcast"));
    assert_eq!(
        sub_err(&p, &d, Some(&q(ME, S))),
        AclError::SessionNotAllowed
    );
    let empty = me_limited(&[]);
    assert_eq!(
        sub_err(&empty, &d, Some(&q(ME, S))),
        AclError::SessionNotAllowed
    );
}

#[test]
fn subscribe_rejects_invalid_node_ids_in_key() {
    for node in ["", "a/b", "a b", "a\tb", "a\u{7}b"] {
        let key = format!("session.{S}.node.{node}");
        let e = sub_err(&me(), &dest(&key), Some(&q(ME, S)));
        assert!(matches!(e, AclError::BadNodeId(_)), "{node:?}: {e:?}");
    }
}

#[test]
fn queue_name_length_is_bounded() {
    // mpc.session. (12) + sub + . (1) + uuid (36) <= 255  =>  sub <= 206
    let ok = Principal {
        sub: "a".repeat(206),
        sessions: None,
    };
    let d = dest(&format!("session.{S}.broadcast"));
    assert!(authorize_subscribe(&ok, EX, &d, Some(&q(&ok.sub, S))).is_ok());
    let long = Principal {
        sub: "a".repeat(207),
        sessions: None,
    };
    assert_eq!(
        authorize_subscribe(&long, EX, &d, Some(&q(&long.sub, S))),
        Err(AclError::TooLong)
    );
}

// ---- SEND ---------------------------------------------------------------

#[test]
fn send_allowed() {
    for key in [
        format!("session.{S}.broadcast"),
        format!("session.{S}.node.agent-0"),
        format!("session.{S}.node.{ME}"),
        format!("session.{S}.node.some.dotted.id"),
        format!("session.{S}.node.\u{e9}t\u{e9}"),
    ] {
        let g = authorize_send(&me(), EX, &dest(&key)).unwrap_or_else(|e| panic!("{key}: {e}"));
        assert_eq!(g.routing_key, key);
        assert_eq!(g.session, S);
    }
}

#[test]
fn send_rejected() {
    let cases: Vec<(String, AclError)> = vec![
        (
            format!("/queue/session.{S}.broadcast"),
            AclError::UnsupportedDestination,
        ),
        (
            format!("/topic/session.{S}.broadcast"),
            AclError::UnsupportedDestination,
        ),
        ("/amq/queue/x".to_string(), AclError::UnsupportedDestination),
        (
            "/temp-queue/x".to_string(),
            AclError::UnsupportedDestination,
        ),
        (
            format!("/exchange/other/session.{S}.broadcast"),
            AclError::ForeignExchange,
        ),
        (dest(&format!("session.{S}.*")), AclError::Wildcard),
        (dest(&format!("session.{S}.node.#")), AclError::Wildcard),
        (dest("anything.else"), AclError::BadRoutingKey),
        (
            dest(&format!("session.{S}.node.")),
            AclError::BadNodeId("empty"),
        ),
        (
            dest(&format!("session.{S}.node.a b")),
            AclError::BadNodeId("contains whitespace"),
        ),
        (
            dest(&format!("session.{S}.node.a/b")),
            AclError::BadNodeId("contains '/'"),
        ),
        (
            dest("session.NOT-A-UUID-AT-ALL-000000000000000000.broadcast"),
            AclError::BadSession,
        ),
    ];
    for (d, want) in cases {
        assert_eq!(authorize_send(&me(), EX, &d), Err(want), "{d}");
    }
}

#[test]
fn send_outside_sessions_claim() {
    let p = me_limited(&[S2]);
    assert_eq!(
        authorize_send(&p, EX, &dest(&format!("session.{S}.broadcast"))),
        Err(AclError::SessionNotAllowed)
    );
    assert!(authorize_send(&p, EX, &dest(&format!("session.{S2}.node.agent-0"))).is_ok());
}

#[test]
fn routing_key_length_is_bounded() {
    // session. (8) + uuid (36) + .node. (6) + id <= 255  =>  id <= 205
    let ok = format!("session.{S}.node.{}", "n".repeat(205));
    assert!(parse_routing_key(&ok).is_ok());
    let long = format!("session.{S}.node.{}", "n".repeat(206));
    assert_eq!(parse_routing_key(&long), Err(AclError::TooLong));
}

// ---- node ids -----------------------------------------------------------

#[test]
fn node_ids() {
    for ok in [
        "a",
        "device-1",
        "agent.0",
        "x".repeat(255).as_str(),
        "\u{e9}",
        "a:b",
        "a@b",
    ] {
        assert!(validate_node_id(ok).is_ok(), "{ok:?}");
    }
    for bad in [
        String::new(),
        "x".repeat(256),
        "a*".into(),
        "#".into(),
        "a/b".into(),
        "a b".into(),
        "a\tb".into(),
        "a\nb".into(),
        "a\u{0}b".into(),
        "a\u{7f}b".into(),
        "a\u{a0}b".into(),
        "a\u{2028}b".into(),
    ] {
        assert!(validate_node_id(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn routing_key_parse_targets() {
    assert_eq!(
        parse_routing_key(&format!("session.{S}.broadcast"))
            .unwrap()
            .target,
        Target::Broadcast
    );
    assert_eq!(
        parse_routing_key(&format!("session.{S}.node.agent-1"))
            .unwrap()
            .target,
        Target::Node("agent-1".into())
    );
}

#[test]
fn canonical_uuid() {
    assert!(is_canonical_uuid(S));
    assert!(!is_canonical_uuid(&S.to_uppercase()));
    assert!(!is_canonical_uuid(&S[..35]));
}
