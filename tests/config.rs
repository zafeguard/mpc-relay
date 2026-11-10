use std::time::Duration;

use mpc_relay::config::{parse_duration, Config, ConfigError, KeySource, LogFormat};

const SECRET: &str = "0123456789abcdef0123456789abcdef";

fn base() -> Vec<(&'static str, String)> {
    vec![
        ("MPC_RELAY_AMQP_URL", "amqp://u:p@localhost:5672/%2f".into()),
        ("MPC_RELAY_EXCHANGE", "mpc.cohort".into()),
        ("MPC_RELAY_JWT_SECRET", SECRET.into()),
        ("PATH", "/usr/bin".into()),
        ("RUST_LOG", "debug".into()),
    ]
}

fn with(
    mut vars: Vec<(&'static str, String)>,
    k: &'static str,
    v: &str,
) -> Vec<(&'static str, String)> {
    vars.retain(|(name, _)| *name != k);
    vars.push((k, v.into()));
    vars
}

fn without(mut vars: Vec<(&'static str, String)>, k: &str) -> Vec<(&'static str, String)> {
    vars.retain(|(name, _)| *name != k);
    vars
}

#[test]
fn minimal_config_with_defaults() {
    let c = Config::from_vars(base()).unwrap();
    assert_eq!(c.listen.to_string(), "0.0.0.0:8080");
    assert_eq!(c.ws_path, "/ws");
    assert_eq!(c.exchange, "mpc.cohort");
    assert!(matches!(c.auth.source, KeySource::Hmac(_)));
    assert_eq!(c.auth.leeway, Duration::from_secs(30));
    assert_eq!(c.limits.max_connections, 10_000);
    assert_eq!(c.limits.max_subscriptions, 16);
    assert_eq!(c.limits.max_frame_bytes, 4 * 1024 * 1024);
    assert_eq!(c.limits.send_rate, 200.0);
    assert_eq!(c.limits.send_burst, 400);
    assert_eq!(c.limits.connect_timeout, Duration::from_secs(10));
    assert_eq!(c.limits.idle_timeout, Duration::from_secs(300));
    assert_eq!(c.log_format, LogFormat::Text);
}

#[test]
fn required_values() {
    assert_eq!(
        Config::from_vars(without(base(), "MPC_RELAY_AMQP_URL")).unwrap_err(),
        ConfigError::Missing("MPC_RELAY_AMQP_URL")
    );
    assert_eq!(
        Config::from_vars(without(base(), "MPC_RELAY_EXCHANGE")).unwrap_err(),
        ConfigError::Missing("MPC_RELAY_EXCHANGE")
    );
}

#[test]
fn unknown_variable_is_refused() {
    let e = Config::from_vars(with(base(), "MPC_RELAY_JWT_ISUER", "x")).unwrap_err();
    assert_eq!(e, ConfigError::Unknown("MPC_RELAY_JWT_ISUER".into()));
}

#[test]
fn empty_value_is_refused() {
    let e = Config::from_vars(with(base(), "MPC_RELAY_JWT_AUDIENCE", "")).unwrap_err();
    assert_eq!(e, ConfigError::Empty("MPC_RELAY_JWT_AUDIENCE".into()));
}

#[test]
fn exactly_one_key_source() {
    let none = without(base(), "MPC_RELAY_JWT_SECRET");
    assert!(matches!(
        Config::from_vars(none.clone()),
        Err(ConfigError::Conflict(_))
    ));
    let two = with(
        base(),
        "MPC_RELAY_JWKS_URL",
        "https://idp.example/jwks.json",
    );
    assert!(matches!(
        Config::from_vars(two),
        Err(ConfigError::Conflict(_))
    ));
    let three = with(base(), "MPC_RELAY_AUTH", "none");
    assert!(matches!(
        Config::from_vars(three),
        Err(ConfigError::Conflict(_))
    ));
    let jwks = with(
        none.clone(),
        "MPC_RELAY_JWKS_URL",
        "https://idp.example/jwks.json",
    );
    assert!(matches!(
        Config::from_vars(jwks).unwrap().auth.source,
        KeySource::Jwks { .. }
    ));
    let dev = with(none, "MPC_RELAY_AUTH", "none");
    assert!(matches!(
        Config::from_vars(dev).unwrap().auth.source,
        KeySource::Disabled
    ));
}

#[test]
fn auth_mode_values() {
    let v = with(
        without(base(), "MPC_RELAY_JWT_SECRET"),
        "MPC_RELAY_AUTH",
        "jwt",
    );
    assert!(matches!(
        Config::from_vars(v),
        Err(ConfigError::Invalid {
            var: "MPC_RELAY_AUTH",
            ..
        })
    ));
}

#[test]
fn checks_that_cannot_apply_without_verification_are_refused() {
    let v = with(
        with(
            without(base(), "MPC_RELAY_JWT_SECRET"),
            "MPC_RELAY_AUTH",
            "none",
        ),
        "MPC_RELAY_JWT_ISSUER",
        "https://idp",
    );
    assert!(matches!(
        Config::from_vars(v),
        Err(ConfigError::Conflict(_))
    ));
    let v = with(base(), "MPC_RELAY_JWKS_REFRESH_INTERVAL", "60s");
    assert!(matches!(
        Config::from_vars(v),
        Err(ConfigError::Conflict(_))
    ));
}

#[test]
fn short_hmac_secret_is_refused() {
    let v = with(base(), "MPC_RELAY_JWT_SECRET", "short");
    assert!(matches!(
        Config::from_vars(v),
        Err(ConfigError::Invalid {
            var: "MPC_RELAY_JWT_SECRET",
            ..
        })
    ));
}

#[test]
fn jwks_url_must_be_https_except_loopback_or_explicit_override() {
    let jwks = |url: &str| {
        with(
            without(base(), "MPC_RELAY_JWT_SECRET"),
            "MPC_RELAY_JWKS_URL",
            url,
        )
    };
    assert!(Config::from_vars(jwks("http://idp.example/jwks")).is_err());
    assert!(Config::from_vars(jwks("http://127.0.0.1:9000/jwks")).is_ok());
    assert!(Config::from_vars(jwks("http://localhost/jwks")).is_ok());
    assert!(Config::from_vars(jwks("http://[::1]/jwks")).is_ok());
    assert!(Config::from_vars(jwks("ftp://idp.example/jwks")).is_err());
    let allowed = with(
        jwks("http://idp.internal/jwks"),
        "MPC_RELAY_JWKS_ALLOW_HTTP",
        "true",
    );
    assert!(Config::from_vars(allowed).is_ok());
}

#[test]
fn amqp_url_and_exchange_are_validated() {
    assert!(Config::from_vars(with(base(), "MPC_RELAY_AMQP_URL", "http://broker")).is_err());
    assert!(Config::from_vars(with(
        base(),
        "MPC_RELAY_AMQP_URL",
        "amqps://u:p@broker:5671/vh"
    ))
    .is_ok());
    for bad in ["has/slash", "has space", "x".repeat(256).as_str()] {
        assert!(
            Config::from_vars(with(base(), "MPC_RELAY_EXCHANGE", bad)).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn limits_and_durations() {
    let v = with(
        with(
            with(base(), "MPC_RELAY_CONNECT_TIMEOUT", "500ms"),
            "MPC_RELAY_IDLE_TIMEOUT",
            "5m",
        ),
        "MPC_RELAY_MAX_SUBSCRIPTIONS",
        "4",
    );
    let c = Config::from_vars(v).unwrap();
    assert_eq!(c.limits.connect_timeout, Duration::from_millis(500));
    assert_eq!(c.limits.idle_timeout, Duration::from_secs(300));
    assert_eq!(c.limits.max_subscriptions, 4);
    assert!(Config::from_vars(with(base(), "MPC_RELAY_MAX_SUBSCRIPTIONS", "0")).is_err());
    assert!(Config::from_vars(with(base(), "MPC_RELAY_MAX_SUBSCRIPTIONS", "-1")).is_err());
    assert!(Config::from_vars(with(base(), "MPC_RELAY_SEND_RATE", "lots")).is_err());
    assert!(Config::from_vars(with(base(), "MPC_RELAY_IDLE_TIMEOUT", "10x")).is_err());
    assert!(Config::from_vars(with(base(), "MPC_RELAY_IDLE_TIMEOUT", "0")).is_err());
    assert!(Config::from_vars(with(base(), "MPC_RELAY_PING_INTERVAL", "400s")).is_err());
    assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
    assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
}

#[test]
fn tls_needs_both_files() {
    assert!(matches!(
        Config::from_vars(with(base(), "MPC_RELAY_TLS_CERT", "/c.pem")),
        Err(ConfigError::Conflict(_))
    ));
    let both = with(
        with(base(), "MPC_RELAY_TLS_CERT", "/c.pem"),
        "MPC_RELAY_TLS_KEY",
        "/k.pem",
    );
    assert!(Config::from_vars(both).unwrap().tls.is_some());
}

#[test]
fn log_format() {
    assert_eq!(
        Config::from_vars(with(base(), "MPC_RELAY_LOG_FORMAT", "json"))
            .unwrap()
            .log_format,
        LogFormat::Json
    );
    assert!(Config::from_vars(with(base(), "MPC_RELAY_LOG_FORMAT", "xml")).is_err());
}

#[test]
fn ws_path() {
    assert_eq!(
        Config::from_vars(with(base(), "MPC_RELAY_WS_PATH", "/stomp"))
            .unwrap()
            .ws_path,
        "/stomp"
    );
    assert!(Config::from_vars(with(base(), "MPC_RELAY_WS_PATH", "ws")).is_err());
    assert!(Config::from_vars(with(base(), "MPC_RELAY_WS_PATH", "/readyz")).is_err());
}

#[test]
fn secret_is_not_printed_by_debug() {
    let c = Config::from_vars(base()).unwrap();
    assert!(!format!("{c:?}").contains(SECRET));
}
