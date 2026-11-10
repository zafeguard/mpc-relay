//! Configuration, read from `MPC_RELAY_*` environment variables.
//!
//! The relay refuses to start on a missing required value, on a value that
//! does not parse, on a variable that is set but empty, and on any
//! `MPC_RELAY_*` variable it does not know. A typo such as
//! `MPC_RELAY_JWT_ISUER` must stop the process rather than silently run
//! without the issuer check it was meant to enable, and an empty value
//! (`MPC_RELAY_JWT_AUDIENCE=${UNSET}` in a manifest) is the same mistake.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Every variable the relay reads. Anything else with the `MPC_RELAY_`
/// prefix is rejected at startup.
pub const KNOWN_VARS: &[&str] = &[
    "MPC_RELAY_LISTEN",
    "MPC_RELAY_WS_PATH",
    "MPC_RELAY_METRICS_LISTEN",
    "MPC_RELAY_TLS_CERT",
    "MPC_RELAY_TLS_KEY",
    "MPC_RELAY_AMQP_URL",
    "MPC_RELAY_AMQP_CONNECTION_NAME",
    "MPC_RELAY_EXCHANGE",
    "MPC_RELAY_AUTH",
    "MPC_RELAY_JWT_SECRET",
    "MPC_RELAY_JWKS_URL",
    "MPC_RELAY_JWKS_REFRESH_INTERVAL",
    "MPC_RELAY_JWKS_MIN_REFRESH_INTERVAL",
    "MPC_RELAY_JWKS_ALLOW_HTTP",
    "MPC_RELAY_JWT_ISSUER",
    "MPC_RELAY_JWT_AUDIENCE",
    "MPC_RELAY_JWT_LEEWAY",
    "MPC_RELAY_JWT_MAX_TTL",
    "MPC_RELAY_MAX_CONNECTIONS",
    "MPC_RELAY_MAX_SUBSCRIPTIONS",
    "MPC_RELAY_MAX_FRAME_BYTES",
    "MPC_RELAY_SEND_RATE",
    "MPC_RELAY_SEND_BURST",
    "MPC_RELAY_CONNECT_TIMEOUT",
    "MPC_RELAY_IDLE_TIMEOUT",
    "MPC_RELAY_WRITE_TIMEOUT",
    "MPC_RELAY_PING_INTERVAL",
    "MPC_RELAY_PREFETCH",
    "MPC_RELAY_SHUTDOWN_GRACE",
    "MPC_RELAY_LOG_FORMAT",
];

/// Shortest HMAC secret accepted. HS256 with a short secret can be brute
/// forced offline from a single captured token.
pub const MIN_HMAC_SECRET_BYTES: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("unknown configuration variable {0} (typo? known variables are listed in the README)")]
    Unknown(String),
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{0} is set but empty; unset it or give it a value")]
    Empty(String),
    #[error("{var}: {reason}")]
    Invalid { var: &'static str, reason: String },
    #[error("{0}")]
    Conflict(String),
}

fn invalid(var: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        var,
        reason: reason.into(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// Where JWT verification keys come from. Exactly one is configured, and it
/// fixes the accepted algorithm set: the token header never chooses it.
#[derive(Clone)]
pub enum KeySource {
    /// `MPC_RELAY_JWT_SECRET`: HS256, HS384 or HS512 with this secret.
    Hmac(Vec<u8>),
    /// `MPC_RELAY_JWKS_URL`: RS256, ES256 or EdDSA with keys from the set.
    Jwks {
        url: String,
        refresh_interval: Duration,
        min_refresh_interval: Duration,
    },
    /// `MPC_RELAY_AUTH=none`: no verification, `login` becomes `sub`.
    /// Development only.
    Disabled,
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::Hmac(_) => f.write_str("Hmac(<redacted>)"),
            KeySource::Jwks { url, .. } => write!(f, "Jwks({url})"),
            KeySource::Disabled => f.write_str("Disabled"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub source: KeySource,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub leeway: Duration,
    pub max_ttl: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_connections: usize,
    pub max_subscriptions: usize,
    pub max_frame_bytes: usize,
    /// Sustained SEND (and SUBSCRIBE / UNSUBSCRIBE) frames per second.
    pub send_rate: f64,
    pub send_burst: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
    pub ping_interval: Duration,
    /// AMQP prefetch per consumer: how many deliveries may be in flight
    /// towards one subscription before the broker holds the rest.
    pub prefetch: u16,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: 10_000,
            max_subscriptions: 16,
            max_frame_bytes: 4 * 1024 * 1024,
            send_rate: 200.0,
            send_burst: 400,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            write_timeout: Duration::from_secs(30),
            ping_interval: Duration::from_secs(20),
            prefetch: 64,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub ws_path: String,
    pub metrics_listen: Option<SocketAddr>,
    pub tls: Option<TlsFiles>,
    pub amqp_url: String,
    pub amqp_connection_name: String,
    pub exchange: String,
    pub auth: AuthConfig,
    pub limits: Limits,
    pub shutdown_grace: Duration,
    pub log_format: LogFormat,
}

impl Config {
    /// A configuration with defaults for everything optional. Used by tests
    /// and by `from_vars` as its starting point.
    pub fn new(amqp_url: impl Into<String>, exchange: impl Into<String>, source: KeySource) -> Self {
        Config {
            listen: "0.0.0.0:8080".parse().expect("static address"),
            ws_path: "/ws".into(),
            metrics_listen: None,
            tls: None,
            amqp_url: amqp_url.into(),
            amqp_connection_name: "mpc-relay".into(),
            exchange: exchange.into(),
            auth: AuthConfig {
                source,
                issuer: None,
                audience: None,
                leeway: Duration::from_secs(30),
                max_ttl: None,
            },
            limits: Limits::default(),
            shutdown_grace: Duration::from_secs(20),
            log_format: LogFormat::Text,
        }
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(std::env::vars_os().filter_map(|(k, v)| {
            // A non-UTF-8 name cannot be one of ours; a non-UTF-8 value for
            // one of ours is reported as invalid below.
            let k = k.into_string().ok()?;
            Some((k, v.into_string().unwrap_or_else(|_| "\u{FFFD}".into())))
        }))
    }

    /// Parse from an explicit set of variables. Non-`MPC_RELAY_` names are
    /// ignored (`RUST_LOG` is read by the logger, not here).
    pub fn from_vars<I, K, V>(vars: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut env = BTreeMap::new();
        for (k, v) in vars {
            let (k, v) = (k.into(), v.into());
            if !k.starts_with("MPC_RELAY_") {
                continue;
            }
            if !KNOWN_VARS.contains(&k.as_str()) {
                return Err(ConfigError::Unknown(k));
            }
            if v.is_empty() {
                return Err(ConfigError::Empty(k));
            }
            env.insert(k, v);
        }
        let get = |name: &'static str| env.get(name).cloned();

        let amqp_url = get("MPC_RELAY_AMQP_URL").ok_or(ConfigError::Missing("MPC_RELAY_AMQP_URL"))?;
        if !(amqp_url.starts_with("amqp://") || amqp_url.starts_with("amqps://")) {
            return Err(invalid(
                "MPC_RELAY_AMQP_URL",
                "must start with amqp:// or amqps://",
            ));
        }
        amqp_url
            .parse::<lapin::uri::AMQPUri>()
            .map_err(|e| invalid("MPC_RELAY_AMQP_URL", e))?;

        let exchange = get("MPC_RELAY_EXCHANGE").ok_or(ConfigError::Missing("MPC_RELAY_EXCHANGE"))?;
        validate_exchange(&exchange).map_err(|r| invalid("MPC_RELAY_EXCHANGE", r))?;

        // Exactly one key source.
        let secret = get("MPC_RELAY_JWT_SECRET");
        let jwks = get("MPC_RELAY_JWKS_URL");
        let auth_mode = get("MPC_RELAY_AUTH");
        let disabled = match auth_mode.as_deref() {
            None => false,
            Some("none") => true,
            Some(other) => {
                return Err(invalid(
                    "MPC_RELAY_AUTH",
                    format!("the only accepted value is `none`, got `{other}`"),
                ))
            }
        };
        let chosen = [secret.is_some(), jwks.is_some(), disabled]
            .iter()
            .filter(|b| **b)
            .count();
        if chosen != 1 {
            return Err(ConfigError::Conflict(
                "exactly one of MPC_RELAY_JWT_SECRET, MPC_RELAY_JWKS_URL or MPC_RELAY_AUTH=none must be set".into(),
            ));
        }
        let jwks_only = [
            "MPC_RELAY_JWKS_REFRESH_INTERVAL",
            "MPC_RELAY_JWKS_MIN_REFRESH_INTERVAL",
            "MPC_RELAY_JWKS_ALLOW_HTTP",
        ];
        if jwks.is_none() {
            if let Some(v) = jwks_only.iter().find(|v| env.contains_key(**v)) {
                return Err(ConfigError::Conflict(format!(
                    "{v} only applies with MPC_RELAY_JWKS_URL"
                )));
            }
        }
        let source = if let Some(secret) = secret {
            if secret.len() < MIN_HMAC_SECRET_BYTES {
                return Err(invalid(
                    "MPC_RELAY_JWT_SECRET",
                    format!("must be at least {MIN_HMAC_SECRET_BYTES} bytes"),
                ));
            }
            KeySource::Hmac(secret.into_bytes())
        } else if let Some(url) = jwks {
            let allow_http = match get("MPC_RELAY_JWKS_ALLOW_HTTP") {
                Some(v) => parse_bool(&v).map_err(|r| invalid("MPC_RELAY_JWKS_ALLOW_HTTP", r))?,
                None => false,
            };
            validate_jwks_url(&url, allow_http).map_err(|r| invalid("MPC_RELAY_JWKS_URL", r))?;
            KeySource::Jwks {
                url,
                refresh_interval: duration_or(&env, "MPC_RELAY_JWKS_REFRESH_INTERVAL", Duration::from_secs(300))?,
                min_refresh_interval: duration_or(
                    &env,
                    "MPC_RELAY_JWKS_MIN_REFRESH_INTERVAL",
                    Duration::from_secs(10),
                )?,
            }
        } else {
            for v in [
                "MPC_RELAY_JWT_ISSUER",
                "MPC_RELAY_JWT_AUDIENCE",
                "MPC_RELAY_JWT_MAX_TTL",
            ] {
                if env.contains_key(v) {
                    return Err(ConfigError::Conflict(format!(
                        "{v} has no effect with MPC_RELAY_AUTH=none"
                    )));
                }
            }
            KeySource::Disabled
        };

        let mut cfg = Config::new(amqp_url, exchange, source);

        if let Some(v) = get("MPC_RELAY_LISTEN") {
            cfg.listen = v.parse().map_err(|e| invalid("MPC_RELAY_LISTEN", format!("{e}")))?;
        }
        if let Some(v) = get("MPC_RELAY_METRICS_LISTEN") {
            cfg.metrics_listen = Some(v.parse().map_err(|e| invalid("MPC_RELAY_METRICS_LISTEN", format!("{e}")))?);
        }
        if let Some(v) = get("MPC_RELAY_WS_PATH") {
            if !v.starts_with('/') || v.contains(['?', '#', ' ']) {
                return Err(invalid("MPC_RELAY_WS_PATH", "must be an absolute path such as /ws"));
            }
            if ["/healthz", "/readyz", "/metrics"].contains(&v.as_str()) {
                return Err(invalid("MPC_RELAY_WS_PATH", "collides with an HTTP endpoint"));
            }
            cfg.ws_path = v;
        }
        match (get("MPC_RELAY_TLS_CERT"), get("MPC_RELAY_TLS_KEY")) {
            (Some(cert), Some(key)) => {
                cfg.tls = Some(TlsFiles {
                    cert: cert.into(),
                    key: key.into(),
                })
            }
            (None, None) => {}
            _ => {
                return Err(ConfigError::Conflict(
                    "MPC_RELAY_TLS_CERT and MPC_RELAY_TLS_KEY must be set together".into(),
                ))
            }
        }
        if let Some(v) = get("MPC_RELAY_AMQP_CONNECTION_NAME") {
            cfg.amqp_connection_name = v;
        }
        cfg.auth.issuer = get("MPC_RELAY_JWT_ISSUER");
        cfg.auth.audience = get("MPC_RELAY_JWT_AUDIENCE");
        cfg.auth.leeway = duration_or(&env, "MPC_RELAY_JWT_LEEWAY", cfg.auth.leeway)?;
        if let Some(v) = get("MPC_RELAY_JWT_MAX_TTL") {
            let d = parse_duration(&v).map_err(|r| invalid("MPC_RELAY_JWT_MAX_TTL", r))?;
            if d.is_zero() {
                return Err(invalid("MPC_RELAY_JWT_MAX_TTL", "must be greater than zero"));
            }
            cfg.auth.max_ttl = Some(d);
        }

        let l = &mut cfg.limits;
        l.max_connections = positive(&env, "MPC_RELAY_MAX_CONNECTIONS", l.max_connections)?;
        l.max_subscriptions = positive(&env, "MPC_RELAY_MAX_SUBSCRIPTIONS", l.max_subscriptions)?;
        l.max_frame_bytes = positive(&env, "MPC_RELAY_MAX_FRAME_BYTES", l.max_frame_bytes)?;
        if l.max_frame_bytes < 1024 {
            return Err(invalid("MPC_RELAY_MAX_FRAME_BYTES", "must be at least 1024"));
        }
        l.send_rate = positive::<u32>(&env, "MPC_RELAY_SEND_RATE", l.send_rate as u32)? as f64;
        l.send_burst = positive(&env, "MPC_RELAY_SEND_BURST", l.send_burst)?;
        l.connect_timeout = nonzero_duration(&env, "MPC_RELAY_CONNECT_TIMEOUT", l.connect_timeout)?;
        l.idle_timeout = nonzero_duration(&env, "MPC_RELAY_IDLE_TIMEOUT", l.idle_timeout)?;
        l.write_timeout = nonzero_duration(&env, "MPC_RELAY_WRITE_TIMEOUT", l.write_timeout)?;
        l.ping_interval = nonzero_duration(&env, "MPC_RELAY_PING_INTERVAL", l.ping_interval)?;
        l.prefetch = positive(&env, "MPC_RELAY_PREFETCH", l.prefetch)?;
        if l.ping_interval >= l.idle_timeout {
            return Err(ConfigError::Conflict(
                "MPC_RELAY_PING_INTERVAL must be shorter than MPC_RELAY_IDLE_TIMEOUT, or a healthy client answering pings would still idle out".into(),
            ));
        }
        cfg.shutdown_grace = duration_or(&env, "MPC_RELAY_SHUTDOWN_GRACE", cfg.shutdown_grace)?;
        cfg.log_format = match get("MPC_RELAY_LOG_FORMAT").as_deref() {
            None | Some("text") => LogFormat::Text,
            Some("json") => LogFormat::Json,
            Some(other) => {
                return Err(invalid(
                    "MPC_RELAY_LOG_FORMAT",
                    format!("expected `json` or `text`, got `{other}`"),
                ))
            }
        };
        Ok(cfg)
    }
}

/// Exchange names are restricted to the AMQP-safe set so that
/// `/exchange/<name>/<key>` splits unambiguously.
pub fn validate_exchange(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 255 {
        return Err("must be 1..=255 bytes".into());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err("may contain only letters, digits, '-', '_', '.' and ':'".into());
    }
    Ok(())
}

fn validate_jwks_url(url: &str, allow_http: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match parsed.host() {
                Some(url::Host::Domain(d)) => d == "localhost",
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if loopback || allow_http {
                Ok(())
            } else {
                Err("must be https:// (plain http lets anyone on the path substitute signing keys); set MPC_RELAY_JWKS_ALLOW_HTTP=true to override".into())
            }
        }
        other => Err(format!("unsupported scheme {other}")),
    }
}

pub fn parse_bool(v: &str) -> Result<bool, String> {
    match v {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("expected true or false, got `{v}`")),
    }
}

/// `10`, `10s`, `500ms`, `5m`, `1h`. A bare number is seconds.
pub fn parse_duration(v: &str) -> Result<Duration, String> {
    let v = v.trim();
    let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let (num, unit) = v.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("expected a duration such as 10s, 500ms or 5m, got `{v}`"))?;
    let d = match unit {
        "" | "s" => Duration::from_secs(n),
        "ms" => Duration::from_millis(n),
        "m" => Duration::from_secs(n.saturating_mul(60)),
        "h" => Duration::from_secs(n.saturating_mul(3600)),
        _ => return Err(format!("unknown duration unit `{unit}` in `{v}`")),
    };
    Ok(d)
}

fn duration_or(
    env: &BTreeMap<String, String>,
    var: &'static str,
    default: Duration,
) -> Result<Duration, ConfigError> {
    match env.get(var) {
        Some(v) => parse_duration(v).map_err(|r| invalid(var, r)),
        None => Ok(default),
    }
}

fn nonzero_duration(
    env: &BTreeMap<String, String>,
    var: &'static str,
    default: Duration,
) -> Result<Duration, ConfigError> {
    let d = duration_or(env, var, default)?;
    if d.is_zero() {
        return Err(invalid(var, "must be greater than zero"));
    }
    Ok(d)
}

fn positive<T>(env: &BTreeMap<String, String>, var: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr + PartialOrd + Default,
{
    match env.get(var) {
        None => Ok(default),
        Some(v) => {
            let n: T = v
                .parse()
                .map_err(|_| invalid(var, format!("expected a positive integer, got `{v}`")))?;
            if n <= T::default() {
                return Err(invalid(var, "must be greater than zero"));
            }
            Ok(n)
        }
    }
}
