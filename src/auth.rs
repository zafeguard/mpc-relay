//! JWT authentication of the CONNECT frame's `passcode`.
//!
//! The accepted algorithm set is fixed by the configured key source and never
//! by the token: HS256/HS384/HS512 for a shared secret, RS256/ES256/EdDSA for
//! a JWKS. `alg: none` is refused before any library code sees the token, and
//! a JWKS key is only ever used with the one algorithm its key type implies,
//! so neither HMAC-with-a-public-key nor ECDSA-with-an-RSA-key confusion is
//! reachable.
//!
//! Failures are reported to the client as a bare "authentication failed";
//! the reason ([`AuthError::reason`]) goes to logs and metrics only.

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{errors::ErrorKind, Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use crate::acl::{validate_node_id, Principal};
use crate::config::{AuthConfig, KeySource};

/// Tokens longer than this are refused unparsed.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Largest JWKS document accepted.
pub const MAX_JWKS_BYTES: usize = 1024 * 1024;

const HMAC_ALGS: &[Algorithm] = &[Algorithm::HS256, Algorithm::HS384, Algorithm::HS512];
const JWKS_ALGS: &[Algorithm] = &[Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub principal: Principal,
    /// The token's `exp`, seconds since the Unix epoch. `None` only when
    /// authentication is disabled.
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("no token in passcode")]
    MissingToken,
    #[error("token is not a well-formed JWT")]
    Malformed,
    #[error("token uses a header parameter this relay does not support")]
    UnsupportedHeader,
    #[error("algorithm not accepted for the configured key source")]
    BadAlgorithm,
    #[error("signature does not verify")]
    BadSignature,
    #[error("no key with that kid in the JWKS")]
    UnknownKey,
    #[error("signing keys are not available yet")]
    KeysUnavailable,
    #[error("token has expired")]
    Expired,
    #[error("token is not valid yet")]
    NotYetValid,
    #[error("token was issued in the future")]
    IssuedInFuture,
    #[error("wrong issuer")]
    BadIssuer,
    #[error("wrong audience")]
    BadAudience,
    #[error("required claim missing: {0}")]
    MissingClaim(String),
    #[error("claim has the wrong type or value: {0}")]
    InvalidClaim(String),
    #[error("token lifetime exceeds the configured maximum")]
    TtlTooLong,
    #[error("sub is not a valid node id")]
    InvalidSub,
    #[error("sub does not match MPC_RELAY_SUB_PATTERN")]
    SubNotAllowed,
}

impl AuthError {
    /// Stable, low-cardinality label for `mpc_relay_auth_failures_total`.
    pub fn reason(&self) -> &'static str {
        match self {
            AuthError::MissingToken => "missing_token",
            AuthError::Malformed => "malformed",
            AuthError::UnsupportedHeader => "unsupported_header",
            AuthError::BadAlgorithm => "bad_algorithm",
            AuthError::BadSignature => "bad_signature",
            AuthError::UnknownKey => "unknown_key",
            AuthError::KeysUnavailable => "keys_unavailable",
            AuthError::Expired => "expired",
            AuthError::NotYetValid => "not_yet_valid",
            AuthError::IssuedInFuture => "issued_in_future",
            AuthError::BadIssuer => "bad_issuer",
            AuthError::BadAudience => "bad_audience",
            AuthError::MissingClaim(_) => "missing_claim",
            AuthError::InvalidClaim(_) => "invalid_claim",
            AuthError::TtlTooLong => "ttl_too_long",
            AuthError::InvalidSub => "invalid_sub",
            AuthError::SubNotAllowed => "sub_not_allowed",
        }
    }
}

fn map_jwt_error(e: jsonwebtoken::errors::Error) -> AuthError {
    match e.kind() {
        ErrorKind::InvalidSignature => AuthError::BadSignature,
        ErrorKind::ExpiredSignature => AuthError::Expired,
        ErrorKind::ImmatureSignature => AuthError::NotYetValid,
        ErrorKind::InvalidIssuer => AuthError::BadIssuer,
        ErrorKind::InvalidAudience => AuthError::BadAudience,
        ErrorKind::MissingRequiredClaim(c) => AuthError::MissingClaim(c.clone()),
        ErrorKind::InvalidClaimFormat(c) => AuthError::InvalidClaim(c.clone()),
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::UnsupportedAlgorithm
        | ErrorKind::MissingAlgorithm => AuthError::BadAlgorithm,
        // A key that does not fit the algorithm, or a signature of the wrong
        // shape, is a failed verification as far as the client is concerned.
        ErrorKind::InvalidEcdsaKey
        | ErrorKind::InvalidEddsaKey
        | ErrorKind::InvalidRsaKey(_)
        | ErrorKind::InvalidKeyFormat => AuthError::BadSignature,
        _ => AuthError::Malformed,
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read `alg` from the protected header without trusting anything else in
/// the token, and refuse what must never reach a verifier.
fn peek_header(token: &str) -> Result<(Algorithm, Option<String>), AuthError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(AuthError::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(h), Some(_), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AuthError::Malformed);
    };
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(h)
        .map_err(|_| AuthError::Malformed)?;
    let header: Map<String, Value> =
        serde_json::from_slice(&raw).map_err(|_| AuthError::Malformed)?;
    // RFC 7515 4.1.11: a recipient that does not understand a `crit`
    // extension must reject the token. This relay understands none.
    if header.contains_key("crit") {
        return Err(AuthError::UnsupportedHeader);
    }
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(AuthError::BadAlgorithm)?;
    if alg.eq_ignore_ascii_case("none") {
        return Err(AuthError::BadAlgorithm);
    }
    let alg = Algorithm::from_str(alg).map_err(|_| AuthError::BadAlgorithm)?;
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(k)) => Some(k.clone()),
        Some(_) => return Err(AuthError::Malformed),
    };
    Ok((alg, kid))
}

struct VerifyKey {
    kid: Option<String>,
    alg: Algorithm,
    key: DecodingKey,
}

/// The single algorithm a JWK may be used with, or `None` if this relay
/// will not use it at all.
fn jwk_to_key(jwk: &Jwk) -> Option<VerifyKey> {
    if let Some(u) = &jwk.common.public_key_use {
        if *u != PublicKeyUse::Signature {
            return None;
        }
    }
    if let Some(ops) = &jwk.common.key_operations {
        if !ops.contains(&KeyOperations::Verify) {
            return None;
        }
    }
    let (alg, declared) = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => (Algorithm::RS256, KeyAlgorithm::RS256),
        AlgorithmParameters::EllipticCurve(p) if p.curve == EllipticCurve::P256 => {
            (Algorithm::ES256, KeyAlgorithm::ES256)
        }
        AlgorithmParameters::OctetKeyPair(p) if p.curve == EllipticCurve::Ed25519 => {
            (Algorithm::EdDSA, KeyAlgorithm::EdDSA)
        }
        // `oct` (symmetric) keys in a JWKS are never honoured: that is the
        // HMAC-with-a-published-key confusion this module exists to prevent.
        _ => return None,
    };
    if let Some(ka) = &jwk.common.key_algorithm {
        if *ka != declared {
            return None;
        }
    }
    let key = DecodingKey::from_jwk(jwk).ok()?;
    Some(VerifyKey {
        kid: jwk.common.key_id.clone(),
        alg,
        key,
    })
}

/// Parse a JWKS document into usable verification keys. Keys this relay
/// cannot or will not use are skipped, not fatal.
fn parse_jwks(body: &[u8]) -> Result<Vec<VerifyKey>, String> {
    let doc: Value = serde_json::from_slice(body).map_err(|e| format!("not JSON: {e}"))?;
    let keys = doc
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("no `keys` array")?;
    let mut out = Vec::new();
    for k in keys {
        match serde_json::from_value::<Jwk>(k.clone()) {
            Ok(jwk) => match jwk_to_key(&jwk) {
                Some(vk) => out.push(vk),
                None => {
                    tracing::debug!(kid = ?jwk.common.key_id, "skipping JWKS key not usable for RS256/ES256/EdDSA verification")
                }
            },
            Err(e) => tracing::warn!(error = %e, "skipping unparseable JWKS key"),
        }
    }
    Ok(out)
}

enum Lookup {
    Found(Vec<DecodingKey>),
    /// A key with this kid exists but is for a different algorithm.
    WrongAlgorithm,
    NotFound,
}

pub struct Jwks {
    url: String,
    client: reqwest::Client,
    keys: RwLock<Arc<Vec<VerifyKey>>>,
    loaded: AtomicBool,
    last_attempt: Mutex<Option<Instant>>,
    refresh_lock: tokio::sync::Mutex<()>,
    min_interval: Duration,
    fetches: AtomicU64,
}

impl Jwks {
    fn new(url: String, min_interval: Duration) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("mpc-relay/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Jwks {
            url,
            client,
            keys: RwLock::new(Arc::new(Vec::new())),
            loaded: AtomicBool::new(false),
            last_attempt: Mutex::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
            min_interval,
            fetches: AtomicU64::new(0),
        })
    }

    /// Number of fetch attempts so far (for tests and diagnostics).
    pub fn fetch_count(&self) -> u64 {
        self.fetches.load(Ordering::Relaxed)
    }

    async fn fetch(&self) -> Result<Vec<VerifyKey>, String> {
        let mut resp = self
            .client
            .get(&self.url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_JWKS_BYTES {
                return Err(format!("document larger than {MAX_JWKS_BYTES} bytes"));
            }
        }
        parse_jwks(&body)
    }

    /// Fetch and install the key set. The caller holds `refresh_lock`.
    async fn refresh_locked(&self) {
        *self.last_attempt.lock().expect("lock") = Some(Instant::now());
        self.fetches.fetch_add(1, Ordering::Relaxed);
        match self.fetch().await {
            Ok(keys) => {
                if keys.is_empty() {
                    // Install the empty set anyway: a provider that removed
                    // every key has revoked them, and keeping the old ones
                    // would keep accepting their tokens.
                    tracing::error!("JWKS fetched but contains no usable RS256/ES256/EdDSA signing keys; every token will be rejected");
                } else {
                    tracing::info!(keys = keys.len(), "JWKS refreshed");
                }
                *self.keys.write().expect("lock") = Arc::new(keys);
                self.loaded.store(true, Ordering::Release);
            }
            Err(e) => {
                // Keep serving the last good set; a transient outage of the
                // key provider must not lock every device out.
                tracing::warn!(error = %e, "JWKS refresh failed; keeping the previous key set");
            }
        }
    }

    /// Refresh because a token named a key we do not have, at most once per
    /// `min_interval` however many tokens ask.
    async fn refresh_for_unknown_key(&self) {
        let _guard = self.refresh_lock.lock().await;
        let recent = self
            .last_attempt
            .lock()
            .expect("lock")
            .is_some_and(|t| t.elapsed() < self.min_interval);
        if !recent {
            self.refresh_locked().await;
        }
    }

    fn lookup(&self, kid: Option<&str>, alg: Algorithm) -> Lookup {
        let keys = self.keys.read().expect("lock").clone();
        let named: Vec<&VerifyKey> = keys
            .iter()
            .filter(|k| kid.is_none() || k.kid.as_deref() == kid)
            .collect();
        if named.is_empty() {
            return Lookup::NotFound;
        }
        let usable: Vec<DecodingKey> = named
            .iter()
            .filter(|k| k.alg == alg)
            .map(|k| k.key.clone())
            .collect();
        if usable.is_empty() {
            if kid.is_some() {
                Lookup::WrongAlgorithm
            } else {
                Lookup::NotFound
            }
        } else {
            Lookup::Found(usable)
        }
    }

    async fn run_refresher(self: Arc<Self>, interval: Duration, shutdown: CancellationToken) {
        loop {
            {
                let _guard = self.refresh_lock.lock().await;
                self.refresh_locked().await;
            }
            // Until the first successful load, retry at the rate limit
            // instead of waiting a full refresh interval.
            let wait = if self.loaded.load(Ordering::Acquire) {
                interval
            } else {
                self.min_interval.min(interval)
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.cancelled() => return,
            }
        }
    }
}

enum Mode {
    Hmac(DecodingKey),
    Jwks(Arc<Jwks>),
    Disabled,
}

pub struct Authenticator {
    mode: Mode,
    cfg: AuthConfig,
}

impl Authenticator {
    /// Build the authenticator. With a JWKS source this spawns the refresher
    /// task, so it must be called inside a Tokio runtime.
    pub fn new(cfg: AuthConfig, shutdown: CancellationToken) -> anyhow::Result<Arc<Self>> {
        let mode = match &cfg.source {
            KeySource::Hmac(secret) => Mode::Hmac(DecodingKey::from_secret(secret)),
            KeySource::Jwks {
                url,
                refresh_interval,
                min_refresh_interval,
            } => {
                let jwks = Arc::new(Jwks::new(url.clone(), *min_refresh_interval)?);
                tokio::spawn(jwks.clone().run_refresher(*refresh_interval, shutdown));
                Mode::Jwks(jwks)
            }
            KeySource::Disabled => Mode::Disabled,
        };
        Ok(Arc::new(Authenticator { mode, cfg }))
    }

    pub fn is_disabled(&self) -> bool {
        matches!(self.mode, Mode::Disabled)
    }

    /// False only while a JWKS source has never loaded successfully.
    pub fn is_ready(&self) -> bool {
        match &self.mode {
            Mode::Jwks(j) => j.loaded.load(Ordering::Acquire),
            _ => true,
        }
    }

    pub fn jwks(&self) -> Option<&Arc<Jwks>> {
        match &self.mode {
            Mode::Jwks(j) => Some(j),
            _ => None,
        }
    }

    pub async fn authenticate(
        &self,
        login: Option<&str>,
        passcode: Option<&str>,
    ) -> Result<Identity, AuthError> {
        if let Mode::Disabled = self.mode {
            let sub = login
                .filter(|l| !l.is_empty())
                .ok_or(AuthError::MissingClaim("login".into()))?;
            validate_node_id(sub).map_err(|_| AuthError::InvalidSub)?;
            self.check_sub_pattern(sub)?;
            return Ok(Identity {
                principal: Principal {
                    sub: sub.to_owned(),
                    sessions: None,
                },
                expires_at: None,
            });
        }
        let token = passcode
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or(AuthError::MissingToken)?;
        let (alg, kid) = peek_header(token)?;
        let claims = match &self.mode {
            Mode::Hmac(key) => {
                if !HMAC_ALGS.contains(&alg) {
                    return Err(AuthError::BadAlgorithm);
                }
                self.verify(token, alg, key)?
            }
            Mode::Jwks(jwks) => {
                if !JWKS_ALGS.contains(&alg) {
                    return Err(AuthError::BadAlgorithm);
                }
                let mut lookup = jwks.lookup(kid.as_deref(), alg);
                if let Lookup::NotFound = lookup {
                    jwks.refresh_for_unknown_key().await;
                    lookup = jwks.lookup(kid.as_deref(), alg);
                }
                match lookup {
                    Lookup::Found(keys) => {
                        let mut last = AuthError::BadSignature;
                        let mut ok = None;
                        for key in &keys {
                            match self.verify(token, alg, key) {
                                Ok(c) => {
                                    ok = Some(c);
                                    break;
                                }
                                Err(AuthError::BadSignature) => continue,
                                Err(e) => {
                                    last = e;
                                    break;
                                }
                            }
                        }
                        ok.ok_or(last)?
                    }
                    Lookup::WrongAlgorithm => return Err(AuthError::BadAlgorithm),
                    Lookup::NotFound if !jwks.loaded.load(Ordering::Acquire) => {
                        return Err(AuthError::KeysUnavailable)
                    }
                    Lookup::NotFound => return Err(AuthError::UnknownKey),
                }
            }
            Mode::Disabled => unreachable!("handled above"),
        };
        self.check_claims(claims)
    }

    fn verify(
        &self,
        token: &str,
        alg: Algorithm,
        key: &DecodingKey,
    ) -> Result<Map<String, Value>, AuthError> {
        let mut v = Validation::new(alg);
        v.algorithms = vec![alg];
        v.leeway = self.cfg.leeway.as_secs();
        v.validate_exp = true;
        v.validate_nbf = true;
        let mut required = vec!["exp", "sub"];
        match &self.cfg.issuer {
            Some(iss) => {
                v.set_issuer(&[iss]);
                required.push("iss");
            }
            None => v.iss = None,
        }
        match &self.cfg.audience {
            Some(aud) => {
                v.set_audience(&[aud]);
                required.push("aud");
            }
            None => v.validate_aud = false,
        }
        v.set_required_spec_claims(&required);
        jsonwebtoken::decode::<Map<String, Value>>(token, key, &v)
            .map(|d| d.claims)
            .map_err(map_jwt_error)
    }

    /// `MPC_RELAY_SUB_PATTERN`: the operator's statement of which node ids
    /// a device token may claim, so that none can claim an agent's.
    fn check_sub_pattern(&self, sub: &str) -> Result<(), AuthError> {
        match &self.cfg.sub_pattern {
            Some(re) if !re.is_match(sub) => Err(AuthError::SubNotAllowed),
            _ => Ok(()),
        }
    }

    /// Checks on top of the library's: types of the optional claims, `iat`,
    /// the lifetime cap, `sub` as a node id, and `sessions`.
    fn check_claims(&self, claims: Map<String, Value>) -> Result<Identity, AuthError> {
        let now = unix_now();
        let leeway = self.cfg.leeway.as_secs();
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::MissingClaim("sub".into()))?;
        validate_node_id(sub).map_err(|_| AuthError::InvalidSub)?;
        self.check_sub_pattern(sub)?;
        let exp = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or_else(|| AuthError::InvalidClaim("exp".into()))?;
        // Belt and braces with the library's own check.
        if exp.saturating_add(leeway) < now {
            return Err(AuthError::Expired);
        }
        if let Some(nbf) = claims.get("nbf") {
            let nbf = nbf
                .as_u64()
                .ok_or_else(|| AuthError::InvalidClaim("nbf".into()))?;
            if nbf > now.saturating_add(leeway) {
                return Err(AuthError::NotYetValid);
            }
        }
        let iat = match claims.get("iat") {
            None => None,
            Some(v) => {
                let iat = v
                    .as_u64()
                    .ok_or_else(|| AuthError::InvalidClaim("iat".into()))?;
                if iat > now.saturating_add(leeway) {
                    return Err(AuthError::IssuedInFuture);
                }
                Some(iat)
            }
        };
        if let Some(max) = self.cfg.max_ttl {
            let max = max.as_secs();
            let iat = iat.ok_or_else(|| AuthError::MissingClaim("iat".into()))?;
            // exp - iat bounds the declared lifetime; exp - now bounds what
            // is left of it, which an iat in the near future could stretch.
            if exp.saturating_sub(iat) > max || exp.saturating_sub(now) > max.saturating_add(leeway)
            {
                return Err(AuthError::TtlTooLong);
            }
        }
        let sessions = match claims.get("sessions") {
            None => None,
            Some(Value::Array(items)) => {
                let mut set = HashSet::with_capacity(items.len());
                for item in items {
                    let s = item
                        .as_str()
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())
                        .ok_or_else(|| AuthError::InvalidClaim("sessions".into()))?;
                    set.insert(s.hyphenated().to_string());
                }
                Some(set)
            }
            // Present but not an array (including null) is malformed, never
            // "unrestricted".
            Some(_) => return Err(AuthError::InvalidClaim("sessions".into())),
        };
        Ok(Identity {
            principal: Principal {
                sub: sub.to_owned(),
                sessions,
            },
            expires_at: Some(exp),
        })
    }
}
