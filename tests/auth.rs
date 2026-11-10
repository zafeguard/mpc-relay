//! JWT verification: HS256/384/512 with a secret, RS256/ES256/EdDSA from a
//! JWKS served by a local HTTP server, and the rejections.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mpc_relay::auth::{unix_now, AuthError, Authenticator};
use mpc_relay::config::{AuthConfig, KeySource};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef-hs";
const S: &str = "0b9f4c1e-6d2a-4f6b-9e0c-3a5d7b8c9d0e";

fn auth_cfg(source: KeySource) -> AuthConfig {
    AuthConfig {
        source,
        issuer: None,
        audience: None,
        leeway: Duration::from_secs(30),
        max_ttl: None,
    }
}

fn hs(cfg: AuthConfig) -> Arc<Authenticator> {
    Authenticator::new(cfg, CancellationToken::new()).unwrap()
}

fn hs_default() -> Arc<Authenticator> {
    hs(auth_cfg(KeySource::Hmac(SECRET.to_vec())))
}

fn claims(sub: &str, ttl: i64) -> Value {
    let now = unix_now() as i64;
    json!({ "sub": sub, "iat": now, "exp": now + ttl })
}

fn hs_token(alg: Algorithm, claims: &Value) -> String {
    encode(&Header::new(alg), claims, &EncodingKey::from_secret(SECRET)).unwrap()
}

/// Build `header.payload.signature` by hand, for tokens no library will
/// produce.
fn raw_token(header: &Value, claims: &Value, sig: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        B64.encode(header.to_string()),
        B64.encode(claims.to_string()),
        B64.encode(sig)
    )
}

async fn check(a: &Authenticator, token: &str) -> Result<String, AuthError> {
    a.authenticate(None, Some(token))
        .await
        .map(|i| i.principal.sub)
}

// ---- HMAC -----------------------------------------------------------------

#[tokio::test]
async fn hs256_384_512_accepted() {
    let a = hs_default();
    for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let t = hs_token(alg, &claims("device-1", 300));
        let id = a.authenticate(None, Some(&t)).await.unwrap();
        assert_eq!(id.principal.sub, "device-1", "{alg:?}");
        assert!(id.principal.sessions.is_none());
        assert!(id.expires_at.unwrap() > unix_now());
    }
}

#[tokio::test]
async fn wrong_secret() {
    let a = hs_default();
    let t = encode(
        &Header::new(Algorithm::HS256),
        &claims("d", 300),
        &EncodingKey::from_secret(b"another-secret-of-sufficient-length!!"),
    )
    .unwrap();
    assert_eq!(check(&a, &t).await, Err(AuthError::BadSignature));
}

#[tokio::test]
async fn tampered_payload() {
    let a = hs_default();
    let t = hs_token(Algorithm::HS256, &claims("device-1", 300));
    let mut parts: Vec<String> = t.split('.').map(str::to_owned).collect();
    parts[1] = B64.encode(claims("device-2", 300).to_string());
    assert_eq!(
        check(&a, &parts.join(".")).await,
        Err(AuthError::BadSignature)
    );
}

#[tokio::test]
async fn expired_and_leeway() {
    let a = hs_default();
    let now = unix_now() as i64;
    let expired = hs_token(Algorithm::HS256, &json!({"sub": "d", "exp": now - 120}));
    assert_eq!(check(&a, &expired).await, Err(AuthError::Expired));
    let within_leeway = hs_token(Algorithm::HS256, &json!({"sub": "d", "exp": now - 10}));
    assert_eq!(check(&a, &within_leeway).await.as_deref(), Ok("d"));
}

#[tokio::test]
async fn nbf_honoured() {
    let a = hs_default();
    let now = unix_now() as i64;
    let early = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 600, "nbf": now + 120}),
    );
    assert_eq!(check(&a, &early).await, Err(AuthError::NotYetValid));
    let ok = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 600, "nbf": now + 10}),
    );
    assert!(check(&a, &ok).await.is_ok());
    let bad_type = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 600, "nbf": "soon"}),
    );
    assert_eq!(
        check(&a, &bad_type).await,
        Err(AuthError::InvalidClaim("nbf".into()))
    );
}

#[tokio::test]
async fn issuer_checked_when_configured() {
    let mut cfg = auth_cfg(KeySource::Hmac(SECRET.to_vec()));
    cfg.issuer = Some("https://issuer.example".into());
    let a = hs(cfg);
    let now = unix_now() as i64;
    let right = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 60, "iss": "https://issuer.example"}),
    );
    let wrong = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 60, "iss": "https://evil.example"}),
    );
    let missing = hs_token(Algorithm::HS256, &json!({"sub": "d", "exp": now + 60}));
    assert!(check(&a, &right).await.is_ok());
    assert_eq!(check(&a, &wrong).await, Err(AuthError::BadIssuer));
    assert_eq!(
        check(&a, &missing).await,
        Err(AuthError::MissingClaim("iss".into()))
    );
}

#[tokio::test]
async fn audience_checked_when_configured() {
    let mut cfg = auth_cfg(KeySource::Hmac(SECRET.to_vec()));
    cfg.audience = Some("mpc-relay".into());
    let a = hs(cfg);
    let now = unix_now() as i64;
    let right = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 60, "aud": "mpc-relay"}),
    );
    let in_list = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 60, "aud": ["x", "mpc-relay"]}),
    );
    let wrong = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 60, "aud": "other"}),
    );
    let missing = hs_token(Algorithm::HS256, &json!({"sub": "d", "exp": now + 60}));
    assert!(check(&a, &right).await.is_ok());
    assert!(check(&a, &in_list).await.is_ok());
    assert_eq!(check(&a, &wrong).await, Err(AuthError::BadAudience));
    assert_eq!(
        check(&a, &missing).await,
        Err(AuthError::MissingClaim("aud".into()))
    );
    // Not configured: an aud claim is not a reason to reject.
    let b = hs_default();
    assert!(check(&b, &wrong).await.is_ok());
}

#[tokio::test]
async fn required_claims() {
    let a = hs_default();
    let now = unix_now() as i64;
    let no_sub = hs_token(Algorithm::HS256, &json!({"exp": now + 60}));
    assert_eq!(
        check(&a, &no_sub).await,
        Err(AuthError::MissingClaim("sub".into()))
    );
    let no_exp = hs_token(Algorithm::HS256, &json!({"sub": "d"}));
    assert_eq!(
        check(&a, &no_exp).await,
        Err(AuthError::MissingClaim("exp".into()))
    );
    let numeric_sub = hs_token(Algorithm::HS256, &json!({"sub": 7, "exp": now + 60}));
    assert!(check(&a, &numeric_sub).await.is_err());
    let string_exp = hs_token(Algorithm::HS256, &json!({"sub": "d", "exp": "never"}));
    assert!(check(&a, &string_exp).await.is_err());
}

#[tokio::test]
async fn sub_must_be_a_valid_node_id() {
    let a = hs_default();
    for sub in ["", "a*b", "a#", "a/b", "a b", &"x".repeat(256)] {
        let t = hs_token(Algorithm::HS256, &claims(sub, 60));
        assert!(check(&a, &t).await.is_err(), "{sub:?}");
    }
    let t = hs_token(Algorithm::HS256, &claims("a b", 60));
    assert_eq!(check(&a, &t).await, Err(AuthError::InvalidSub));
}

#[tokio::test]
async fn alg_none_is_refused() {
    let a = hs_default();
    for alg in ["none", "None", "NONE", "nOnE"] {
        let t = raw_token(&json!({"alg": alg, "typ": "JWT"}), &claims("d", 60), b"");
        assert_eq!(check(&a, &t).await, Err(AuthError::BadAlgorithm), "{alg}");
        // Also with the signature segment omitted entirely.
        let t = format!(
            "{}.{}.",
            B64.encode(json!({"alg": alg}).to_string()),
            B64.encode(claims("d", 60).to_string())
        );
        assert_eq!(check(&a, &t).await, Err(AuthError::BadAlgorithm), "{alg}");
    }
    let no_alg = raw_token(&json!({"typ": "JWT"}), &claims("d", 60), b"x");
    assert_eq!(check(&a, &no_alg).await, Err(AuthError::BadAlgorithm));
}

#[tokio::test]
async fn hmac_source_refuses_asymmetric_algorithms() {
    let a = hs_default();
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let t = encode(
        &Header::new(Algorithm::ES256),
        &claims("d", 60),
        &EncodingKey::from_ec_der(pkcs8.as_ref()),
    )
    .unwrap();
    assert_eq!(check(&a, &t).await, Err(AuthError::BadAlgorithm));
    for alg in ["RS256", "PS256", "EdDSA", "ES384", "XS256"] {
        let t = raw_token(&json!({"alg": alg}), &claims("d", 60), b"sig");
        assert_eq!(check(&a, &t).await, Err(AuthError::BadAlgorithm), "{alg}");
    }
}

#[tokio::test]
async fn crit_header_is_refused() {
    let a = hs_default();
    let t = raw_token(
        &json!({"alg": "HS256", "crit": ["b64"]}),
        &claims("d", 60),
        b"x",
    );
    assert_eq!(check(&a, &t).await, Err(AuthError::UnsupportedHeader));
}

#[tokio::test]
async fn malformed_tokens() {
    let a = hs_default();
    for t in [
        "",
        "   ",
        "abc",
        "a.b",
        "a.b.c.d",
        "!!!.###.$$$",
        &"a".repeat(20_000),
    ] {
        let r = check(&a, t).await;
        assert!(
            matches!(r, Err(AuthError::Malformed | AuthError::MissingToken)),
            "{t:.20}: {r:?}"
        );
    }
    assert_eq!(
        a.authenticate(None, None).await.unwrap_err(),
        AuthError::MissingToken
    );
}

#[tokio::test]
async fn max_ttl() {
    let mut cfg = auth_cfg(KeySource::Hmac(SECRET.to_vec()));
    cfg.max_ttl = Some(Duration::from_secs(600));
    let a = hs(cfg);
    let now = unix_now() as i64;
    let ok = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "iat": now, "exp": now + 600}),
    );
    assert!(check(&a, &ok).await.is_ok());
    let long = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "iat": now, "exp": now + 601}),
    );
    assert_eq!(check(&a, &long).await, Err(AuthError::TtlTooLong));
    let no_iat = hs_token(Algorithm::HS256, &json!({"sub": "d", "exp": now + 60}));
    assert_eq!(
        check(&a, &no_iat).await,
        Err(AuthError::MissingClaim("iat".into()))
    );
    // A future iat does not stretch the window: the token is refused as
    // issued in the future before the lifetime check.
    let future = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "iat": now + 3600, "exp": now + 3900}),
    );
    assert_eq!(check(&a, &future).await, Err(AuthError::IssuedInFuture));
}

#[tokio::test]
async fn iat_in_future() {
    let a = hs_default();
    let now = unix_now() as i64;
    let t = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "iat": now + 120, "exp": now + 600}),
    );
    assert_eq!(check(&a, &t).await, Err(AuthError::IssuedInFuture));
}

#[tokio::test]
async fn sessions_claim() {
    let a = hs_default();
    let now = unix_now() as i64;
    let upper = S.to_uppercase();
    let t = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 60, "sessions": [upper, "11111111-2222-4333-8444-555555555555"]}),
    );
    let id = a.authenticate(None, Some(&t)).await.unwrap();
    let sessions = id.principal.sessions.unwrap();
    assert!(sessions.contains(S), "canonicalised to lowercase");
    assert_eq!(sessions.len(), 2);
    let empty = hs_token(
        Algorithm::HS256,
        &json!({"sub": "d", "exp": now + 60, "sessions": []}),
    );
    assert_eq!(
        a.authenticate(None, Some(&empty))
            .await
            .unwrap()
            .principal
            .sessions
            .unwrap()
            .len(),
        0
    );
    for bad in [
        json!(null),
        json!("not-an-array"),
        json!([1]),
        json!(["not-a-uuid"]),
        json!({}),
    ] {
        let t = hs_token(
            Algorithm::HS256,
            &json!({"sub": "d", "exp": now + 60, "sessions": bad}),
        );
        assert_eq!(
            check(&a, &t).await,
            Err(AuthError::InvalidClaim("sessions".into())),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn disabled_mode_uses_login() {
    let a = hs(auth_cfg(KeySource::Disabled));
    assert!(a.is_disabled());
    let id = a.authenticate(Some("dev-node"), None).await.unwrap();
    assert_eq!(id.principal.sub, "dev-node");
    assert_eq!(id.expires_at, None);
    assert!(a.authenticate(None, Some("anything")).await.is_err());
    assert_eq!(
        a.authenticate(Some("a b"), None).await.unwrap_err(),
        AuthError::InvalidSub
    );
}

#[test]
fn reasons_are_stable_labels() {
    for (e, r) in [
        (AuthError::Expired, "expired"),
        (AuthError::BadAlgorithm, "bad_algorithm"),
        (AuthError::BadSignature, "bad_signature"),
        (AuthError::BadIssuer, "bad_issuer"),
        (AuthError::BadAudience, "bad_audience"),
        (AuthError::NotYetValid, "not_yet_valid"),
    ] {
        assert_eq!(e.reason(), r);
    }
}

// ---- JWKS -----------------------------------------------------------------

struct Keys {
    rsa: aws_lc_rs::rsa::KeyPair,
    ec_pkcs8: Vec<u8>,
    ed_pkcs8: Vec<u8>,
}

impl Keys {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        Keys {
            rsa: aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap(),
            ec_pkcs8: EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap()
                .as_ref()
                .to_vec(),
            ed_pkcs8: Ed25519KeyPair::generate_pkcs8(&rng)
                .unwrap()
                .as_ref()
                .to_vec(),
        }
    }

    fn rsa_encoding(&self) -> EncodingKey {
        let der = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&self.rsa).unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der.as_ref())
        );
        EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()
    }

    fn rsa_n(&self) -> Vec<u8> {
        self.rsa
            .public_key()
            .modulus()
            .big_endian_without_leading_zero()
            .to_vec()
    }

    fn rsa_jwk(&self, kid: &str) -> Value {
        let pk = self.rsa.public_key();
        json!({
            "kty": "RSA", "kid": kid, "use": "sig",
            "n": B64.encode(pk.modulus().big_endian_without_leading_zero()),
            "e": B64.encode(pk.exponent().big_endian_without_leading_zero()),
        })
    }

    fn ec_jwk(&self, kid: &str) -> Value {
        let kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.ec_pkcs8).unwrap();
        let point = kp.public_key().as_ref();
        assert_eq!(point.len(), 65);
        json!({
            "kty": "EC", "kid": kid, "crv": "P-256", "alg": "ES256",
            "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65]),
        })
    }

    fn ed_jwk(&self, kid: &str) -> Value {
        let kp = Ed25519KeyPair::from_pkcs8(&self.ed_pkcs8).unwrap();
        json!({ "kty": "OKP", "kid": kid, "crv": "Ed25519", "x": B64.encode(kp.public_key().as_ref()) })
    }
}

fn signed(alg: Algorithm, kid: Option<&str>, key: &EncodingKey, c: &Value) -> String {
    let mut h = Header::new(alg);
    h.kid = kid.map(str::to_owned);
    encode(&h, c, key).unwrap()
}

#[derive(Clone)]
struct JwksServer {
    doc: Arc<Mutex<Value>>,
    hits: Arc<AtomicU64>,
    url: String,
}

impl JwksServer {
    async fn start(doc: Value) -> Self {
        let doc = Arc::new(Mutex::new(doc));
        let hits = Arc::new(AtomicU64::new(0));
        let state = (doc.clone(), hits.clone());
        let app = Router::new()
            .route(
                "/jwks.json",
                get(
                    |State((doc, hits)): State<(Arc<Mutex<Value>>, Arc<AtomicU64>)>| async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Json(doc.lock().unwrap().clone())
                    },
                ),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks.json", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        JwksServer { doc, hits, url }
    }

    fn set(&self, doc: Value) {
        *self.doc.lock().unwrap() = doc;
    }

    fn hits(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn jwks_auth(server: &JwksServer, min_refresh: Duration) -> Arc<Authenticator> {
    mpc_relay::server::init_crypto();
    let a = Authenticator::new(
        auth_cfg(KeySource::Jwks {
            url: server.url.clone(),
            refresh_interval: Duration::from_secs(3600),
            min_refresh_interval: min_refresh,
        }),
        CancellationToken::new(),
    )
    .unwrap();
    for _ in 0..100 {
        if a.is_ready() {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("JWKS never loaded");
}

#[tokio::test]
async fn jwks_rs256_es256_eddsa_accepted() {
    let k = Keys::generate();
    let server =
        JwksServer::start(json!({"keys": [k.rsa_jwk("r1"), k.ec_jwk("e1"), k.ed_jwk("d1")]})).await;
    let a = jwks_auth(&server, Duration::from_secs(60)).await;
    let c = claims("device-9", 300);
    let rs = signed(Algorithm::RS256, Some("r1"), &k.rsa_encoding(), &c);
    let es = signed(
        Algorithm::ES256,
        Some("e1"),
        &EncodingKey::from_ec_der(&k.ec_pkcs8),
        &c,
    );
    let ed = signed(
        Algorithm::EdDSA,
        Some("d1"),
        &EncodingKey::from_ed_der(&k.ed_pkcs8),
        &c,
    );
    for t in [&rs, &es, &ed] {
        assert_eq!(check(&a, t).await.as_deref(), Ok("device-9"));
    }
    // No kid: tried against the keys of the right type.
    let es_nokid = signed(
        Algorithm::ES256,
        None,
        &EncodingKey::from_ec_der(&k.ec_pkcs8),
        &c,
    );
    assert_eq!(check(&a, &es_nokid).await.as_deref(), Ok("device-9"));
}

#[tokio::test]
async fn jwks_alg_confusion_hmac_with_public_key() {
    let k = Keys::generate();
    let server = JwksServer::start(json!({"keys": [k.rsa_jwk("r1"), k.ec_jwk("e1")]})).await;
    let a = jwks_auth(&server, Duration::from_secs(60)).await;
    let c = claims("attacker", 300);
    // The classic: HS256 keyed with material the attacker can read.
    let jwk_json = k.rsa_jwk("r1").to_string();
    let n = k.rsa_n();
    for secret in [jwk_json.as_bytes(), n.as_slice()] {
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            let t = signed(alg, Some("r1"), &EncodingKey::from_secret(secret), &c);
            assert_eq!(check(&a, &t).await, Err(AuthError::BadAlgorithm), "{alg:?}");
        }
    }
}

#[tokio::test]
async fn jwks_alg_must_match_the_keys_type() {
    let k = Keys::generate();
    let server = JwksServer::start(json!({"keys": [k.rsa_jwk("r1"), k.ec_jwk("e1")]})).await;
    let a = jwks_auth(&server, Duration::from_secs(60)).await;
    let c = claims("d", 300);
    // ES256 token pointing at the RSA key's kid.
    let t = signed(
        Algorithm::ES256,
        Some("r1"),
        &EncodingKey::from_ec_der(&k.ec_pkcs8),
        &c,
    );
    assert_eq!(check(&a, &t).await, Err(AuthError::BadAlgorithm));
    // RS512 / PS256 with the right key: outside the fixed set.
    for alg in [Algorithm::RS512, Algorithm::PS256] {
        let t = signed(alg, Some("r1"), &k.rsa_encoding(), &c);
        assert_eq!(check(&a, &t).await, Err(AuthError::BadAlgorithm), "{alg:?}");
    }
    // Signed by a different RSA key under the same kid.
    let other = Keys::generate();
    let t = signed(Algorithm::RS256, Some("r1"), &other.rsa_encoding(), &c);
    assert_eq!(check(&a, &t).await, Err(AuthError::BadSignature));
}

#[tokio::test]
async fn jwks_symmetric_and_mislabelled_keys_are_ignored() {
    let k = Keys::generate();
    let mut mislabelled = k.rsa_jwk("r-enc");
    mislabelled["use"] = json!("enc");
    let mut wrong_alg = k.rsa_jwk("r-512");
    wrong_alg["alg"] = json!("RS512");
    let server = JwksServer::start(json!({"keys": [
        {"kty": "oct", "kid": "o1", "k": B64.encode(SECRET)},
        mislabelled, wrong_alg,
        {"kty": "EC", "kid": "p384", "crv": "P-384", "x": "AA", "y": "AA"},
        {"kty": "weird", "kid": "w"},
        k.ec_jwk("e1"),
    ]}))
    .await;
    let a = jwks_auth(&server, Duration::from_secs(60)).await;
    let c = claims("d", 300);
    let hs = signed(
        Algorithm::HS256,
        Some("o1"),
        &EncodingKey::from_secret(SECRET),
        &c,
    );
    assert_eq!(check(&a, &hs).await, Err(AuthError::BadAlgorithm));
    let enc = signed(Algorithm::RS256, Some("r-enc"), &k.rsa_encoding(), &c);
    assert_eq!(check(&a, &enc).await, Err(AuthError::UnknownKey));
    let r512 = signed(Algorithm::RS256, Some("r-512"), &k.rsa_encoding(), &c);
    assert_eq!(check(&a, &r512).await, Err(AuthError::UnknownKey));
    let es = signed(
        Algorithm::ES256,
        Some("e1"),
        &EncodingKey::from_ec_der(&k.ec_pkcs8),
        &c,
    );
    assert!(
        check(&a, &es).await.is_ok(),
        "the usable key in the same set still works"
    );
}

#[tokio::test]
async fn jwks_alg_none_refused() {
    let k = Keys::generate();
    let server = JwksServer::start(json!({"keys": [k.ec_jwk("e1")]})).await;
    let a = jwks_auth(&server, Duration::from_secs(60)).await;
    let t = raw_token(&json!({"alg": "none", "kid": "e1"}), &claims("d", 60), b"");
    assert_eq!(check(&a, &t).await, Err(AuthError::BadAlgorithm));
}

#[tokio::test]
async fn jwks_expired_token() {
    let k = Keys::generate();
    let server = JwksServer::start(json!({"keys": [k.ed_jwk("d1")]})).await;
    let a = jwks_auth(&server, Duration::from_secs(60)).await;
    let now = unix_now() as i64;
    let t = signed(
        Algorithm::EdDSA,
        Some("d1"),
        &EncodingKey::from_ed_der(&k.ed_pkcs8),
        &json!({"sub": "d", "exp": now - 3600}),
    );
    assert_eq!(check(&a, &t).await, Err(AuthError::Expired));
}

#[tokio::test]
async fn jwks_unknown_kid_refreshes_rate_limited() {
    let k1 = Keys::generate();
    let k2 = Keys::generate();
    let server = JwksServer::start(json!({"keys": [k1.ec_jwk("old")]})).await;
    let a = jwks_auth(&server, Duration::from_millis(500)).await;
    assert_eq!(server.hits(), 1);
    let c = claims("d", 300);
    let new_token = signed(
        Algorithm::ES256,
        Some("new"),
        &EncodingKey::from_ec_der(&k2.ec_pkcs8),
        &c,
    );

    // Rotated at the provider; the relay has not seen it yet.
    server.set(json!({"keys": [k1.ec_jwk("old"), k2.ec_jwk("new")]}));
    // Within the rate limit of the initial fetch: no refetch, refused.
    assert_eq!(check(&a, &new_token).await, Err(AuthError::UnknownKey));
    assert_eq!(server.hits(), 1, "rate limit held");

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(check(&a, &new_token).await.as_deref(), Ok("d"));
    assert_eq!(
        server.hits(),
        2,
        "unknown kid triggered exactly one refetch"
    );

    // A burst of unknown kids right after: at most one fetch per interval.
    let bogus = signed(
        Algorithm::ES256,
        Some("bogus"),
        &EncodingKey::from_ec_der(&k2.ec_pkcs8),
        &c,
    );
    for _ in 0..20 {
        assert_eq!(check(&a, &bogus).await, Err(AuthError::UnknownKey));
    }
    assert_eq!(server.hits(), 2, "burst did not hammer the provider");
}

#[tokio::test]
async fn jwks_removed_key_stops_working_after_refresh() {
    let k1 = Keys::generate();
    let k2 = Keys::generate();
    let server = JwksServer::start(json!({"keys": [k1.ec_jwk("a")]})).await;
    let a = jwks_auth(&server, Duration::from_millis(100)).await;
    let c = claims("d", 300);
    let old = signed(
        Algorithm::ES256,
        Some("a"),
        &EncodingKey::from_ec_der(&k1.ec_pkcs8),
        &c,
    );
    assert!(check(&a, &old).await.is_ok());
    server.set(json!({"keys": [k2.ec_jwk("b")]}));
    tokio::time::sleep(Duration::from_millis(150)).await;
    // A token for the new key triggers the refresh that drops the old one.
    let new = signed(
        Algorithm::ES256,
        Some("b"),
        &EncodingKey::from_ec_der(&k2.ec_pkcs8),
        &c,
    );
    assert!(check(&a, &new).await.is_ok());
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(check(&a, &old).await, Err(AuthError::UnknownKey));
}

#[tokio::test]
async fn jwks_unreachable_is_not_ready() {
    mpc_relay::server::init_crypto();
    let a = Authenticator::new(
        auth_cfg(KeySource::Jwks {
            url: "http://127.0.0.1:9/jwks.json".into(),
            refresh_interval: Duration::from_secs(3600),
            min_refresh_interval: Duration::from_secs(60),
        }),
        CancellationToken::new(),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!a.is_ready());
    let k = Keys::generate();
    let t = signed(
        Algorithm::ES256,
        Some("e"),
        &EncodingKey::from_ec_der(&k.ec_pkcs8),
        &claims("d", 60),
    );
    assert_eq!(check(&a, &t).await, Err(AuthError::KeysUnavailable));
}
