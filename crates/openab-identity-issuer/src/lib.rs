use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{json, Value};
use url::Url;

pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
pub const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

#[derive(Debug, Clone)]
pub struct Config {
    pub issuer: String,
    pub listen: String,
    pub jwks: Value,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let issuer = std::env::var("OPENAB_IDENTITY_ISSUER")
            .context("OPENAB_IDENTITY_ISSUER is required")?;
        let listen = match std::env::var("OPENAB_IDENTITY_ISSUER_LISTEN") {
            Ok(value) => value,
            Err(_) => match std::env::var("PORT") {
                Ok(port) => format!("0.0.0.0:{port}"),
                Err(_) => DEFAULT_LISTEN.to_string(),
            },
        };

        let inline = std::env::var("OPENAB_IDENTITY_JWKS").ok();
        let file = std::env::var("OPENAB_IDENTITY_JWKS_FILE").ok();
        let raw = match (inline, file) {
            (Some(_), Some(_)) => bail!(
                "set exactly one of OPENAB_IDENTITY_JWKS or OPENAB_IDENTITY_JWKS_FILE, not both"
            ),
            (Some(raw), None) => raw,
            (None, Some(path)) => std::fs::read_to_string(PathBuf::from(&path))
                .with_context(|| format!("read OPENAB_IDENTITY_JWKS_FILE {path}"))?,
            (None, None) => {
                bail!("one of OPENAB_IDENTITY_JWKS or OPENAB_IDENTITY_JWKS_FILE is required")
            }
        };
        let jwks: Value = serde_json::from_str(&raw).context("parse JWKS JSON")?;

        Self::new(issuer, listen, jwks)
    }

    pub fn new(issuer: String, listen: String, jwks: Value) -> Result<Self> {
        validate_issuer(&issuer)?;
        validate_listen(&listen)?;
        validate_jwks(&jwks)?;
        Ok(Self {
            issuer,
            listen,
            jwks,
        })
    }
}

fn validate_issuer(issuer: &str) -> Result<()> {
    let url = Url::parse(issuer).context("OPENAB_IDENTITY_ISSUER must be an absolute URL")?;
    if url.scheme() != "https" {
        bail!("OPENAB_IDENTITY_ISSUER must use https");
    }
    if url.host_str().is_none() {
        bail!("OPENAB_IDENTITY_ISSUER must include a host");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("OPENAB_IDENTITY_ISSUER must not include a query or fragment");
    }
    if url.path() != "/" {
        bail!("OPENAB_IDENTITY_ISSUER must not include a path");
    }
    if issuer.ends_with('/') {
        bail!("OPENAB_IDENTITY_ISSUER must not end with a slash");
    }
    Ok(())
}

fn validate_listen(listen: &str) -> Result<()> {
    listen
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid issuer listen address {listen:?}"))?;
    Ok(())
}

fn validate_jwks(jwks: &Value) -> Result<()> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .context("JWKS must contain a keys array")?;
    if keys.is_empty() {
        bail!("JWKS keys array must not be empty");
    }

    let mut kids = HashSet::new();
    for (index, key) in keys.iter().enumerate() {
        let object = key
            .as_object()
            .with_context(|| format!("JWKS key {index} must be an object"))?;
        for private_field in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
            if object.contains_key(private_field) {
                bail!("JWKS key {index} contains private RSA field {private_field:?}");
            }
        }

        required_string(object, index, "n")?;
        required_string(object, index, "e")?;
        let kid = required_string(object, index, "kid")?;
        if !kids.insert(kid.to_string()) {
            bail!("JWKS contains duplicate kid {kid:?}");
        }
        if required_string(object, index, "kty")? != "RSA" {
            bail!("JWKS key {index} must use kty=RSA");
        }
        if let Some(alg) = object.get("alg").and_then(Value::as_str) {
            if alg != "RS256" {
                bail!("JWKS key {index} must use alg=RS256 when alg is present");
            }
        }
        if let Some(key_use) = object.get("use").and_then(Value::as_str) {
            if key_use != "sig" {
                bail!("JWKS key {index} must use use=sig when use is present");
            }
        }
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    index: usize,
    field: &str,
) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("JWKS key {index} requires a non-empty string {field:?}"))
}

#[derive(Clone)]
struct AppState {
    issuer: String,
    jwks: Value,
}

#[derive(Serialize)]
struct DiscoveryDocument<'a> {
    issuer: &'a str,
    jwks_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
    response_types_supported: [&'static str; 1],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 1],
    scopes_supported: [&'static str; 1],
    claims_supported: [&'static str; 8],
}

pub fn router(config: Config) -> Router {
    let state = Arc::new(AppState {
        issuer: config.issuer,
        jwks: config.jwks,
    });
    Router::new()
        .route(DISCOVERY_PATH, get(discovery))
        .route(JWKS_PATH, get(jwks))
        .route("/healthz", get(healthz))
        .with_state(state)
}

async fn discovery(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    cached_json(&DiscoveryDocument {
        issuer: &state.issuer,
        jwks_uri: format!("{}{}", state.issuer, JWKS_PATH),
        authorization_endpoint: format!("{}/authorize", state.issuer),
        token_endpoint: format!("{}/token", state.issuer),
        response_types_supported: ["id_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: ["openid"],
        claims_supported: [
            "iss",
            "aud",
            "sub",
            "client_id",
            "scope",
            "groups",
            "iat",
            "exp",
        ],
    })
}

async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    cached_json(&state.jwks)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

fn cached_json(value: &impl Serialize) -> Response<Body> {
    let body = serde_json::to_vec(value).expect("serialize validated issuer response");
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    response
}

#[cfg(test)]
mod tests {
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    fn valid_jwks() -> Value {
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "openab-poc-1",
                "n": "public-modulus",
                "e": "AQAB"
            }]
        })
    }

    fn config() -> Config {
        Config::new(
            "https://identity.example.com".into(),
            DEFAULT_LISTEN.into(),
            valid_jwks(),
        )
        .unwrap()
    }

    #[test]
    fn rejects_non_https_issuer() {
        let error = Config::new(
            "http://identity.example.com".into(),
            DEFAULT_LISTEN.into(),
            valid_jwks(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("must use https"));
    }

    #[test]
    fn rejects_private_key_material_in_jwks() {
        let mut jwks = valid_jwks();
        jwks["keys"][0]["d"] = Value::String("private-exponent".into());
        let error = Config::new(
            "https://identity.example.com".into(),
            DEFAULT_LISTEN.into(),
            jwks,
        )
        .unwrap_err();
        assert!(error.to_string().contains("private RSA field"));
    }

    #[test]
    fn rejects_duplicate_kids() {
        let key = valid_jwks()["keys"][0].clone();
        let error = Config::new(
            "https://identity.example.com".into(),
            DEFAULT_LISTEN.into(),
            json!({ "keys": [key.clone(), key] }),
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate kid"));
    }

    #[tokio::test]
    async fn serves_discovery_with_matching_issuer_and_jwks_uri() {
        let response = router(config())
            .oneshot(
                Request::builder()
                    .uri(DISCOVERY_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=300"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let document: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(document["issuer"], "https://identity.example.com");
        assert_eq!(
            document["jwks_uri"],
            "https://identity.example.com/.well-known/jwks.json"
        );
        assert_eq!(
            document["id_token_signing_alg_values_supported"],
            json!(["RS256"])
        );
        assert_eq!(
            document["authorization_endpoint"],
            "https://identity.example.com/authorize"
        );
        assert_eq!(
            document["token_endpoint"],
            "https://identity.example.com/token"
        );
    }

    #[tokio::test]
    async fn serves_only_public_jwks() {
        let response = router(config())
            .oneshot(
                Request::builder()
                    .uri(JWKS_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let document: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(document["keys"][0]["kid"], "openab-poc-1");
        assert!(document["keys"][0].get("d").is_none());
    }

    #[tokio::test]
    async fn health_endpoint_has_no_identity_metadata() {
        let response = router(config())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"status":"ok"})
        );
    }
}
