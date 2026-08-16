//! Human-delegated GitHub MCP broker.
//!
//! OpenAB authenticates the chat human and sends a short-lived signed identity
//! JWT. This service resolves `sub` to a GitHub user credential and injects it
//! only into the request-scoped upstream GitHub MCP connection. The coding
//! agent never receives, stores, or configures the GitHub credential.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use openab_mcp::mcp::runtime::McpRuntimeManager;
use openab_mcp::rmcp;
use rmcp::handler::server::ServerHandler;
use rmcp::model::Extensions;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::ErrorData as McpError;
use serde::Deserialize;
use serde_json::Value;

const UPSTREAM_NAME: &str = "github";
const DEFAULT_GITHUB_MCP_URL: &str = "https://api.githubcopilot.com/mcp/";

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub upstream_url: String,
    pub issuer: String,
    pub audience: String,
    public_key_pem: String,
    connections: HashMap<String, String>,
    pub request_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let connections_raw = required_env("OPENAB_GITHUB_BROKER_CONNECTIONS_JSON")?;
        let connections: HashMap<String, String> = serde_json::from_str(&connections_raw)
            .context("parse OPENAB_GITHUB_BROKER_CONNECTIONS_JSON as subject-to-token JSON map")?;
        anyhow::ensure!(
            !connections.is_empty(),
            "GitHub connection map must not be empty"
        );
        for (subject, token) in &connections {
            anyhow::ensure!(
                !subject.trim().is_empty(),
                "GitHub connection subject must not be empty"
            );
            anyhow::ensure!(
                !token.trim().is_empty(),
                "GitHub connection token must not be empty"
            );
        }

        let request_timeout_secs = std::env::var("OPENAB_GITHUB_BROKER_REQUEST_TIMEOUT_SECS")
            .ok()
            .map(|v| v.parse::<u64>().context("parse request timeout seconds"))
            .transpose()?
            .unwrap_or(60);
        anyhow::ensure!(
            (1..=300).contains(&request_timeout_secs),
            "request timeout must be between 1 and 300 seconds"
        );

        Ok(Self {
            listen: std::env::var("OPENAB_GITHUB_BROKER_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8080".into()),
            upstream_url: std::env::var("OPENAB_GITHUB_MCP_URL")
                .unwrap_or_else(|_| DEFAULT_GITHUB_MCP_URL.into()),
            issuer: required_env("OPENAB_GITHUB_BROKER_IDENTITY_ISSUER")?,
            audience: required_env("OPENAB_GITHUB_BROKER_IDENTITY_AUDIENCE")?,
            public_key_pem: required_env("OPENAB_GITHUB_BROKER_IDENTITY_PUBLIC_KEY")?,
            connections,
            request_timeout_secs,
        })
    }

    fn verifier(&self) -> Result<IdentityVerifier> {
        IdentityVerifier::new(
            &self.public_key_pem,
            self.issuer.clone(),
            self.audience.clone(),
        )
    }
}

fn required_env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is not set"))?;
    anyhow::ensure!(!value.trim().is_empty(), "{name} must not be empty");
    Ok(value)
}

#[derive(Debug, Deserialize)]
struct IdentityClaims {
    sub: String,
}

#[derive(Clone)]
struct IdentityVerifier {
    key: Arc<DecodingKey>,
    validation: Arc<Validation>,
}

impl IdentityVerifier {
    fn new(public_key_pem: &str, issuer: String, audience: String) -> Result<Self> {
        let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .context("parse broker identity RSA public key")?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        Ok(Self {
            key: Arc::new(key),
            validation: Arc::new(validation),
        })
    }

    fn subject(&self, bearer: &str) -> Result<String> {
        let claims = decode::<IdentityClaims>(bearer, &self.key, &self.validation)
            .context("verify OpenAB Human identity JWT")?
            .claims;
        anyhow::ensure!(
            !claims.sub.trim().is_empty(),
            "identity JWT subject is empty"
        );
        Ok(claims.sub)
    }
}

#[derive(Clone)]
pub struct GithubBroker {
    verifier: IdentityVerifier,
    connections: Arc<HashMap<String, String>>,
    upstream_url: Arc<str>,
    request_timeout_secs: u64,
}

impl GithubBroker {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            verifier: config.verifier()?,
            connections: Arc::new(config.connections.clone()),
            upstream_url: Arc::from(config.upstream_url.clone()),
            request_timeout_secs: config.request_timeout_secs,
        })
    }

    fn delegated_credential(&self, extensions: &Extensions) -> Result<(String, String)> {
        let parts = extensions
            .get::<axum::http::request::Parts>()
            .context("authenticated HTTP request context required")?;
        let authorization = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .context("Authorization: Bearer identity token required")?;
        let bearer = authorization
            .strip_prefix("Bearer ")
            .or_else(|| authorization.strip_prefix("bearer "))
            .context("Authorization header must use Bearer")?;
        let subject = self.verifier.subject(bearer)?;
        let github_token = self.github_token_for_subject(&subject)?;
        Ok((subject, github_token))
    }

    fn github_token_for_subject(&self, subject: &str) -> Result<String> {
        self.connections
            .get(subject)
            .cloned()
            .ok_or_else(|| anyhow!("GitHub account is not connected for subject {subject:?}"))
    }

    fn runtime(&self, github_token: String) -> McpRuntimeManager {
        McpRuntimeManager::for_request_bearer(
            UPSTREAM_NAME,
            self.upstream_url.to_string(),
            github_token,
            self.request_timeout_secs,
        )
    }

    async fn discover(&self, extensions: &Extensions) -> Result<Vec<rmcp::model::Tool>> {
        let (subject, github_token) = self.delegated_credential(extensions)?;
        tracing::info!(%subject, "delegated GitHub MCP discovery");
        let runtime = self.runtime(github_token);
        let result = openab_mcp::mcp::discover_server_tools(&runtime, UPSTREAM_NAME).await;
        let _ = runtime.disconnect(UPSTREAM_NAME).await;
        result
    }

    async fn invoke(
        &self,
        extensions: &Extensions,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult> {
        let (subject, github_token) = self.delegated_credential(extensions)?;
        let tool = request.name.to_string();
        tracing::info!(%subject, %tool, "delegated GitHub MCP call");
        let arguments = request.arguments.map(Value::Object).unwrap_or(Value::Null);
        let runtime = self.runtime(github_token);
        let result =
            openab_mcp::mcp::invoke_server_tool(&runtime, UPSTREAM_NAME, tool, arguments).await;
        let _ = runtime.disconnect(UPSTREAM_NAME).await;
        let (value, _) = result?;
        serde_json::from_value(value).context("decode upstream GitHub MCP tool result")
    }
}

impl ServerHandler for GithubBroker {
    fn get_info(&self) -> ServerInfo {
        let mut implementation = Implementation::default();
        implementation.name = "openab-github-mcp-broker".into();
        implementation.version = env!("CARGO_PKG_VERSION").into();
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = implementation;
        info.instructions = Some(
            "GitHub tools are executed with the authenticated OpenAB Human's delegated credential."
                .into(),
        );
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = self.discover(&context.extensions).await.map_err(|e| {
            McpError::invalid_params(openab_mcp::mcp::redact_secrets(&format!("{e:#}")), None)
        })?;
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.invoke(&context.extensions, request)
            .await
            .map_err(|e| {
                McpError::invalid_params(openab_mcp::mcp::redact_secrets(&format!("{e:#}")), None)
            })
    }
}

pub fn router(config: Config) -> Result<axum::Router> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService,
    };
    let broker = GithubBroker::new(&config)?;
    let service = StreamableHttpService::new(
        move || Ok(broker.clone()),
        LocalSessionManager::default().into(),
        Default::default(),
    );
    Ok(axum::Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .nest_service("/mcp", service))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvYzs+XFImjKXN4TwdMFt
OQkm+K94TtKXDGDCrL3OxGXOr3v1EdZ7QcyWRCgtLmw5LzOV6DoHBpMk4k3ZYSuT
DP0xThxUbLvLJ2ZrRUOls04cBex4sCvDVhUplwAco6+XhX1FD5xCtFmKuFaSSecp
B6edLSsnoAFGmbcAMWmqs3F+4SA271Kd544aJ6ZFSFfK/IMYqsoeGIKywKXL4VVY
L4iRPEGhLluAlpKn5BbWgs9UxeW3yXN5rei4peYEhe/GUeJoqR8vgz71X5t+NSJg
KnypscJHThLt6CU5VS/ZpEpCrh8CcS99GW7BwYkKslVse7EMGIvfS70CoBtuTt65
/wIDAQAB
-----END PUBLIC KEY-----"#;

    // Signed by a disposable test-only private key that is not stored in the
    // repository. `exp` is 2100-01-01 so this deterministic fixture stays valid.
    const TEST_IDENTITY_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbXBsb3llZS1zaDF1biIsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUiLCJhdWQiOiJvcGVuYWItZ2l0aHViLWJyb2tlciIsImV4cCI6NDEwMjQ0NDgwMH0.rO-BqE7a4BmmVZ5L_vaVQPjUQpCiLTpvA19nvt6dLB4q2mRIQboZaUcSOzeSGDp9NlOWLv4_zgfoyQFBu86uoFM5qWwa0MykWz1HSRPYd2_3ElHQUu3gQn75W1c07SNbju1Y7YVSv0iO6b1UO07PHEUpLbvMK-sxsFkvZK8nwEiP4YBLjfhtMr39fTWW-xpgmQgMSw7kIuMLKngeviR5OXykFKghXISlsrhtGjpTWtY2iF0eOhorgLdQt-q5Q-6oqbbOU1yOD9Pt1850JMb9QsHdLkqlFLE6gkAXaMdbQby1sI9LjpyVKi_VpSPVjYEFGuwwat_nc6S7xDWWk_rs9w";
    const TEST_HR_IDENTITY_JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbXBsb3llZS1ociIsImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUiLCJhdWQiOiJvcGVuYWItZ2l0aHViLWJyb2tlciIsImV4cCI6NDEwMjQ0NDgwMH0.XsxrSxb98cYgTcGbdFKbUHQKDgygC5SNG4iodtRnYnOAfVyfC3tXKnwvybm9uG8A3Con93uCmD6hfNIIsn3fQLLIs3jFLmEoL3On7baVIMhsRotlkL7lEsxfXm7LwxUwoKpVzf29nvIxS_B0PLfciS6ej8MGI8oco5u57FMmp8wA8EYBsg0WJ7sAbE2ESHFZGxtPJyTI30rd9n5tOcCIJHzZs9ZvYBn8RJClKWkA4_mS8akmeT1-OBPQUhHSlZGmSaJFH7rxKM6n7M-BhT-ap20OJw_5Wos-Z3tcn8lbH42bhN4IuIptYIFIH_vI6nihjTdWHGREy9czfZPOEAeLgQ";

    fn broker() -> GithubBroker {
        let config = Config {
            listen: "127.0.0.1:0".into(),
            upstream_url: "https://example.invalid/mcp".into(),
            issuer: "https://issuer.example".into(),
            audience: "openab-github-broker".into(),
            public_key_pem: TEST_PUBLIC_KEY.into(),
            connections: HashMap::from([
                ("employee-sh1un".into(), "github-user-token-a".into()),
                ("employee-hr".into(), "github-user-token-b".into()),
            ]),
            request_timeout_secs: 5,
        };
        GithubBroker::new(&config).unwrap()
    }

    fn request_extensions(jwt: Option<&str>) -> Extensions {
        let mut request = axum::http::Request::builder().uri("/mcp");
        if let Some(jwt) = jwt {
            request = request.header(axum::http::header::AUTHORIZATION, format!("Bearer {jwt}"));
        }
        let (parts, _) = request.body(()).unwrap().into_parts();
        let mut extensions = Extensions::new();
        extensions.insert(parts);
        extensions
    }

    #[test]
    fn valid_identity_jwt_resolves_human_subject() {
        let broker = broker();
        assert_eq!(
            broker.verifier.subject(TEST_IDENTITY_JWT).unwrap(),
            "employee-sh1un"
        );
        assert_eq!(
            broker.verifier.subject(TEST_HR_IDENTITY_JWT).unwrap(),
            "employee-hr"
        );
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let verifier = IdentityVerifier::new(
            TEST_PUBLIC_KEY,
            "https://issuer.example".into(),
            "some-other-service".into(),
        )
        .unwrap();
        assert!(verifier.subject(TEST_IDENTITY_JWT).is_err());
    }

    #[test]
    fn connection_lookup_is_subject_scoped() {
        let broker = broker();
        assert_ne!(
            broker.github_token_for_subject("employee-sh1un").unwrap(),
            broker.github_token_for_subject("employee-hr").unwrap()
        );
        assert!(broker.github_token_for_subject("unknown-human").is_err());
    }

    #[test]
    fn authenticated_requests_select_different_human_tokens() {
        let broker = broker();
        let (shiun_subject, shiun_token) = broker
            .delegated_credential(&request_extensions(Some(TEST_IDENTITY_JWT)))
            .unwrap();
        let (hr_subject, hr_token) = broker
            .delegated_credential(&request_extensions(Some(TEST_HR_IDENTITY_JWT)))
            .unwrap();

        assert_eq!(shiun_subject, "employee-sh1un");
        assert_eq!(hr_subject, "employee-hr");
        assert_eq!(shiun_token, "github-user-token-a");
        assert_eq!(hr_token, "github-user-token-b");
        assert_ne!(shiun_token, hr_token);
    }

    #[test]
    fn missing_identity_header_fails_closed() {
        let err = broker()
            .delegated_credential(&request_extensions(None))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Authorization"), "got {err}");
    }

    #[test]
    fn connection_json_rejects_non_map_shape() {
        let parsed = serde_json::from_str::<HashMap<String, String>>(r#"["token"]"#);
        assert!(parsed.is_err());
    }
}
