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
use serde_json::{json, Value};

mod oauth;

use oauth::{CallbackQuery, GithubOAuth, OAuthConfig};

const UPSTREAM_NAME: &str = "github";
const DEFAULT_GITHUB_MCP_URL: &str = "https://api.githubcopilot.com/mcp/";

#[derive(Clone)]
pub struct Config {
    pub listen: String,
    pub allowed_hosts: Vec<String>,
    pub upstream_url: String,
    pub issuer: String,
    pub audience: String,
    public_key_pem: String,
    connections: HashMap<String, String>,
    oauth: Option<OAuthConfig>,
    pub request_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let connections: HashMap<String, String> =
            match std::env::var("OPENAB_GITHUB_BROKER_CONNECTIONS_JSON") {
                Ok(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw).context(
                    "parse OPENAB_GITHUB_BROKER_CONNECTIONS_JSON as subject-to-token JSON map",
                )?,
                _ => HashMap::new(),
            };
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
        let oauth = OAuthConfig::from_env()?;
        anyhow::ensure!(
            !connections.is_empty() || oauth.is_some(),
            "configure either OPENAB_GITHUB_BROKER_CONNECTIONS_JSON or the GitHub App OAuth settings"
        );

        let request_timeout_secs = std::env::var("OPENAB_GITHUB_BROKER_REQUEST_TIMEOUT_SECS")
            .ok()
            .map(|v| v.parse::<u64>().context("parse request timeout seconds"))
            .transpose()?
            .unwrap_or(60);
        anyhow::ensure!(
            (1..=300).contains(&request_timeout_secs),
            "request timeout must be between 1 and 300 seconds"
        );

        let allowed_hosts = broker_allowed_hosts(
            std::env::var("OPENAB_GITHUB_BROKER_ALLOWED_HOSTS")
                .ok()
                .as_deref(),
            std::env::var("CONTAINER_HOSTNAME").ok().as_deref(),
        )?;

        Ok(Self {
            listen: std::env::var("OPENAB_GITHUB_BROKER_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8080".into()),
            allowed_hosts,
            upstream_url: std::env::var("OPENAB_GITHUB_MCP_URL")
                .unwrap_or_else(|_| DEFAULT_GITHUB_MCP_URL.into()),
            issuer: required_env("OPENAB_GITHUB_BROKER_IDENTITY_ISSUER")?,
            audience: required_env("OPENAB_GITHUB_BROKER_IDENTITY_AUDIENCE")?,
            public_key_pem: required_env("OPENAB_GITHUB_BROKER_IDENTITY_PUBLIC_KEY")?,
            connections,
            oauth,
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

fn broker_allowed_hosts(
    explicit: Option<&str>,
    container_hostname: Option<&str>,
) -> Result<Vec<String>> {
    let mut hosts = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    for raw in explicit.into_iter().chain(container_hostname) {
        for host in raw
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
        {
            anyhow::ensure!(
                !host.contains("://")
                    && !host.contains('/')
                    && !host.chars().any(char::is_whitespace),
                "broker allowed host must be a hostname or host:port authority"
            );
            if !hosts.iter().any(|existing| existing == host) {
                hosts.push(host.to_owned());
            }
        }
    }
    Ok(hosts)
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
    oauth: Option<GithubOAuth>,
    upstream_url: Arc<str>,
    request_timeout_secs: u64,
}

impl GithubBroker {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            verifier: config.verifier()?,
            connections: Arc::new(config.connections.clone()),
            oauth: config.oauth.clone().map(GithubOAuth::new).transpose()?,
            upstream_url: Arc::from(config.upstream_url.clone()),
            request_timeout_secs: config.request_timeout_secs,
        })
    }

    fn authenticated_subject(&self, extensions: &Extensions) -> Result<String> {
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
        self.verifier.subject(bearer)
    }

    async fn github_token_for_subject(&self, subject: &str) -> Result<String> {
        if let Some(oauth) = &self.oauth {
            if oauth.is_connected(subject).await {
                return oauth.access_token(subject).await;
            }
        }
        self.connections
            .get(subject)
            .cloned()
            .ok_or_else(|| anyhow!("GitHub account is not connected for subject {subject:?}"))
    }

    async fn delegated_credential(&self, extensions: &Extensions) -> Result<(String, String)> {
        let subject = self.authenticated_subject(extensions)?;
        let github_token = self.github_token_for_subject(&subject).await?;
        Ok((subject, github_token))
    }

    fn connect_tool() -> rmcp::model::Tool {
        rmcp::model::Tool::new(
            "connect_github",
            "Create a short-lived GitHub App authorization URL for the authenticated Human. Use this when GitHub is not connected or when the Human asks to reconnect.",
            Arc::new(
                json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                })
                .as_object()
                .expect("object schema")
                .clone(),
            ),
        )
    }

    async fn begin_oauth(&self, extensions: &Extensions) -> Result<CallToolResult> {
        let subject = self.authenticated_subject(extensions)?;
        let oauth = self
            .oauth
            .as_ref()
            .context("GitHub App OAuth is not configured")?;
        let authorization_url = oauth.begin(subject.clone()).await?;
        tracing::info!(%subject, "created delegated GitHub OAuth authorization URL");
        Ok(CallToolResult::success(vec![rmcp::model::Content::text(
            serde_json::to_string(&json!({
                "provider": "github",
                "authorization_url": authorization_url,
                "expires_in_seconds": 600,
                "instructions": "Open this URL, authorize the GitHub App, then return to Slack and retry the GitHub request."
            }))?,
        )]))
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
        let subject = self.authenticated_subject(extensions)?;
        let mut tools = Vec::new();
        if self.oauth.is_some() {
            tools.push(Self::connect_tool());
        }
        let github_token = match self.github_token_for_subject(&subject).await {
            Ok(token) => token,
            Err(error) if self.oauth.is_some() => {
                tracing::info!(%subject, %error, "delegated GitHub account is not connected");
                return Ok(tools);
            }
            Err(error) => return Err(error),
        };
        tracing::info!(%subject, "delegated GitHub MCP discovery");
        let runtime = self.runtime(github_token);
        let result = openab_mcp::mcp::discover_server_tools(&runtime, UPSTREAM_NAME).await;
        let _ = runtime.disconnect(UPSTREAM_NAME).await;
        tools.extend(result?);
        Ok(tools)
    }

    async fn invoke(
        &self,
        extensions: &Extensions,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult> {
        let tool = request.name.to_string();
        if tool == "connect_github" {
            anyhow::ensure!(
                request
                    .arguments
                    .as_ref()
                    .is_none_or(|arguments| arguments.is_empty()),
                "connect_github does not accept arguments"
            );
            return self.begin_oauth(extensions).await;
        }
        let (subject, github_token) = self.delegated_credential(extensions).await?;
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
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    let broker = GithubBroker::new(&config)?;
    let oauth = broker.oauth.clone();
    let server_config =
        StreamableHttpServerConfig::default().with_allowed_hosts(config.allowed_hosts.clone());
    let service = StreamableHttpService::new(
        move || Ok(broker.clone()),
        LocalSessionManager::default().into(),
        server_config,
    );
    let mut router = axum::Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .nest_service("/mcp", service);
    if let Some(oauth) = oauth {
        router = router.route(
            "/oauth/github/callback",
            axum::routing::get(
                move |axum::extract::Query(query): axum::extract::Query<CallbackQuery>| {
                    oauth::callback_response(oauth.clone(), query)
                },
            ),
        );
    }
    Ok(router)
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
            allowed_hosts: vec!["localhost".into()],
            upstream_url: "https://example.invalid/mcp".into(),
            issuer: "https://issuer.example".into(),
            audience: "openab-github-broker".into(),
            public_key_pem: TEST_PUBLIC_KEY.into(),
            connections: HashMap::from([
                ("employee-sh1un".into(), "github-user-token-a".into()),
                ("employee-hr".into(), "github-user-token-b".into()),
            ]),
            oauth: None,
            request_timeout_secs: 5,
        };
        GithubBroker::new(&config).unwrap()
    }

    fn oauth_broker(store_path: std::path::PathBuf) -> GithubBroker {
        let config = Config {
            listen: "127.0.0.1:0".into(),
            allowed_hosts: vec!["localhost".into()],
            upstream_url: "https://example.invalid/mcp".into(),
            issuer: "https://issuer.example".into(),
            audience: "openab-github-broker".into(),
            public_key_pem: TEST_PUBLIC_KEY.into(),
            connections: HashMap::new(),
            oauth: Some(OAuthConfig {
                client_id: "github-app-client-id".into(),
                client_secret: "github-app-client-secret".into(),
                redirect_uri: "https://broker.example/oauth/github/callback".into(),
                store_path,
                store_key: [9; 32],
                authorize_url: "https://github.example/oauth/authorize".into(),
                token_url: "https://github.example/oauth/token".into(),
                api_url: "https://api.github.example".into(),
            }),
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

    #[tokio::test]
    async fn connection_lookup_is_subject_scoped() {
        let broker = broker();
        assert_ne!(
            broker
                .github_token_for_subject("employee-sh1un")
                .await
                .unwrap(),
            broker
                .github_token_for_subject("employee-hr")
                .await
                .unwrap()
        );
        assert!(broker
            .github_token_for_subject("unknown-human")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn authenticated_requests_select_different_human_tokens() {
        let broker = broker();
        let (shiun_subject, shiun_token) = broker
            .delegated_credential(&request_extensions(Some(TEST_IDENTITY_JWT)))
            .await
            .unwrap();
        let (hr_subject, hr_token) = broker
            .delegated_credential(&request_extensions(Some(TEST_HR_IDENTITY_JWT)))
            .await
            .unwrap();

        assert_eq!(shiun_subject, "employee-sh1un");
        assert_eq!(hr_subject, "employee-hr");
        assert_eq!(shiun_token, "github-user-token-a");
        assert_eq!(hr_token, "github-user-token-b");
        assert_ne!(shiun_token, hr_token);
    }

    #[tokio::test]
    async fn unconnected_oauth_human_sees_only_connect_capability() {
        let directory = tempfile::tempdir().unwrap();
        let broker = oauth_broker(directory.path().join("connections.enc.json"));
        let tools = broker
            .discover(&request_extensions(Some(TEST_IDENTITY_JWT)))
            .await
            .unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "connect_github");
    }

    #[tokio::test]
    async fn connect_url_uses_state_and_pkce_without_exposing_subject() {
        let directory = tempfile::tempdir().unwrap();
        let broker = oauth_broker(directory.path().join("connections.enc.json"));
        let oauth = broker.oauth.as_ref().unwrap();
        let url = oauth.begin("employee-sh1un".into()).await.unwrap();
        let url = url::Url::parse(&url).unwrap();
        let parameters: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(parameters["client_id"], "github-app-client-id");
        assert_eq!(parameters["code_challenge_method"], "S256");
        assert!(parameters.contains_key("state"));
        assert!(parameters.contains_key("code_challenge"));
        assert!(!url.as_str().contains("employee-sh1un"));
        assert!(!url.as_str().contains("github-app-client-secret"));
    }

    #[test]
    fn allowed_hosts_include_loopback_container_and_explicit_authorities() {
        let hosts = broker_allowed_hosts(
            Some("broker.example.com, broker.example.com:8443"),
            Some("openab-github-mcp-broker.zeabur.internal"),
        )
        .unwrap();
        assert!(hosts.contains(&"localhost".to_owned()));
        assert!(hosts.contains(&"openab-github-mcp-broker.zeabur.internal".to_owned()));
        assert!(hosts.contains(&"broker.example.com".to_owned()));
        assert!(hosts.contains(&"broker.example.com:8443".to_owned()));
    }

    #[test]
    fn allowed_hosts_reject_urls_and_paths() {
        assert!(broker_allowed_hosts(Some("https://broker.example.com"), None).is_err());
        assert!(broker_allowed_hosts(Some("broker.example.com/mcp"), None).is_err());
    }

    #[tokio::test]
    async fn missing_identity_header_fails_closed() {
        let err = broker()
            .delegated_credential(&request_extensions(None))
            .await
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
