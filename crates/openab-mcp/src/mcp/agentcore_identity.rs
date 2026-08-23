//! Chat-native AgentCore Identity OAuth consent bridge.
//!
//! A browser callback cannot prove which Slack member is in front of it.
//! Consequently the callback never calls `CompleteResourceTokenAuth` itself.
//! It marks the AWS session as browser-returned and displays a one-time code;
//! the initiating Human must submit that code through the authenticated OAB
//! MCP Facade turn. The trusted `ResolvedRequestContext` is checked again
//! before AgentCore Identity binds the OAuth session.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rmcp::model::Tool;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;

use super::credential::{self, CredentialProviderConfig};
use super::runtime::McpRuntimeManager;
use super::sources::{CapabilitySource, SessionCtx};

const PROVIDER: &str = "agentcore_identity";
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_PENDING: usize = 1024;

#[derive(Debug, Clone)]
struct Connection {
    server: String,
    name: String,
    config: CredentialProviderConfig,
}

#[derive(Debug, Clone)]
struct PendingAuthorization {
    code: String,
    server: String,
    connection_name: String,
    subject: String,
    session_uri: String,
    created_at: u64,
    browser_returned: bool,
    completing: bool,
}

#[derive(Default)]
struct Coordinator {
    pending: Mutex<HashMap<String, PendingAuthorization>>,
}

static COORDINATOR: OnceLock<Arc<Coordinator>> = OnceLock::new();

fn coordinator() -> Arc<Coordinator> {
    COORDINATOR
        .get_or_init(|| Arc::new(Coordinator::default()))
        .clone()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn confirmation_code() -> Result<String> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).context("generate AgentCore authorization confirmation code")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

impl Coordinator {
    async fn insert(&self, pending: PendingAuthorization) -> Result<()> {
        let now = now_epoch();
        let mut entries = self.pending.lock().await;
        entries.retain(|_, value| {
            now.saturating_sub(value.created_at) <= PENDING_TTL.as_secs()
                && !(value.subject == pending.subject && value.server == pending.server)
        });
        anyhow::ensure!(
            entries.len() < MAX_PENDING,
            "too many pending AgentCore Identity authorization sessions"
        );
        entries.insert(pending.code.clone(), pending);
        Ok(())
    }

    async fn mark_browser_returned(
        &self,
        session_uri: &str,
        custom_state: Option<&str>,
    ) -> Result<String> {
        let now = now_epoch();
        let mut entries = self.pending.lock().await;
        entries.retain(|_, value| now.saturating_sub(value.created_at) <= PENDING_TTL.as_secs());
        let pending = entries
            .values_mut()
            .find(|value| value.session_uri == session_uri)
            .context("authorization session is invalid, expired, or already completed")?;
        if let Some(custom_state) = custom_state {
            anyhow::ensure!(
                constant_time_eq(custom_state.as_bytes(), pending.code.as_bytes()),
                "authorization callback state does not match"
            );
        }
        pending.browser_returned = true;
        Ok(pending.code.clone())
    }

    async fn claim(
        &self,
        code: &str,
        subject: &str,
        connection_name: &str,
    ) -> Result<PendingAuthorization> {
        let now = now_epoch();
        let mut entries = self.pending.lock().await;
        entries.retain(|_, value| now.saturating_sub(value.created_at) <= PENDING_TTL.as_secs());
        let pending = entries
            .get_mut(code)
            .context("confirmation code is invalid, expired, or already used")?;
        anyhow::ensure!(
            constant_time_eq(subject.as_bytes(), pending.subject.as_bytes()),
            "confirmation code belongs to a different authenticated Human"
        );
        anyhow::ensure!(
            pending.connection_name == connection_name,
            "confirmation code belongs to a different connection"
        );
        anyhow::ensure!(
            pending.browser_returned,
            "provider authorization has not returned to the OpenAB callback yet"
        );
        anyhow::ensure!(
            !pending.completing,
            "authorization completion is already in progress"
        );
        pending.completing = true;
        Ok(pending.clone())
    }

    async fn finish(&self, code: &str, session_uri: &str, success: bool) {
        let mut entries = self.pending.lock().await;
        if success {
            if entries
                .get(code)
                .is_some_and(|pending| pending.session_uri == session_uri)
            {
                entries.remove(code);
            }
        } else if let Some(pending) = entries.get_mut(code) {
            if pending.session_uri == session_uri {
                pending.completing = false;
            }
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&left, &right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

#[derive(Clone)]
pub(crate) struct AgentCoreIdentitySource {
    connections: Arc<Vec<Connection>>,
    coordinator: Arc<Coordinator>,
}

impl AgentCoreIdentitySource {
    pub(crate) fn from_manager(manager: &McpRuntimeManager) -> Option<Self> {
        let connections: Vec<_> = manager
            .catalog()
            .iter()
            .filter_map(|entry| {
                let config = entry.credential_provider.as_ref()?;
                let name = credential::connection_name(config, &entry.name)?;
                Some(Connection {
                    server: entry.name.clone(),
                    name,
                    config: config.clone(),
                })
            })
            .collect();
        (!connections.is_empty()).then(|| Self {
            connections: Arc::new(connections),
            coordinator: coordinator(),
        })
    }

    fn action<'a>(&'a self, tool: &str) -> Option<(&'a Connection, bool)> {
        self.connections.iter().find_map(|connection| {
            if tool == format!("connect_{}", connection.name) {
                Some((connection, false))
            } else if tool == format!("complete_{}", connection.name) {
                Some((connection, true))
            } else {
                None
            }
        })
    }

    async fn begin(
        &self,
        connection: &Connection,
        request: &openab_context::ResolvedRequestContext,
    ) -> Result<Value> {
        let code = confirmation_code()?;
        let start = credential::begin_authorization(&connection.config, request, &code).await?;
        self.coordinator
            .insert(PendingAuthorization {
                code,
                server: connection.server.clone(),
                connection_name: connection.name.clone(),
                subject: request.identity.subject.clone(),
                session_uri: start.session_uri,
                created_at: now_epoch(),
                browser_returned: false,
                completing: false,
            })
            .await?;
        Ok(json!({
            "authorization_url": start.authorization_url,
            "expires_in_seconds": PENDING_TTL.as_secs(),
            "next_step": format!(
                "Open the URL. After consent, the callback page shows a confirmation code. Return to this same chat and execute complete_{} with that code.",
                connection.name
            ),
        }))
    }

    async fn complete(
        &self,
        connection: &Connection,
        request: &openab_context::ResolvedRequestContext,
        args: &Map<String, Value>,
    ) -> Result<Value> {
        let code = args
            .get("confirmation_code")
            .and_then(Value::as_str)
            .context("confirmation_code must be a string")?;
        let pending = self
            .coordinator
            .claim(code, &request.identity.subject, &connection.name)
            .await?;
        let result =
            credential::complete_authorization(&connection.config, request, &pending.session_uri)
                .await;
        self.coordinator
            .finish(code, &pending.session_uri, result.is_ok())
            .await;
        result?;
        Ok(json!({
            "success": true,
            "connection": connection.name,
            "message": "Authorization is bound to this authenticated Human. Retry capability discovery or the original operation.",
        }))
    }
}

#[async_trait::async_trait]
impl CapabilitySource for AgentCoreIdentitySource {
    fn provider(&self) -> &str {
        PROVIDER
    }

    fn tools(&self, ctx: Option<&SessionCtx>) -> Vec<Tool> {
        if ctx.is_none() {
            return Vec::new();
        }
        let empty_schema = Arc::new(Map::from_iter([
            ("type".into(), Value::String("object".into())),
            ("additionalProperties".into(), Value::Bool(false)),
        ]));
        let complete_schema = Arc::new(
            json!({
                "type": "object",
                "properties": {
                    "confirmation_code": {
                        "type": "string",
                        "description": "One-time code shown by the OpenAB AgentCore Identity callback page."
                    }
                },
                "required": ["confirmation_code"],
                "additionalProperties": false
            })
            .as_object()
            .expect("schema literal")
            .clone(),
        );
        self.connections
            .iter()
            .flat_map(|connection| {
                [
                    Tool::new(
                        format!("connect_{}", connection.name),
                        format!(
                            "Start user-scoped {} OAuth authorization through AgentCore Identity.",
                            connection.name
                        ),
                        empty_schema.clone(),
                    ),
                    Tool::new(
                        format!("complete_{}", connection.name),
                        format!(
                            "Complete {} authorization using the one-time callback confirmation code.",
                            connection.name
                        ),
                        complete_schema.clone(),
                    ),
                ]
            })
            .collect()
    }

    async fn call(
        &self,
        ctx: Option<&SessionCtx>,
        tool: &str,
        args: &Map<String, Value>,
    ) -> Result<(Value, bool)> {
        let request = ctx
            .and_then(|ctx| ctx.request.as_ref())
            .context("authenticated human request context required")?;
        let (connection, complete) = self
            .action(tool)
            .with_context(|| format!("unknown AgentCore Identity capability {tool:?}"))?;
        let value = if complete {
            self.complete(connection, request, args).await?
        } else {
            anyhow::ensure!(args.is_empty(), "connect capability accepts no arguments");
            self.begin(connection, request).await?
        };
        Ok((value, false))
    }

    fn requires_session(&self) -> bool {
        true
    }
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    #[serde(alias = "sessionUri")]
    session_id: String,
    #[serde(default, alias = "customState", alias = "custom_state")]
    state: Option<String>,
}

async fn callback(
    axum::extract::Query(query): axum::extract::Query<CallbackQuery>,
) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::{Html, IntoResponse};

    let response = match coordinator()
        .mark_browser_returned(&query.session_id, query.state.as_deref())
        .await
    {
        Ok(code) => Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Authorization ready</title><h1>Authorization ready</h1><p>Return to the same Slack conversation and provide this one-time confirmation code:</p><pre>{}</pre><p>This code expires in ten minutes.</p>",
            html_escape(&code)
        ))
        .into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "AgentCore Identity callback rejected");
            (
                StatusCode::BAD_REQUEST,
                Html("<!doctype html><meta charset=\"utf-8\"><title>Authorization failed</title><h1>Authorization failed</h1><p>The session is invalid, expired, or already completed. Return to Slack and start again.</p>".to_string()),
            )
                .into_response()
        }
    };
    let mut response = response;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
    );
    response
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub async fn serve_callback(addr: &str) -> Result<()> {
    let sock: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid AgentCore Identity callback listen address {addr:?}"))?;
    let router = axum::Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route("/oauth/agentcore/callback", axum::routing::get(callback));
    let listener = tokio::net::TcpListener::bind(sock)
        .await
        .with_context(|| format!("bind AgentCore Identity callback listener on {sock}"))?;
    tracing::info!(addr = %sock, "AgentCore Identity callback listening");
    axum::serve(listener, router)
        .await
        .context("AgentCore Identity callback server terminated")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(code: &str, subject: &str, session_uri: &str) -> PendingAuthorization {
        PendingAuthorization {
            code: code.into(),
            server: "github-human".into(),
            connection_name: "github".into(),
            subject: subject.into(),
            session_uri: session_uri.into(),
            created_at: now_epoch(),
            browser_returned: false,
            completing: false,
        }
    }

    #[tokio::test]
    async fn callback_then_same_human_can_claim_once() {
        let coordinator = Coordinator::default();
        coordinator
            .insert(pending("code-a", "employee-sh1un", "urn:session:a"))
            .await
            .unwrap();
        let code = coordinator
            .mark_browser_returned("urn:session:a", Some("code-a"))
            .await
            .unwrap();
        assert_eq!(code, "code-a");
        let claimed = coordinator
            .claim("code-a", "employee-sh1un", "github")
            .await
            .unwrap();
        assert_eq!(claimed.session_uri, "urn:session:a");
        assert!(coordinator
            .claim("code-a", "employee-sh1un", "github")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn different_human_cannot_claim_forwarded_flow() {
        let coordinator = Coordinator::default();
        coordinator
            .insert(pending("code-b", "employee-sh1un", "urn:session:b"))
            .await
            .unwrap();
        coordinator
            .mark_browser_returned("urn:session:b", None)
            .await
            .unwrap();
        assert!(coordinator
            .claim("code-b", "employee-hr", "github")
            .await
            .is_err());
    }

    #[test]
    fn configured_connection_publishes_connect_and_complete_capabilities() {
        let config: super::super::config::McpConfig =
            serde_json::from_value(serde_json::json!({
                "mcpServers": {
                    "github-human": {
                        "type": "http",
                        "url": "https://github-mcp.example/mcp",
                        "credential_provider": {
                            "type": "agentcore_identity",
                            "region": "ap-southeast-1",
                            "workload_name": "openab-codex",
                            "resource_credential_provider_name": "openab-github",
                            "resource_oauth2_return_url": "https://openab.example.com/oauth/agentcore/callback",
                            "connection_name": "github",
                            "scopes": ["read:user"]
                        }
                    }
                }
            }))
            .unwrap();
        let manager = McpRuntimeManager::from_config(config);
        let source = AgentCoreIdentitySource::from_manager(&manager).unwrap();
        let ctx = SessionCtx {
            channel_id: "C123".into(),
            request: None,
        };
        let names: Vec<_> = source
            .tools(Some(&ctx))
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(names, ["connect_github", "complete_github"]);
        assert!(source.tools(None).is_empty());
    }
}
