//! Downstream credential extension point. Vendor-specific claim translation
//! lives here, outside Slack, ACP, sessions, and identity resolution.

use anyhow::{Context, Result};
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialProviderConfig {
    AgentcoreGateway {
        issuer: String,
        audience: String,
        client_id: String,
        private_key_env: String,
        key_id: String,
        #[serde(default)]
        scopes: Vec<String>,
        #[serde(default = "default_credential_ttl_seconds")]
        ttl_seconds: u64,
    },
    AgentcoreIdentity {
        region: String,
        workload_name: String,
        resource_credential_provider_name: String,
        resource_oauth2_return_url: String,
        /// Human-facing suffix for the synthetic `connect_*` and
        /// `complete_*` Facade capabilities. Defaults to the MCP server name.
        #[serde(default)]
        connection_name: Option<String>,
        #[serde(default = "default_user_id_namespace")]
        user_id_namespace: String,
        scopes: Vec<String>,
    },
}

fn default_credential_ttl_seconds() -> u64 {
    300
}

fn default_user_id_namespace() -> String {
    "openab".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialOutcome {
    Bearer(String),
    AuthorizationRequired { authorization_url: String },
}

#[async_trait]
pub trait CredentialProvider: Send + Sync {
    async fn credential(
        &self,
        context: &openab_context::ResolvedRequestContext,
    ) -> Result<CredentialOutcome>;
}

pub fn from_config(config: &CredentialProviderConfig) -> Result<Box<dyn CredentialProvider>> {
    match config {
        CredentialProviderConfig::AgentcoreGateway {
            issuer,
            audience,
            client_id,
            private_key_env,
            key_id,
            scopes,
            ttl_seconds,
        } => {
            anyhow::ensure!(
                (1..=900).contains(ttl_seconds),
                "agentcore_gateway credential ttl_seconds must be between 1 and 900"
            );
            anyhow::ensure!(
                !issuer.trim().is_empty()
                    && !audience.trim().is_empty()
                    && !client_id.trim().is_empty(),
                "agentcore_gateway issuer, audience, and client_id must be non-empty"
            );
            Ok(Box::new(AgentCoreGatewayCredentialProvider {
                issuer: issuer.clone(),
                audience: audience.clone(),
                client_id: client_id.clone(),
                private_key_env: private_key_env.clone(),
                key_id: key_id.clone(),
                scopes: scopes.clone(),
                ttl_seconds: *ttl_seconds,
            }))
        }
        CredentialProviderConfig::AgentcoreIdentity {
            region,
            workload_name,
            resource_credential_provider_name,
            resource_oauth2_return_url,
            connection_name,
            user_id_namespace,
            scopes,
        } => {
            validate_agentcore_identity_config(
                region,
                workload_name,
                resource_credential_provider_name,
                resource_oauth2_return_url,
                connection_name.as_deref(),
                user_id_namespace,
                scopes,
            )?;
            #[cfg(feature = "agentcore-identity")]
            {
                Ok(Box::new(AgentCoreIdentityCredentialProvider {
                    region: region.clone(),
                    workload_name: workload_name.clone(),
                    resource_credential_provider_name: resource_credential_provider_name.clone(),
                    resource_oauth2_return_url: resource_oauth2_return_url.clone(),
                    user_id_namespace: user_id_namespace.clone(),
                    scopes: scopes.clone(),
                }))
            }
            #[cfg(not(feature = "agentcore-identity"))]
            {
                anyhow::bail!(
                    "agentcore_identity credential provider requires the agentcore-identity build feature"
                )
            }
        }
    }
}

pub(crate) fn validate_agentcore_identity_config(
    region: &str,
    workload_name: &str,
    resource_credential_provider_name: &str,
    resource_oauth2_return_url: &str,
    connection_name: Option<&str>,
    user_id_namespace: &str,
    scopes: &[String],
) -> Result<()> {
    anyhow::ensure!(
        !region.is_empty()
            && !region.starts_with('-')
            && !region.ends_with('-')
            && region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "agentcore_identity region must contain only lowercase ASCII letters, digits, and hyphens"
    );
    anyhow::ensure!(
        (3..=255).contains(&workload_name.len())
            && workload_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')),
        "agentcore_identity workload_name must be 3-255 characters from [A-Za-z0-9_.-]"
    );
    anyhow::ensure!(
        (1..=128).contains(&resource_credential_provider_name.len())
            && resource_credential_provider_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "agentcore_identity resource_credential_provider_name must be 1-128 characters from [A-Za-z0-9_-]"
    );
    let return_url = url::Url::parse(resource_oauth2_return_url)
        .context("parse agentcore_identity resource_oauth2_return_url")?;
    anyhow::ensure!(
        return_url.scheme() == "https",
        "agentcore_identity resource_oauth2_return_url must use HTTPS"
    );
    if let Some(connection_name) = connection_name {
        anyhow::ensure!(
            !connection_name.is_empty()
                && connection_name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "agentcore_identity connection_name must contain only lowercase ASCII letters, digits, and underscores"
        );
    }
    anyhow::ensure!(
        !user_id_namespace.trim().is_empty(),
        "agentcore_identity user_id_namespace must be non-empty"
    );
    anyhow::ensure!(
        !scopes.is_empty() && scopes.iter().all(|scope| !scope.trim().is_empty()),
        "agentcore_identity scopes must contain at least one non-empty scope"
    );
    Ok(())
}

pub(crate) fn connection_name<'a>(
    config: &'a CredentialProviderConfig,
    server_name: &'a str,
) -> Option<String> {
    let CredentialProviderConfig::AgentcoreIdentity {
        connection_name, ..
    } = config
    else {
        return None;
    };
    Some(
        connection_name
            .clone()
            .unwrap_or_else(|| sanitize_connection_name(server_name)),
    )
}

fn sanitize_connection_name(server_name: &str) -> String {
    let value: String = server_name
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                c
            } else if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    value.trim_matches('_').to_string()
}

#[cfg(feature = "agentcore-identity")]
fn validate_session_uri(session_uri: &str) -> Result<()> {
    let value = session_uri
        .strip_prefix("urn:ietf:params:oauth:request_uri:")
        .context("AgentCore Identity session URI has an invalid prefix")?;
    anyhow::ensure!(
        !value.is_empty()
            && value
                .bytes()
                .all(|b| { b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') }),
        "AgentCore Identity session URI has invalid characters"
    );
    Ok(())
}

/// PoC adapter for AgentCore Gateway CUSTOM_JWT inbound authorization.
/// The configured issuer's JWKS must contain the public key matching the PEM
/// loaded from `private_key_env`.
struct AgentCoreGatewayCredentialProvider {
    issuer: String,
    audience: String,
    client_id: String,
    private_key_env: String,
    key_id: String,
    scopes: Vec<String>,
    ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
struct AgentCoreClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    client_id: &'a str,
    scope: String,
    groups: &'a [String],
    request_id: &'a str,
    agent_id: &'a str,
    source: &'a str,
    iat: u64,
    exp: u64,
}

fn agentcore_claims<'a>(
    provider: &'a AgentCoreGatewayCredentialProvider,
    context: &'a openab_context::ResolvedRequestContext,
    now: u64,
) -> AgentCoreClaims<'a> {
    AgentCoreClaims {
        iss: &provider.issuer,
        aud: &provider.audience,
        sub: &context.identity.subject,
        client_id: &provider.client_id,
        scope: provider.scopes.join(" "),
        groups: &context.identity.groups,
        request_id: &context.request.request_id,
        agent_id: &context.request.agent_identity.id,
        source: &context.request.source.kind,
        iat: now,
        exp: now.saturating_add(provider.ttl_seconds),
    }
}

#[async_trait]
impl CredentialProvider for AgentCoreGatewayCredentialProvider {
    async fn credential(
        &self,
        context: &openab_context::ResolvedRequestContext,
    ) -> Result<CredentialOutcome> {
        let pem = std::env::var(&self.private_key_env).with_context(|| {
            format!(
                "credential private key env {} is not set",
                self.private_key_env
            )
        })?;
        let key = EncodingKey::from_rsa_pem(pem.as_bytes())
            .context("parse AgentCore credential RSA private key")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let claims = agentcore_claims(self, context, now);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());
        let token =
            jsonwebtoken::encode(&header, &claims, &key).context("sign AgentCore request JWT")?;
        Ok(CredentialOutcome::Bearer(token))
    }
}

#[cfg(any(feature = "agentcore-identity", test))]
fn namespaced_user_id(namespace: &str, subject: &str) -> Result<String> {
    anyhow::ensure!(
        !subject.trim().is_empty(),
        "trusted identity subject must be non-empty"
    );
    let user_id = format!("{}:{}", namespace.trim(), subject);
    anyhow::ensure!(
        (1..=128).contains(&user_id.len()),
        "derived AgentCore Identity user ID exceeds 128 bytes"
    );
    Ok(user_id)
}

#[cfg(feature = "agentcore-identity")]
struct AgentCoreIdentityCredentialProvider {
    region: String,
    workload_name: String,
    resource_credential_provider_name: String,
    resource_oauth2_return_url: String,
    user_id_namespace: String,
    scopes: Vec<String>,
}

#[cfg(feature = "agentcore-identity")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkloadTokenRequest<'a> {
    user_id: &'a str,
    workload_name: &'a str,
}

#[cfg(feature = "agentcore-identity")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkloadTokenResponse {
    workload_access_token: String,
}

#[cfg(feature = "agentcore-identity")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceTokenRequest<'a> {
    workload_identity_token: &'a str,
    resource_credential_provider_name: &'a str,
    scopes: &'a [String],
    oauth2_flow: &'static str,
    resource_oauth2_return_url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_state: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    force_authentication: Option<bool>,
}

#[cfg(feature = "agentcore-identity")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceTokenResponse {
    access_token: Option<String>,
    authorization_url: Option<String>,
    session_status: Option<String>,
    session_uri: Option<String>,
}

#[cfg(feature = "agentcore-identity")]
fn resource_token_outcome(response: ResourceTokenResponse) -> Result<CredentialOutcome> {
    anyhow::ensure!(
        response.session_status.as_deref() != Some("FAILED"),
        "AgentCore Identity authorization session failed"
    );
    if let Some(token) = response.access_token.filter(|value| !value.is_empty()) {
        return Ok(CredentialOutcome::Bearer(token));
    }
    if let Some(url) = response.authorization_url.filter(|value| !value.is_empty()) {
        let parsed = url::Url::parse(&url).context("parse AgentCore Identity authorization URL")?;
        anyhow::ensure!(
            parsed.scheme() == "https",
            "AgentCore Identity authorization URL must use HTTPS"
        );
        return Ok(CredentialOutcome::AuthorizationRequired {
            authorization_url: url,
        });
    }
    anyhow::bail!(
        "AgentCore Identity returned neither an access token nor an authorization URL (session status: {})",
        response.session_status.as_deref().unwrap_or("unknown")
    )
}

#[cfg(feature = "agentcore-identity")]
async fn signed_post_bytes<T: Serialize>(region: &str, path: &str, request: &T) -> Result<Vec<u8>> {
    use aws_credential_types::provider::ProvideCredentials;
    use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
    use aws_sigv4::sign::v4;
    use std::time::SystemTime;

    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await;
    let credentials = sdk_config
        .credentials_provider()
        .context("no AWS credentials provider available for AgentCore Identity")?
        .provide_credentials()
        .await
        .context("load AWS credentials for AgentCore Identity")?;
    let identity = credentials.into();
    let host = format!("bedrock-agentcore.{region}.amazonaws.com");
    let url = format!("https://{host}{path}");
    let body = serde_json::to_vec(request).context("serialize AgentCore Identity request")?;
    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("bedrock-agentcore")
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()
        .context("build AgentCore Identity signing parameters")?;
    let headers = [
        ("host", host.as_str()),
        ("content-type", "application/json"),
    ];
    let signable = SignableRequest::new(
        "POST",
        &url,
        headers.into_iter(),
        SignableBody::Bytes(&body),
    )?;
    let (instructions, _) = sign(signable, &signing_params.into())?.into_parts();

    let client = reqwest::Client::new();
    let mut builder = client
        .post(&url)
        .header("host", &host)
        .header("content-type", "application/json")
        .body(body);
    for (name, value) in instructions.headers() {
        builder = builder.header(name, value);
    }
    let response = builder
        .send()
        .await
        .context("send AgentCore Identity request")?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("AgentCore Identity request failed with HTTP {status}");
    }
    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .context("read AgentCore Identity response")
}

#[cfg(feature = "agentcore-identity")]
async fn signed_post<T: Serialize, R: for<'de> Deserialize<'de>>(
    region: &str,
    path: &str,
    request: &T,
) -> Result<R> {
    let body = signed_post_bytes(region, path, request).await?;
    serde_json::from_slice(&body).context("decode AgentCore Identity response")
}

#[cfg(feature = "agentcore-identity")]
#[async_trait]
impl CredentialProvider for AgentCoreIdentityCredentialProvider {
    async fn credential(
        &self,
        context: &openab_context::ResolvedRequestContext,
    ) -> Result<CredentialOutcome> {
        let user_id = namespaced_user_id(&self.user_id_namespace, &context.identity.subject)?;
        let workload: WorkloadTokenResponse = signed_post(
            &self.region,
            "/identities/GetWorkloadAccessTokenForUserId",
            &WorkloadTokenRequest {
                user_id: &user_id,
                workload_name: &self.workload_name,
            },
        )
        .await?;
        anyhow::ensure!(
            !workload.workload_access_token.is_empty(),
            "AgentCore Identity returned an empty workload access token"
        );
        let resource: ResourceTokenResponse = signed_post(
            &self.region,
            "/identities/oauth2/token",
            &ResourceTokenRequest {
                workload_identity_token: &workload.workload_access_token,
                resource_credential_provider_name: &self.resource_credential_provider_name,
                scopes: &self.scopes,
                oauth2_flow: "USER_FEDERATION",
                resource_oauth2_return_url: &self.resource_oauth2_return_url,
                custom_state: None,
                force_authentication: None,
            },
        )
        .await?;
        resource_token_outcome(resource)
    }
}

#[cfg(feature = "agentcore-identity")]
#[derive(Debug, Clone)]
pub(crate) struct AgentCoreAuthorizationStart {
    pub authorization_url: String,
    pub session_uri: String,
}

#[cfg(feature = "agentcore-identity")]
fn identity_provider_from_config(
    config: &CredentialProviderConfig,
) -> Result<AgentCoreIdentityCredentialProvider> {
    let CredentialProviderConfig::AgentcoreIdentity {
        region,
        workload_name,
        resource_credential_provider_name,
        resource_oauth2_return_url,
        connection_name: _,
        user_id_namespace,
        scopes,
    } = config
    else {
        anyhow::bail!("credential provider is not agentcore_identity");
    };
    validate_agentcore_identity_config(
        region,
        workload_name,
        resource_credential_provider_name,
        resource_oauth2_return_url,
        None,
        user_id_namespace,
        scopes,
    )?;
    Ok(AgentCoreIdentityCredentialProvider {
        region: region.clone(),
        workload_name: workload_name.clone(),
        resource_credential_provider_name: resource_credential_provider_name.clone(),
        resource_oauth2_return_url: resource_oauth2_return_url.clone(),
        user_id_namespace: user_id_namespace.clone(),
        scopes: scopes.clone(),
    })
}

#[cfg(feature = "agentcore-identity")]
async fn workload_token(
    provider: &AgentCoreIdentityCredentialProvider,
    context: &openab_context::ResolvedRequestContext,
) -> Result<(String, String)> {
    let user_id = namespaced_user_id(&provider.user_id_namespace, &context.identity.subject)?;
    let response: WorkloadTokenResponse = signed_post(
        &provider.region,
        "/identities/GetWorkloadAccessTokenForUserId",
        &WorkloadTokenRequest {
            user_id: &user_id,
            workload_name: &provider.workload_name,
        },
    )
    .await?;
    anyhow::ensure!(
        !response.workload_access_token.is_empty(),
        "AgentCore Identity returned an empty workload access token"
    );
    Ok((user_id, response.workload_access_token))
}

#[cfg(feature = "agentcore-identity")]
pub(crate) async fn begin_authorization(
    config: &CredentialProviderConfig,
    context: &openab_context::ResolvedRequestContext,
    custom_state: &str,
) -> Result<AgentCoreAuthorizationStart> {
    let provider = identity_provider_from_config(config)?;
    let (_, workload_identity_token) = workload_token(&provider, context).await?;
    let response: ResourceTokenResponse = signed_post(
        &provider.region,
        "/identities/oauth2/token",
        &ResourceTokenRequest {
            workload_identity_token: &workload_identity_token,
            resource_credential_provider_name: &provider.resource_credential_provider_name,
            scopes: &provider.scopes,
            oauth2_flow: "USER_FEDERATION",
            resource_oauth2_return_url: &provider.resource_oauth2_return_url,
            custom_state: Some(custom_state),
            force_authentication: Some(true),
        },
    )
    .await?;
    anyhow::ensure!(
        response.session_status.as_deref() != Some("FAILED"),
        "AgentCore Identity authorization session failed"
    );
    let authorization_url = response
        .authorization_url
        .filter(|value| !value.is_empty())
        .context("AgentCore Identity did not return an authorization URL")?;
    let parsed = url::Url::parse(&authorization_url)
        .context("parse AgentCore Identity authorization URL")?;
    anyhow::ensure!(
        parsed.scheme() == "https",
        "AgentCore Identity authorization URL must use HTTPS"
    );
    let session_uri = response
        .session_uri
        .filter(|value| !value.is_empty())
        .context("AgentCore Identity did not return a session URI")?;
    validate_session_uri(&session_uri)?;
    Ok(AgentCoreAuthorizationStart {
        authorization_url,
        session_uri,
    })
}

#[cfg(feature = "agentcore-identity")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompleteResourceTokenAuthRequest<'a> {
    session_uri: &'a str,
    user_identifier: UserIdentifier<'a>,
}

#[cfg(feature = "agentcore-identity")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserIdentifier<'a> {
    user_id: &'a str,
}

#[cfg(feature = "agentcore-identity")]
pub(crate) async fn complete_authorization(
    config: &CredentialProviderConfig,
    context: &openab_context::ResolvedRequestContext,
    session_uri: &str,
) -> Result<()> {
    validate_session_uri(session_uri)?;
    let provider = identity_provider_from_config(config)?;
    let user_id = namespaced_user_id(&provider.user_id_namespace, &context.identity.subject)?;
    let response = signed_post_bytes(
        &provider.region,
        "/identities/CompleteResourceTokenAuth",
        &CompleteResourceTokenAuthRequest {
            session_uri,
            user_identifier: UserIdentifier { user_id: &user_id },
        },
    )
    .await?;
    anyhow::ensure!(
        response.is_empty(),
        "AgentCore Identity completion returned an unexpected response body"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(subject: &str, groups: &[&str]) -> openab_context::ResolvedRequestContext {
        openab_context::ResolvedRequestContext {
            request: openab_context::RequestContext {
                request_id: format!("req-{subject}"),
                source: openab_context::SourceContext {
                    kind: "slack".into(),
                    workspace_id: Some("T123".into()),
                    channel_id: "C123".into(),
                },
                human_identity: openab_context::HumanIdentity {
                    external_id: format!("U-{subject}"),
                },
                agent_identity: openab_context::AgentIdentity { id: "suma".into() },
                session_id: format!("thread-{subject}"),
            },
            identity: openab_context::NormalizedIdentity {
                subject: subject.into(),
                groups: groups.iter().map(|g| (*g).to_string()).collect(),
            },
        }
    }

    #[test]
    fn agentcore_adapter_maps_different_humans_to_different_policy_claims() {
        let provider = AgentCoreGatewayCredentialProvider {
            issuer: "https://issuer.example".into(),
            audience: "agentcore-gateway".into(),
            client_id: "openab".into(),
            private_key_env: "UNUSED".into(),
            key_id: "poc-key".into(),
            scopes: vec!["gateway:invoke".into()],
            ttl_seconds: 300,
        };
        let cloud = context("employee-001", &["cloud-engineer", "github-source-reader"]);
        let hr = context("employee-002", &["hr"]);
        let cloud_claims = serde_json::to_value(agentcore_claims(&provider, &cloud, 100)).unwrap();
        let hr_claims = serde_json::to_value(agentcore_claims(&provider, &hr, 100)).unwrap();

        assert_eq!(cloud_claims["sub"], "employee-001");
        assert_eq!(cloud_claims["groups"][1], "github-source-reader");
        assert_eq!(hr_claims["sub"], "employee-002");
        assert_eq!(hr_claims["groups"], serde_json::json!(["hr"]));
        assert_eq!(cloud_claims["exp"], 400);
        assert_ne!(cloud_claims, hr_claims);
    }

    #[test]
    fn agentcore_identity_user_ids_are_namespaced_and_subject_bound() {
        assert_eq!(
            namespaced_user_id("openab-slack", "employee-sh1un").unwrap(),
            "openab-slack:employee-sh1un"
        );
        assert_ne!(
            namespaced_user_id("openab-slack", "employee-sh1un").unwrap(),
            namespaced_user_id("openab-slack", "employee-hr").unwrap()
        );
        assert!(namespaced_user_id("openab-slack", " ").is_err());
    }

    #[test]
    fn validates_agentcore_identity_configuration() {
        validate_agentcore_identity_config(
            "ap-southeast-1",
            "openab-codex",
            "openab-github",
            "https://openab.example.com/oauth/agentcore/callback",
            Some("github"),
            "openab-slack",
            &["read:user".into()],
        )
        .unwrap();
        assert!(validate_agentcore_identity_config(
            "ap-southeast-1",
            "openab-codex",
            "openab-github",
            "http://openab.example.com/callback",
            Some("github"),
            "openab-slack",
            &["read:user".into()],
        )
        .is_err());
        assert!(validate_agentcore_identity_config(
            "ap-southeast-1.example.com",
            "openab-codex",
            "openab-github",
            "https://openab.example.com/callback",
            Some("github"),
            "openab-slack",
            &["read:user".into()],
        )
        .is_err());
    }

    #[cfg(feature = "agentcore-identity")]
    #[test]
    fn maps_agentcore_identity_responses_without_exposing_session_state() {
        let token = resource_token_outcome(ResourceTokenResponse {
            access_token: Some("provider-secret".into()),
            authorization_url: None,
            session_status: None,
            session_uri: None,
        })
        .unwrap();
        assert_eq!(token, CredentialOutcome::Bearer("provider-secret".into()));

        let challenge = resource_token_outcome(ResourceTokenResponse {
            access_token: None,
            authorization_url: Some("https://signin.example/authorize".into()),
            session_status: Some("IN_PROGRESS".into()),
            session_uri: Some("urn:session:example".into()),
        })
        .unwrap();
        assert_eq!(
            challenge,
            CredentialOutcome::AuthorizationRequired {
                authorization_url: "https://signin.example/authorize".into()
            }
        );

        assert!(resource_token_outcome(ResourceTokenResponse {
            access_token: None,
            authorization_url: Some("http://signin.example/authorize".into()),
            session_status: Some("IN_PROGRESS".into()),
            session_uri: Some("urn:session:example".into()),
        })
        .is_err());
        assert!(resource_token_outcome(ResourceTokenResponse {
            access_token: None,
            authorization_url: Some("https://signin.example/authorize".into()),
            session_status: Some("FAILED".into()),
            session_uri: Some("urn:session:example".into()),
        })
        .is_err());
    }
}
