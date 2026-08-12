//! Downstream credential extension point. Vendor-specific claim translation
//! lives here, outside Slack, ACP, sessions, and identity resolution.

use anyhow::{Context, Result};
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
}

fn default_credential_ttl_seconds() -> u64 {
    300
}

pub trait CredentialProvider: Send + Sync {
    fn credential(&self, context: &openab_context::ResolvedRequestContext) -> Result<String>;
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
    }
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

impl CredentialProvider for AgentCoreGatewayCredentialProvider {
    fn credential(&self, context: &openab_context::ResolvedRequestContext) -> Result<String> {
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
        jsonwebtoken::encode(&header, &claims, &key).context("sign AgentCore request JWT")
    }
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
}
