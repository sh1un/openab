//! Framework-neutral, vendor-neutral identity carried through an OpenAB turn.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceContext {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub channel_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanIdentity {
    pub external_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub source: SourceContext,
    pub human_identity: HumanIdentity,
    pub agent_identity: AgentIdentity,
    pub session_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedIdentity {
    pub subject: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedRequestContext {
    pub request: RequestContext,
    pub identity: NormalizedIdentity,
}

pub trait IdentityResolver: Send + Sync {
    fn resolve(&self, source: &SourceContext, human: &HumanIdentity) -> Option<NormalizedIdentity>;
}
