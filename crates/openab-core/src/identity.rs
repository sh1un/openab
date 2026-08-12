use std::collections::HashMap;

use openab_context::{HumanIdentity, IdentityResolver, NormalizedIdentity, SourceContext};

use crate::config::{IdentityMapping, IdentityPropagationConfig};

/// PoC resolver backed by config. The key is `(source.type, external_id)`;
/// message text and display names are deliberately never inputs.
pub struct MappingIdentityResolver {
    mappings: HashMap<String, HashMap<String, IdentityMapping>>,
}

impl MappingIdentityResolver {
    pub fn new(config: &IdentityPropagationConfig) -> Self {
        Self {
            mappings: config.mappings.clone(),
        }
    }
}

impl IdentityResolver for MappingIdentityResolver {
    fn resolve(&self, source: &SourceContext, human: &HumanIdentity) -> Option<NormalizedIdentity> {
        let mapped = self.mappings.get(&source.kind)?.get(&human.external_id)?;
        if mapped.subject.trim().is_empty() {
            return None;
        }
        Some(NormalizedIdentity {
            subject: mapped.subject.clone(),
            groups: mapped.groups.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_only_authenticated_source_id() {
        let config: IdentityPropagationConfig = toml::from_str(
            r#"
agent_id = "suma"
[mappings.slack.U123456]
subject = "employee-001"
groups = ["cloud-engineer", "github-source-reader"]
"#,
        )
        .unwrap();
        let resolver = MappingIdentityResolver::new(&config);
        let source = SourceContext {
            kind: "slack".into(),
            workspace_id: Some("T123".into()),
            channel_id: "C123".into(),
        };
        let got = resolver
            .resolve(
                &source,
                &HumanIdentity {
                    external_id: "U123456".into(),
                },
            )
            .unwrap();
        assert_eq!(got.subject, "employee-001");
        assert_eq!(got.groups, ["cloud-engineer", "github-source-reader"]);
        assert!(resolver
            .resolve(
                &source,
                &HumanIdentity {
                    external_id: "U999999".into(),
                },
            )
            .is_none());
    }
}
