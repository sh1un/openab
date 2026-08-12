/// Root-side adapter between the core session lifecycle and the MCP facade's
/// token registry. It is platform-neutral and available even when the custom
/// ACP gateway adapter feature is disabled (for example Slack-only builds).
pub struct FacadeRegistrar(pub openab_mcp::mcp::sources::SessionTokens);

impl openab_core::acp_mcp::SessionTokenRegistrar for FacadeRegistrar {
    fn mint(&self, channel_id: &str) -> String {
        self.0.mint(channel_id)
    }

    fn revoke(&self, token: &str) {
        self.0.revoke_token(token)
    }

    fn activate_request(&self, token: &str, context: openab_context::ResolvedRequestContext) {
        self.0.activate_request(token, context)
    }

    fn clear_request(&self, token: &str) {
        self.0.clear_request(token)
    }
}
