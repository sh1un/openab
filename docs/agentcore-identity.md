# AgentCore Identity Credential Backend

OpenAB supports two coexisting ways to give a shared AI agent access to a
human's GitHub, Jira, or other OAuth account:

1. an external, self-hosted credential broker; or
2. the optional Amazon Bedrock AgentCore Identity backend.

The choice is made per downstream MCP server. Enabling the AWS backend does not
remove or alter the broker path.

## Data path

```text
Slack user
  │ authenticated Slack member ID
  ▼
OpenAB identity resolver
  │ trusted normalized subject (not prompt text)
  ▼
ACP agent / Codex chooses an MCP tool
  │ tool name + ordinary tool arguments only
  ▼
OpenAB MCP Facade
  │ resolves the server-side RequestContext
  ▼
CredentialProvider selected for this MCP server
  ├─ custom-broker path ─────────────► self-hosted broker
  └─ agentcore_identity path
       ├─ GetWorkloadAccessTokenForUserId
       ├─ GetResourceOauth2Token
       └─ inject returned bearer token into downstream HTTP request
                                          │
                                          ▼
                                  GitHub/Jira MCP server
```

Codex sees enough conversational context to decide that it should call a tool.
It does not receive the AgentCore workload token or the downstream provider
token. Credential selection and bearer injection happen after the tool call
crosses the loopback-only Facade boundary.

## Build-time opt-in

The AgentCore Identity client is excluded from default builds. Enable it
explicitly:

```bash
cargo build --release --features agentcore-identity
```

The running OpenAB service also needs AWS credentials from the normal AWS SDK
credential chain and IAM permissions for the AgentCore Identity data-plane
operations used by the backend.

## Configuration

Configure only the MCP servers that should use AgentCore Identity:

```json
{
  "mcp_servers": {
    "github-human": {
      "url": "https://your-github-mcp.example.com/mcp",
      "credential_provider": {
        "type": "agentcore_identity",
        "region": "ap-southeast-1",
        "workload_name": "openab-codex",
        "resource_credential_provider_name": "openab-github",
        "resource_oauth2_return_url": "https://openab.example.com/oauth/agentcore/callback",
        "user_id_namespace": "openab-slack",
        "scopes": ["read:user", "repo"]
      }
    },
    "jira-human": {
      "url": "https://your-jira-mcp.example.com/mcp",
      "credential_provider": {
        "type": "agentcore_identity",
        "region": "ap-southeast-1",
        "workload_name": "openab-codex",
        "resource_credential_provider_name": "openab-jira",
        "resource_oauth2_return_url": "https://openab.example.com/oauth/agentcore/callback",
        "user_id_namespace": "openab-slack",
        "scopes": ["read:jira-work", "write:jira-work", "offline_access"]
      }
    }
  }
}
```

`user_id_namespace` separates the same normalized subject across applications.
For example, subject `employee-sh1un` becomes the opaque AgentCore user ID
`openab-slack:employee-sh1un`. This ID is derived inside the Facade and cannot
be supplied by the model.

The callback URL must be registered as an allowed resource OAuth return URL on
the AgentCore workload identity. Keep scopes minimal and provider-specific.

## OAuth consent and callback binding

On the first request, AgentCore Identity may return an authorization URL instead
of an access token. Showing the URL is only the start of OAuth; it is not proof
that the person who clicked it is the Slack user who initiated the request.

A production callback must:

1. run on public HTTPS;
2. authenticate the browser user using the application's own session;
3. derive the same trusted namespaced user ID;
4. verify CSRF state and the short-lived AgentCore session URI;
5. call `CompleteResourceTokenAuth`; and
6. reveal no provider or workload token to the browser, Slack, or model.

AgentCore authorization sessions are short-lived. If callback identity binding
is not available, OpenAB must report that authorization is required and refuse
the downstream operation.

## AWS setup checklist

1. Create an AgentCore workload identity for the OpenAB deployment.
2. Register the public callback URL on that workload identity.
3. Create an AgentCore OAuth credential provider for GitHub or Atlassian.
4. Register AgentCore's provider callback URL in the provider's OAuth app.
5. Grant the OpenAB runtime IAM role only the required AgentCore Identity calls.
6. Build OpenAB with `agentcore-identity` and configure one MCP server.
7. Test two Slack identities and confirm their downstream accounts remain
   separate.
8. Confirm logs, MCP results, ACP environment, and model transcript contain no
   access or refresh token.

## Rollback

Remove the `agentcore_identity` credential provider from the affected MCP server
and point that server back to the self-hosted broker. No Slack mapping or ACP
agent change is required.

## References

- [AgentCore Identity overview](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-overview.html)
- [GetWorkloadAccessTokenForUserId](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_GetWorkloadAccessTokenForUserId.html)
- [GetResourceOauth2Token](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_GetResourceOauth2Token.html)
- [OAuth authorization URL session binding](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/oauth2-authorization-url-session-binding.html)

