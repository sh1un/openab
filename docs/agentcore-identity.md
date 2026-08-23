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
       ├─ first use: connect_* → browser callback → complete_*
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

Configure only the MCP servers that should use AgentCore Identity in
`~/.openab/agent/mcp.json` (or the project-local
`.openab/agent/mcp.json` layer):

```json
{
  "mcpServers": {
    "github-human": {
      "type": "http",
      "url": "https://your-github-mcp.example.com/mcp",
      "credential_provider": {
        "type": "agentcore_identity",
        "region": "ap-southeast-1",
        "workload_name": "openab-codex",
        "resource_credential_provider_name": "openab-github",
        "resource_oauth2_return_url": "https://openab.example.com/oauth/agentcore/callback",
        "connection_name": "github",
        "user_id_namespace": "openab-slack",
        "scopes": ["read:user", "repo"]
      }
    },
    "jira-human": {
      "type": "http",
      "url": "https://your-jira-mcp.example.com/mcp",
      "credential_provider": {
        "type": "agentcore_identity",
        "region": "ap-southeast-1",
        "workload_name": "openab-codex",
        "resource_credential_provider_name": "openab-jira",
        "resource_oauth2_return_url": "https://openab.example.com/oauth/agentcore/callback",
        "connection_name": "jira",
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

Enable the public callback listener in `config.toml`. Zeabur terminates TLS and
forwards the public HTTPS route to this container port:

```toml
[agentcore_identity_callback]
listen = "0.0.0.0:8080"
```

## OAuth consent and callback binding

On first use, discovery exposes `connect_github` and `complete_github` (or the
names selected by `connection_name`). The chat-native flow is:

1. The same Slack Human executes `connect_github`.
2. OpenAB calls `GetResourceOauth2Token` with a random `customState` and stores
   the returned short-lived session URI in memory.
3. The Human opens `authorization_url` and authorizes GitHub.
4. AgentCore redirects the browser to the public callback. The callback checks
   the session and displays a one-time confirmation code; it does **not** bind
   identity yet.
5. The Human returns to the same Slack conversation and executes
   `complete_github` with `confirmation_code`.
6. The Facade obtains the live trusted Slack identity, verifies it matches the
   initiating subject, and calls `CompleteResourceTokenAuth`.
7. The original GitHub capability is retried; AgentCore now returns the
   user-scoped token from its vault.

This extra Slack confirmation is deliberate. A browser callback has no Slack
login cookie, so callback arrival alone cannot prove who clicked a forwarded
authorization link. The one-time code is not a GitHub or AWS credential, is
valid for ten minutes, is scoped to one subject and connection, and is removed
after successful completion.

Pending sessions are memory-only. Restarting OpenAB invalidates outstanding
links but does not remove completed credentials from AgentCore's token vault.

Suggested Slack prompts:

```text
請務必使用 openab MCP：搜尋 connect_github，執行後把 authorization_url 給我。
```

After the browser callback displays the code:

```text
請務必使用 openab MCP：搜尋 complete_github，使用 confirmation_code「貼上畫面中的代碼」完成授權。
```

Then retry `get_me` or the original GitHub operation.

## AWS setup checklist

1. Create an AgentCore workload identity for the OpenAB deployment.
2. Register the public callback URL on that workload identity.
3. Create an AgentCore OAuth credential provider for GitHub or Atlassian.
4. Register AgentCore's provider callback URL in the provider's OAuth app.
5. Grant the OpenAB runtime IAM role only the required AgentCore Identity calls.
6. Build OpenAB with `agentcore-identity` and configure one MCP server.
7. Expose container port `8080` (or the configured port) through Zeabur HTTPS.
8. Test two Slack identities and confirm their downstream accounts remain
   separate.
9. Confirm logs, MCP results, ACP environment, and model transcript contain no
   access or refresh token.

The runtime data-plane policy needs these actions, scoped to the workload
identity, credential provider, token vault, and identity directory resources
used by this deployment:

```json
{
  "Effect": "Allow",
  "Action": [
    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
    "bedrock-agentcore:GetResourceOauth2Token",
    "bedrock-agentcore:CompleteResourceTokenAuth"
  ],
  "Resource": [
    "<workload identity ARN>",
    "<workload identity directory ARN>",
    "<OAuth2 credential provider ARN>",
    "<token vault ARN>"
  ]
}
```

Use the concrete ARNs produced in your account instead of granting
`Resource: "*"`. Creating or updating the workload identity and OAuth provider
is a control-plane setup task and should use a separate operator role.

## Rollback

Remove the `agentcore_identity` credential provider from the affected MCP server
and point that server back to the self-hosted broker. No Slack mapping or ACP
agent change is required.

## References

- [AgentCore Identity overview](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity-overview.html)
- [GetWorkloadAccessTokenForUserId](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_GetWorkloadAccessTokenForUserId.html)
- [GetResourceOauth2Token](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_GetResourceOauth2Token.html)
- [CompleteResourceTokenAuth](https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_CompleteResourceTokenAuth.html)
- [OAuth authorization URL session binding](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/oauth2-authorization-url-session-binding.html)
- [OAuth authorization URL session binding](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/oauth2-authorization-url-session-binding.html)
