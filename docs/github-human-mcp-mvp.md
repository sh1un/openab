# Human GitHub MCP MVP

This MVP proves that one shared OpenAB bot can call GitHub MCP as the Human who
sent the Slack or Discord request. GitHub credentials exist only in a separate
broker service; Codex receives only its normal `OPENAB_SESSION_TOKEN`.

## 1. Build the broker image

```bash
docker build \
  --target github-mcp-broker \
  -t ghcr.io/YOUR_ACCOUNT/openab-github-mcp-broker:mvp \
  -f Dockerfile.unified .
```

Deploy this image as a service separate from `openab-codex`.

Alternatively, run the **Build Human GitHub MCP Broker** workflow. It builds
the same target on GitHub Actions and pushes an immutable
`ghcr.io/<owner>/openab:github-mcp-broker-<sha>` image.

## 2. Configure broker environment

```text
OPENAB_GITHUB_BROKER_IDENTITY_ISSUER=https://YOUR_IDENTITY_ISSUER
OPENAB_GITHUB_BROKER_IDENTITY_AUDIENCE=openab-github-mcp-broker
OPENAB_GITHUB_BROKER_IDENTITY_PUBLIC_KEY=<RSA public PEM content>
OPENAB_GITHUB_MCP_URL=https://api.githubcopilot.com/mcp/
OPENAB_GITHUB_BROKER_CONNECTIONS_JSON={"employee-sh1un":"<SH1UN_GITHUB_TOKEN>","employee-hr":"<HR_GITHUB_TOKEN>"}
```

The broker keeps rmcp's DNS-rebinding protection enabled. It automatically
adds the platform-provided `CONTAINER_HOSTNAME` to the loopback allowlist. For
other deployment hostnames, add comma-separated hostname or `host:port`
authorities with `OPENAB_GITHUB_BROKER_ALLOWED_HOSTS`; do not include a URL
scheme or path.

The connection map is an MVP-only manual substitute for `/connect github`.
Use Human credentials with the minimum repository permissions necessary. Never
put this map on `openab-codex`; it belongs only on the broker service.

## 3. Register the broker in OpenAB's downstream `mcp.json`

```json
{
  "mcpServers": {
    "github-human": {
      "type": "http",
      "url": "https://YOUR_BROKER_SERVICE/mcp",
      "credential_provider": {
        "type": "agentcore_gateway",
        "issuer": "https://YOUR_IDENTITY_ISSUER",
        "audience": "openab-github-mcp-broker",
        "client_id": "openab-codex",
        "private_key_env": "OPENAB_IDENTITY_SIGNING_KEY",
        "key_id": "openab-poc-1",
        "scopes": ["github:mcp"],
        "ttl_seconds": 300
      },
      "tool_filter": {
        "include": ["get_me", "get_file_contents", "search_code"]
      }
    }
  }
}
```

`OPENAB_IDENTITY_SIGNING_KEY` remains on `openab-codex`; it contains the RSA
private PEM content used to sign identity JWTs. It is not a GitHub credential.

## 4. Experience the proof

Ask each Slack Human to run the same prompt:

```text
請務必使用 openab MCP：
1. search_capabilities 搜尋 get_me
2. execute_capability 呼叫找到的 GitHub get_me capability
3. 告訴我 GitHub login
```

Expected:

- `employee-sh1un` receives the GitHub account attached to that subject.
- `employee-hr` receives the HR GitHub account, not Shiun's account.
- An unmapped Human receives `GitHub account is not connected`.
- A missing, forged, expired, or wrong-audience identity JWT is rejected before
  any GitHub MCP connection is opened.

## MVP limitations

- Tokens are configured manually and are not refreshed.
- The JSON map is secret material; use the deployment platform's secret/env
  facility and deploy the broker in a different pod.
- This proves credential routing, not the final OAuth UX. The next milestone is
  GitHub App User Access Token OAuth with `/connect github`, encrypted storage,
  refresh locking, revocation, and policy/audit enrichment.
