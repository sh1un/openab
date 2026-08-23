# GitHub App User OAuth for the Human MCP Broker

This document describes the first OAuth milestone for a shared OpenAB agent.
Every Slack Human uses the same agent and MCP facade, but GitHub API calls use
that Human's GitHub App user access token. The agent never receives a GitHub
access token, refresh token, or GitHub App client secret.

## Scope

This milestone adds:

- a local `connect_github` capability that is visible before GitHub is
  connected;
- GitHub App web authorization with one-time `state` and PKCE (`S256`);
- callback code exchange and durable GitHub user ID/login binding;
- AES-256-GCM encrypted connection storage on a persistent volume;
- automatic rotating refresh-token exchange before an access token expires;
- the existing subject-to-PAT map as a backward-compatible fallback.

This milestone does not add a native Slack slash command. A Human asks the
agent to connect GitHub; the agent discovers and calls `connect_github`, then
returns its authorization URL. A later UI can map `/connect github` directly to
the same capability without changing the broker protocol.

## Data path

```mermaid
sequenceDiagram
    actor H as Slack Human
    participant A as OpenAB / Codex
    participant F as OpenAB MCP Facade
    participant B as GitHub Credential Broker
    participant G as GitHub App OAuth
    participant V as Encrypted Connection Store
    participant M as GitHub MCP

    H->>A: Connect my GitHub account
    A->>F: search_capabilities(connect_github)
    F->>B: tools/list + short-lived Human identity JWT
    B-->>F: connect_github
    A->>F: execute_capability(connect_github)
    F->>B: tools/call + short-lived Human identity JWT
    B-->>H: one-time GitHub authorization URL
    H->>G: Authorize GitHub App
    G->>B: callback(code, state)
    B->>G: exchange code + PKCE verifier
    B->>G: GET /user
    B->>V: encrypt token record keyed by OpenAB subject
    B-->>H: Connected; return to Slack

    H->>A: Read GitHub data
    A->>F: execute GitHub capability
    F->>B: tool call + short-lived Human identity JWT
    B->>V: resolve subject; refresh if needed
    B->>M: request-scoped bearer injection
    M-->>B: result
    B-->>A: result only (no credential)
```

The OAuth `state` is random and exists only in broker memory for ten minutes.
It binds the callback to the OpenAB subject that requested the connection. It
is single-use. Restarting the broker invalidates outstanding authorization
links but does not remove completed connections.

## Register the GitHub App

Create a GitHub App owned by the organization that contains the repositories.
Configure:

1. **Callback URL**:
   `https://YOUR_BROKER_HOST/oauth/github/callback`
2. **Expire user authorization tokens**: enabled.
3. **Repository permissions**: only the permissions required by the exposed
   MCP tool allowlist. Start read-only for the first validation.
4. Install the App only on the repositories OpenAB is allowed to access.

The callback URL used by the broker must exactly match one of the GitHub App's
registered callback URLs. A GitHub App user access token is constrained by
both the App installation and the Human's own access.

## Broker configuration

Keep the existing identity-verification variables and add:

```text
OPENAB_GITHUB_APP_CLIENT_ID=<GitHub App client ID>
OPENAB_GITHUB_APP_CLIENT_SECRET=<GitHub App client secret>
OPENAB_GITHUB_APP_REDIRECT_URI=https://YOUR_BROKER_HOST/oauth/github/callback

OPENAB_GITHUB_BROKER_STORE_PATH=/data/github-connections.enc.json
OPENAB_GITHUB_BROKER_STORE_KEY=<base64 of exactly 32 random bytes>
```

Generate the store key once:

```bash
openssl rand -base64 32
```

Store the key and GitHub App client secret in Zeabur Secrets. Mount a persistent
volume at `/data`. Losing the volume requires users to reconnect. Losing the
encryption key makes the stored connections intentionally unreadable; changing
the key without migration prevents broker startup.

The old `OPENAB_GITHUB_BROKER_CONNECTIONS_JSON` becomes optional. During
migration, OAuth records take precedence and the static map remains a fallback.
Remove the static map after all pilot users have connected.

Add `connect_github` to the downstream server's facade allowlist. For example:

```json
"tool_filter": {
  "include": ["connect_github", "get_me", "get_file_contents", "search_code"]
}
```

If it is omitted, OpenAB correctly filters the connection capability out along
with every other non-allowlisted tool.

Provider endpoint overrides exist only for development and integration tests:

```text
OPENAB_GITHUB_AUTHORIZE_URL
OPENAB_GITHUB_TOKEN_URL
OPENAB_GITHUB_API_URL
```

They must use HTTPS.

## User experience

First ask the shared Slack agent:

```text
請使用 openab MCP 搜尋並執行 connect_github，把授權網址給我。
```

Open the URL, authorize the GitHub App, and close the success page. Then test:

```text
請使用 openab MCP 搜尋 get_me，執行後告訴我 GitHub login。
```

Expected behavior:

- an unconnected Human sees `connect_github`, not upstream GitHub tools;
- after callback, the same Human sees the permitted upstream tools;
- another Human remains unconnected and cannot reuse the first Human's token;
- an expired access token is refreshed inside the broker;
- a forged, expired, or wrong-audience OpenAB JWT is rejected before lookup;
- callback responses and logs never contain access or refresh tokens.

## Storage and concurrency

The encrypted file contains a map keyed by the immutable OpenAB Human subject.
Each record contains the durable GitHub numeric user ID, display login, access
token, refresh token, expiry timestamps, and a credential version. The complete
payload is authenticated and encrypted with AES-256-GCM; the JSON envelope
contains only a version, nonce, and ciphertext.

Token lookup and refresh are serialized by the broker. This is conservative
but prevents two concurrent requests from reusing a rotating refresh token.
For a larger deployment, replace the file with a transactional secret store and
use a per-connection lock keyed by `(tenant, provider, subject)`.

## Security boundaries and remaining work

- The broker must run in a different pod from the arbitrary-code agent.
- Only the broker receives the GitHub App client secret and connection-store
  key. Neither belongs in `openab-codex`.
- The MCP request still requires the audience-scoped OpenAB Human identity JWT.
- `connect_github` does not accept a subject argument; the subject comes only
  from the verified JWT.
- GitHub account linking currently accepts any GitHub account the Human chooses.
  Production onboarding should additionally enforce the expected GitHub
  organization/enterprise and record the approved organization IDs.
- Revocation webhooks, disconnect UI, SCIM offboarding, database/KMS storage,
  and append-only audit persistence remain follow-up work.
- Tool discovery is not authorization. The facade and broker still validate
  identity again on every execution.
