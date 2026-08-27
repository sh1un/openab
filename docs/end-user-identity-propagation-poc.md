# End-User Identity Propagation PoC

## Existing request flow

Slack Socket Mode authenticates the WebSocket with the app token. The Slack
adapter then applies channel/user trust, bot-message rules, thread routing, and
constructs `SenderContext`. `Dispatcher` groups arrivals and obtains a
`SessionPool` connection keyed by `slack:<thread_ts>`. `AcpConnection` sends
`session/prompt` over stdio. An ACP-compatible agent reaches downstream tools
through the loopback OAB MCP Facade using the broker-minted
`OPENAB_SESSION_TOKEN`.

The PoC reuses four extension points:

- authenticated Slack event fields, after existing ingress checks;
- `BufferedMessage`, which already carries per-arrival metadata;
- the per-session ACP mutex, which already serializes turns;
- the MCP Facade session-token registry, which already resolves an opaque token
  per MCP HTTP request.

No agent-specific parsing or AgentCore code is added to Slack, dispatch, ACP, or
session lifecycle modules.

## PoC configuration

Enable the Facade and configure the static resolver in `config.toml`:

```toml
[mcp]
listen = "127.0.0.1:8848"

[identity]
agent_id = "suma"

[identity.mappings.slack.U123456]
subject = "employee-001"
groups = ["cloud-engineer", "github-source-reader"]

[identity.mappings.slack.U999999]
subject = "employee-002"
groups = ["hr"]
```

Configure the AgentCore Gateway in `~/.openab/agent/mcp.json` (or the project
layer at `.openab/agent/mcp.json`):

```json
{
  "mcpServers": {
    "source-gateway": {
      "type": "http",
      "url": "https://GATEWAY_ID.gateway.bedrock-agentcore.REGION.amazonaws.com/mcp",
      "credential_provider": {
        "type": "agentcore_gateway",
        "issuer": "https://identity.example.com",
        "audience": "agentcore-source-gateway",
        "client_id": "openab",
        "private_key_env": "OPENAB_IDENTITY_SIGNING_KEY",
        "key_id": "openab-poc-1",
        "scopes": ["gateway:invoke"],
        "ttl_seconds": 300
      },
      "tool_filter": { "include": ["read_source"] }
    }
  }
}
```

Inject an RSA private key through `OPENAB_IDENTITY_SIGNING_KEY`; do not put it
in either config file. Configure the Gateway `CUSTOM_JWT` authorizer with the
matching discovery URL, audience/client, and JWKS public key. AgentCore Gateway
Policy evaluates `principal` from `sub` and may inspect the `groups` claim.

OpenAB advertises the Facade in ACP `session/new` and `session/load` through the
standard `mcpServers` field. The advertisement includes the opaque,
session-scoped credential in an `X-OpenAB-Session-Token` HTTP header. It travels
over the local ACP control channel, is redacted from ACP debug logs, and is not
written to the shared workdir or added to the model prompt.

For `codex-acp`, OpenAB also mirrors that entry into the spawned process's
in-memory `CODEX_CONFIG` using a literal `http_headers` value. This compatibility
bridge is required by Codex 0.144.x, which accepts the per-thread ACP MCP URL but
does not consistently apply its per-thread header values. Each Slack session has
its own `codex-acp` process, so the credential remains session-scoped; malformed
`CODEX_CONFIG` fails the session closed instead of starting an unauthenticated
Facade connection. Other ACP agents receive only the standard `mcpServers`
advertisement.

The generated `.openab/mcp-facade.json` remains an operator-facing compatibility
artifact for ACP agents that do not honor `mcpServers`. Static Codex wiring via
the adapter's documented `CODEX_CONFIG` environment variable is also a fallback:

```toml
[agent.env]
CODEX_CONFIG = '''{"mcp_servers":{"openab":{"url":"http://127.0.0.1:8848/mcp","bearer_token_env_var":"OPENAB_SESSION_TOKEN"}}}'''
```

Codex versions that do not forward `bearer_token_env_var` to Streamable HTTP may
use an environment-backed dedicated header when ACP injection is unavailable:

```toml
[agent.env]
CODEX_CONFIG = '''{"mcp_servers":{"openab":{"url":"http://127.0.0.1:8848/mcp","env_http_headers":{"X-OpenAB-Session-Token":"OPENAB_SESSION_TOKEN"}}}}'''
```

The value remains in the child process environment; the static configuration
contains only the environment variable name. The Facade accepts this dedicated
header as an alternative to `Authorization: Bearer` and resolves both through
the same opaque session-token registry.

OpenAB mints `OPENAB_SESSION_TOKEN` per ACP session and injects it into that
agent process. Do not put the AgentCore signing-key environment variable in
`[agent.env]` or `[agent].inherit_env`; the signing key belongs only to the
parent OpenAB process.

## Demo

1. Start OpenAB with Slack Socket Mode, `[mcp]`, and `[identity]` enabled.
2. As `U123456`, ask `@Suma` to use `read_source`. Inspect policy/audit output:
   `sub=employee-001`, `groups` contains `github-source-reader`; expect ALLOW.
3. In a separate Slack thread/session, repeat as `U999999`. Expect
   `sub=employee-002`, `groups=[hr]`; the same Gateway, agent, and tool should
   return DENY.
4. Send both requests concurrently. Their distinct Facade tokens must resolve
   to their own request IDs and subjects.

OpenAB does not decide ALLOW/DENY. It only supplies authenticated request
identity; AgentCore Gateway Policy remains the enforcement point.

## Security and isolation

- Slack `user`, `team_id`, `channel`, and `thread_ts` are captured from the
  authenticated event, never parsed from message text.
- Every human arrival receives a UUID v4 `request_id`.
- Identity is activated only after acquiring the ACP session mutex.
- Each identity-enabled arrival is a separate ACP turn, including when message
  batching is configured.
- The Facade token is opaque and session-scoped. The trusted resolved identity
  is not supplied by the MCP request body or prompt.
- Context is cleared by a drop guard. A background tool call after its ACP turn
  has ended fails closed because no human request context remains.
- Provider JWT lifetime is restricted to 1–900 seconds; 300 seconds is the
  default. Private keys and generated bearer tokens are never logged.

## Tests

The PoC adds coverage for:

- mapping authenticated Slack IDs to normalized subjects/groups;
- different humans producing different AgentCore policy claims;
- two concurrent session tokens retaining independent contexts;
- clearing session A without affecting session B;
- preventing two identity-enabled arrivals from sharing an ACP turn;
- serializing generic `RequestContext` across the ACP prompt boundary.

## Files changed and why

- `crates/openab-context/`: defines the vendor-neutral request and identity
  contracts shared across ingress, ACP, and MCP layers.
- `crates/openab-core/src/identity.rs` and configuration types: implement the
  PoC static Slack-ID resolver without coupling adapters to a policy vendor.
- Slack, dispatch, adapter, and ACP pool modules: capture authenticated event
  identity, preserve one human per turn, and bind/clear context while holding
  the session lock.
- `crates/openab-mcp/src/mcp/sources.rs` and Facade/runtime modules: associate
  opaque Facade tokens with trusted request context and create isolated
  contextual downstream connections.
- `crates/openab-mcp/src/mcp/credential.rs`: contains the generic credential
  provider seam and the isolated AgentCore Gateway JWT adapter.
- `src/facade_registrar.rs` and startup wiring: connect the core session pool
  to the Facade registry for Slack-only as well as ACP-tunnel builds.
- `docs/config-reference.md` and this ADR/demo documentation: describe the
  opt-in configuration, security boundary, limitations, and upstream path.

## Known limitations

- Static mappings are a PoC. They do not refresh from OIDC, corporate IAM, or
  an HR directory.
- The RS256 provider assumes an operator-managed issuer, discovery document,
  and JWKS. OpenAB does not host an OIDC issuer.
- The contextual downstream MCP connection is intentionally ephemeral so a
  bearer or Gateway MCP session is never reused for another human. This adds a
  handshake per discovery/execution request.
- Only Slack creates trusted human context in this PoC. The model is reusable,
  but other adapters need equivalent authenticated-field capture.
- A user missing from the mapping can still use non-contextual agent features,
  but contextual downstream servers fail closed and are unavailable.

## Upstream assessment

The generic context crate, mapping resolver seam, turn isolation, and Facade
token binding are reasonable upstream candidates: they reuse existing
architecture, preserve defaults, and contain no Hermes/AWS vocabulary. The
AgentCore provider is separable and could be accepted as an optional example or
maintained out of tree if upstream prefers a smaller vendor-neutral core. Before
production upstreaming, replace the local signing-key PoC with a pluggable
managed credential exchange and add an end-to-end test against a mock OIDC/JWKS
and MCP Gateway.
