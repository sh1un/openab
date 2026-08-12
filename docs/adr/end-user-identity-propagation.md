# ADR: End-User Identity Propagation

- **Status:** Proposed (PoC)
- **Date:** 2026-08-13
- **Related:** [OAB MCP Adapter](oab-mcp-adapter.md), [Identity Trust-None](identity-trust-none.md)

## Context

OpenAB authenticates a Slack Socket Mode connection and filters its events, but
downstream MCP calls historically carry only the agent process identity. A
governance gateway therefore cannot distinguish two humans using the same agent.

The initiating identity cannot safely be reconstructed from prompt text. It must
come from authenticated adapter fields, remain scoped to one turn, and be
unmodifiable by the LLM.

## Decision

Add a small vendor-neutral `openab-context` crate containing `RequestContext`,
`NormalizedIdentity`, `IdentityResolver`, and related value types. The Slack
adapter constructs source identity only after its existing authentication and
trust gates. A configurable mapping resolver is the PoC implementation.

Reuse the existing MCP Facade session credential rather than adding identity to
ACP protocol-specific fields:

1. The broker mints one opaque Facade token per ACP session.
2. The dispatcher serializes each identity-enabled arrival as its own ACP turn.
3. After acquiring the session mutex, the broker temporarily binds that turn's
   trusted resolved context to the opaque token.
4. The Facade resolves the token on every MCP HTTP request.
5. An RAII guard clears the context at turn completion, error, cancellation, or
   task abort.

The prompt receives the generic `RequestContext` for agent interoperability, but
the Facade never trusts that prompt copy. Its authorization input is the
broker-side context bound to the opaque token.

Downstream credentials use a generic `CredentialProvider` extension point. The
first provider is isolated in `mcp::credential` and issues a short-lived RS256
JWT for an AgentCore Gateway `CUSTOM_JWT` authorizer. `sub` is the normalized
human subject and `groups` is a custom claim for policy evaluation.

## Consequences

- Existing deployments are unchanged unless `[identity]` and a downstream
  `credential_provider` are configured.
- Hermes, Claude Code, Codex, and other ACP agents need no identity-specific
  implementation.
- Human identity cannot be selected from message content or rewritten by the
  agent for authorization.
- Identity-enabled arrivals cannot share a batched ACP turn. This trades some
  batching efficiency for an unambiguous authorization principal.
- The PoC resolver is static config, not a production IdP integration.
- The PoC JWT signer expects an external OIDC issuer/JWKS configuration and a
  private key injected through an OpenAB environment variable. Production use
  should replace it with a managed token exchange or workload identity service.
