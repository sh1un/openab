# ADR: Human-Delegated MCP Credentials

- **Status:** Proposed (MVP implemented for GitHub)
- **Date:** 2026-08-16
- **Related:** `end-user-identity-propagation.md`, `oab-mcp-adapter.md`

## Context

A shared OpenAB deployment serves multiple authenticated chat humans. Using one
GitHub PAT or one GitHub App installation token for every request loses the
human authorization boundary and attributes work to the automation identity.
Putting one PAT per human in the agent pod is also unsafe: the coding agent can
execute arbitrary code and must not be able to inspect durable credentials.

OpenAB already propagates a normalized Human `subject` into every authenticated
MCP facade request and can mint a short-lived downstream JWT from that context.

## Decision

Human-owned downstream credentials live behind a separate credential broker.
OpenAB sends only a signed, short-lived identity JWT. The broker validates the
JWT, resolves `sub` to the Human's provider connection, and injects that
credential into a request-scoped upstream MCP connection.

```text
Human -> OpenAB session -> signed identity JWT -> credential broker
                                              -> Human token -> provider MCP
```

The client-supplied GitHub Authorization header is never trusted or forwarded.
Discovery and execution are both authenticated. Execution must always repeat
authorization; successful discovery is not an authorization grant.

## MVP

`openab-github-mcp-broker` implements the first slice:

- RS256 issuer/audience/expiry validation for OpenAB identity JWTs;
- exact `sub` to GitHub token resolution;
- request-scoped proxying to GitHub's remote MCP server;
- no GitHub token in OpenAB's `mcp.json`, `auth.json`, agent environment, or
  agent pod when the broker is deployed as a separate service;
- fail-closed behavior for missing, invalid, expired, wrong-audience, or
  unconnected identities.

The MVP uses an operator-provided JSON connection map. It deliberately does not
yet implement GitHub App OAuth, encrypted database storage, refresh, account
linking, or revocation UI.

## Consequences

- Existing deployments are unchanged unless the broker is deployed and added
  as a contextual MCP downstream.
- The broker becomes a security boundary and must be deployed separately from
  the arbitrary-code agent workload.
- Each request currently creates a fresh upstream MCP runtime. This is slower
  but prevents cross-human connection/cache reuse. A future pool must key by
  `(provider, subject, credential_version)`.
- Production storage must replace the environment JSON map with encrypted
  GitHub App User Access Token records and serialized refresh per connection.
