# ADR: Optional AgentCore Identity Credential Backend

- **Status:** Proposed
- **Date:** 2026-08-24
- **Related:** [End-User Identity Propagation](end-user-identity-propagation.md), [Agent Control Plane](agent-control-plane.md)

## Context

OpenAB can already bind a trusted end-user identity to one MCP Facade request
and mint a short-lived JWT for an AgentCore Gateway. It can also connect to an
external credential broker that owns downstream OAuth tokens. The latter keeps
provider credentials outside the agent process, but every deployment currently
has to implement token storage, OAuth refresh, user consent, and provider
integration itself.

Amazon Bedrock AgentCore Identity provides managed workload identities, OAuth
credential providers, and a token vault. It can exchange a trusted OpenAB human
identity for a user-scoped resource token without exposing the GitHub, Jira, or
other provider token to the model or ACP child process.

Adopting AgentCore Identity as the only credential path would unnecessarily tie
all OpenAB deployments to AWS. The integration must coexist with the existing
external-broker path and preserve current behavior by default.

## Decision

Add AgentCore Identity as an optional implementation of the existing
`CredentialProvider` extension point.

Selection is per downstream MCP server:

- A server with no credential provider keeps its existing authentication path.
- A server whose URL points at a custom broker continues to use that broker.
- A server configured with `credential_provider.type = "agentcore_identity"`
  obtains a user-scoped OAuth token from AgentCore Identity and injects it only
  into the trusted downstream HTTP transport.

The AWS backend requires two independent opt-ins:

1. compile OpenAB with the `agentcore-identity` Cargo feature; and
2. explicitly configure `agentcore_identity` for a downstream server.

Neither opt-in is part of the default build or default configuration.

For the first implementation, OpenAB uses the authenticated adapter mapping's
normalized `subject` as an opaque AgentCore user ID. A configured namespace is
prepended so identities from different applications cannot collide. The model,
tool arguments, prompt text, and Slack display name cannot choose this value.

The provider performs this data path:

1. `GetWorkloadAccessTokenForUserId(workloadName, userId)` using the OpenAB
   service's AWS workload credentials and SigV4.
2. `GetResourceOauth2Token` using that workload token, a configured resource
   credential provider, and an explicit OAuth scope list.
3. If an access token is returned, inject it as the downstream MCP bearer token.
4. If user consent is required, expose synthetic `connect_<name>` and
   `complete_<name>` capabilities. Never log or return the workload token or
   provider access token.

Slack has no browser session that an HTTPS callback can independently inspect.
Therefore the callback does not complete the AWS session. It marks the returned
session and displays a one-time code; the Human submits that code through the
same authenticated Slack conversation. The Facade compares the live trusted
subject with the initiating subject and only then calls
`CompleteResourceTokenAuth` with the same user ID and AgentCore session URI.
OpenAB fails closed while that binding is incomplete. The public callback is a
separate listener from the loopback-only MCP Facade.

## Security invariants

- Downstream provider tokens never enter the prompt, MCP tool arguments, tool
  results, ACP environment, or agent subprocess environment.
- Only trusted `ResolvedRequestContext.identity.subject` selects the human.
- A missing request context, failed AWS exchange, missing consent, or invalid
  response prevents the downstream MCP request.
- Workload and provider tokens are not persisted by OpenAB.
- OAuth scopes are deployment configuration, not model-controlled input.
- Authorization URLs may be shown only to the human who initiated the request;
  a forwarded URL cannot be completed by a different Slack identity.
- Confirmation codes are short-lived, single-use, scoped to one connection and
  initiating subject, and are not downstream provider credentials.
- Custom brokers remain a supported vendor-neutral alternative.

## Consequences

- Existing installations and self-hosted brokers are unchanged.
- AWS users can delegate OAuth token storage and refresh to AgentCore Identity.
- Each configured MCP server can independently choose its credential strategy.
- The AWS feature adds SigV4 and AWS configuration dependencies only to builds
  that enable it.
- Production user federation needs a public callback plus live confirmation
  from the initiating authenticated chat identity; callback arrival alone is
  not sufficient identity proof.
- Initial implementation uses the user-ID exchange because OpenAB's adapter has
  already authenticated and normalized the source identity. Deployments that
  have an enterprise IdP should later prefer the JWT exchange API so AgentCore
  can verify the end-user assertion itself.

## Alternatives considered

### Replace the custom broker with AgentCore Identity

Rejected. It creates avoidable AWS lock-in and removes a valid self-hosted trust
boundary.

### Pass GitHub or Jira OAuth tokens into the agent process

Rejected. Arbitrary tool and shell execution would make credential exfiltration
part of the agent's blast radius.

### Let the model provide `userId`, scopes, or credential-provider name

Rejected. Prompt injection could then select another user or broaden access.
Those values come only from trusted request context and administrator config.
