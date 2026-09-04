# ADR: Existing Hermes Profile Adoption

- **Status:** Accepted
- **Date:** 2026-09-04
- **Related:** [Lifecycle Hooks](./hooks.md), [Hermes Agent](../hermes.md)

## Context

OpenAB can start `hermes-acp`, but an existing Hermes deployment may also own
personality, instructions, skills, scripts, cron definitions, and integration
configuration. Copying its complete writable home into an image or sharing that
home with both `hermes gateway run` and OpenAB mixes immutable configuration
with credentials, sessions, memory, and databases.

OpenAB also starts one ACP subprocess per active session. It cannot assume that
every Hermes state backend supports concurrent processes.

## Decision

Add an optional `[agent.profile]` startup contract with these properties:

1. Lifecycle hooks or deployment volumes prepare an immutable, non-secret profile.
2. The profile root and mutable state directory must be separate, non-overlapping paths.
3. A strict TOML manifest identifies schema, profile version, runtime version, required paths, and managed paths.
4. OpenAB scans the profile tree for common credential material by default.
5. An optional reviewed doctor runs after `pre_seed` and `pre_boot`, but before secret resolution and agent pool creation.
6. Profile or doctor failures abort startup.
7. OpenAB logs the profile identity, expected runtime version, paths, and the `per-session-stdio-acp` process model.
8. More than one configured session produces an explicit mutable-state concurrency warning.

The contract initially supports only Hermes. It is absent by default, preserving
all existing deployments.

## Consequences

- Existing Hermes behavior becomes a versioned artifact that can be reviewed and rolled back independently of the runtime image.
- Credentials and mutable databases are not valid profile contents.
- Operators must still define how profile-owned files are installed into the Hermes home, normally through an idempotent `pre_boot` script.
- Credential scanning is defense in depth, not proof that an arbitrary profile or doctor is safe.
- The doctor receives a scrubbed environment but is not filesystem-sandboxed, so it must be trusted code.
- This decision does not make Hermes state multi-process safe and does not change OpenAB's ACP pool architecture.

## Alternatives Considered

### Bake the existing Hermes home into the image

Rejected because it couples behavior updates to image builds and can persist
credentials or mutable state in image layers.

### Mount the live existing Hermes home into OpenAB

Rejected because `hermes gateway run` and multiple `hermes-acp` processes may
write the same state without a verified concurrency contract.

### Implement a shared or remote Hermes runtime immediately

Deferred until compatibility tests show that isolated `hermes-acp` processes
cannot meet the required behavior. That larger change would affect session
ownership, reconnect, cancellation, health, and backpressure.
