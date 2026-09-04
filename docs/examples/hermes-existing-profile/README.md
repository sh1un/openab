# Existing Hermes Profile Example

This example demonstrates the OpenAB `[agent.profile]` adoption contract. It
contains only non-secret, reviewable profile metadata and a read-only doctor.

Suggested runtime layout:

```text
/home/team-hermes-profile/   immutable profile volume or pre_seed target
/home/agent/          mutable Hermes PVC and HOME
```

Copy the example files into the profile artifact, add your reviewed
configuration and skills, then configure OpenAB with `openab-config.toml`.
The two directories must remain separate. The example `pre_boot` installer
atomically replaces the profile-owned Hermes `config.yaml`; move any existing
credentials out of that file and inject them at runtime before adopting it.

The included doctor verifies metadata and runtime availability without reading
credentials. Extend it with organization-specific compatibility checks, but do
not print environment values or token-bearing files.
