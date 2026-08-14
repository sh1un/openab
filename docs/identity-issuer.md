# OpenAB identity issuer companion

`openab-identity-issuer` is a verification-only companion for the end-user
identity propagation PoC. It publishes the public metadata that an AgentCore
Gateway `CUSTOM_JWT` authorizer needs to verify JWTs signed by OpenAB:

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /healthz`

It does not implement login, authorization, or token issuance. Most
importantly, it must never receive the RSA private key. The private key remains
in the parent OpenAB service as `OPENAB_IDENTITY_SIGNING_KEY`.

The discovery document advertises conventional authorization and token URLs so
OIDC metadata parsers can validate it, but this verification-only companion
does not serve those endpoints. OpenAB signs the short-lived tokens directly.

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `OPENAB_IDENTITY_ISSUER` | yes | Public HTTPS origin, with no path or trailing slash, for example `https://openab-identity.example.com` |
| `OPENAB_IDENTITY_JWKS` | one of | Inline public JWKS JSON |
| `OPENAB_IDENTITY_JWKS_FILE` | one of | Path to a public JWKS JSON file |
| `OPENAB_IDENTITY_ISSUER_LISTEN` | no | Socket address; overrides `PORT` |
| `PORT` | no | Port on `0.0.0.0`; defaults to `8080` |

The process refuses to start when a JWK contains private RSA parameters such
as `d`, `p`, or `q`. Every key must be RSA, have a unique `kid`, and use RS256
when `alg` is present.

Example public JWKS shape:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "openab-poc-1",
      "n": "BASE64URL_MODULUS",
      "e": "AQAB"
    }
  ]
}
```

Generate a 3072-bit key pair and matching public JWKS without printing the
private key to the terminal:

```bash
node scripts/generate-identity-issuer-key.mjs /tmp/openab-identity-key
```

The command creates owner-only `private.pem` and public `jwks.json`. Move the
private PEM directly into the OpenAB secret environment and do not commit it.

## Build and run

For a deployable `linux/amd64` image, prefer the dedicated GitHub Actions
workflow. Push a tag matching `identity-issuer-*`, or run **Build Identity
Issuer** manually. It publishes an immutable image to the repository owner's
existing `openab` GHCR package:

```text
ghcr.io/OWNER/openab:identity-issuer-<12-char-commit-sha>
```

Using the existing package avoids accidentally creating a private companion
package when the `openab` package is already public.

For local development, build the dedicated target from the primary
multi-target Dockerfile:

```bash
docker build \
  --target identity-issuer \
  -t openab-identity-issuer:local \
  -f Dockerfile.unified .
```

Run it with public JWKS only:

```bash
docker run --rm -p 8080:8080 \
  -e OPENAB_IDENTITY_ISSUER=https://openab-identity.example.com \
  -e 'OPENAB_IDENTITY_JWKS={"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"openab-poc-1","n":"BASE64URL_MODULUS","e":"AQAB"}]}' \
  openab-identity-issuer:local
```

Verify all three endpoints before creating the AgentCore Gateway:

```bash
curl -fsS https://openab-identity.example.com/healthz
curl -fsS https://openab-identity.example.com/.well-known/openid-configuration
curl -fsS https://openab-identity.example.com/.well-known/jwks.json
```

The discovery response's `issuer` must exactly match the `iss` configured in
OpenAB, and its `jwks_uri` must be reachable by AgentCore over public HTTPS.

## Zeabur deployment

Deploy the `identity-issuer` image as a separate Zeabur service with a public
domain and set only:

```text
OPENAB_IDENTITY_ISSUER=https://the-public-issuer-domain
OPENAB_IDENTITY_JWKS={public JWKS JSON}
```

Set the matching private PEM only on the existing OpenAB service:

```text
OPENAB_IDENTITY_SIGNING_KEY={private PEM}
```

Do not copy `OPENAB_IDENTITY_SIGNING_KEY` to the issuer service or to
`[agent.env]`.

## AgentCore and OpenAB alignment

These values must agree across all components:

| Value | Issuer companion | OpenAB credential provider | AgentCore Gateway |
| --- | --- | --- | --- |
| issuer | discovery `issuer` | `issuer` | discovery URL resolves to it |
| key ID | JWKS `kid` | `key_id` | resolved from JWKS |
| audience | not applicable | `audience` | allowed audience |
| algorithm | JWKS `alg=RS256` | RS256 signer | JWT validation |

For a target named `SourceTarget` with a schema tool named `read_source`, the
Gateway-visible MCP tool is `SourceTarget___read_source`. Use that full name in
OpenAB's static `tool_filter`.
