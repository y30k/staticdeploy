---
id: guides-openid-connect-providers
title: Configuring OpenID Connect identity providers
---

StaticDeploy's v2 control plane uses server-side OpenID Connect Authorization
Code flow with S256 PKCE. The browser receives only an opaque, Secure, HttpOnly,
host-only session cookie. It does not exchange or store provider tokens.

Register exactly this HTTPS callback at the provider:

```text
https://$MANAGEMENT_HOSTNAME/api/v2/auth/callback
```

Enable Authorization Code and S256 PKCE. Disable implicit and hybrid grants. The
provider metadata must advertise `code`, `S256`, `RS256`, and the public client
token authentication method `none`. The discovery, authorization, token, and
JWKS endpoints must share the configured issuer origin.

Configure all of the following together; partial configuration fails startup:

- `ENFORCE_AUTH=true`
- `OIDC_CONFIGURATION_URL`
- `OIDC_EXPECTED_ISSUER`
- `OIDC_CLIENT_ID`
- `OIDC_REDIRECT_URI` (the exact callback above)
- `PORTAL_ORIGIN` (for example `https://staticdeploy.example.com`)
- `OIDC_SESSION_PRIMARY_KEY_ID`
- `OIDC_SESSION_ENCRYPTION_KEYS`, a JSON array of unique key IDs and canonical
  base64-encoded 32-byte AES keys; retain old decrypt keys during rotation
- `OIDC_POSTGRES_URL`, a dedicated non-owner runtime identity with no direct
  table or schema-write privileges and execute access only to the documented v2
  authentication wrappers
- `OIDC_TRUSTED_PROXY_HOPS`, set explicitly to `0` for direct client connections
  or to the exact fixed ingress hop count from 1 through 8
- optional `OIDC_PROVIDER_NAME`

Schema migration uses the separately controlled migration identity. Production
role/grant acceptance remains an operator handoff (B-PG); do not reuse the
migration owner for `OIDC_POSTGRES_URL`. At a positive trusted-proxy hop count,
StaticDeploy accepts exactly one bounded `X-Forwarded-For` chain, validates
every entry as an IP literal, and selects the configured hop from the right.
Missing, duplicate, malformed, or shorter chains fail closed. At `0`, forwarded
addresses are ignored and the direct socket peer is used. Configure the ingress
to replace rather than append untrusted client-supplied forwarding headers.
`OIDC_ALLOW_HTTP_LOOPBACK_FOR_TESTS` is accepted only with `NODE_ENV=test` and
must never be used in production.

Real issuer/client registration, provider key rotation, group identifiers, and
provider logout behavior remain subject to B-OKTA acceptance. The historical
browser implicit-flow settings are legacy-only and are not the v2 session
contract.
