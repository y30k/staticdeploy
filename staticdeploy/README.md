# @staticdeploy/staticdeploy

Main service of the StaticDeploy platform.

## Run

This fork does not publish a legacy service image. Build the current baseline
locally from the repository root when characterization requires it:

```sh
docker build -f staticdeploy/Dockerfile -t staticdeploy-service:local .
```

You can check the health status of the service via
`GET $MANAGEMENT_HOSTNAME/api/health`: the server will return a `200` if the
service is in a healthy status, a `503` otherwise. If the request is
authenticated, the (json) body of the response contains details about the health
status.

## Configure

The following environment variables can be used to configure the server:

#### General service configurations

- `LOG_LEVEL`: validated minimum local structured-log level (`trace`, `debug`,
  `info`, `warn`, `error`, or `fatal`; defaults to `info`). Any other value
  stops startup with a structured error. In non-test environments the service
  writes newline-delimited JSON to standard output with its application name and
  version. Test runs are silent. Each request receives a server-generated UUID;
  caller `X-Request-Id` values are ignored. Terminal request records use `info`
  for completed responses (including 4xx), `warn` for aborted requests, and
  `error` for errors or 5xx responses. Query strings, fragments, and sensitive
  values are removed before output. `SIGINT`/`SIGTERM` close the HTTP server and
  drain logs within bounded shutdown waits. Logging has no transport, remote
  export, Eyes endpoint, or Eyes enablement; product ingestion remains gated.
- `MANAGEMENT_HOSTNAME` _(required)_: the hostname at which the Management
  Console and API will be served
- `ENABLE_MANAGEMENT_ENDPOINTS`: whether to enable or not the Management Console
  and API. Defaults to `true`
- `MAX_REQUEST_BODY_SIZE`: the max size of accepted request bodies, which mainly
  limits the size of (base64-encoded) bundles that can be uploaded. Defaults to
  `100mb`

#### Routing configurations

- `HOSTNAME_HEADER`: the header from which to retrieve the hostname of requests
  for static assets. By default `Host` - or `X-Forwarded-Host` if present - are
  used. Some proxies however use other headers to pass the information upstream
  (example: Azure's Verizon CDN uses `X-Host`), so you can use this option to
  make StaticDeploy work behind such proxies

#### Auth configurations

- `ENFORCE_AUTH`: `true` or `false`, determines whether authentication and
  authorization are enforced (i.e. requests must be authenticated, and the user
  performing the request must have the appropriate roles). Defaults to `true`
- `CREATE_ROOT_USER`: on startup, create (if they don't already exist) a `root`
  user and group with the `root` role. Defaults to `true`
- `JWT_SECRET_OR_PUBLIC_KEY`: the secret or public key (base64 encoded) used to
  validate authorization JWTs. JWT authentication is enabled only when this and
  `JWT_ALGORITHM` are both set
- `JWT_ALGORITHM`: required with `JWT_SECRET_OR_PUBLIC_KEY`; must be exactly
  `HS256` for a shared secret or `RS256` for an RSA public key. Startup fails
  closed when a key is configured without an explicit algorithm. When server
  sessions are also enabled, machine/CI requests with exactly one Authorization
  header continue through JWT validation; duplicate headers fail closed. The
  portal receives no bearer configuration and remains cookie/CSRF-only.
- Server-side OIDC sessions require `ENFORCE_AUTH=true` and the complete set
  `OIDC_CONFIGURATION_URL`, `OIDC_EXPECTED_ISSUER`, `OIDC_CLIENT_ID`,
  `OIDC_REDIRECT_URI`, `PORTAL_ORIGIN`, `OIDC_SESSION_PRIMARY_KEY_ID`,
  `OIDC_SESSION_ENCRYPTION_KEYS`, `OIDC_POSTGRES_URL`, and
  `OIDC_TRUSTED_PROXY_HOPS`. Partial settings fail startup. The registered
  callback is `https://$MANAGEMENT_HOSTNAME/api/v2/auth/callback`; enable
  Authorization Code with S256 PKCE and disable implicit/hybrid grants.
- `OIDC_SESSION_ENCRYPTION_KEYS`: JSON array of unique IDs and canonical base64
  32-byte AES keys. Keep overlap decrypt keys during rotation.
- `OIDC_POSTGRES_URL`: dedicated least-privilege runtime identity, separate from
  `POSTGRES_URL` and the migration owner. Production grants remain B-PG.
- `OIDC_TRUSTED_PROXY_HOPS`: explicit ingress trust boundary. Use `0` only when
  clients connect directly. For a fixed proxy chain, use the exact hop count
  (1–8); login admission then uses that hop from one validated `X-Forwarded-For`
  chain. Missing, duplicate, malformed, or shorter chains fail closed, and
  forwarded headers are ignored at `0`.
- `OIDC_ALLOW_HTTP_LOOPBACK_FOR_TESTS`: loopback HTTP escape accepted only with
  `NODE_ENV=test`; never enable it in production.
- `OIDC_PROVIDER_NAME`: the name to show in the "Login with" interface. Real
  provider registration and key/logout acceptance remain B-OKTA.

#### pg-s3 storages configurations

The pg-s3 storages module is enabled when `POSTGRES_URL`, `S3_BUCKET`, and
`S3_ENDPOINT` are set (the memory one is used otherwise):

- `POSTGRES_URL`: connection string for the
  [PostgreSQL](https://www.postgresql.org/) database
- `S3_BUCKET`: name of the S3 bucket to use for storing static content
- `S3_ENDPOINT`: endpoint of the S3 server
- `S3_REGION`: S3 signing region. Defaults to `us-east-1`
- `S3_FORCE_PATH_STYLE`: `true` or `false`. Defaults to `true` to preserve the
  existing MinIO-compatible addressing behavior
- `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY`: optional explicit credentials.
  Set both or neither. When both are omitted, the supported AWS SDK default Node
  credential provider chain is used (for example environment, shared config, or
  workload identity credentials)
- `S3_ENABLE_GCS_COMPATIBILITY`: `true` or `false`, enables compatibility with
  Google Cloud Storage, which doesn't support some S3 APIs. Defaults to `false`
