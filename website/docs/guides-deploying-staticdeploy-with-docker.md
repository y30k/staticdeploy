---
id: guides-deploying-staticdeploy-with-docker
title: Deploying StaticDeploy with docker
---

This legacy guide describes the baseline service image, which this fork no
longer publishes. Build it locally from the repository root as
`staticdeploy-service:local` when characterization requires it. It is stateless,
so it can be evaluated on a container platform such as
[Kubernetes](https://kubernetes.io/) or
[Amazon ECS](https://aws.amazon.com/ecs/).

The image contains the **staticdeploy** service that hosts:

- the **Management API**, a RESTful API to manage StaticDeploy's entities like
  bundles and entrypoints. Clients of this API are the **Management Console**
  and the StaticDeploy **CLI**
- the **Management Console**, a web GUI for graphically managing StaticDeploy's
  entities
- the **Static Server**, the component responsible for serving the assets
  deployed on StaticDeploy. Clients of this server are end-users accessing the
  deployed websites

The service needs a persistence layer (storages) where it can store and read
back entities and static content. Currently it ships with two storages:

- `pg-s3-storages`: a persistence layer backed by
  [PostgreSQL](https://www.postgresql.org/) and
  [Amazon S3](https://aws.amazon.com/s3/) (or any other API-compatible service
  like [Minio](https://minio.io/))
- `memory-storages`: an in-memory "persistence" layer

For any kind of non-demo deployment you're probably going to use the
`pg-s3-storages` module, that can be enabled just by setting the appropriate
configuration options.

## Configuration

The **staticdeploy** service accepts the configuration options listed below,
passed in via environment variables.

#### General service configurations

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
- `JWT_SECRET_OR_PUBLIC_KEY`: together with `JWT_ALGORITHM`, enables the JWT
  authentication strategy (see [the guide](/docs/guides-jwt-providers)). The
  value is a base64-encoded HMAC secret, or the base64 encoding of the RSA
  public key PEM file/text
- `JWT_ALGORITHM`: required with `JWT_SECRET_OR_PUBLIC_KEY`; must be `HS256` for
  an HMAC secret or `RS256` for an RSA public key
- `OIDC_CONFIGURATION_URL`: by setting this config (and the following one) the
  OpenID Connect authentication strategy will be enabled (see
  [the guide](/docs/guides-openid-connect-providers) for details). The config is
  the configuration url of the OpenID Connect provider (e.g.
  `https://example.com/.well-known/openid-configuration`)
- `OIDC_CLIENT_ID`: the client id of the OpenID Connect application
- `OIDC_PROVIDER_NAME`: the name to show in the "Login with" interface

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

## Monitoring

You can check the health status of the **staticdeploy** service via
`GET $MANAGEMENT_HOSTNAME/api/health`: the server will return a `200` if the
service is in a healthy status, a `503` otherwise. If the request is
authenticated, the (json) body of the response contains details about the health
status
