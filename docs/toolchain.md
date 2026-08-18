# Supported toolchain

StaticDeploy development, required pull-request checks, and the service image
builder use these exact versions:

- Node.js `24.19.0`;
- Yarn `4.18.0`; and
- Lerna `10.0.0`.

Node is pinned in `.nvmrc`, `.node-version`, the root manifest, Actions, and the
service Dockerfile. Yarn is selected by the root `packageManager` field and uses
the `node-modules` linker from `.yarnrc.yml`. Use Corepack rather than a global
Yarn installation:

```sh
corepack enable
node scripts/check-install-policy.mjs
node scripts/test-install-policy.mjs
yarn install --immutable
yarn check:install-scripts
```

Immutable installs must not change `yarn.lock`. TypeScript `5.9.3` is
centralized at the root so every retained TypeScript project uses the same
version supported by `typescript-eslint`. The exact `minipass@3.1.6` pin and
`skipLibCheck` remain narrow compatibility requirements for the legacy
`@types/tar`/Minipass declarations: application source is still checked
strictly, while incompatible third-party declaration internals are deferred to
the tar dependency slice. A toolchain pin change requires updating every pin
together and rerunning the complete M2 checks.

## Dependency install scripts

Third-party dependency lifecycle scripts are globally disabled with Yarn's
supported `enableScripts: false` setting. The exact currently resolved
package/version/script inventory is in `config/install-scripts.json`. Root
`dependenciesMeta` denies every reviewed entry; no third-party lifecycle script
is allowed. The pre-install policy gate also rejects Git dependencies, Git
repository approvals, non-immutable configuration, global script enablement, and
any metadata decision not represented exactly in the inventory. Its committed
negative tests prove those cases fail before installation.

The post-install inventory check records scripts materialized on the supported
Linux CI platform and fails when a reviewed script disappears or a new one is
present. Platform-conditional scripts not materialized on Linux remain blocked
by Yarn's global setting and cannot execute because the pre-install gate permits
no unreviewed `dependenciesMeta` approval. A dependency update that changes the
inventory requires explicit review of the exact package version and command.

Lerna's Nx-backed runner is disabled because its postinstall is blocked; Lerna
10 uses its supported legacy task runner instead. Do not enable scripts
globally.

## Retired website source

The Docusaurus 1 website is no longer an installable Yarn workspace and its
publication path remains retired. Historical website source and documentation
stay in the repository for reference and remain covered by centralized format
and lint checks, but modern install, compile, test, image, and audit graphs do
not resolve Docusaurus or its mutable image-optimization binaries.

## Central quality checks

The root owns the supported ESLint flat config, Prettier config, TypeScript
version, and CI entry points. `yarn format:check`, `yarn lint`,
`yarn typecheck`, `yarn compile`, and `yarn unit` are intentionally separate:
standalone typechecking enforces 28 source/test projects across all 13
TypeScript workspaces and always passes `--noEmit`, while compile remains the
only quality phase that emits workspace builds. Tests remain a separate phase
and do not emit, but retained workspace package entrypoints resolve through
compiled `lib/` artifacts; the supported execution order is therefore
`yarn compile` followed by `yarn unit` or `yarn coverage`, as encoded in CI.
`tsconfig.test.json` supplies the shared no-emit test-project contract. Root
tooling scripts, the CLI executable, and all owned website JavaScript are
included in the centralized lint/format paths.

ESLint covers retained TypeScript/TSX and the historical website's
JavaScript/React. Narrow exceptions are documented beside their rules in
`eslint.config.mjs`: only the exact inventoried v1 serialization, adapter, form,
callback, test, and typing boundary files may retain explicit `any` until
M2-04/M4 replaces those contracts; new files remain prohibited. TypeScript owns
unused-symbol correctness and typed console props do not duplicate runtime
PropTypes. The configuration still applies ESLint, typescript-eslint, and React
recommended correctness rules and rejects unused disable comments. Add
exceptions only for an exact rule and file scope with a rationale; do not add
blanket file or project disables.

Prettier `3.6.2` centralizes the supported formatting contract. Its one-time,
mechanical output update is included with this migration and does not alter
application behavior. Formatting paths are centralized in the root commands;
forwarding workspace configs and copies of formatter dependencies are forbidden
by the workspace-contract test. Dependency-managed Git hooks were removed
because GitHub Actions required checks are authoritative.

## Management console build and test foundation

`@staticdeploy/management-console` builds with exact Vite `8.2.1` and the React
plugin `6.0.5`; CRA, Webpack 4, the OpenSSL legacy provider, preflight bypass,
and embedded-lint bypass are removed. React `18.3.1` and Ant Design `5.29.3` are
the supported compatibility line while M4-11 still owns routing and form
replacement. The console's Vitest `4.1.10` suite uses Testing Library rather
than Enzyme and tests rendered behavior in JSDOM.

The dynamic `script#app-config` marker remains in `index.html` so the existing
server embedding path can inject trusted runtime configuration before the Vite
module entry executes. Vite uses root-relative assets so deep-route HTML
fallback cannot resolve JavaScript beneath the route path. Its build check
rejects `unsafe-eval`-style code construction. Vite uses a narrow
`@staticdeploy/core/browser` facade; it adds no Node core polyfill to the
browser bundle.

The browser OIDC client is exact `oidc-client-ts@3.5.0` and uses Authorization
Code with PKCE. The repository-owned loopback mock provides one-time codes, an
exact `127.0.0.1:5173` redirect allowlist, token and JWKS endpoints, and RS256
tokens using the same bounded `jose@5.10.0` release accepted for backend tests.
Credentialed CORS and preflight are restricted to that exact origin. Run it with
`yarn workspace @staticdeploy/management-console dev:mock-server`; it is never a
production identity provider.

## Exact registry security corrections

The root manifest carries three reviewed, exact Yarn resolutions because the
current supported parent releases pin newly disclosed vulnerable children:

- `nx@23.1.1`'s exact `brace-expansion@5.0.8` is corrected to `5.0.9`;
- `lerna@10.0.0`'s exact `js-yaml@4.3.0` is corrected to `4.3.1`; and
- Mocha `11.8.0`'s `serialize-javascript@^6.0.2` range is corrected to `7.1.0`.

All corrected packages remain registry-backed. The first two corrections are
security patch releases on the same API line. The serializer correction crosses
a major boundary because no secure 6.x exists; Mocha uses it only for reporter
metadata serialization. A focused two-worker parallel-mode check exercises that
path, and the complete backend test suite is the broader compatibility contract.
These are not wildcard suppressions or vulnerability exceptions: raw audit
output sees the corrected resolved graph, and no finding is hidden.

`config/dependency-resolutions.json` records each exact selector, result, owner,
rationale, and removal condition. The install-policy checker rejects unreviewed,
wildcard, non-registry, changed, or ownerless resolution decisions. Remove each
correction as soon as its supported parent accepts the secure child version.

## Bounded CommonJS package bridges

The retained TypeScript packages still emit CommonJS. The legacy CLI therefore
pins `chalk@4.1.2` and `yargs@17.7.2`: Chalk's newer majors and the Yargs
release line after 17 no longer provide the CommonJS boundary this executable
consumes. These are module-format bridges, not general upgrade exceptions.
StaticDeploy runtime maintainers own them, and M3-09 must either retire the
legacy CLI or reassess its output boundary while splitting the supported runtime
commands.

Core likewise retains the CommonJS-compatible `mime@3` and
`escape-string-regexp@4` release lines. It also temporarily retains `md5@2` in
the server-oriented barrel. The Vite console now consumes the narrow
`@staticdeploy/core/browser` facade and receives no Node crypto polyfill; M4-05
still owns separating the server-only bundle finalizer from the package's main
exports, replacing the legacy MD5 implementation with Node crypto, and replacing
the MIME bridge when the v2 release finalizer takes over content detection. The
M4 application and content-route implementation owns removing the legacy
role-matcher escape bridge. No browser shim, hidden require, crypto polyfill, or
newer ESM-only major may be loaded through an ad hoc dynamic-import wrapper in
the current output.

The only remaining direct Bluebird owner is immutable PostgreSQL migration `02`;
current core, archive, and storage concurrency paths use native promises. The
historical migration remains byte-stable so an existing database can still
verify and execute the original migration source.

## Local structured logging

The backend uses exact `pino@10.3.1` and `pino-http@11.0.0` without transports
or workers. Non-test service logs are newline-delimited JSON written only to
standard output; test configuration is silent. `LOG_LEVEL` accepts only the six
standard levels and fails startup otherwise. Records retain application
name/version and serialize errors, causes, and aggregates while recursively
redacting case-insensitive authorization, cookie, credential, token, password,
API-key, proxy-auth, and secret/private-key variants. Logged request URLs omit
query strings and fragments.

Every request receives a server-generated UUID returned as `X-Request-Id`;
caller values are neither trusted nor retained in request headers. Exactly one
terminal record uses `request completed` at `info` for successful and 4xx
responses, `request aborted` at `warn`, or `request failed` at `error` for
errors/5xx. `SIGINT` and `SIGTERM` share an idempotent bounded close path and
flush/drain standard output. Startup failures set a nonzero exit code only after
the final structured error is drained. This local logging slice does not
configure telemetry export, an endpoint, credentials, dashboards, analytics, or
Eyes ingestion. Eyes product onboarding and application ingestion remain
externally gated.

## Express 4 and convexpress compatibility bridge

The legacy management API remains on exact `convexpress@2.3.0` and Express 4;
Express 5 is intentionally outside the M2 HTTP dependency slice because it would
change routing and error semantics. The regenerated lock resolves convexpress's
compatible ranges to `express@4.22.2`, `body-parser@1.20.6`,
`path-to-regexp@0.1.13`, and `qs@6.15.3`. Focused adapter tests preserve the
current malformed-body, content-type, query, encoded-parameter, not-found,
asynchronous-error, route-schema, and Swagger contracts. The oversized-body 500
response is recorded only as temporary legacy characterization; M4 must reassess
it and map rejected oversized payloads to an appropriate client error rather
than preserve the 500 assertion.

This is a bounded API compatibility bridge, not a vulnerability exception. The
StaticDeploy backend maintainers own it, and the M4 API route modernization
milestone must remove convexpress and reassess the Express major version while
implementing the modern API routes.

## Distribution

These commands install, check, compile, test, report, and build locally only.
They do not publish a package or image and do not deploy StaticDeploy.
