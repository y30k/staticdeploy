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
yarn provision:optipng
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

## Reviewed legacy build binary

The retired website workspace still requires `optipng-bin@5.1.0` to compile, but
its upstream postinstall downloads and executes mutable remote content. That
postinstall remains blocked. `yarn provision:optipng` instead downloads the
reviewed Linux x64 artifact, verifies its repository-owned SHA-256 before it can
execute, and fails on unsupported platforms or digest mismatch. This narrow
bridge is for retained compile evidence only and must not be reused for release
artifacts.

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

ESLint covers retained TypeScript/TSX and the website's JavaScript/React. Narrow
exceptions are documented beside their rules in `eslint.config.mjs`: only the
exact inventoried v1 serialization, adapter, form, callback, test, and typing
boundary files may retain explicit `any` until M2-04/M4 replaces those
contracts; new files remain prohibited. TypeScript owns unused-symbol
correctness, typed console props do not duplicate runtime PropTypes, and
Docusaurus v1 receives dynamic props. The configuration still applies ESLint,
typescript-eslint, and React recommended correctness rules and rejects unused
disable comments. Add exceptions only for an exact rule and file scope with a
rationale; do not add blanket file or project disables.

Prettier `3.6.2` centralizes the supported formatting contract. Its one-time,
mechanical output update is included with this migration and does not alter
application behavior. Formatting paths are centralized in the root commands;
forwarding workspace configs and copies of formatter dependencies are forbidden
by the workspace-contract test. Dependency-managed Git hooks were removed
because GitHub Actions required checks are authoritative.

## Legacy console build bridge

Only `@staticdeploy/management-console`'s `compile` command sets
`NODE_OPTIONS=--openssl-legacy-provider`, `SKIP_PREFLIGHT_CHECK=true`, and
`DISABLE_ESLINT_PLUGIN=true`. All three are build-only compatibility bridges for
CRA 4/Webpack 4: the OpenSSL bridge permits Webpack 4 hashing, the preflight
bridge permits the centralized supported TypeScript/ESLint versions, and the
ESLint-plugin bridge prevents CRA from invoking its obsolete embedded lint
toolchain after the root ESLint phase has passed. None is set globally, in
tests, or in service runtime configuration. Work item M4-10 must remove all
three bridges when CRA/Webpack 4 is replaced.

## Express 4 and convexpress compatibility bridge

The legacy management API remains on exact `convexpress@2.3.0` and Express 4;
Express 5 is intentionally outside the M2 HTTP dependency slice because it would
change routing and error semantics. The regenerated lock resolves convexpress's
compatible ranges to `express@4.21.2`, `body-parser@1.20.3`,
`path-to-regexp@0.1.12`, and `qs@6.13.0`. Focused adapter tests preserve the
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
