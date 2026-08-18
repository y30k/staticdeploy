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

Immutable installs must not change `yarn.lock`. The root's exact
`minipass@3.1.6` development dependency preserves the TypeScript 4-era
`@types/tar` resolution when Lerna 10 introduces modern transitive Minipass
versions. Remove this narrow compatibility pin when the tar/TypeScript
dependency slice is upgraded. A toolchain pin change requires updating every pin
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

## Legacy console build bridge

Only `@staticdeploy/management-console`'s `compile` command sets
`NODE_OPTIONS=--openssl-legacy-provider`. This is a build-only compatibility
bridge for CRA 4/Webpack 4; it is not set globally, in tests, or in service
runtime configuration. Work item M4-10 must remove the bridge when CRA/Webpack 4
is replaced.

## Distribution

These commands install, check, compile, test, report, and build locally only.
They do not publish a package or image and do not deploy StaticDeploy.
