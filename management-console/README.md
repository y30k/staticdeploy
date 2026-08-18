# @staticdeploy/management-console

Web application through which admin users can manage StaticDeploy's entities
(bundles, apps, entrypoints, and operation logs).

## Supported development foundation

The console uses Vite and React 18. Run the browser and loopback-only mock API
in separate terminals:

```sh
yarn workspace @staticdeploy/management-console dev:mock-server
yarn workspace @staticdeploy/management-console dev
```

The Vite server binds canonically to `127.0.0.1:5173`; the repository-owned mock
API binds to `127.0.0.1:3456`. The checked-in development `app-config.js` uses
only those loopback origins and disables authentication by default. Neither
command is a production deployment path.

Build and test with:

```sh
yarn workspace @staticdeploy/management-console compile
yarn workspace @staticdeploy/management-console test
yarn workspace @staticdeploy/management-console test:build
```

The root-based Vite build keeps `script#app-config` in `index.html`.
StaticDeploy's existing server-side embedding path removes its placeholder `src`
and injects runtime configuration before the Vite module entry runs. Root-based
assets remain valid when a deep browser route receives the HTML fallback. Do not
replace the marker with build-time environment values or add a browser Node-core
polyfill. `test:build` proves root-relative generated assets and rejects
`unsafe-eval`-style code construction; rendered Testing Library coverage
exercises the Ant Design runtime. M5 still owns the final response CSP header
and nonce/hash contract.

The local OIDC fixture implements Authorization Code with PKCE, one-time codes,
an exact redirect allowlist, a token endpoint, and RS256 discovery/JWKS. Its
CORS policy allows credentials only from `http://127.0.0.1:5173`; it is not an
identity-provider substitute.

M4-11 owns replacement of React Router 5 and Redux Form. Their existing routes,
validation, and submission behavior remain bounded compatibility in this
foundation change.
