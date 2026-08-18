# @staticdeploy/management-console

Web application through which admin users can manage StaticDeploy's entities
(bundles, apps, entrypoints, and operation logs).

## Supported development foundation

The console uses Vite and React 18. Run the browser and loopback-only mock API in
separate terminals:

```sh
yarn workspace @staticdeploy/management-console dev:mock-server
yarn workspace @staticdeploy/management-console dev
```

The Vite server binds to `127.0.0.1`; the repository-owned mock API binds to
`127.0.0.1:3456`. Neither command is a production deployment path.

Build and test with:

```sh
yarn workspace @staticdeploy/management-console compile
yarn workspace @staticdeploy/management-console test
```

The build keeps `script#app-config` in `index.html`. StaticDeploy's existing
server-side embedding path removes its placeholder `src` and injects runtime
configuration before the Vite module entry runs. Do not replace this marker with
build-time environment values or add a browser Node-core polyfill.

M4-11 owns replacement of React Router 5 and Redux Form. Their existing routes,
validation, and submission behavior remain bounded compatibility in this
foundation change.
