# @staticdeploy/sdk

Browser and nodejs SDK for the StaticDeploy API.

## Build from this repository

The SDK is retained for legacy characterization only and is not published by
this fork. Build it with its workspace dependencies from a frozen checkout:

```sh
corepack enable
yarn install --immutable
yarn lerna run compile \
  --scope=@staticdeploy/sdk \
  --include-dependencies \
  --stream \
  --concurrency 1
```

## Quickstart

```ts
import StaticdeployClient from "@staticdeploy/sdk";

const client = new StaticdeployClient({
  apiUrl: process.env.STATICDEPLOY_API_URL,
  apiToken: process.env.STATICDEPLOY_API_TOKEN
});

/* In some async function... */

const apps = await client.apps.getAll();
console.log(apps);

const createdApp = await client.apps.create({ name: "my-app" });
console.log(createdApp);
```
