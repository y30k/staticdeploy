---
id: getting-started-quickstart
title: Quickstart
---

This legacy quickstart builds the source locally; this fork publishes neither
the service image nor the CLI. You need Docker, Git, Node 14, and Yarn 1.

## Check out and start StaticDeploy

```sh
git clone https://github.com/y30k/staticdeploy.git
cd staticdeploy
docker build -f staticdeploy/Dockerfile -t staticdeploy-service:local .
docker run --rm --init \
  -e MANAGEMENT_HOSTNAME=localhost \
  -e ENFORCE_AUTH=false \
  -e PORT=8080 \
  -p 127.0.0.1:8080:8080 \
  staticdeploy-service:local
```

The loopback-only port binding is required because authentication is disabled.
Visit the Management Console at <http://localhost:8080/>.

## Build the repository-local CLI

In another terminal, from the same checkout:

```sh
yarn install --frozen-lockfile
yarn lerna run compile \
  --scope=@staticdeploy/cli \
  --include-dependencies \
  --stream \
  --concurrency 1
alias staticdeploy='node cli/bin/staticdeploy.js'
export STATICDEPLOY_API_URL=http://localhost:8080/api
```

## Publish a repository-owned fixture

```sh
staticdeploy bundle \
  --from website/demo-static-app \
  --name demo-static-app \
  --tag local \
  --description "local characterization fixture"

staticdeploy deploy \
  --app demo-static-app \
  --entrypoint demo-static-app.localhost/ \
  --bundle demo-static-app:local

curl --fail \
  --header 'Host: demo-static-app.localhost' \
  http://127.0.0.1:8080/
```

The final command should return the fixture HTML. Stop the container when the
characterization run is complete; memory-backed state is intentionally
discarded.
