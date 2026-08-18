# This Dockerfile is executed with the monorepo root as its build context.
FROM node:24.19.0-alpine AS builder

WORKDIR /opt/staticdeploy

COPY package.json lerna.json yarn.lock .yarnrc.yml tsconfig.json ./
COPY config/install-scripts.json config/dependency-resolutions.json ./config/
COPY scripts/check-install-policy.mjs scripts/check-install-scripts.mjs ./scripts/
COPY management-console/package.json management-console/tsconfig.json management-console/index.html management-console/vite.config.mts ./management-console/
COPY management-console/scripts ./management-console/scripts/
COPY cli/package.json ./cli/
COPY core/package.json core/tsconfig.json core/tsconfig.browser.json ./core/
COPY http-adapters/package.json http-adapters/tsconfig.json ./http-adapters/
COPY jwt-authentication-strategy/package.json jwt-authentication-strategy/tsconfig.json ./jwt-authentication-strategy/
COPY memory-storages/package.json memory-storages/tsconfig.json ./memory-storages/
COPY oidc-authentication-strategy/package.json oidc-authentication-strategy/tsconfig.json ./oidc-authentication-strategy/
COPY pg-s3-storages/package.json pg-s3-storages/tsconfig.json ./pg-s3-storages/
COPY sdk/package.json sdk/tsconfig.json sdk/tsconfig.browser.json ./sdk/
COPY serve-static/package.json serve-static/tsconfig.json ./serve-static/
COPY staticdeploy/package.json staticdeploy/tsconfig.json ./staticdeploy/
COPY storages-test-suite/package.json storages-test-suite/tsconfig.json ./storages-test-suite/
COPY tar-archiver/package.json tar-archiver/tsconfig.json ./tar-archiver/

COPY management-console/public ./management-console/public/
COPY management-console/src ./management-console/src/
COPY core/src ./core/src/
COPY http-adapters/src ./http-adapters/src/
COPY jwt-authentication-strategy/src ./jwt-authentication-strategy/src/
COPY memory-storages/src ./memory-storages/src/
COPY oidc-authentication-strategy/src ./oidc-authentication-strategy/src/
COPY pg-s3-storages/src ./pg-s3-storages/src/
COPY sdk/src ./sdk/src/
COPY serve-static/src ./serve-static/src/
COPY storages-test-suite/src ./storages-test-suite/src/
COPY tar-archiver/src ./tar-archiver/src/
COPY staticdeploy/typings ./staticdeploy/typings/
COPY staticdeploy/src ./staticdeploy/src/

RUN corepack enable && \
    test "$(yarn --version)" = "4.18.0" && \
    node scripts/check-install-policy.mjs && \
    yarn install --immutable && \
    yarn check:install-scripts && \
    yarn lerna run compile --scope=@staticdeploy/staticdeploy --include-dependencies --stream --concurrency 1 && \
    rm -rf node_modules */node_modules && \
    yarn workspaces focus @staticdeploy/staticdeploy --production && \
    rm -f yarn.lock tsconfig.json lerna.json .yarnrc.yml && \
    rm -rf .yarn config scripts && \
    rm -rf management-console/tsconfig.json management-console/vite.config.mts management-console/index.html management-console/public management-console/scripts management-console/src && \
    rm -rf core/tsconfig.json core/tsconfig.browser.json core/src && \
    rm -rf http-adapters/tsconfig.json http-adapters/src && \
    rm -rf jwt-authentication-strategy/tsconfig.json jwt-authentication-strategy/src && \
    rm -rf memory-storages/tsconfig.json memory-storages/src && \
    rm -rf oidc-authentication-strategy/tsconfig.json oidc-authentication-strategy/src && \
    rm -rf pg-s3-storages/tsconfig.json pg-s3-storages/src && \
    rm -rf sdk/tsconfig.json sdk/tsconfig.browser.json sdk/src && \
    rm -rf serve-static/tsconfig.json serve-static/src && \
    rm -rf storages-test-suite && \
    rm -rf tar-archiver/tsconfig.json tar-archiver/src && \
    rm -rf staticdeploy/tsconfig.json staticdeploy/src staticdeploy/typings && \
    find node_modules -type d \( -name test -o -name tests -o -name __tests__ \) -prune -exec rm -rf '{}' +

FROM node:24.19.0-alpine AS runtime

RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack && \
    rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

WORKDIR /opt/staticdeploy/staticdeploy
COPY --from=builder --chown=node:node /opt/staticdeploy /opt/staticdeploy

ENV NODE_ENV=production
ENV PORT=80
EXPOSE 80

USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["node", "-e", "const http=require('http');const request=http.get({host:'127.0.0.1',port:process.env.PORT,path:'/api/health',headers:{host:process.env.MANAGEMENT_HOSTNAME}},response=>{response.resume();process.exit(response.statusCode===200?0:1)});request.setTimeout(4000,()=>request.destroy());request.on('error',()=>process.exit(1));"]

CMD ["node", "build/server.js"]
