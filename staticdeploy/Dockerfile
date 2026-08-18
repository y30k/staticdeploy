# Note: this Dockerfile is executed with the root of the staticdeploy monorepo
# as context. M2-07 owns the later image-hardening/multi-stage conversion.
FROM node:24.19.0-alpine

WORKDIR /opt/staticdeploy

# Use the repository-pinned Yarn release and immutable node-modules install.
COPY package.json lerna.json yarn.lock .yarnrc.yml tsconfig.json ./
COPY config/install-scripts.json ./config/install-scripts.json
COPY scripts/check-install-policy.mjs scripts/check-install-scripts.mjs scripts/provision-optipng.mjs ./scripts/
COPY management-console/package.json management-console/tsconfig.json ./management-console/
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
COPY website/package.json ./website/

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
    yarn provision:optipng && \
    yarn lerna run compile --scope=@staticdeploy/staticdeploy --include-dependencies --stream --concurrency 1 && \
    yarn workspaces focus @staticdeploy/staticdeploy --production && \
    rm yarn.lock tsconfig.json && \
    rm -rf management-console/tsconfig.json management-console/public management-console/src && \
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
    rm -rf config scripts && \
    apk add --no-cache curl

ENV NODE_ENV=production
ENV YARN_VERSION=4.18.0
ENV PORT=80
EXPOSE 80

HEALTHCHECK CMD curl -f -H "Host: $MANAGEMENT_HOSTNAME" http://localhost:$PORT/api/health || exit 1

WORKDIR /opt/staticdeploy/staticdeploy
CMD ["node", "build/server.js"]
