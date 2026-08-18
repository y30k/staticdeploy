# This Dockerfile is executed with the monorepo root as its build context.
FROM node:24.19.0-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS builder

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
    find node_modules -type d \( -name test -o -name tests -o -name __tests__ -o -name spec -o -name specs -o -name examples \) -prune -exec rm -rf '{}' + && \
    find . -type f \( -name '*.map' -o -name '*.ts' -o -name '*.tsx' \) -delete

FROM scratch AS runtime

COPY --from=builder /lib/ld-musl-*.so.1 /lib/
COPY --from=builder /usr/lib/libstdc++.so.6 /usr/lib/libstdc++.so.6
COPY --from=builder /usr/lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/local/bin/node /nodejs/bin/node
WORKDIR /opt/staticdeploy/staticdeploy
COPY --from=builder /opt/staticdeploy/package.json /opt/staticdeploy/package.json
COPY --from=builder /opt/staticdeploy/node_modules /opt/staticdeploy/node_modules
COPY --from=builder /opt/staticdeploy/core/package.json /opt/staticdeploy/core/package.json
COPY --from=builder /opt/staticdeploy/core/lib /opt/staticdeploy/core/lib
COPY --from=builder /opt/staticdeploy/http-adapters/package.json /opt/staticdeploy/http-adapters/package.json
COPY --from=builder /opt/staticdeploy/http-adapters/lib /opt/staticdeploy/http-adapters/lib
COPY --from=builder /opt/staticdeploy/jwt-authentication-strategy/package.json /opt/staticdeploy/jwt-authentication-strategy/package.json
COPY --from=builder /opt/staticdeploy/jwt-authentication-strategy/lib /opt/staticdeploy/jwt-authentication-strategy/lib
COPY --from=builder /opt/staticdeploy/management-console/package.json /opt/staticdeploy/management-console/package.json
COPY --from=builder /opt/staticdeploy/management-console/build /opt/staticdeploy/management-console/build
COPY --from=builder /opt/staticdeploy/memory-storages/package.json /opt/staticdeploy/memory-storages/package.json
COPY --from=builder /opt/staticdeploy/memory-storages/lib /opt/staticdeploy/memory-storages/lib
COPY --from=builder /opt/staticdeploy/oidc-authentication-strategy/package.json /opt/staticdeploy/oidc-authentication-strategy/package.json
COPY --from=builder /opt/staticdeploy/oidc-authentication-strategy/lib /opt/staticdeploy/oidc-authentication-strategy/lib
COPY --from=builder /opt/staticdeploy/pg-s3-storages/package.json /opt/staticdeploy/pg-s3-storages/package.json
COPY --from=builder /opt/staticdeploy/pg-s3-storages/lib /opt/staticdeploy/pg-s3-storages/lib
COPY --from=builder /opt/staticdeploy/sdk/package.json /opt/staticdeploy/sdk/package.json
COPY --from=builder /opt/staticdeploy/sdk/lib /opt/staticdeploy/sdk/lib
COPY --from=builder /opt/staticdeploy/serve-static/package.json /opt/staticdeploy/serve-static/package.json
COPY --from=builder /opt/staticdeploy/serve-static/lib /opt/staticdeploy/serve-static/lib
COPY --from=builder /opt/staticdeploy/tar-archiver/package.json /opt/staticdeploy/tar-archiver/package.json
COPY --from=builder /opt/staticdeploy/tar-archiver/lib /opt/staticdeploy/tar-archiver/lib
COPY --from=builder /opt/staticdeploy/staticdeploy/package.json /opt/staticdeploy/staticdeploy/package.json
COPY --from=builder /opt/staticdeploy/staticdeploy/build /opt/staticdeploy/staticdeploy/build

ENV NODE_ENV=production
ENV PORT=80
EXPOSE 80

USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/nodejs/bin/node", "-e", "const net=require('net');const socket=net.connect({host:'127.0.0.1',port:Number(process.env.PORT)},()=>{socket.destroy();process.exit(0)});socket.setTimeout(4000,()=>socket.destroy());socket.on('error',()=>process.exit(1));"]

ENTRYPOINT ["/nodejs/bin/node"]
CMD ["build/server.js"]
