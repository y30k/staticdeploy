import { managementApiAdapter } from "@staticdeploy/http-adapters";
import { V2OidcSessions } from "@staticdeploy/pg-s3-storages";
import serveStatic from "@staticdeploy/serve-static";
import express from "express";
import { dirname } from "path";

import IConfig from "../common/IConfig";
import removeUndefs from "../common/removeUndefs";
import V2SessionAuthenticationStrategy from "./V2SessionAuthenticationStrategy";
import v2SessionRouter, { requireV2ApiSession } from "./v2SessionRouter";

export default async (
    config: IConfig,
    sessions?: V2OidcSessions,
    sessionAuthentication?: V2SessionAuthenticationStrategy
): Promise<express.Router> => {
    if (!config.enableManagementEndpoints) {
        return express.Router().use((_req, res) => {
            res.status(404).send({
                message: "Management endpoints not enabled",
            });
        });
    }
    const managementConsoleStaticServer = await serveStatic({
        root: dirname(require.resolve("@staticdeploy/management-console")),
        fallbackAssetPath: "/index.html",
        fallbackStatusCode: 200,
        configuration: removeUndefs({
            API_URL:
                config.managementHostname === "localhost"
                    ? `http://localhost:${config.port}/api`
                    : `//${config.managementHostname}/api`,
            AUTH_ENFORCED: config.enforceAuth.toString(),
            OIDC_ENABLED: (
                sessions === undefined &&
                !!config.oidcConfigurationUrl &&
                !!config.oidcClientId
            ).toString(),
            OIDC_CONFIGURATION_URL:
                sessions === undefined
                    ? config.oidcConfigurationUrl
                    : undefined,
            OIDC_CLIENT_ID:
                sessions === undefined ? config.oidcClientId : undefined,
            OIDC_REDIRECT_URL:
                sessions === undefined
                    ? config.managementHostname === "localhost"
                        ? `http://localhost:${config.port}`
                        : `https://${config.managementHostname}`
                    : undefined,
            OIDC_PROVIDER_NAME:
                sessions === undefined ? config.oidcProviderName : undefined,
            SERVER_SESSION_ENABLED: (sessions !== undefined).toString(),
            SERVER_SESSION_AUTH_URL:
                sessions === undefined ? undefined : "/api/v2/auth",
            SERVER_SESSION_PROVIDER_NAME:
                sessions === undefined ? undefined : config.oidcProviderName,
            JWT_ENABLED: (
                sessions === undefined && !!config.jwtSecretOrPublicKey
            ).toString(),
        }),
        headers: {},
    });

    const router = express.Router();
    if (sessions !== undefined) {
        if (sessionAuthentication === undefined)
            throw new Error("server sessions require request authentication");
        router.use(
            "/api/v2/auth",
            v2SessionRouter(sessions, config.oidcTrustedProxyHops!)
        );
        router.use(
            "/api",
            requireV2ApiSession(
                sessions,
                sessionAuthentication,
                config.maxRequestBodySize
            )
        );
    }

    return router
        .use(
            "/api",
            managementApiAdapter({
                serviceName: config.appName,
                serviceVersion: config.appVersion,
                serviceHost: config.managementHostname,
                serviceBasePath: "/api",
                maxRequestBodySize: config.maxRequestBodySize,
            })
        )
        .use(managementConsoleStaticServer);
};
