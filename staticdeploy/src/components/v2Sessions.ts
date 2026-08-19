import {
    createV2OidcSessions,
    V2OidcSessions,
} from "@staticdeploy/pg-s3-storages";

import IConfig from "../common/IConfig";
import ILogger from "../common/ILogger";

export default async function getV2Sessions(
    config: IConfig,
    logger?: ILogger
): Promise<V2OidcSessions | undefined> {
    const values = [
        config.oidcConfigurationUrl,
        config.oidcClientId,
        config.oidcExpectedIssuer,
        config.oidcRedirectUri,
        config.portalOrigin,
        config.oidcSessionPrimaryKeyId,
        config.oidcSessionEncryptionKeys,
        config.oidcAdministratorGroupIds,
        config.oidcAuthorizationClaimsVersion,
        config.oidcPostgresUrl,
        config.oidcTrustedProxyHops,
    ];
    const requested =
        values.some((value) => value !== undefined) ||
        config.oidcAllowHttpLoopbackForTests === true;
    if (!requested) return undefined;
    if (values.some((value) => value === undefined))
        throw new Error(
            "server-side OIDC sessions require complete OIDC, keyring, and dedicated PostgreSQL configuration"
        );
    if (!config.enforceAuth)
        throw new Error("server-side OIDC sessions require ENFORCE_AUTH=true");
    if (
        config.oidcAllowHttpLoopbackForTests === true &&
        config.nodeEnv !== "test"
    )
        throw new Error(
            "OIDC_ALLOW_HTTP_LOOPBACK_FOR_TESTS is restricted to NODE_ENV=test"
        );
    const sessions = createV2OidcSessions(config.oidcPostgresUrl!, {
        configurationUrl: config.oidcConfigurationUrl!,
        clientId: config.oidcClientId!,
        expectedIssuer: config.oidcExpectedIssuer!,
        redirectUri: config.oidcRedirectUri!,
        portalOrigin: config.portalOrigin!,
        primaryKeyId: config.oidcSessionPrimaryKeyId!,
        encryptionKeys: config.oidcSessionEncryptionKeys!,
        allowHttpLoopbackForTests:
            config.oidcAllowHttpLoopbackForTests === true,
        onCleanupFailure: () =>
            logger?.error(
                new Error("OIDC_SESSION_CLEANUP_FAILED"),
                "OIDC session cleanup failed"
            ),
    });
    try {
        await sessions.verifyReady();
        return sessions;
    } catch (error) {
        await sessions.destroy();
        throw error;
    }
}
