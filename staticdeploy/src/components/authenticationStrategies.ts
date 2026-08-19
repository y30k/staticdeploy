import { IAuthenticationStrategy } from "@staticdeploy/core";
import JwtAuthenticationStrategy from "@staticdeploy/jwt-authentication-strategy";
import OidcAuthenticationStrategy from "@staticdeploy/oidc-authentication-strategy";

import IConfig from "../common/IConfig";
import ILogger from "../common/ILogger";
import V2SessionAuthenticationStrategy from "./V2SessionAuthenticationStrategy";

export default (
    config: IConfig,
    logger: ILogger,
    sessionAuthentication?: V2SessionAuthenticationStrategy
): IAuthenticationStrategy[] => {
    const authenticationStrategies: IAuthenticationStrategy[] = [];

    if (sessionAuthentication !== undefined)
        authenticationStrategies.push(sessionAuthentication);

    if (config.jwtSecretOrPublicKey) {
        if (!config.jwtAlgorithm) {
            throw new Error(
                "JWT_ALGORITHM is required when JWT_SECRET_OR_PUBLIC_KEY is configured"
            );
        }
        logger.info("Using JwtAuthenticationStrategy authentication strategy");
        authenticationStrategies.push(
            new JwtAuthenticationStrategy(
                config.jwtSecretOrPublicKey,
                config.jwtAlgorithm
            )
        );
    }

    if (
        config.oidcConfigurationUrl &&
        config.oidcClientId &&
        config.oidcSessionEncryptionKeys === undefined
    ) {
        logger.info("Using OidcAuthenticationStrategy authentication strategy");
        authenticationStrategies.push(
            new OidcAuthenticationStrategy(
                config.oidcConfigurationUrl,
                config.oidcClientId,
                logger
            )
        );
    }

    return authenticationStrategies;
};
