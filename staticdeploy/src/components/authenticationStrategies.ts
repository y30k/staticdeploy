import { IAuthenticationStrategy } from "@staticdeploy/core";
import JwtAuthenticationStrategy from "@staticdeploy/jwt-authentication-strategy";
import OidcAuthenticationStrategy from "@staticdeploy/oidc-authentication-strategy";
import Logger from "bunyan";

import IConfig from "../common/IConfig";

export default (config: IConfig, logger: Logger): IAuthenticationStrategy[] => {
    const authenticationStrategies: IAuthenticationStrategy[] = [];

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

    if (config.oidcConfigurationUrl && config.oidcClientId) {
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
