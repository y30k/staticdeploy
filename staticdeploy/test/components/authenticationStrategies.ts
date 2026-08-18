import JwtAuthenticationStrategy from "@staticdeploy/jwt-authentication-strategy";
import OidcAuthenticationStrategy from "@staticdeploy/oidc-authentication-strategy";
import { expect } from "chai";

import getAuthenticationStrategies from "../../src/components/authenticationStrategies";
import getLogger from "../../src/components/logger";
import config from "../../src/config";

describe("authenticationStrategies composition", () => {
    it("rejects an ambiguous JWT key without an explicit algorithm", () => {
        expect(() =>
            getAuthenticationStrategies(
                { ...config, jwtSecretOrPublicKey: Buffer.from("secret") },
                getLogger(config)
            )
        ).to.throw(
            "JWT_ALGORITHM is required when JWT_SECRET_OR_PUBLIC_KEY is configured"
        );
    });

    it("composes the CommonJS JWT and OIDC strategy bridges when configured", () => {
        const strategies = getAuthenticationStrategies(
            {
                ...config,
                jwtSecretOrPublicKey: Buffer.from("secret"),
                jwtAlgorithm: "HS256",
                oidcConfigurationUrl:
                    "https://issuer.localhost/.well-known/openid-configuration",
                oidcClientId: "clientId",
            },
            getLogger(config)
        );

        expect(strategies).to.have.length(2);
        expect(strategies[0]).to.be.instanceOf(JwtAuthenticationStrategy);
        expect(strategies[1]).to.be.instanceOf(OidcAuthenticationStrategy);
    });
});
