import { IAuthenticationStrategy, IIdpUser } from "@staticdeploy/core";
import { createPublicKey, JsonWebKey, KeyObject } from "crypto";
import { jwtVerify } from "jose";
import { has, isString } from "lodash";

export type JwtVerificationAlgorithm = "HS256" | "RS256";

export default class JwtAuthenticationStrategy
    implements IAuthenticationStrategy
{
    private verifyingKey: KeyObject | Uint8Array;

    constructor(
        secretOrPublicKey: Buffer,
        private algorithm: JwtVerificationAlgorithm
    ) {
        if (algorithm === "HS256") {
            this.verifyingKey = new Uint8Array(secretOrPublicKey);
            return;
        }

        const publicKey = createConfiguredPublicKey(secretOrPublicKey);
        if (publicKey.asymmetricKeyType !== "rsa") {
            throw new TypeError("RS256 requires an RSA public key");
        }
        this.verifyingKey = publicKey;
    }

    async getIdpUserFromAuthToken(authToken: string): Promise<IIdpUser | null> {
        try {
            const { payload: jwt } = await jwtVerify(
                authToken,
                this.verifyingKey,
                { algorithms: [this.algorithm] }
            );
            return has(jwt, "sub") &&
                isString(jwt.sub) &&
                has(jwt, "iss") &&
                isString(jwt.iss)
                ? { idp: jwt.iss, id: jwt.sub }
                : null;
        } catch {
            // When errors occur, we simply return a null idp user
            return null;
        }
    }
}

function createConfiguredPublicKey(value: Buffer): KeyObject {
    const text = value.toString("utf8").trim();
    if (text.startsWith("{")) {
        return createPublicKey({
            key: JSON.parse(text) as JsonWebKey,
            format: "jwk",
        });
    }

    const candidates: Parameters<typeof createPublicKey>[0][] = [
        value,
        { key: value, format: "der", type: "spki" },
        { key: value, format: "der", type: "pkcs1" },
    ];
    for (const candidate of candidates) {
        try {
            return createPublicKey(candidate);
        } catch {
            // Continue through the explicit RSA public-key encodings.
        }
    }
    throw new TypeError("Invalid RSA public key");
}
