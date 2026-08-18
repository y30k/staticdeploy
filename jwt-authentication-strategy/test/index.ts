import { generateKeyPairSync, KeyObject } from "crypto";
import { expect } from "chai";
import { SignJWT } from "jose";

import JwtAuthenticationStrategy from "../src";

type SigningKey = KeyObject | Uint8Array;

const signToken = async (
    payload: Record<string, unknown>,
    signingKey: SigningKey,
    algorithm: string,
    protectedHeader: Record<string, unknown> = {}
): Promise<string> =>
    new SignJWT(payload)
        .setProtectedHeader({ alg: algorithm, ...protectedHeader })
        .sign(signingKey);

describe("JwtAuthenticationStrategy", () => {
    describe("getIdpUserFromAuthToken", () => {
        const iss = "iss";
        const sub = "sub";
        const secret = Buffer.from("secret");
        const differentSecret = Buffer.from("different-secret");
        const { publicKey, privateKey } = generateKeyPairSync("rsa", {
            modulusLength: 2048,
        });
        const rsaPublicKey = Buffer.from(
            publicKey.export({ type: "spki", format: "pem" })
        );
        const rsaPublicKeyDer = publicKey.export({
            type: "spki",
            format: "der",
        });
        const rsaPublicKeyJwk = Buffer.from(
            JSON.stringify(publicKey.export({ format: "jwk" }))
        );

        const cases: Array<{
            type: string;
            verifyingKey: Buffer;
            signingKey: SigningKey;
            wrongSigningKey: SigningKey;
            algorithm: "HS256" | "RS256";
        }> = [
            {
                type: "symmetric secret",
                verifyingKey: secret,
                signingKey: new Uint8Array(secret),
                wrongSigningKey: new Uint8Array(differentSecret),
                algorithm: "HS256",
            },
            {
                type: "RSA key",
                verifyingKey: rsaPublicKey,
                signingKey: privateKey,
                wrongSigningKey: generateKeyPairSync("rsa", {
                    modulusLength: 2048,
                }).privateKey,
                algorithm: "RS256",
            },
        ];

        for (const testCase of cases) {
            describe(`cases with ${testCase.type} as signing key`, () => {
                const strategy = new JwtAuthenticationStrategy(
                    testCase.verifyingKey,
                    testCase.algorithm
                );

                it("returns null on an un-decodable jwt", async () => {
                    expect(
                        await strategy.getIdpUserFromAuthToken("un-decodable")
                    ).to.equal(null);
                });

                it("returns null on jwt without sub", async () => {
                    const authToken = await signToken(
                        { iss },
                        testCase.signingKey,
                        testCase.algorithm
                    );
                    expect(
                        await strategy.getIdpUserFromAuthToken(authToken)
                    ).to.equal(null);
                });

                it("returns null on jwt without iss", async () => {
                    const authToken = await signToken(
                        { sub },
                        testCase.signingKey,
                        testCase.algorithm
                    );
                    expect(
                        await strategy.getIdpUserFromAuthToken(authToken)
                    ).to.equal(null);
                });

                it("returns null on jwt with wrong signature", async () => {
                    const authToken = await signToken(
                        { sub, iss },
                        testCase.wrongSigningKey,
                        testCase.algorithm
                    );
                    expect(
                        await strategy.getIdpUserFromAuthToken(authToken)
                    ).to.equal(null);
                });

                it("returns null on an expired jwt", async () => {
                    const authToken = await new SignJWT({ sub, iss })
                        .setProtectedHeader({ alg: testCase.algorithm })
                        .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
                        .sign(testCase.signingKey);
                    expect(
                        await strategy.getIdpUserFromAuthToken(authToken)
                    ).to.equal(null);
                });

                it("returns null before the jwt not-before time", async () => {
                    const authToken = await new SignJWT({ sub, iss })
                        .setProtectedHeader({ alg: testCase.algorithm })
                        .setNotBefore(Math.floor(Date.now() / 1000) + 300)
                        .sign(testCase.signingKey);
                    expect(
                        await strategy.getIdpUserFromAuthToken(authToken)
                    ).to.equal(null);
                });

                it("returns the idp user on valid jwt", async () => {
                    const authToken = await signToken(
                        { sub, iss },
                        testCase.signingKey,
                        testCase.algorithm
                    );
                    expect(
                        await strategy.getIdpUserFromAuthToken(authToken)
                    ).to.deep.equal({ id: sub, idp: iss });
                });
            });
        }

        it("rejects an HS256 algorithm-confusion token for an RSA key", async () => {
            const strategy = new JwtAuthenticationStrategy(
                rsaPublicKey,
                "RS256"
            );
            const authToken = await signToken(
                { sub, iss },
                new Uint8Array(rsaPublicKey),
                "HS256"
            );

            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        for (const [name, encodedPublicKey] of [
            ["DER", rsaPublicKeyDer],
            ["JWK", rsaPublicKeyJwk],
        ] as const) {
            it(`does not treat an ${name} RSA public key as an HMAC secret`, async () => {
                const strategy = new JwtAuthenticationStrategy(
                    encodedPublicKey,
                    "RS256"
                );
                const forgedToken = await signToken(
                    { sub, iss },
                    new Uint8Array(encodedPublicKey),
                    "HS256"
                );
                const validToken = await signToken(
                    { sub, iss },
                    privateKey,
                    "RS256"
                );

                expect(
                    await strategy.getIdpUserFromAuthToken(forgedToken)
                ).to.equal(null);
                expect(
                    await strategy.getIdpUserFromAuthToken(validToken)
                ).to.deep.equal({ id: sub, idp: iss });
            });
        }

        it("rejects unsupported symmetric algorithms", async () => {
            const strategy = new JwtAuthenticationStrategy(secret, "HS256");
            const authToken = await signToken(
                { sub, iss },
                new Uint8Array(secret),
                "HS384"
            );

            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });

        it("rejects unsupported RSA algorithms", async () => {
            const strategy = new JwtAuthenticationStrategy(
                rsaPublicKey,
                "RS256"
            );
            const authToken = await signToken(
                { sub, iss },
                privateKey,
                "PS256"
            );

            expect(await strategy.getIdpUserFromAuthToken(authToken)).to.equal(
                null
            );
        });
    });
});
