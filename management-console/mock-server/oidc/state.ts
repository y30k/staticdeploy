import {
    createHash,
    randomBytes,
    randomUUID,
    timingSafeEqual,
} from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export const MOCK_HOST = "127.0.0.1";
export const MOCK_PORT = 3456;
export const DEV_ORIGIN = "http://127.0.0.1:5173";
export const ISSUER = `http://${MOCK_HOST}:${MOCK_PORT}`;
export const CLIENT_ID = "clientId";
export const REDIRECT_URIS = new Set([
    `${DEV_ORIGIN}/?oidcRedirect=true`,
    `${DEV_ORIGIN}/?oidcSilentRedirect=true`,
]);

interface AuthorizationCode {
    challenge: string;
    createdAt: number;
    clientId: string;
    nonce?: string;
    redirectUri: string;
}

const codes = new Map<string, AuthorizationCode>();
const codeTtlMs = 5 * 60 * 1000;
const maxCodes = 100;
const keyPair = generateKeyPair("RS256", { extractable: true });
const keyId = "staticdeploy-local-mock";

function sha256Base64Url(value: string) {
    return createHash("sha256").update(value).digest("base64url");
}

export function createAuthorizationCode(
    input: Omit<AuthorizationCode, "createdAt">
) {
    const now = Date.now();
    for (const [code, value] of codes) {
        if (now - value.createdAt > codeTtlMs) codes.delete(code);
    }
    while (codes.size >= maxCodes) codes.delete(codes.keys().next().value!);
    const code = randomBytes(32).toString("base64url");
    codes.set(code, { ...input, createdAt: now });
    return code;
}

export function redeemAuthorizationCode(input: {
    code: string;
    clientId: string;
    redirectUri: string;
    verifier: string;
}) {
    const stored = codes.get(input.code);
    codes.delete(input.code);
    if (
        !stored ||
        Date.now() - stored.createdAt > codeTtlMs ||
        stored.clientId !== input.clientId ||
        stored.redirectUri !== input.redirectUri
    ) {
        return null;
    }
    const actual = Buffer.from(sha256Base64Url(input.verifier));
    const expected = Buffer.from(stored.challenge);
    if (
        actual.length !== expected.length ||
        !timingSafeEqual(actual, expected)
    ) {
        return null;
    }
    return stored;
}

export async function createToken(nonce: string | undefined, clientId: string) {
    const { privateKey } = await keyPair;
    return new SignJWT({ nonce, preferred_username: "mock-user" })
        .setProtectedHeader({ alg: "RS256", kid: keyId })
        .setIssuer(ISSUER)
        .setAudience(clientId)
        .setSubject("mock-user")
        .setJti(randomUUID())
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
}

export async function getJwks() {
    const { publicKey } = await keyPair;
    return {
        keys: [
            {
                ...(await exportJWK(publicKey)),
                alg: "RS256",
                kid: keyId,
                use: "sig",
            },
        ],
    };
}
