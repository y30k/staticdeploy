import { generateKeyPair, SignJWT } from "jose";
import { Request, RequestHandler } from "express";
import qs from "querystring";

interface Query {
    redirect_uri: string;
    state?: string;
    nonce?: string;
    client_id?: string;
}

const signingKey = generateKeyPair("RS256").then(
    ({ privateKey }) => privateKey
);

export default (async (req: Request<any, any, any, Query>, res) => {
    const { redirect_uri, state, nonce, client_id = "clientId" } = req.query;
    const idToken = await new SignJWT({ nonce })
        .setProtectedHeader({ alg: "RS256" })
        .setIssuer("http://localhost:3456")
        .setAudience(client_id)
        .setSubject("mock-user")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(await signingKey);
    const redirectUrl = [
        redirect_uri,
        "#?",
        qs.stringify({
            id_token: idToken,
            state,
        }),
    ].join("");
    res.status(302).location(redirectUrl).send();
}) as RequestHandler<any, any, any, Query>;
