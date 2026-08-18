import { Request, RequestHandler, Response } from "express";

import { CLIENT_ID, createToken, redeemAuthorizationCode } from "../state";

interface TokenBody {
    client_id?: string;
    code?: string;
    code_verifier?: string;
    grant_type?: string;
    redirect_uri?: string;
}

export default (async (
    req: Request<Record<string, never>, unknown, TokenBody>,
    res: Response
) => {
    const { client_id, code, code_verifier, grant_type, redirect_uri } =
        req.body;
    if (
        client_id !== CLIENT_ID ||
        grant_type !== "authorization_code" ||
        typeof code !== "string" ||
        typeof code_verifier !== "string" ||
        typeof redirect_uri !== "string"
    ) {
        res.status(400).send({ error: "invalid_request" });
        return;
    }
    const authorization = redeemAuthorizationCode({
        clientId: client_id,
        code,
        redirectUri: redirect_uri,
        verifier: code_verifier,
    });
    if (!authorization) {
        res.status(400).send({ error: "invalid_grant" });
        return;
    }
    res.setHeader("cache-control", "no-store");
    res.setHeader("pragma", "no-cache");
    res.send({
        access_token: await createToken(authorization.nonce, client_id),
        expires_in: 300,
        id_token: await createToken(authorization.nonce, client_id),
        scope: "openid profile",
        token_type: "Bearer",
    });
}) as RequestHandler<Record<string, never>, unknown, TokenBody>;
