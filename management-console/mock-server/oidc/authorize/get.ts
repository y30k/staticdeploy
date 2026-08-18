import { Request, RequestHandler } from "express";

import { CLIENT_ID, createAuthorizationCode, REDIRECT_URIS } from "../state";

interface Query {
    client_id?: string;
    code_challenge?: string;
    code_challenge_method?: string;
    nonce?: string;
    redirect_uri?: string;
    response_type?: string;
    state?: string;
}

export default ((req: Request<any, any, any, Query>, res) => {
    const {
        client_id,
        code_challenge,
        code_challenge_method,
        nonce,
        redirect_uri,
        response_type,
        state,
    } = req.query;
    if (
        client_id !== CLIENT_ID ||
        response_type !== "code" ||
        code_challenge_method !== "S256" ||
        typeof code_challenge !== "string" ||
        !/^[A-Za-z0-9_-]{43,128}$/.test(code_challenge) ||
        typeof nonce !== "string" ||
        nonce.length < 8 ||
        nonce.length > 256 ||
        typeof state !== "string" ||
        state.length < 8 ||
        state.length > 512 ||
        typeof redirect_uri !== "string" ||
        !REDIRECT_URIS.has(redirect_uri)
    ) {
        res.status(400).send({ message: "Invalid authorization request" });
        return;
    }

    const code = createAuthorizationCode({
        challenge: code_challenge,
        clientId: client_id,
        nonce,
        redirectUri: redirect_uri,
    });
    const redirect = new URL(redirect_uri);
    redirect.searchParams.set("code", code);
    redirect.searchParams.set("state", state);
    res.redirect(302, redirect.toString());
}) as RequestHandler<any, any, any, Query>;
