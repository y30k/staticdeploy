import { RequestHandler } from "express";

import { ISSUER } from "../state";

export default ((_req, res) => {
    res.send({
        authorization_endpoint: `${ISSUER}/oidc/authorize`,
        code_challenge_methods_supported: ["S256"],
        grant_types_supported: ["authorization_code"],
        id_token_signing_alg_values_supported: ["RS256"],
        issuer: ISSUER,
        jwks_uri: `${ISSUER}/oidc/jwks`,
        response_types_supported: ["code"],
        scopes_supported: ["openid", "profile"],
        subject_types_supported: ["public"],
        token_endpoint: `${ISSUER}/oidc/token`,
    });
}) as RequestHandler;
