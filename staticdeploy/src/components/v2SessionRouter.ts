import {
    V2AuthenticatedSession,
    V2OidcSessions,
} from "@staticdeploy/pg-s3-storages";
import express from "express";

import IRequestWithAuthToken from "../common/IRequestWithAuthToken";
import V2SessionAuthenticationStrategy from "./V2SessionAuthenticationStrategy";

export interface V2SessionRequest extends express.Request {
    v2Session?: V2AuthenticatedSession;
}

const reject = (
    res: express.Response,
    status = 401,
    clearCookie?: string
): void => {
    if (clearCookie !== undefined) res.set("set-cookie", clearCookie);
    res.status(status).set("cache-control", "no-store").json({
        message: "Authentication failed",
    });
};

const duplicateRawHeader = (
    request: express.Request,
    headerName: string
): boolean => {
    let matches = 0;
    for (let index = 0; index < request.rawHeaders.length; index += 2)
        if (request.rawHeaders[index].toLowerCase() === headerName) matches++;
    return matches !== 1;
};

const isUnsafe = (method: string): boolean =>
    !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());

const precheckMutation = (
    sessions: V2OidcSessions,
    request: express.Request,
    contentType: "application/json" | "application/octet-stream"
): void => {
    if (
        duplicateRawHeader(request, "origin") ||
        duplicateRawHeader(request, "content-type") ||
        duplicateRawHeader(request, "x-staticdeploy-csrf")
    )
        throw new Error("ambiguous request headers");
    sessions.assertRequestShape(
        request.headers.origin,
        request.headers["content-type"],
        contentType
    );
};

export function requireV2ApiSession(
    sessions: V2OidcSessions,
    authentication: V2SessionAuthenticationStrategy,
    maxRequestBodySize: string
): express.Router {
    const router = express.Router();
    router.use(async (request, response, next) => {
        try {
            if (!isUnsafe(request.method)) {
                const accepted = await sessions.authenticate(
                    request.headers.cookie
                );
                if (accepted === null)
                    return reject(response, 401, sessions.clearSessionCookie);
                (request as V2SessionRequest).v2Session = accepted;
                (request as IRequestWithAuthToken).authToken =
                    authentication.issue(accepted);
                return next();
            }
            precheckMutation(sessions, request, "application/json");
            const inspected = await sessions.inspect(request.headers.cookie);
            if (inspected === null)
                return reject(response, 401, sessions.clearSessionCookie);
            sessions.validateMutation(
                inspected,
                request.headers.origin,
                request.header("x-staticdeploy-csrf") ?? undefined,
                request.headers["content-type"],
                "application/json"
            );
            (request as V2SessionRequest).v2Session = inspected;
            return next();
        } catch {
            return reject(response, 401, sessions.clearSessionCookie);
        }
    });
    router.use(express.json({ limit: maxRequestBodySize, strict: true }));
    router.use(
        async (
            request: V2SessionRequest,
            response: express.Response,
            next: express.NextFunction
        ) => {
            if (!isUnsafe(request.method)) return next();
            try {
                const accepted = await sessions.acceptInspected(
                    request.v2Session!
                );
                if (accepted === null)
                    return reject(response, 401, sessions.clearSessionCookie);
                request.v2Session = accepted;
                (request as IRequestWithAuthToken).authToken =
                    authentication.issue(accepted);
                return next();
            } catch {
                return reject(response, 401, sessions.clearSessionCookie);
            }
        }
    );
    router.use(
        (
            _error: unknown,
            _request: express.Request,
            response: express.Response,
            _next: express.NextFunction
        ) => reject(response, 400)
    );
    return router;
}

export default function v2SessionRouter(
    sessions: V2OidcSessions
): express.Router {
    const router = express.Router();
    router.get("/login", async (request, response) => {
        try {
            // Express trust-proxy is disabled; only the direct peer socket is
            // used for admission, never caller-controlled forwarded headers.
            const login = await sessions.beginLogin(
                request.socket.remoteAddress ?? "unknown-peer"
            );
            response
                .status(302)
                .set("cache-control", "no-store")
                .set("set-cookie", login.loginCookie)
                .set("location", login.authorizationUrl)
                .end();
        } catch {
            reject(response, 503);
        }
    });
    router.get("/callback", async (request, response) => {
        const redirect = () =>
            response
                .status(303)
                .set("cache-control", "no-store")
                .set("set-cookie", sessions.clearLoginCookie)
                .set("location", sessions.portalRedirectUrl)
                .end();
        try {
            if (typeof request.query.state !== "string") return redirect();
            if (
                typeof request.query.code !== "string" ||
                request.query.code.length < 1 ||
                request.query.code.length > 4096 ||
                request.query.error !== undefined
            ) {
                await sessions.consumeFailedLogin(
                    request.query.state,
                    request.headers.cookie
                );
                return redirect();
            }
            const current = await sessions.inspect(request.headers.cookie);
            const result = await sessions.finishLogin(
                request.query.state,
                request.query.code,
                request.headers.cookie,
                current?.id
            );
            return response
                .status(303)
                .set("cache-control", "no-store")
                .set("set-cookie", [result.cookie, result.clearLoginCookie])
                .set("location", sessions.portalRedirectUrl)
                .end();
        } catch {
            return redirect();
        }
    });
    router.get("/session", async (request, response) => {
        try {
            const session = await sessions.authenticate(request.headers.cookie);
            if (session === null)
                return reject(response, 401, sessions.clearSessionCookie);
            response.status(200).set("cache-control", "no-store").json({
                subjectId: session.subjectId,
                issuer: session.issuer,
                claims: session.claims,
                csrfToken: session.csrfToken,
            });
        } catch {
            reject(response, 401, sessions.clearSessionCookie);
        }
    });
    router.post(
        "/logout",
        async (request, response, next) => {
            try {
                precheckMutation(sessions, request, "application/json");
                const inspected = await sessions.inspect(
                    request.headers.cookie
                );
                if (inspected === null)
                    return reject(response, 401, sessions.clearSessionCookie);
                sessions.validateMutation(
                    inspected,
                    request.headers.origin,
                    request.header("x-staticdeploy-csrf") ?? undefined,
                    request.headers["content-type"],
                    "application/json"
                );
                (request as V2SessionRequest).v2Session = inspected;
                return next();
            } catch {
                return reject(response, 401, sessions.clearSessionCookie);
            }
        },
        express.json({ limit: "1kb", strict: true }),
        async (request: V2SessionRequest, response) => {
            try {
                if (
                    request.body === null ||
                    typeof request.body !== "object" ||
                    Array.isArray(request.body) ||
                    Object.keys(request.body).length !== 0
                )
                    return reject(response, 400);
                const accepted = await sessions.acceptInspected(
                    request.v2Session!
                );
                if (accepted === null)
                    return reject(response, 401, sessions.clearSessionCookie);
                const cookie = await sessions.logout(request.headers.cookie);
                return response
                    .status(204)
                    .set("cache-control", "no-store")
                    .set("set-cookie", cookie)
                    .end();
            } catch {
                return reject(response, 401, sessions.clearSessionCookie);
            }
        }
    );
    router.use(
        (
            _error: unknown,
            _request: express.Request,
            response: express.Response,
            _next: express.NextFunction
        ) => reject(response, 400)
    );
    return router;
}
