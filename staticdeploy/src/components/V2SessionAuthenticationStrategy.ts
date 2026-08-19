import { IAuthenticationStrategy } from "@staticdeploy/core";
import { V2AuthenticatedSession } from "@staticdeploy/pg-s3-storages";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Bridges an already validated server session into the legacy use-case identity. */
export default class V2SessionAuthenticationStrategy
    implements IAuthenticationStrategy
{
    private readonly key = randomBytes(32);

    issue(session: V2AuthenticatedSession): string {
        const payload = Buffer.from(
            JSON.stringify({ id: session.subjectId, idp: session.issuer }),
            "utf8"
        ).toString("base64url");
        const signature = createHmac("sha256", this.key)
            .update(payload, "ascii")
            .digest("base64url");
        return `v2-session.${payload}.${signature}`;
    }

    async getIdpUserFromAuthToken(token: string) {
        const parts = token.split(".");
        if (parts.length !== 3 || parts[0] !== "v2-session") return null;
        const expected = createHmac("sha256", this.key)
            .update(parts[1], "ascii")
            .digest();
        let actual: Buffer;
        try {
            actual = Buffer.from(parts[2], "base64url");
        } catch {
            return null;
        }
        if (
            actual.length !== expected.length ||
            !timingSafeEqual(actual, expected)
        )
            return null;
        try {
            const value = JSON.parse(
                Buffer.from(parts[1], "base64url").toString("utf8")
            ) as unknown;
            if (
                value === null ||
                typeof value !== "object" ||
                !("id" in value) ||
                !("idp" in value) ||
                typeof value.id !== "string" ||
                typeof value.idp !== "string"
            )
                return null;
            return { id: value.id, idp: value.idp };
        } catch {
            return null;
        }
    }
}
