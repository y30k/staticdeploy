import { expect } from "chai";

import injectMakeUsecase from "../../src/middleware/injectMakeUsecase";

describe("M3-07 v2 authorization integration", () => {
    it("resolves the post-session principal through the internal core use case", async () => {
        let observed: unknown;
        const authorization = {
            authorize: async (
                actor: unknown,
                applicationId: string,
                capability: string
            ) => ({
                actor,
                applicationId,
                capability,
                allowed: true,
            }),
            authorizeApplicationCreate: async (actor: unknown) => ({
                actor,
                allowed: true,
            }),
            replaceBindings: async (input: unknown) => {
                observed = input;
                return {
                    outcome: "APPLIED",
                    resultingVersion: 2,
                    resultDigest: "a".repeat(64),
                    effectiveRole: "OWNER",
                    source: "APPLICATION_BINDING",
                };
            },
        };
        const request: any = { authToken: null };
        injectMakeUsecase({} as any, {
            archiver: {} as any,
            authenticationStrategies: [],
            config: { enforceAuth: true },
            storages: {} as any,
            v2Authorization: authorization as any,
        })(request, {} as any, () => undefined);
        request.v2Principal = {
            sessionId: "10000000-0000-4000-8000-000000000001",
            subjectId: "subject",
            issuer: "https://idp.example",
            groups: ["stable-owner"],
            claimsVersion: 1,
        };
        const authorizer = request.makeV2Authorizer();
        expect(
            await authorizer.authorize(
                "20000000-0000-4000-8000-000000000001",
                "APPLICATION_READ"
            )
        ).to.include({ allowed: true, capability: "APPLICATION_READ" });
        expect(await authorizer.authorizeApplicationCreate()).to.include({
            allowed: true,
        });
        await request.makeReplaceV2Bindings().exec({
            applicationId: "20000000-0000-4000-8000-000000000001",
            expectedVersion: 1,
            idempotencyKey: "replace-1",
            bindings: [{ groupId: "successor", role: "OWNER" }],
        });
        expect((observed as any).actor).to.deep.equal(request.v2Principal);
        expect(
            ((await authorizer.authorizeApplicationCreate()) as any).actor
        ).to.deep.equal(request.v2Principal);
    });
});
