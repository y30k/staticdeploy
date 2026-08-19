import { expect } from "chai";

import IV2AuthorizationStorage from "../../src/dependencies/IV2AuthorizationStorage";
import V2Authorizer from "../../src/services/V2Authorizer";

const principal = {
    sessionId: "10000000-0000-4000-8000-000000000001",
    subjectId: "subject",
    issuer: "https://idp.example",
    groups: ["stable-group"],
    claimsVersion: 1,
};

describe("V2Authorizer", () => {
    it("passes the exact structured server principal to the policy", async () => {
        let observed: unknown;
        const storage = {
            authorize: async (actor: unknown) => {
                observed = actor;
                return {
                    allowed: true,
                    effectiveRole: "OWNER",
                    source: "APPLICATION_BINDING",
                    bindingVersion: 1,
                } as const;
            },
        } as unknown as IV2AuthorizationStorage;
        const decision = await new V2Authorizer(storage, principal).authorize(
            "20000000-0000-4000-8000-000000000001",
            "APPLICATION_UPDATE"
        );
        expect(decision.allowed).to.equal(true);
        expect(observed).to.deep.equal(principal);
    });

    it("fails closed without the server principal", async () => {
        const storage = {} as IV2AuthorizationStorage;
        expect(() =>
            new V2Authorizer(storage, undefined).authorize(
                "20000000-0000-4000-8000-000000000001",
                "APPLICATION_READ"
            )
        ).to.throw("v2 server principal is required");
    });
});
