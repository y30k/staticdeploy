import { expect } from "chai";

import IV2AuthorizationStorage from "../../src/dependencies/IV2AuthorizationStorage";
import V2Authorizer from "../../src/services/V2Authorizer";
import ReplaceV2Bindings from "../../src/usecases/ReplaceV2Bindings";

const principal = {
    sessionId: "10000000-0000-4000-8000-000000000001",
    subjectId: "subject",
    issuer: "https://idp.example",
    groups: ["stable-owner"],
    claimsVersion: 1,
};

describe("ReplaceV2Bindings", () => {
    it("binds replacement to the exact structured principal", async () => {
        let observed: unknown;
        const storage = {
            replaceBindings: async (input: unknown) => {
                observed = input;
                return {
                    outcome: "APPLIED",
                    resultingVersion: 2,
                    resultDigest: "a".repeat(64),
                    effectiveRole: "OWNER",
                    source: "APPLICATION_BINDING",
                } as const;
            },
        } as unknown as IV2AuthorizationStorage;
        const input = {
            applicationId: "20000000-0000-4000-8000-000000000001",
            expectedVersion: 1,
            idempotencyKey: "replacement-1",
            bindings: [{ groupId: "successor", role: "OWNER" as const }],
        };
        const result = await new ReplaceV2Bindings(
            new V2Authorizer(storage, principal)
        ).exec(input);
        expect(result.outcome).to.equal("APPLIED");
        expect(observed).to.deep.equal({ actor: principal, ...input });
    });
});
