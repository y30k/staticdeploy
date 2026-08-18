import { expect } from "chai";

import IAuthenticationStrategy from "../../src/dependencies/IAuthenticationStrategy";
import Authenticator from "../../src/services/Authenticator";

describe("service Authenticator", () => {
    describe("getIdpUser", () => {
        const idpUser0 = { id: "id0", idp: "idp0" };
        const idpUser1 = { id: "id1", idp: "idp1" };

        it("returns null if the passed in auth token is null", async () => {
            const authenticationStrategies: IAuthenticationStrategy[] = [
                { getIdpUserFromAuthToken: async () => idpUser0 },
            ];
            const authenticator = new Authenticator(
                authenticationStrategies,
                null
            );
            const idpUser = await authenticator.getIdpUser();
            expect(idpUser).to.equal(null);
        });

        describe("returns the first non-null idp user returned by one of the authentications trategies", () => {
            it("case: first authentication strategy returns a non-null idp user", async () => {
                const authenticationStrategies: IAuthenticationStrategy[] = [
                    { getIdpUserFromAuthToken: async () => idpUser0 },
                    { getIdpUserFromAuthToken: async () => null },
                ];
                const authenticator = new Authenticator(
                    authenticationStrategies,
                    "authToken"
                );
                const idpUser = await authenticator.getIdpUser();
                expect(idpUser).to.equal(idpUser0);
            });

            it("case: second authentication strategy returns a non-null idp user", async () => {
                const authenticationStrategies: IAuthenticationStrategy[] = [
                    { getIdpUserFromAuthToken: async () => null },
                    { getIdpUserFromAuthToken: async () => idpUser1 },
                ];
                const authenticator = new Authenticator(
                    authenticationStrategies,
                    "authToken"
                );
                const idpUser = await authenticator.getIdpUser();
                expect(idpUser).to.equal(idpUser1);
            });

            it("case: first and second authentication strategy return a non-null idp user", async () => {
                const authenticationStrategies: IAuthenticationStrategy[] = [
                    { getIdpUserFromAuthToken: async () => idpUser0 },
                    { getIdpUserFromAuthToken: async () => idpUser1 },
                ];
                const authenticator = new Authenticator(
                    authenticationStrategies,
                    "authToken"
                );
                const idpUser = await authenticator.getIdpUser();
                expect(idpUser).to.equal(idpUser0);
            });
        });

        it("runs authentication strategies sequentially and stops at the first match", async () => {
            const calls: number[] = [];
            const authenticationStrategies: IAuthenticationStrategy[] = [
                {
                    getIdpUserFromAuthToken: async () => {
                        calls.push(0);
                        return null;
                    },
                },
                {
                    getIdpUserFromAuthToken: async () => {
                        calls.push(1);
                        return idpUser1;
                    },
                },
                {
                    getIdpUserFromAuthToken: async () => {
                        calls.push(2);
                        return idpUser0;
                    },
                },
            ];
            const authenticator = new Authenticator(
                authenticationStrategies,
                "authToken"
            );

            expect(await authenticator.getIdpUser()).to.equal(idpUser1);
            expect(calls).to.deep.equal([0, 1]);
        });

        it("rejects if an authentication strategy rejects", async () => {
            const expectedError = new Error("strategy failed");
            let secondStrategyCalled = false;
            const authenticationStrategies: IAuthenticationStrategy[] = [
                {
                    getIdpUserFromAuthToken: async () => {
                        throw expectedError;
                    },
                },
                {
                    getIdpUserFromAuthToken: async () => {
                        secondStrategyCalled = true;
                        return null;
                    },
                },
            ];
            const authenticator = new Authenticator(
                authenticationStrategies,
                "authToken"
            );

            await expect(authenticator.getIdpUser()).to.be.rejectedWith(
                expectedError
            );
            expect(secondStrategyCalled).to.equal(false);
        });

        describe("returns null if all authentication strategies return null", () => {
            it("case: 0 authentication strategies", async () => {
                const authenticator = new Authenticator([], "authToken");
                const idpUser = await authenticator.getIdpUser();
                expect(idpUser).to.equal(null);
            });

            it("case: 1 authentication strategy", async () => {
                const authenticationStrategies: IAuthenticationStrategy[] = [
                    { getIdpUserFromAuthToken: async () => null },
                ];
                const authenticator = new Authenticator(
                    authenticationStrategies,
                    "authToken"
                );
                const idpUser = await authenticator.getIdpUser();
                expect(idpUser).to.equal(null);
            });

            it("case: multiple authentication strategies", async () => {
                const authenticationStrategies: IAuthenticationStrategy[] = [
                    { getIdpUserFromAuthToken: async () => null },
                    { getIdpUserFromAuthToken: async () => null },
                ];
                const authenticator = new Authenticator(
                    authenticationStrategies,
                    "authToken"
                );
                const idpUser = await authenticator.getIdpUser();
                expect(idpUser).to.equal(null);
            });
        });
    });
});
