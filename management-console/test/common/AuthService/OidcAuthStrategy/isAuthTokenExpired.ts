import { expect } from "chai";

import isAuthTokenExpired from "../../../../src/common/AuthService/OidcAuthStrategy/isAuthTokenExpired";

function jwtWithExpiration(expiration: number) {
    const encode = (value: object) =>
        Buffer.from(JSON.stringify(value)).toString("base64url");
    return `${encode({ alg: "none", typ: "JWT" })}.${encode({ exp: expiration })}.`;
}

describe("OidcAuthStrategy util isAuthTokenExpired", () => {
    describe("returns whether a jwt auth token is expired", () => {
        it("case: expired", () => {
            const nowInSeconds = Date.now() / 1000;
            expect(
                isAuthTokenExpired(jwtWithExpiration(nowInSeconds - 1000))
            ).to.equal(true);
        });

        it("case: not expired", () => {
            const nowInSeconds = Date.now() / 1000;
            expect(
                isAuthTokenExpired(jwtWithExpiration(nowInSeconds + 1000))
            ).to.equal(false);
        });
    });
});
