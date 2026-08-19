import { expect } from "chai";
import sinon from "sinon";

import ServerSessionAuthStrategy from "../../../src/common/AuthService/ServerSessionAuthStrategy";

describe("ServerSessionAuthStrategy", () => {
    beforeEach(() => {
        window.localStorage.clear();
        window.sessionStorage.clear();
    });
    afterEach(() => sinon.restore());

    it("keeps CSRF in memory and sends no bearer or OIDC token", async () => {
        const fetchStub = sinon.stub(globalThis, "fetch");
        fetchStub.onFirstCall().resolves(
            new Response(JSON.stringify({ csrfToken: "csrf-memory" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            })
        );
        fetchStub.onSecondCall().resolves(new Response(null, { status: 204 }));
        window.localStorage.setItem("oidc.user:legacy", "id-token-canary");
        window.sessionStorage.setItem("oidc.state:legacy", "state-canary");
        window.localStorage.setItem("unrelated", "preserved");
        const strategy = new ServerSessionAuthStrategy(
            "/api/v2/auth",
            "Provider"
        );
        await strategy.init();
        expect(strategy.getCsrfToken()).to.equal("csrf-memory");
        expect(await strategy.getAuthToken()).to.equal("server-session");
        expect(fetchStub.firstCall.args[1]?.headers).not.to.have.property(
            "Authorization"
        );
        expect(window.localStorage.getItem("oidc.user:legacy")).to.equal(null);
        expect(window.sessionStorage.getItem("oidc.state:legacy")).to.equal(
            null
        );
        expect(window.localStorage.getItem("unrelated")).to.equal("preserved");
        await strategy.logout();
        expect(fetchStub.secondCall.args[1]?.headers).to.deep.equal({
            "Content-Type": "application/json",
            "X-StaticDeploy-CSRF": "csrf-memory",
        });
        expect(strategy.getCsrfToken()).to.equal(null);
    });

    it("keeps authenticated state when server logout fails", async () => {
        const fetchStub = sinon.stub(globalThis, "fetch");
        fetchStub.onFirstCall().resolves(
            new Response(JSON.stringify({ csrfToken: "csrf-memory" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            })
        );
        fetchStub.onSecondCall().resolves(new Response(null, { status: 500 }));
        const strategy = new ServerSessionAuthStrategy(
            "/api/v2/auth",
            "Provider"
        );
        await strategy.init();
        let failed = false;
        try {
            await strategy.logout();
        } catch {
            failed = true;
        }
        expect(failed).to.equal(true);
        expect(strategy.getCsrfToken()).to.equal("csrf-memory");
        expect(await strategy.getAuthToken()).to.equal("server-session");
    });
});
