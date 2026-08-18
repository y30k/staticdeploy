import { expect } from "chai";
import sinon from "sinon";

import OidcAuthStrategy from "../../../../src/common/AuthService/OidcAuthStrategy";

const makeStrategy = () =>
    new OidcAuthStrategy(
        "https://issuer.example/.well-known/openid-configuration",
        "management-console",
        "https://console.example/",
        "Example Identity"
    );

const jwtWithExpiration = (expiration: number) => {
    const encode = (value: object) =>
        Buffer.from(JSON.stringify(value)).toString("base64url");
    return `${encode({ alg: "none", typ: "JWT" })}.${encode({ exp: expiration })}.`;
};

describe("OidcAuthStrategy", () => {
    afterEach(() => {
        window.history.replaceState(null, "", "/");
        sinon.restore();
    });

    it("configures Authorization Code flow and distinct callback URLs", () => {
        const strategy = makeStrategy();
        const settings = (strategy as any).userManager.settings;

        expect(settings.authority).to.equal("https://issuer.example");
        expect(settings.metadataUrl).to.equal(
            "https://issuer.example/.well-known/openid-configuration"
        );
        expect(settings.client_id).to.equal("management-console");
        expect(settings.response_type).to.equal("code");
        expect(settings.response_mode).to.equal("query");
        expect(settings.redirect_uri).to.equal(
            "https://console.example/?oidcRedirect=true"
        );
        expect(settings.silent_redirect_uri).to.equal(
            "https://console.example/?oidcSilentRedirect=true"
        );
        expect(settings.loadUserInfo).to.equal(false);
        expect(strategy.displayName).to.equal("Example Identity");
    });

    it("completes the interactive callback without propagating provider errors", async () => {
        window.history.replaceState(null, "", "/?oidcRedirect=true");
        const strategy = makeStrategy();
        const manager = {
            signinRedirectCallback: sinon.stub().rejects(new Error("invalid")),
            signinSilentCallback: sinon.stub(),
        };
        (strategy as any).userManager = manager;

        await strategy.init();

        expect(manager.signinRedirectCallback.callCount).to.equal(1);
        expect(manager.signinSilentCallback.callCount).to.equal(0);
    });

    it("completes the silent callback and avoids starting another renewal", async () => {
        window.history.replaceState(null, "", "/?oidcSilentRedirect=true");
        const strategy = makeStrategy();
        const manager = {
            signinRedirectCallback: sinon.stub(),
            signinSilentCallback: sinon.stub().resolves(),
            getUser: sinon.stub(),
        };
        (strategy as any).userManager = manager;

        await strategy.init();
        expect(await strategy.getAuthToken()).to.equal(null);

        expect(manager.signinSilentCallback.callCount).to.equal(1);
        expect(manager.signinRedirectCallback.callCount).to.equal(0);
        expect(manager.getUser.callCount).to.equal(0);
    });

    it("removes incomplete provider users instead of returning a token", async () => {
        const strategy = makeStrategy();
        const manager = {
            getUser: sinon.stub().resolves({ id_token: "", profile: {} }),
            removeUser: sinon.stub().resolves(),
        };
        (strategy as any).userManager = manager;

        expect(await strategy.getAuthToken()).to.equal(null);
        expect(manager.removeUser.callCount).to.equal(1);
    });

    it("renews an expired token with a login hint and fresh nonce", async () => {
        const strategy = makeStrategy();
        const renewed = jwtWithExpiration(Date.now() / 1000 + 3600);
        const manager = {
            getUser: sinon.stub().resolves({
                id_token: jwtWithExpiration(Date.now() / 1000 - 60),
                profile: { preferred_username: "user@example.test" },
            }),
            signinSilent: sinon
                .stub()
                .resolves({ id_token: renewed, profile: {} }),
            removeUser: sinon.stub().resolves(),
        };
        (strategy as any).userManager = manager;

        expect(await strategy.getAuthToken()).to.equal(renewed);
        expect(manager.signinSilent.callCount).to.equal(1);
        expect(manager.signinSilent.firstCall.args[0].login_hint).to.equal(
            "user@example.test"
        );
        expect(manager.signinSilent.firstCall.args[0].nonce).to.be.a("string");
        expect(manager.removeUser.callCount).to.equal(0);
    });

    it("logs out when silent renewal fails", async () => {
        const strategy = makeStrategy();
        const manager = {
            getUser: sinon.stub().resolves({
                id_token: jwtWithExpiration(Date.now() / 1000 - 60),
                profile: { sub: "subject" },
            }),
            signinSilent: sinon
                .stub()
                .rejects(new Error("provider unavailable")),
            removeUser: sinon.stub().resolves(),
        };
        (strategy as any).userManager = manager;

        expect(await strategy.getAuthToken()).to.equal(null);
        expect(manager.removeUser.callCount).to.equal(1);
    });
});
