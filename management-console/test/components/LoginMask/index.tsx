import { render, screen } from "@testing-library/react";
import { expect } from "chai";
import type { ReactNode } from "react";
import { Provider } from "react-redux";
import sinon from "sinon";

import LoginMask from "../../../src/components/LoginMask";
import reduxStore from "../../../src/reduxStore";

const status = {
    authToken: null,
    isLoggingIn: false,
    isLoggedIn: false,
    loginError: null,
    requiresUserCreation: false,
    requiresUserCreationError: null,
};

function getAuthService(overrides: Record<string, unknown> = {}) {
    return {
        onStatusChange: sinon.stub(),
        offStatusChange: sinon.stub(),
        getStatus: sinon.stub().returns(status),
        authEnforced: true,
        hasAuthStrategy: sinon.stub().returns(false),
        getStrategyDisplayName: sinon.stub().returns("provider"),
        ...overrides,
    } as any;
}

function renderMask(authService: any, children?: ReactNode) {
    return render(
        <Provider store={reduxStore}>
            <LoginMask authService={authService}>{children}</LoginMask>
        </Provider>
    );
}

describe("LoginMask", () => {
    it("renders the configured OIDC login", () => {
        const authService = getAuthService();
        authService.hasAuthStrategy.withArgs("oidc").returns(true);
        renderMask(authService);
        expect(
            screen.getByRole("button", { name: "Login with provider" })
        ).to.not.equal(null);
    });

    it("renders the configured JWT login", () => {
        const authService = getAuthService();
        authService.hasAuthStrategy.withArgs("jwt").returns(true);
        renderMask(authService);
        expect(
            screen.getByRole("button", { name: "Login with provider" })
        ).to.not.equal(null);
    });

    it("shows progress while logging in", () => {
        const authService = getAuthService({
            getStatus: sinon.stub().returns({ ...status, isLoggingIn: true }),
        });
        const { container } = renderMask(authService);
        expect(container.querySelector(".ant-spin-spinning")).to.not.equal(
            null
        );
    });

    it("renders login errors", () => {
        const authService = getAuthService({
            getStatus: sinon.stub().returns({
                ...status,
                loginError: new Error("Error logging in"),
            }),
        });
        renderMask(authService);
        expect(screen.getByText("Error logging in")).to.not.equal(null);
    });

    it("renders children when auth is not enforced", () => {
        renderMask(getAuthService({ authEnforced: false }), <div>child</div>);
        expect(screen.getByText("child")).to.not.equal(null);
    });

    it("renders children when the user is logged in", () => {
        const authService = getAuthService({
            getStatus: sinon.stub().returns({ ...status, isLoggedIn: true }),
        });
        renderMask(authService, <div>child</div>);
        expect(screen.getByText("child")).to.not.equal(null);
    });
});
