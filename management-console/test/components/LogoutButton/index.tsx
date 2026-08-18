import { fireEvent, render } from "@testing-library/react";
import { expect } from "chai";
import sinon from "sinon";

import LogoutButton from "../../../src/components/LogoutButton";

describe("LogoutButton", () => {
    it("doesn't render when auth is not enforced", () => {
        const { container } = render(
            <LogoutButton authService={{ authEnforced: false } as any} />
        );
        expect(container.childElementCount).to.equal(0);
    });

    it("calls the auth service logout method when clicked", () => {
        const authService = { authEnforced: true, logout: sinon.spy() };
        const { container } = render(
            <LogoutButton authService={authService as any} />
        );
        fireEvent.click(container.querySelector(".c-LogoutButton")!);
        expect(authService.logout).to.have.callCount(1);
    });
});
