import { render, screen } from "@testing-library/react";
import { expect } from "chai";

import RolesFieldRO from "../../../src/components/RolesFieldRO";

describe("RolesFieldRO", () => {
    it("renders each role", () => {
        render(
            <RolesFieldRO
                title="title"
                roles={["root", "app-manager:12345678"]}
            />
        );
        expect(screen.getByText("root")).to.not.equal(null);
        expect(screen.getByText("app-manager:12345678")).to.not.equal(null);
    });
});
