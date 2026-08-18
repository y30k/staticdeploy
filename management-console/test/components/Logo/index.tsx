import { render, screen } from "@testing-library/react";
import { expect } from "chai";

import Logo from "../../../src/components/Logo";

describe("Logo", () => {
    it("renders an image", () => {
        render(<Logo withShadow={false} />);
        expect(screen.getByRole("img", { name: "logo" })).to.not.equal(null);
    });
});
