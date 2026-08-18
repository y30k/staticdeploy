import { render, screen } from "@testing-library/react";
import { expect } from "chai";

import ConfigurationFieldRO from "../../../src/components/ConfigurationFieldRO";

describe("ConfigurationFieldRO", () => {
    it("renders every configuration key and value", () => {
        render(
            <ConfigurationFieldRO
                title="title"
                configuration={{ key0: "value0", key1: "value1" }}
            />
        );
        for (const text of ["key0", "key1", "value0", "value1"]) {
            expect(screen.getByText(text)).to.not.equal(null);
        }
    });
});
