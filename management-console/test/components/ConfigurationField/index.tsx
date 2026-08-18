import { render, screen } from "@testing-library/react";
import { expect } from "chai";
import { vi } from "vitest";

vi.mock("../../../src/components/TextField", () => ({
    default: ({ name }: { name: string }) => (
        <input data-testid="configuration-input" data-field-name={name} />
    ),
}));

import { WrappedConfigurationField } from "../../../src/components/ConfigurationField";

function fields() {
    return {
        map: (renderField: any) => renderField("fieldName", 0, fields()),
        push: vi.fn(),
        remove: vi.fn(),
    } as any;
}

describe("ConfigurationField", () => {
    it("renders an optional label", () => {
        const { rerender } = render(
            <WrappedConfigurationField
                name="name"
                fields={fields()}
                meta={{} as any}
                label="label"
            />
        );
        expect(screen.getByText("label")).to.not.equal(null);
        rerender(
            <WrappedConfigurationField
                name="name"
                fields={fields()}
                meta={{} as any}
            />
        );
        expect(screen.queryByText("label")).to.equal(null);
    });

    it("renders key and value fields for every configuration pair", () => {
        render(
            <WrappedConfigurationField
                name="name"
                fields={fields()}
                meta={{} as any}
            />
        );
        const names = screen
            .getAllByTestId("configuration-input")
            .map((input) => input.getAttribute("data-field-name"));
        expect(names).to.deep.equal(["fieldName.key", "fieldName.value"]);
    });
});
