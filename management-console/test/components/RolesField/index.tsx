import { render, screen } from "@testing-library/react";
import { expect } from "chai";
import { vi } from "vitest";

vi.mock("../../../src/components/TextField", () => ({
    default: ({ name }: { name: string }) => (
        <input data-testid="role-input" data-field-name={name} />
    ),
}));

import { WrappedRolesField } from "../../../src/components/RolesField";

function fields() {
    return {
        map: (renderField: any) => renderField("fieldName", 0, fields()),
        push: vi.fn(),
        remove: vi.fn(),
    } as any;
}

describe("RolesField", () => {
    it("renders an optional label", () => {
        const { rerender } = render(
            <WrappedRolesField
                name="name"
                fields={fields()}
                meta={{} as any}
                label="label"
            />
        );
        expect(screen.getByText("label")).to.not.equal(null);
        rerender(
            <WrappedRolesField name="name" fields={fields()} meta={{} as any} />
        );
        expect(screen.queryByText("label")).to.equal(null);
    });

    it("renders the role field name supplied by redux-form", () => {
        render(
            <WrappedRolesField name="name" fields={fields()} meta={{} as any} />
        );
        expect(
            screen.getByTestId("role-input").getAttribute("data-field-name")
        ).to.equal("fieldName");
    });
});
