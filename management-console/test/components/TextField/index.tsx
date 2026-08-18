import { render, screen } from "@testing-library/react";
import { expect } from "chai";
import sinon from "sinon";

import { WrappedTextField } from "../../../src/components/TextField";

function props(meta: { error: string; touched: boolean }, inlineError = false) {
    return {
        meta,
        input: {
            name: "field",
            value: "",
            onChange: sinon.spy(),
            onBlur: sinon.spy(),
            onFocus: sinon.spy(),
        },
        inlineError,
    } as any;
}

describe("TextField", () => {
    it("does not display an untouched error", () => {
        const { container } = render(
            <WrappedTextField {...props({ error: "error", touched: false })} />
        );
        expect(screen.queryByText("error")).to.equal(null);
        expect(container.querySelector(".ant-form-item-has-error")).to.equal(
            null
        );
    });

    it("displays a touched non-inline error as help text", () => {
        const { container } = render(
            <WrappedTextField {...props({ error: "error", touched: true })} />
        );
        expect(screen.getByText("error")).to.not.equal(null);
        expect(
            container.querySelector(".ant-form-item-has-error")
        ).to.not.equal(null);
        expect(container.querySelector(".anticon-question-circle")).to.equal(
            null
        );
    });

    it("displays a touched inline error as an input suffix", () => {
        const { container } = render(
            <WrappedTextField
                {...props({ error: "error", touched: true }, true)}
            />
        );
        expect(
            container.querySelector(".ant-form-item-has-error")
        ).to.not.equal(null);
        expect(
            container.querySelector(".anticon-question-circle")
        ).to.not.equal(null);
        expect(screen.queryByText("error")).to.equal(null);
    });
});
