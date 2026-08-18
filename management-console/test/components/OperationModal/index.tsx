import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect } from "chai";
import sinon from "sinon";

import OperationModal from "../../../src/components/OperationModal";

function openModal(operation: sinon.SinonStub) {
    render(
        <OperationModal
            title="title"
            operation={operation}
            trigger={<button>Open operation</button>}
        >
            <div>Operation content</div>
        </OperationModal>
    );
    fireEvent.click(screen.getByRole("button", { name: "Open operation" }));
}

describe("OperationModal", () => {
    it("opens and renders its children from the trigger", () => {
        openModal(sinon.stub().resolves("result"));
        expect(screen.getByRole("dialog")).to.not.equal(null);
        expect(screen.getByText("Operation content")).to.not.equal(null);
    });

    it("replaces its children with success content after completion", async () => {
        openModal(sinon.stub().resolves("result"));
        fireEvent.click(
            screen.getByRole("button", { name: "Start operation" })
        );
        await screen.findByText("Operation succeeded");
        expect(screen.queryByText("Operation content")).to.equal(null);
    });

    it("retains its children and shows the error after failure", async () => {
        openModal(sinon.stub().rejects(new Error("operation failed")));
        fireEvent.click(
            screen.getByRole("button", { name: "Start operation" })
        );
        await waitFor(
            () => expect(screen.getByText("operation failed")).to.exist
        );
        expect(screen.getByText("Operation content")).to.not.equal(null);
    });
});
