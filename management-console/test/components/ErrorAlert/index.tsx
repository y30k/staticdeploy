import { fireEvent, render, screen } from "@testing-library/react";
import { expect } from "chai";
import sinon from "sinon";

import ErrorAlert from "../../../src/components/ErrorAlert";

describe("ErrorAlert", () => {
    it("renders retry and reload actions when retry is available", () => {
        render(<ErrorAlert message="Error message" onRetry={sinon.spy()} />);
        expect(screen.getByText("Error message")).to.not.equal(null);
        expect(screen.getByText("Retry")).to.not.equal(null);
        expect(screen.getByText("Reload the page")).to.not.equal(null);
    });

    it("calls onRetry when the retry action is clicked", () => {
        const onRetry = sinon.spy();
        render(<ErrorAlert message="Error message" onRetry={onRetry} />);
        fireEvent.click(screen.getByText("Retry"));
        expect(onRetry).to.have.callCount(1);
    });

    it("always renders the page reload action", () => {
        render(<ErrorAlert message="Error message" />);
        expect(screen.queryByText("Retry")).to.equal(null);
        expect(screen.getByText("Reload the page")).to.not.equal(null);
    });
});
