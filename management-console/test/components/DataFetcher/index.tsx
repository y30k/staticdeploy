import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect } from "chai";
import sinon from "sinon";

import StaticdeployClientContext from "../../../src/common/StaticdeployClientContext";
import DataFetcher from "../../../src/components/DataFetcher";

const staticdeployClient = {} as any;

function ResultView(props: any) {
    return (
        <div>
            <span>{`${props.result}:${props.propKey}`}</span>
            <button onClick={props.refetch}>Refetch</button>
        </div>
    );
}

function renderFetcher(
    fetchData: sinon.SinonStub,
    extra: Record<string, unknown> = {}
) {
    const props = {
        fetchData,
        shouldRefetch: sinon.stub().returns(false),
        Component: ResultView,
        proxiedProps: { propKey: "propValue" },
        ...extra,
    };
    const view = render(
        <StaticdeployClientContext.Provider value={staticdeployClient}>
            <DataFetcher {...(props as any)} />
        </StaticdeployClientContext.Provider>
    );
    return { ...view, props };
}

describe("DataFetcher", () => {
    it("fetches with the client and proxied props on mount", async () => {
        const fetchData = sinon.stub().resolves("result");
        renderFetcher(fetchData);
        await screen.findByText("result:propValue");
        expect(fetchData).to.have.been.calledOnceWith(staticdeployClient, {
            propKey: "propValue",
        });
    });

    it("renders a spinner while a request is pending", () => {
        const fetchData = sinon.stub().returns(new Promise(() => undefined));
        const { container } = renderFetcher(fetchData);
        expect(container.querySelector(".ant-spin")).to.not.equal(null);
    });

    it("passes a refetch action to the result component", async () => {
        const fetchData = sinon.stub().resolves("result");
        renderFetcher(fetchData);
        fireEvent.click(await screen.findByRole("button", { name: "Refetch" }));
        await waitFor(() => expect(fetchData).to.have.callCount(2));
    });

    it("renders request failures and a retry action", async () => {
        const fetchData = sinon.stub().rejects(new Error("Error message"));
        renderFetcher(fetchData);
        expect(await screen.findByText("Error message")).to.not.equal(null);
        expect(screen.getByText("Retry")).to.not.equal(null);
    });

    it("refetches when changed proxied props require it", async () => {
        const fetchData = sinon.stub().resolves("result");
        const shouldRefetch = sinon.stub().returns(true);
        const { rerender } = renderFetcher(fetchData, { shouldRefetch });
        await screen.findByText("result:propValue");
        rerender(
            <StaticdeployClientContext.Provider value={staticdeployClient}>
                <DataFetcher
                    fetchData={fetchData}
                    shouldRefetch={shouldRefetch}
                    Component={ResultView}
                    proxiedProps={{ propKey: "nextValue" }}
                />
            </StaticdeployClientContext.Provider>
        );
        await screen.findByText("result:nextValue");
        expect(fetchData).to.have.callCount(2);
    });
});
