import { IOperationLog, Operation } from "@staticdeploy/core/browser";
import { render, screen } from "@testing-library/react";
import { expect } from "chai";
import { MemoryRouter } from "react-router-dom";

import OperationLogsList from "../../../src/components/OperationLogsList";

function getOperationLog(partial: Partial<IOperationLog>) {
    return {
        id: "0",
        operation: Operation.CreateApp,
        parameters: {},
        performedBy: "performedBy",
        performedAt: new Date(),
        ...partial,
    };
}

describe("OperationLogsList", () => {
    it("renders operation logs ordered by performedAt descending", () => {
        render(
            <MemoryRouter>
                <OperationLogsList
                    operationLogs={[
                        getOperationLog({
                            id: "log-0",
                            performedBy: "log-0",
                            performedAt: new Date("1970"),
                        }),
                        getOperationLog({
                            id: "log-1",
                            performedBy: "log-1",
                            performedAt: new Date("1971"),
                        }),
                        getOperationLog({
                            id: "log-2",
                            performedBy: "log-2",
                            performedAt: new Date("1972"),
                        }),
                    ]}
                />
            </MemoryRouter>
        );
        const rows = screen.getAllByRole("row").slice(1);
        const renderedIds = rows.map(
            (row) => row.querySelector("code")?.textContent
        );
        expect(renderedIds).to.deep.equal(["log-2", "log-1", "log-0"]);
    });
});
