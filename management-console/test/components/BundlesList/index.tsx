import { IBundle } from "@staticdeploy/core/browser";
import { render, screen } from "@testing-library/react";
import { expect } from "chai";

import BundlesList from "../../../src/components/BundlesList";

function getBundle(partial: Partial<IBundle>) {
    return {
        id: "0",
        name: "name",
        tag: "tag",
        description: "description",
        hash: "hash",
        assets: [
            {
                path: "/fallback",
                mimeType: "application/octet-stream",
                headers: {},
            },
        ],
        fallbackAssetPath: "/fallback",
        fallbackStatusCode: 200,
        createdAt: new Date("1970"),
        ...partial,
    };
}

describe("BundlesList", () => {
    it("renders bundles ordered by createdAt descending", () => {
        render(
            <BundlesList
                bundles={[
                    getBundle({ id: "bundle-0", createdAt: new Date("1970") }),
                    getBundle({ id: "bundle-1", createdAt: new Date("1971") }),
                    getBundle({ id: "bundle-2", createdAt: new Date("1972") }),
                ]}
            />
        );
        const rows = screen.getAllByRole("row").slice(1);
        const renderedIds = rows.map(
            (row) => row.querySelector("code")?.textContent
        );
        expect(renderedIds).to.deep.equal(["bundle-2", "bundle-1", "bundle-0"]);
    });
});
