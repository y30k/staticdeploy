import { expect } from "chai";

import { isEntrypointUrlMatcherValid as browserValidator } from "../src/browser";
import { isEntrypointUrlMatcherValid as serverValidator } from "../src/entities/Entrypoint";

describe("browser core facade", () => {
    it("keeps strict entrypoint path validation identical to the server", () => {
        const cases: Array<[string, boolean]> = [
            ["example.com/", true],
            ["example.com/path/", true],
            ["sub.example.com/path/subpath/", true],
            ["example.com/%2e%2e/", false],
            ["example.com/%2E/", false],
            ["example.com/path%2fchild/", false],
            ["example.com/path%5cchild/", false],
            ["example.com/path\\segment/", false],
            ["example.com/path?query/", false],
            ["example.com/path#fragment/", false],
            ["example.com/path\u0000/", false],
            ["example.com//", false],
            ["example.com/path//", false],
            ["example.com/./", false],
            ["example.com/path/../", false],
            ["example.com/path", false],
            ["example.com", false],
            ["example.com./", false],
            ["http://example.com/", false],
        ];
        for (const [matcher, expected] of cases) {
            expect(browserValidator(matcher), `browser: ${matcher}`).to.equal(
                expected
            );
            expect(serverValidator(matcher), `server: ${matcher}`).to.equal(
                expected
            );
        }
    });
});
