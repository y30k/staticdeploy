import { expect } from "chai";

import { isEntrypointUrlMatcherValid as browserValidator } from "../src/browser";
import { isEntrypointUrlMatcherValid as serverValidator } from "../src/entities/Entrypoint";

describe("browser core facade", () => {
    it("keeps entrypoint POSIX path validation identical to the server", () => {
        const matchers = [
            "example.com/",
            "example.com/path/",
            "sub.example.com/path/subpath/",
            "example.com/%2e%2e/",
            "example.com/path\\segment/",
            "example.com//",
            "example.com/path//",
            "example.com/./",
            "example.com/path/../",
            "example.com/path",
            "example.com",
            "example.com./",
            "http://example.com/",
        ];
        for (const matcher of matchers) {
            expect(browserValidator(matcher), matcher).to.equal(
                serverValidator(matcher)
            );
        }
    });
});
