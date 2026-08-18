import assert from "node:assert/strict";

import { parseLogLevel } from "../src/config";

describe("service config", () => {
    it("accepts every supported LOG_LEVEL", () => {
        for (const level of [
            "trace",
            "debug",
            "info",
            "warn",
            "error",
            "fatal",
        ]) {
            assert.equal(parseLogLevel(level), level);
        }
    });

    it("rejects unsupported LOG_LEVEL values", () => {
        assert.throws(
            () => parseLogLevel("verbose"),
            /LOG_LEVEL must be one of trace, debug, info, warn, error, fatal/
        );
    });
});
