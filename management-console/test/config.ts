import { expect } from "chai";

import config from "../src/config";

describe("management console development config", () => {
    it("uses safe canonical loopback defaults when APP_CONFIG is absent", () => {
        expect(config.apiUrl).to.equal("http://127.0.0.1:3456");
        expect(config.authEnforced).to.equal(false);
        expect(config.oidcEnabled).to.equal(false);
        expect(config.oidcRedirectUrl).to.equal("http://127.0.0.1:5173");
    });
});
