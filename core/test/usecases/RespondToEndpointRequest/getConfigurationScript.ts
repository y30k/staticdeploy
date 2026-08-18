import { createHash } from "crypto";
import { expect } from "chai";

import getConfigurationScript from "../../../src/usecases/RespondToEndpointRequest/getConfigurationScript";

describe("getConfigurationScript", () => {
    it("generates and returns the configuration script content and sha", () => {
        const configurationScript = getConfigurationScript({ KEY: "VALUE" });
        expect(configurationScript).to.deep.equal({
            content: 'window.APP_CONFIG={"KEY":"VALUE"};',
            sha256: "US+OjL8S9TNtlcjHX2ro44frMkCkcTiKXQtgIC3aPqY=",
        });
    });

    it("escapes characters that can break out of an inline script", () => {
        const configurationScript = getConfigurationScript({
            HOSTILE: "</script><script>&\u2028\u2029",
        });
        expect(configurationScript.content).to.equal(
            'window.APP_CONFIG={"HOSTILE":"\\u003c/script\\u003e\\u003cscript\\u003e\\u0026\\u2028\\u2029"};'
        );
        expect(configurationScript.content).not.to.match(/[<>&\u2028\u2029]/);
        expect(configurationScript.sha256).to.equal(
            createHash("sha256")
                .update(configurationScript.content)
                .digest("base64")
        );
    });
});
