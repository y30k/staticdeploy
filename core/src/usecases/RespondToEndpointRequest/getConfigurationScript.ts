import { createHash } from "crypto";

import { IConfiguration } from "../../entities/Configuration";

export interface IConfigurationScript {
    content: string;
    sha256: string;
}

const scriptSafeJson = (value: unknown): string =>
    JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (character) => {
        const codePoint = character.codePointAt(0);
        if (codePoint === undefined) throw new TypeError("Invalid character");
        return `\\u${codePoint.toString(16).padStart(4, "0")}`;
    });

export default function getConfigurationScript(
    configuration: IConfiguration
): IConfigurationScript {
    const content = `window.APP_CONFIG=${scriptSafeJson(configuration)};`;
    return {
        content: content,
        sha256: createHash("sha256").update(content).digest("base64"),
    };
}
