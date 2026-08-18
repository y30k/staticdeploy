import buildCsp from "content-security-policy-builder";
import parseCsp from "content-security-policy-parser";
import { castArray, compact, keys } from "lodash";

const CSP_HEADER_REGEX = /^content-security-policy$/i;
const SCRIPT_SRC_DIRECTIVE = "script-src";

export default function whitelistInlineScript(
    headers: {
        [name: string]: string;
    },
    inlineScriptSha256: string
): { [name: string]: string } {
    const cspHeaderKey = keys(headers).find((headerKey) =>
        CSP_HEADER_REGEX.test(headerKey)
    );

    // If no CSP header is defined, don't inject anything
    if (!cspHeaderKey) {
        return headers;
    }

    const cspHeaderValue = headers[cspHeaderKey];
    const cspDirectives = cspHeaderValue
        ? parseCsp(cspHeaderValue)
        : new Map<string, string[]>();
    const directives = new Map(cspDirectives);
    directives.set(
        SCRIPT_SRC_DIRECTIVE,
        compact([
            ...castArray(cspDirectives.get(SCRIPT_SRC_DIRECTIVE)),
            `'sha256-${inlineScriptSha256}'`,
        ])
    );

    return {
        ...headers,
        [cspHeaderKey]: buildCsp({ directives }),
    };
}
