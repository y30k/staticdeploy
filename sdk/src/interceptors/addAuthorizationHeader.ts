import { InternalAxiosRequestConfig } from "axios";
import isFunction from "lodash/isFunction";

export default function addAuthorizationHeader(
    apiTokenOrGetApiToken: string | null | (() => Promise<string | null>)
) {
    return async (
        requestConfig: InternalAxiosRequestConfig
    ): Promise<InternalAxiosRequestConfig> => {
        const apiToken = isFunction(apiTokenOrGetApiToken)
            ? await apiTokenOrGetApiToken()
            : apiTokenOrGetApiToken;
        if (apiToken) {
            requestConfig.headers.set("Authorization", `Bearer ${apiToken}`);
        }
        return requestConfig;
    };
}
