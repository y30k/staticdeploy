import { InternalAxiosRequestConfig } from "axios";

const SAFE_METHODS = new Set(["get", "head", "options"]);

export default function addCsrfHeader(getToken: () => string | null) {
    return (
        requestConfig: InternalAxiosRequestConfig
    ): InternalAxiosRequestConfig => {
        const method = (requestConfig.method ?? "get").toLowerCase();
        if (!SAFE_METHODS.has(method)) {
            const token = getToken();
            if (token !== null)
                requestConfig.headers.set("X-StaticDeploy-CSRF", token);
            if (!requestConfig.headers.has("Content-Type"))
                requestConfig.headers.set("Content-Type", "application/json");
        }
        return requestConfig;
    };
}
