import { expect } from "chai";
import { AxiosHeaders, InternalAxiosRequestConfig } from "axios";

import addCsrfHeader from "../../src/interceptors/addCsrfHeader";

const request = (method: string): InternalAxiosRequestConfig =>
    ({ method, headers: new AxiosHeaders() }) as InternalAxiosRequestConfig;

describe("addCsrfHeader", () => {
    it("adds memory CSRF only to unsafe requests", () => {
        const interceptor = addCsrfHeader(() => "csrf-memory");
        const post = interceptor(request("post"));
        const get = interceptor(request("get"));
        expect(post.headers.get("X-StaticDeploy-CSRF")).to.equal("csrf-memory");
        expect(post.headers.get("Content-Type")).to.equal("application/json");
        expect(get.headers.has("X-StaticDeploy-CSRF")).to.equal(false);
        expect(get.headers.has("Content-Type")).to.equal(false);
        expect(post.headers.has("Authorization")).to.equal(false);
    });
});
