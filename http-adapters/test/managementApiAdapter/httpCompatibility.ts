import { expect } from "chai";
import sinon from "sinon";
import request from "supertest";

import { getManagementApiAdapter } from "../testUtils";

describe("managementApiAdapter Express 4 compatibility", () => {
    it("rejects malformed JSON without invoking the route", async () => {
        const execMock = sinon.stub();
        const server = getManagementApiAdapter({ createApp: execMock });

        await request(server)
            .post("/apps")
            .set("content-type", "application/json")
            .send('{"name":')
            .expect(400)
            .expect({ message: "Invalid JSON Syntax" });

        expect(execMock.called).to.equal(false);
    });

    it("rejects a non-JSON request body without invoking the route", async () => {
        const execMock = sinon.stub();
        const server = getManagementApiAdapter({ createApp: execMock });

        await request(server)
            .post("/apps")
            .set("content-type", "text/plain")
            .send("name=app")
            .expect(415)
            .expect({
                message: "Body must have Content-Type application/json",
            });

        expect(execMock.called).to.equal(false);
    });

    it("temporarily characterizes the legacy 500 response for an oversized body", async () => {
        const execMock = sinon.stub();
        const server = getManagementApiAdapter(
            { createApp: execMock },
            { maxRequestBodySize: "10b" }
        );

        await request(server)
            .post("/apps")
            .send({ name: "body exceeds ten bytes" })
            .expect(500)
            .expect({ message: "Internal server error" });

        expect(execMock.called).to.equal(false);
    });

    it("decodes query values before invoking the route", async () => {
        const execMock = sinon.stub().resolves([]);
        const server = getManagementApiAdapter({
            getEntrypointsByAppId: execMock,
        });

        await request(server)
            .get("/entrypoints?appId=app%2Fwith%20space")
            .expect(200)
            .expect([]);

        expect(execMock).to.have.been.calledOnceWith("app/with space");
    });

    it("decodes encoded path parameters before invoking the route", async () => {
        const execMock = sinon.stub().resolves({ id: "app/id" });
        const server = getManagementApiAdapter({ getApp: execMock });

        await request(server)
            .get("/apps/app%2Fid")
            .expect(200)
            .expect({ id: "app/id" });

        expect(execMock).to.have.been.calledOnceWith("app/id");
    });

    it("returns 404 for an unmatched route", () => {
        const server = getManagementApiAdapter({});
        return request(server).get("/not-a-route").expect(404);
    });

    it("preserves the JSON 500 response for an asynchronous route error", () => {
        const server = getManagementApiAdapter({
            getApp: sinon.stub().rejects(new Error("route failed")),
        });
        return request(server)
            .get("/apps/app-id")
            .expect(500)
            .expect({ message: "Internal server error" });
    });

    it("exposes the generated Swagger route contract", async () => {
        const server = getManagementApiAdapter({});
        const response = await request(server)
            .get("/swagger.json")
            .expect(200)
            .expect("content-type", /json/);

        expect(response.body.swagger).to.equal("2.0");
        expect(response.body.host).to.equal("serviceHost");
        expect(response.body.basePath).to.equal("/");
        expect(response.body.paths["/apps/{appId}"].get).to.deep.include({
            description: "Get app",
            tags: ["apps"],
        });
        expect(response.body.paths["/apps"].post.parameters[0]).to.deep.include(
            {
                name: "app",
                in: "body",
                required: true,
            }
        );
    });
});
