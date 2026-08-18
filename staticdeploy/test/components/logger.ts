import assert from "node:assert/strict";
import { IncomingMessage, ServerResponse } from "node:http";

import express from "express";
import { DestinationStream } from "pino";
import request from "supertest";

import IConfig from "../../src/common/IConfig";
import { stripUrlQueryAndHash } from "../../src/common/sanitizeLogValue";
import getLogger, { REDACTED_VALUE } from "../../src/components/logger";
import getRequestLogger, {
    generateRequestId,
} from "../../src/components/requestLogger";
import { getConfig } from "../../src/config";

const loggingConfig: IConfig = {
    ...getConfig(),
    appName: "staticdeploy-logging-test",
    appVersion: "1.2.3-test",
    nodeEnv: "development",
    logLevel: "info",
};

const createRecorder = (): {
    chunks: string[];
    stream: DestinationStream;
} => {
    const chunks: string[] = [];
    return {
        chunks,
        stream: { write: (chunk: string) => chunks.push(chunk) },
    };
};

const parseRecords = (chunks: string[]): Array<Record<string, any>> =>
    chunks.map((chunk) => {
        assert.equal(chunk.endsWith("\n"), true);
        assert.equal(chunk.slice(0, -1).includes("\n"), false);
        return JSON.parse(chunk);
    });

const waitForRecords = async (
    chunks: string[],
    expectedCount: number
): Promise<void> => {
    for (let attempt = 0; attempt < 100; attempt += 1) {
        if (chunks.length >= expectedCount) return;
        await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.fail(`Expected ${expectedCount} records, received ${chunks.length}`);
};

const assertSecretsAbsent = (output: string, secrets: string[]): void => {
    for (const secret of secrets) assert.equal(output.includes(secret), false);
};

describe("structured logger", () => {
    it("writes one JSON record per line with application identity and level filtering", () => {
        const { chunks, stream } = createRecorder();
        const logger = getLogger(
            { ...loggingConfig, logLevel: "warn" },
            stream
        );

        logger.info("filtered info");
        logger.warn("retained warning");
        logger.error("retained error");

        const records = parseRecords(chunks);
        assert.equal(records.length, 2);
        assert.deepEqual(
            records.map(({ level, msg }) => ({ level, msg })),
            [
                { level: 40, msg: "retained warning" },
                { level: 50, msg: "retained error" },
            ]
        );
        for (const record of records) {
            assert.equal(record.name, loggingConfig.appName);
            assert.equal(record.version, loggingConfig.appVersion);
            assert.equal(typeof record.time, "number");
        }
    });

    it("silences all output in the test environment", () => {
        const { chunks, stream } = createRecorder();
        const logger = getLogger(
            { ...loggingConfig, nodeEnv: "test", logLevel: "trace" },
            stream
        );

        logger.fatal("not emitted");
        assert.deepEqual(chunks, []);
    });

    it("serializes error message and stack", () => {
        const { chunks, stream } = createRecorder();
        const logger = getLogger(loggingConfig, stream);
        const error = new Error("deterministic failure");

        logger.error(error, "operation failed");

        const [record] = parseRecords(chunks);
        assert.equal(record.msg, "operation failed");
        assert.equal(record.err.message, "deterministic failure");
        assert.equal(record.err.stack, error.stack);
    });

    it("recursively redacts sensitive variants in objects, errors, causes, aggregates, arrays, and cycles", () => {
        const { chunks, stream } = createRecorder();
        const logger = getLogger(loggingConfig, stream);
        const secrets = [
            "authorization-secret",
            "cookie-secret",
            "credential-secret",
            "password-secret",
            "token-secret",
            "api-key-secret",
            "proxy-auth-secret",
            "error-secret",
            "cause-secret",
            "aggregate-secret",
        ];

        const cyclic: Record<string, unknown> = {
            Authorization: secrets[0],
            nested: [
                {
                    Cookie: secrets[1],
                    client_credentials: secrets[2],
                    userPassword: secrets[3],
                    access_token: secrets[4],
                    "X-Api-Key": secrets[5],
                    "Proxy-Authorization": secrets[6],
                },
            ],
        };
        cyclic.self = cyclic;

        const cause = Object.assign(new Error("safe cause"), {
            refreshToken: secrets[8],
        });
        const aggregate = Object.assign(new Error("safe aggregate"), {
            cause,
            errors: [
                Object.assign(new Error("safe nested error"), {
                    apiKey: secrets[9],
                }),
                cyclic,
            ],
            secretAccessKey: secrets[7],
        });
        (aggregate.errors as unknown[]).push(aggregate);

        logger.info({ payload: cyclic }, "structured values");
        logger.error(aggregate, "aggregate failed");

        const output = chunks.join("");
        assertSecretsAbsent(output, secrets);
        const records = parseRecords(chunks);
        assert.equal(records[0].payload.Authorization, REDACTED_VALUE);
        assert.equal(
            records[0].payload.nested[0]["Proxy-Authorization"],
            REDACTED_VALUE
        );
        assert.equal(records[0].payload.self, "[Circular]");
        assert.equal(records[1].err.secretAccessKey, REDACTED_VALUE);
        assert.equal(records[1].err.cause.refreshToken, REDACTED_VALUE);
        assert.equal(records[1].err.errors[0].apiKey, REDACTED_VALUE);
        assert.equal(records[1].err.errors[2], "[Circular]");
    });

    it("redacts req and res fields written through the root logger", () => {
        const { chunks, stream } = createRecorder();
        const logger = getLogger(loggingConfig, stream);
        const secrets = ["root-request-secret", "root-response-secret"];

        logger.info(
            {
                req: { headers: { Authorization: secrets[0] } },
                res: { headers: { "Set-Cookie": secrets[1] } },
            },
            "root request-shaped record"
        );

        assertSecretsAbsent(chunks.join(""), secrets);
        const [record] = parseRecords(chunks);
        assert.equal(record.req.headers.Authorization, REDACTED_VALUE);
        assert.equal(record.res.headers["Set-Cookie"], REDACTED_VALUE);
    });

    it("minimizes and redacts real Node request and response objects on the root logger", async () => {
        const { chunks, stream } = createRecorder();
        const logger = getLogger(loggingConfig, stream);
        const secrets = [
            "root-real-authorization",
            "root-real-cookie",
            "root-real-set-cookie",
            "root-real-query",
            "root-real-body",
        ];
        const app = express()
            .use(express.json())
            .post("/root-real", (req, res) => {
                res.setHeader("Set-Cookie", secrets[2]);
                logger.info({ req, res }, "root real HTTP objects");
                res.status(204).end();
            });

        await request(app)
            .post(`/root-real?token=${secrets[3]}`)
            .set("Authorization", secrets[0])
            .set("Cookie", secrets[1])
            .send({ password: secrets[4] })
            .expect(204);

        assertSecretsAbsent(chunks.join(""), secrets);
        const [record] = parseRecords(chunks);
        assert.equal(record.req.url, "/root-real");
        assert.equal(record.req.headers.authorization, REDACTED_VALUE);
        assert.equal(record.req.headers.cookie, REDACTED_VALUE);
        assert.equal(record.req.body, undefined);
        assert.equal(record.req.rawHeaders, undefined);
        assert.equal(record.res.headers["set-cookie"], REDACTED_VALUE);
        assert.equal(record.res._header, undefined);
    });

    it("strips query strings and fragments from logged URLs", () => {
        assert.equal(
            stripUrlQueryAndHash("/path/to/app?token=query-secret#fragment"),
            "/path/to/app"
        );
        assert.equal(
            stripUrlQueryAndHash("https://example.test/path#fragment"),
            "https://example.test/path"
        );
    });

    it("always generates a server UUID for hostile caller request IDs", () => {
        const hostileRequestIds: unknown[] = [
            "x".repeat(16 * 1024),
            "caller\r\nInjected: value",
            "cållér-識別子",
            ["duplicate-one", "duplicate-two"],
        ];
        const generated = new Set<string>();

        for (const hostileRequestId of hostileRequestIds) {
            let responseRequestId: unknown;
            const requestWithHostileId = {
                headers: { "x-request-id": hostileRequestId },
                rawHeaders: [
                    "X-Request-Id",
                    "duplicate-one",
                    "X-Request-Id",
                    "duplicate-two",
                ],
            } as unknown as IncomingMessage;
            const response = {
                setHeader: (name: string, value: unknown) => {
                    assert.equal(name, "X-Request-Id");
                    responseRequestId = value;
                },
            } as unknown as ServerResponse;

            const requestId = generateRequestId(requestWithHostileId, response);
            assert.match(requestId, /^[0-9a-f-]{36}$/);
            assert.equal(requestId, responseRequestId);
            assert.equal(
                JSON.stringify(hostileRequestId).includes(requestId),
                false
            );
            generated.add(requestId);
        }
        assert.equal(generated.size, hostileRequestIds.length);
    });

    it("emits exactly one policy-level terminal record per request without leaking request or error secrets", async () => {
        const { chunks, stream } = createRecorder();
        const logger = getLogger(loggingConfig, stream);
        const failedRequestSecrets = [
            "request-authorization-secret",
            "request-cookie-secret",
            "response-cookie-secret",
            "caller-request-id-secret",
            "query-secret",
            "failure-token-secret",
            "failure-password-secret",
        ];
        const failureCause = Object.assign(new Error("safe failure cause"), {
            password: failedRequestSecrets[6],
        });
        const failure = Object.assign(new Error("safe request failure"), {
            cause: failureCause,
            accessToken: failedRequestSecrets[5],
        });
        const app = express()
            .use(getRequestLogger(logger))
            .get("/success", (_request, response) => {
                response.setHeader("Set-Cookie", failedRequestSecrets[2]);
                response.status(204).end();
            })
            .get("/missing", (_request, response) => {
                response.status(404).end();
            })
            .get("/failed", (_request, response) => {
                response.err = failure;
                response.status(500).end();
            })
            .get("/aborted", (_request, response) => {
                response.socket?.destroy();
            });

        const successResponse = await request(app)
            .get(`/success?access_token=${failedRequestSecrets[4]}`)
            .set("X-Request-Id", failedRequestSecrets[3])
            .set("Authorization", failedRequestSecrets[0])
            .set("Cookie", failedRequestSecrets[1])
            .expect(204);
        const generatedId = successResponse.headers["x-request-id"];
        assert.match(generatedId, /^[0-9a-f-]{36}$/);
        assert.notEqual(generatedId, failedRequestSecrets[3]);

        await request(app).get("/missing").expect(404);
        await request(app).get("/failed").expect(500);
        await request(app)
            .get("/aborted")
            .catch(() => undefined);
        await waitForRecords(chunks, 4);

        const records = parseRecords(chunks);
        assert.equal(records.length, 4);
        const byUrl = new Map(
            records.map((record) => [record.req.url, record])
        );
        assert.equal(byUrl.get("/success")?.level, 30);
        assert.equal(byUrl.get("/success")?.msg, "request completed");
        assert.equal(byUrl.get("/success")?.req_id, generatedId);
        assert.equal(byUrl.get("/success")?.req.id, generatedId);
        assert.equal(
            byUrl.get("/success")?.req.headers["x-request-id"],
            undefined
        );
        assert.equal(byUrl.get("/missing")?.level, 30);
        assert.equal(byUrl.get("/missing")?.msg, "request completed");
        assert.equal(byUrl.get("/failed")?.level, 50);
        assert.equal(byUrl.get("/failed")?.msg, "request failed");
        assert.equal(byUrl.get("/failed")?.err.accessToken, REDACTED_VALUE);
        assert.equal(byUrl.get("/failed")?.err.cause.password, REDACTED_VALUE);
        assert.equal(byUrl.get("/aborted")?.level, 40);
        assert.equal(byUrl.get("/aborted")?.msg, "request aborted");

        for (const record of records) {
            assert.equal(record.req.method, "GET");
            assert.match(record.req_id, /^[0-9a-f-]{36}$/);
            if (record.msg === "request aborted") {
                assert.equal(record.res.statusCode, null);
            } else {
                assert.equal(typeof record.res.statusCode, "number");
            }
            assert.equal(typeof record.duration, "number");
        }
        assert.equal(
            byUrl.get("/success")?.req.headers.authorization,
            REDACTED_VALUE
        );
        assert.equal(byUrl.get("/success")?.req.headers.cookie, REDACTED_VALUE);
        assert.equal(
            byUrl.get("/success")?.res.headers["set-cookie"],
            REDACTED_VALUE
        );
        assertSecretsAbsent(chunks.join(""), failedRequestSecrets);
    });
});
