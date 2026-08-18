import { randomUUID } from "node:crypto";
import { IncomingMessage, ServerResponse } from "node:http";

import { Logger } from "pino";
import pinoHttp from "pino-http";

import {
    serializeHttpRequest,
    serializeHttpResponse,
} from "../common/sanitizeLogValue";
import { serializeError } from "./logger";

const REQUEST_ID_HEADER = "X-Request-Id";

export const generateRequestId = (
    _request: IncomingMessage,
    response: ServerResponse
): string => {
    const requestId = randomUUID();
    response.setHeader(REQUEST_ID_HEADER, requestId);
    return requestId;
};

const isFailedRequest = (response: ServerResponse, error?: Error): boolean =>
    error !== undefined ||
    response.err !== undefined ||
    response.statusCode >= 500;

const isAbortedRequest = (
    request: IncomingMessage,
    response: ServerResponse
): boolean => request.readableAborted || !response.writableEnded;

export default (logger: Logger): ReturnType<typeof pinoHttp> =>
    pinoHttp({
        logger,
        genReqId: generateRequestId,
        quietReqLogger: true,
        customAttributeKeys: {
            reqId: "req_id",
            responseTime: "duration",
        },
        customLogLevel: (request, response, error) => {
            if (isFailedRequest(response, error)) return "error";
            if (isAbortedRequest(request, response)) return "warn";
            return "info";
        },
        customSuccessMessage: (request, response) =>
            isAbortedRequest(request, response)
                ? "request aborted"
                : "request completed",
        customErrorMessage: () => "request failed",
        serializers: {
            err: serializeError,
            req: serializeHttpRequest,
            res: serializeHttpResponse,
        },
    });
