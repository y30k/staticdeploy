interface IS3ErrorMetadata {
    httpStatusCode?: number;
}

interface IS3Error {
    $metadata?: IS3ErrorMetadata;
}

export function getS3ErrorStatusCode(error: unknown): number | undefined {
    if (typeof error !== "object" || error === null) {
        return undefined;
    }
    return (error as IS3Error).$metadata?.httpStatusCode;
}

export function isS3NotFoundError(error: unknown): boolean {
    return getS3ErrorStatusCode(error) === 404;
}
