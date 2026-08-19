import {
    DeleteObjectCommand,
    GetObjectCommand,
    PutObjectCommand,
    S3Client,
} from "@aws-sdk/client-s3";
import { Knex } from "knex";
import { createHash, randomUUID } from "node:crypto";

import { isS3NotFoundError } from "./common/s3Errors";
import tables from "./common/tables";

const UUID =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ALLOWED_FINALIZE_STATES = new Set([
    "PROCESSING",
    "AWAITING_DEFAULT_DOCUMENT",
]);
const CREATE_ATTEMPTS = 3;

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_RELEASE_BYTES = 512 * 1024 * 1024;
const MAX_FILES = 1024;
const MAX_PATH_BYTES = 1024;
const ZIP_ENTRY_OVERHEAD_BYTES = 30 + 46 + 2 * MAX_PATH_BYTES;

export const V2_OBJECT_LIMITS = Object.freeze({
    maxFileBytes: MAX_FILE_BYTES,
    maxReleaseBytes: MAX_RELEASE_BYTES,
    maxFiles: MAX_FILES,
    maxManifestBytes: 8 * 1024 * 1024,
    maxSourceDownloadBytes:
        MAX_RELEASE_BYTES + MAX_FILES * ZIP_ENTRY_OVERHEAD_BYTES + 22,
    maxConcurrentObjectWrites: 4,
});

export interface V2ObjectDigest {
    sha256: string;
    size: number;
}

export interface V2ManifestFile extends V2ObjectDigest {
    path: string;
    mime: string;
}

export interface V2ReleaseManifest {
    version: 1;
    applicationId: string;
    releaseId: string;
    defaultPath: string;
    files: V2ManifestFile[];
    sourceDownload: V2ObjectDigest;
}

export interface V2ControlObjectStorage {
    putQuarantineFile(
        uploadId: string,
        path: string,
        content: Uint8Array,
        expected: V2ObjectDigest
    ): Promise<void>;
}

export interface V2WorkerObjectStorage {
    readQuarantineFile(uploadId: string, path: string): Promise<Buffer>;
    deleteQuarantineFile(uploadId: string, path: string): Promise<void>;
    finalizeRelease(input: {
        applicationId: string;
        releaseId: string;
        uploadId: string;
        defaultPath: string;
    }): Promise<V2ReleaseManifest>;
}

/**
 * Content receives the manifest digest from the already verified routing
 * generation. It deliberately has no PostgreSQL dependency or write method.
 */
export interface V2ContentObjectStorage {
    readReleaseContent(
        applicationId: string,
        releaseId: string,
        manifestDigest: string,
        path: string
    ): Promise<Buffer | null>;
}

export interface V2ObjectStorages {
    control: V2ControlObjectStorage;
    worker: V2WorkerObjectStorage;
    content: V2ContentObjectStorage;
}

interface DeclarationSnapshot {
    id: string;
    state: "DECLARED" | "OBSERVED";
    path: string;
    size: number;
    sha256: string;
}

const hasUnpairedSurrogate = (value: string): boolean => {
    for (let index = 0; index < value.length; index += 1) {
        const unit = value.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (next < 0xdc00 || next > 0xdfff) return true;
            index += 1;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) return true;
    }
    return false;
};

export function normalizeV2RelativePath(path: string): string {
    if (
        path.length < 1 ||
        hasUnpairedSurrogate(path) ||
        path.includes("\0") ||
        path.includes("\\") ||
        path.startsWith("/") ||
        path.endsWith("/")
    )
        throw new Error("unsafe relative object path");
    const segments = path.split("/");
    if (
        segments.some(
            (segment) => segment === "" || segment === "." || segment === ".."
        )
    )
        throw new Error("unsafe relative object path");
    if (path.normalize("NFC") !== path)
        throw new Error("object path must use NFC normalization");
    return path;
}

function assertId(value: string, label: string): void {
    if (!UUID.test(value)) throw new Error(`invalid ${label}`);
}

function assertDigest(expected: V2ObjectDigest, maximum: number): void {
    if (
        !Number.isSafeInteger(expected.size) ||
        expected.size < 0 ||
        expected.size > maximum ||
        !SHA256.test(expected.sha256)
    )
        throw new Error("invalid or oversized object digest envelope");
}

function digest(content: Uint8Array): V2ObjectDigest {
    return {
        sha256: createHash("sha256").update(content).digest("hex"),
        size: content.byteLength,
    };
}

function assertContent(
    content: Uint8Array,
    expected: V2ObjectDigest,
    maximum: number
): void {
    assertDigest(expected, maximum);
    if (content.byteLength > maximum)
        throw new Error("object exceeds byte limit");
    const actual = digest(content);
    if (actual.size !== expected.size || actual.sha256 !== expected.sha256)
        throw new Error("object digest or size mismatch");
}

/**
 * Collision identity is NFC plus the closure of ECMAScript Unicode default
 * upper/lower mappings. Node is pinned by the repository, which pins its
 * Unicode data. Iterating to stability includes multi-character folds such as
 * ß/ẞ/SS and final-sigma/sigma while preserving the accepted spelling.
 */
function collisionIdentity(path: string): string {
    let identity = path.normalize("NFC");
    for (let iteration = 0; iteration < 3; iteration += 1) {
        const folded = identity.toUpperCase().toLowerCase();
        if (folded === identity) return identity;
        identity = folded;
    }
    return identity;
}

function assertNoPathCollisions(paths: string[]): void {
    const identities = new Set<string>();
    for (const path of paths) {
        const identity = collisionIdentity(normalizeV2RelativePath(path));
        if (identities.has(identity)) throw new Error("object path collision");
        const segments = identity.split("/");
        for (let index = 1; index < segments.length; index += 1)
            if (identities.has(segments.slice(0, index).join("/")))
                throw new Error("object file-directory collision");
        for (const existing of identities)
            if (existing.startsWith(`${identity}/`))
                throw new Error("object file-directory collision");
        identities.add(identity);
    }
}

function assertS3Key(key: string): string {
    if (Buffer.byteLength(key, "utf8") > 1024)
        throw new Error("object key exceeds S3 UTF-8 byte limit");
    return key;
}

function quarantineKey(uploadId: string, path: string): string {
    assertId(uploadId, "upload id");
    return assertS3Key(
        `v2/quarantine/${uploadId}/files/${normalizeV2RelativePath(path)}`
    );
}

function releaseKey(
    applicationId: string,
    releaseId: string,
    kind: "source" | "content",
    path: string
): string {
    assertId(applicationId, "application id");
    assertId(releaseId, "release id");
    return assertS3Key(
        `v2/releases/${applicationId}/${releaseId}/${kind}/${normalizeV2RelativePath(path)}`
    );
}

function releaseObjectKey(
    applicationId: string,
    releaseId: string,
    name: "manifest.json" | "source-download.zip"
): string {
    assertId(applicationId, "application id");
    assertId(releaseId, "release id");
    return assertS3Key(`v2/releases/${applicationId}/${releaseId}/${name}`);
}

function errorStatus(error: unknown): number | undefined {
    return (error as { $metadata?: { httpStatusCode?: number } })?.$metadata
        ?.httpStatusCode;
}

function isConditionalConflict(error: unknown): boolean {
    const name = (error as { name?: string })?.name;
    return (
        name === "PreconditionFailed" ||
        name === "ConditionalRequestConflict" ||
        errorStatus(error) === 412 ||
        errorStatus(error) === 409
    );
}

function isAttestedConditionalConflict(error: unknown): boolean {
    const name = (error as { name?: string })?.name;
    const status = errorStatus(error);
    return (
        (status === 412 && name === "PreconditionFailed") ||
        (status === 409 && name === "ConditionalRequestConflict")
    );
}

class V2ObjectStoreBase {
    constructor(
        protected readonly client: S3Client,
        protected readonly bucket: string
    ) {
        if (!bucket) throw new Error("V2 object bucket is required");
    }

    protected async read(
        key: string,
        maximum: number,
        expected?: V2ObjectDigest
    ): Promise<Buffer | null> {
        try {
            const response = await this.client.send(
                new GetObjectCommand({ Bucket: this.bucket, Key: key })
            );
            if (response.Body === undefined)
                throw new Error("object response has no body");
            if (
                response.ContentLength !== undefined &&
                response.ContentLength > maximum
            )
                throw new Error("object exceeds byte limit");
            const bytes = Buffer.from(
                await response.Body.transformToByteArray()
            );
            if (bytes.byteLength > maximum)
                throw new Error("object exceeds byte limit");
            if (expected !== undefined) assertContent(bytes, expected, maximum);
            return bytes;
        } catch (error) {
            if (isS3NotFoundError(error)) return null;
            throw error;
        }
    }

    protected async putCreateOnly(
        key: string,
        content: Uint8Array,
        expected: V2ObjectDigest,
        maximum = V2_OBJECT_LIMITS.maxFileBytes
    ): Promise<void> {
        assertContent(content, expected, maximum);
        let lastConflict: unknown;
        for (let attempt = 1; attempt <= CREATE_ATTEMPTS; attempt += 1) {
            try {
                await this.client.send(
                    new PutObjectCommand({
                        Bucket: this.bucket,
                        Key: key,
                        Body: content,
                        ContentLength: expected.size,
                        IfNoneMatch: "*",
                        Metadata: { "staticdeploy-sha256": expected.sha256 },
                    })
                );
                const created = await this.read(key, maximum, expected);
                if (created === null)
                    throw new Error("object missing after create");
                return;
            } catch (error) {
                if (!isConditionalConflict(error)) throw error;
                lastConflict = error;
                const existing = await this.read(key, maximum);
                if (existing !== null) {
                    assertContent(existing, expected, maximum);
                    return;
                }
                // A 409 may be returned while another conditional operation is
                // incomplete. Retry is bounded and always retains If-None-Match.
            }
        }
        throw lastConflict;
    }
}

class ControlObjectStorage
    extends V2ObjectStoreBase
    implements V2ControlObjectStorage
{
    constructor(
        client: S3Client,
        bucket: string,
        private readonly knex: Knex
    ) {
        super(client, bucket);
    }

    async putQuarantineFile(
        uploadId: string,
        path: string,
        content: Uint8Array,
        expected: V2ObjectDigest
    ): Promise<void> {
        assertId(uploadId, "upload id");
        const safePath = normalizeV2RelativePath(path);
        assertDigest(expected, V2_OBJECT_LIMITS.maxFileBytes);
        const declaration = await this.knex(tables.v2UploadFiles)
            .select("declared_size", "declared_digest", "state")
            .where({ release_id: uploadId, declared_path: safePath })
            .first();
        if (
            declaration === undefined ||
            declaration.state !== "DECLARED" ||
            Number(declaration.declared_size) !== expected.size ||
            declaration.declared_digest !== expected.sha256
        )
            throw new Error(
                "quarantine object does not match its database declaration"
            );
        await this.putCreateOnly(
            quarantineKey(uploadId, safePath),
            content,
            expected
        );
    }
}

function bytewiseSort<T extends { path: string }>(rows: T[]): T[] {
    return [...rows].sort((left, right) =>
        Buffer.compare(Buffer.from(left.path), Buffer.from(right.path))
    );
}

function mimeForPath(path: string): string {
    const separator = path.lastIndexOf("/");
    const dot = path.lastIndexOf(".");
    const extension = dot > separator ? path.slice(dot + 1).toLowerCase() : "";
    return (
        {
            css: "text/css; charset=utf-8",
            gif: "image/gif",
            htm: "text/html; charset=utf-8",
            html: "text/html; charset=utf-8",
            jpeg: "image/jpeg",
            jpg: "image/jpeg",
            js: "text/javascript; charset=utf-8",
            json: "application/json",
            png: "image/png",
            svg: "image/svg+xml",
            txt: "text/plain; charset=utf-8",
            webp: "image/webp",
        }[extension] ?? "application/octet-stream"
    );
}

const crcTable = Array.from({ length: 256 }, (_, value) => {
    let crc = value;
    for (let bit = 0; bit < 8; bit += 1)
        crc = (crc & 1) !== 0 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    return crc >>> 0;
});

function crc32(bytes: Uint8Array): number {
    let crc = 0xffffffff;
    for (const byte of bytes) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
}

/** Deterministic ZIP: stored entries, UTF-8 names, 1980-01-01, mode 0644. */
function deterministicZip(
    files: Array<{ path: string; content: Buffer }>
): Buffer {
    const local: Buffer[] = [];
    const central: Buffer[] = [];
    let offset = 0;
    for (const file of bytewiseSort(files)) {
        const name = Buffer.from(file.path);
        const crc = crc32(file.content);
        const header = Buffer.alloc(30);
        header.writeUInt32LE(0x04034b50, 0);
        header.writeUInt16LE(20, 4);
        header.writeUInt16LE(0x0800, 6);
        header.writeUInt16LE(0, 8);
        header.writeUInt16LE(0, 10);
        header.writeUInt16LE(0x0021, 12);
        header.writeUInt32LE(crc, 14);
        header.writeUInt32LE(file.content.length, 18);
        header.writeUInt32LE(file.content.length, 22);
        header.writeUInt16LE(name.length, 26);
        local.push(header, name, file.content);

        const directory = Buffer.alloc(46);
        directory.writeUInt32LE(0x02014b50, 0);
        directory.writeUInt16LE(0x0314, 4);
        directory.writeUInt16LE(20, 6);
        directory.writeUInt16LE(0x0800, 8);
        directory.writeUInt16LE(0, 10);
        directory.writeUInt16LE(0, 12);
        directory.writeUInt16LE(0x0021, 14);
        directory.writeUInt32LE(crc, 16);
        directory.writeUInt32LE(file.content.length, 20);
        directory.writeUInt32LE(file.content.length, 24);
        directory.writeUInt16LE(name.length, 28);
        directory.writeUInt32LE((0o100644 << 16) >>> 0, 38);
        directory.writeUInt32LE(offset, 42);
        central.push(directory, name);
        offset += header.length + name.length + file.content.length;
    }
    const directoryBytes = Buffer.concat(central);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(files.length, 8);
    end.writeUInt16LE(files.length, 10);
    end.writeUInt32LE(directoryBytes.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...local, directoryBytes, end]);
}

function parseManifest(
    bytes: Buffer,
    expected: V2ObjectDigest,
    applicationId: string,
    releaseId: string
): V2ReleaseManifest {
    assertContent(bytes, expected, V2_OBJECT_LIMITS.maxManifestBytes);
    let manifest: V2ReleaseManifest;
    try {
        manifest = JSON.parse(bytes.toString("utf8"));
    } catch {
        throw new Error("invalid release manifest JSON");
    }
    if (
        manifest.version !== 1 ||
        manifest.applicationId !== applicationId ||
        manifest.releaseId !== releaseId ||
        !Array.isArray(manifest.files) ||
        manifest.files.length < 1 ||
        manifest.files.length > V2_OBJECT_LIMITS.maxFiles ||
        !manifest.files.some((file) => file.path === manifest.defaultPath)
    )
        throw new Error("release manifest identity mismatch");
    const sorted = bytewiseSort(manifest.files);
    if (JSON.stringify(sorted) !== JSON.stringify(manifest.files))
        throw new Error("release manifest order mismatch");
    assertNoPathCollisions(manifest.files.map((file) => file.path));
    let total = 0;
    for (const file of manifest.files) {
        normalizeV2RelativePath(file.path);
        assertDigest(file, V2_OBJECT_LIMITS.maxFileBytes);
        if (
            typeof file.mime !== "string" ||
            file.mime !== mimeForPath(file.path)
        )
            throw new Error("release manifest MIME mismatch");
        total += file.size;
    }
    if (total > V2_OBJECT_LIMITS.maxReleaseBytes)
        throw new Error("release exceeds byte limit");
    assertDigest(
        manifest.sourceDownload,
        V2_OBJECT_LIMITS.maxSourceDownloadBytes
    );
    return manifest;
}

class WorkerObjectStorage
    extends V2ObjectStoreBase
    implements V2WorkerObjectStorage
{
    constructor(
        client: S3Client,
        bucket: string,
        private readonly knex: Knex
    ) {
        super(client, bucket);
    }

    async readQuarantineFile(uploadId: string, path: string): Promise<Buffer> {
        const content = await this.read(
            quarantineKey(uploadId, path),
            V2_OBJECT_LIMITS.maxFileBytes
        );
        if (content === null) throw new Error("quarantine object not found");
        return content;
    }

    async deleteQuarantineFile(uploadId: string, path: string): Promise<void> {
        await this.client.send(
            new DeleteObjectCommand({
                Bucket: this.bucket,
                Key: quarantineKey(uploadId, path),
            })
        );
    }

    private async readyManifest(
        release: {
            default_path: string | null;
            manifest_digest: string | null;
        },
        applicationId: string,
        releaseId: string,
        requestedDefault: string
    ): Promise<V2ReleaseManifest> {
        if (
            release.default_path !== requestedDefault ||
            !SHA256.test(release.manifest_digest ?? "")
        )
            throw new Error("READY release identity mismatch");
        const expected = {
            sha256: release.manifest_digest as string,
            size: Number.MAX_SAFE_INTEGER,
        };
        const bytes = await this.read(
            releaseObjectKey(applicationId, releaseId, "manifest.json"),
            V2_OBJECT_LIMITS.maxManifestBytes
        );
        if (bytes === null) throw new Error("READY release manifest missing");
        expected.size = bytes.length;
        return parseManifest(bytes, expected, applicationId, releaseId);
    }

    async finalizeRelease(input: {
        applicationId: string;
        releaseId: string;
        uploadId: string;
        defaultPath: string;
    }): Promise<V2ReleaseManifest> {
        assertId(input.applicationId, "application id");
        assertId(input.releaseId, "release id");
        assertId(input.uploadId, "upload id");
        if (input.uploadId !== input.releaseId)
            throw new Error("upload prefix is not bound to release identity");
        const defaultPath = normalizeV2RelativePath(input.defaultPath);
        const release = await this.knex(tables.v2Releases)
            .where({ id: input.releaseId, application_id: input.applicationId })
            .first();
        if (release === undefined) throw new Error("release not found");
        if (release.state === "READY")
            return this.readyManifest(
                release,
                input.applicationId,
                input.releaseId,
                defaultPath
            );
        if (!ALLOWED_FINALIZE_STATES.has(release.state))
            throw new Error("release state is not eligible for finalization");

        const rows = await this.knex(tables.v2UploadFiles)
            .where({ release_id: input.releaseId })
            .limit(V2_OBJECT_LIMITS.maxFiles + 1);
        if (rows.length < 1 || rows.length > V2_OBJECT_LIMITS.maxFiles)
            throw new Error("release file count is outside limits");
        const snapshot: DeclarationSnapshot[] = bytewiseSort(
            rows.map((row) => {
                if (row.state !== "DECLARED" || row.declared_digest === null)
                    throw new Error(
                        "release has ineligible upload declaration"
                    );
                const item = {
                    id: row.id as string,
                    state: row.state,
                    path: row.declared_path as string,
                    size: Number(row.declared_size),
                    sha256: row.declared_digest as string,
                } as DeclarationSnapshot;
                normalizeV2RelativePath(item.path);
                assertDigest(item, V2_OBJECT_LIMITS.maxFileBytes);
                return item;
            })
        );
        assertNoPathCollisions(snapshot.map((row) => row.path));
        if (!snapshot.some((row) => row.path === defaultPath))
            throw new Error("default path is not declared");
        if (!/[.]html?$/i.test(defaultPath))
            throw new Error("default path must be an HTML document");
        const total = snapshot.reduce((sum, row) => sum + row.size, 0);
        if (
            !Number.isSafeInteger(total) ||
            total > V2_OBJECT_LIMITS.maxReleaseBytes
        )
            throw new Error("release exceeds byte limit");

        const buffered: Array<{
            path: string;
            content: Buffer;
            expected: V2ObjectDigest;
        }> = [];
        const files: V2ManifestFile[] = [];
        for (const declaration of snapshot) {
            const expected = {
                sha256: declaration.sha256,
                size: declaration.size,
            };
            const content = await this.readQuarantineFile(
                input.uploadId,
                declaration.path
            );
            assertContent(content, expected, V2_OBJECT_LIMITS.maxFileBytes);
            buffered.push({ path: declaration.path, content, expected });
            files.push({
                path: declaration.path,
                mime: mimeForPath(declaration.path),
                ...expected,
            });
        }

        for (const file of buffered) {
            await this.putCreateOnly(
                releaseKey(
                    input.applicationId,
                    input.releaseId,
                    "source",
                    file.path
                ),
                file.content,
                file.expected
            );
            await this.putCreateOnly(
                releaseKey(
                    input.applicationId,
                    input.releaseId,
                    "content",
                    file.path
                ),
                file.content,
                file.expected
            );
        }
        const sourceDownloadBytes = deterministicZip(buffered);
        const sourceDownload = digest(sourceDownloadBytes);
        await this.putCreateOnly(
            releaseObjectKey(
                input.applicationId,
                input.releaseId,
                "source-download.zip"
            ),
            sourceDownloadBytes,
            sourceDownload,
            V2_OBJECT_LIMITS.maxSourceDownloadBytes
        );
        const manifest: V2ReleaseManifest = {
            version: 1,
            applicationId: input.applicationId,
            releaseId: input.releaseId,
            defaultPath,
            files,
            sourceDownload,
        };
        const manifestBytes = Buffer.from(JSON.stringify(manifest));
        const manifestDigest = digest(manifestBytes);
        await this.putCreateOnly(
            releaseObjectKey(
                input.applicationId,
                input.releaseId,
                "manifest.json"
            ),
            manifestBytes,
            manifestDigest,
            V2_OBJECT_LIMITS.maxManifestBytes
        );

        await this.knex.transaction(async (transaction) => {
            await transaction(tables.v2Applications)
                .where({ id: input.applicationId })
                .forUpdate()
                .first();
            const current = await transaction(tables.v2Releases)
                .where({
                    id: input.releaseId,
                    application_id: input.applicationId,
                })
                .forUpdate()
                .first();
            if (current === undefined) throw new Error("release not found");
            if (current.state === "READY") {
                if (
                    current.default_path !== defaultPath ||
                    current.manifest_digest !== manifestDigest.sha256
                )
                    throw new Error("READY release identity mismatch");
                return;
            }
            if (current.state !== release.state)
                throw new Error("release changed during finalization");
            const lockedRows = await transaction(tables.v2UploadFiles)
                .where({ release_id: input.releaseId })
                .limit(V2_OBJECT_LIMITS.maxFiles + 1)
                .forUpdate();
            const currentSnapshot = bytewiseSort(
                lockedRows.map((row) => ({
                    id: row.id,
                    state: row.state,
                    path: row.declared_path,
                    size: Number(row.declared_size),
                    sha256: row.declared_digest,
                }))
            );
            if (JSON.stringify(currentSnapshot) !== JSON.stringify(snapshot))
                throw new Error(
                    "upload declarations changed during finalization"
                );
            for (const file of snapshot) {
                const updated = await transaction(tables.v2UploadFiles)
                    .where({
                        id: file.id,
                        release_id: input.releaseId,
                        state: file.state,
                        declared_path: file.path,
                        declared_size: file.size,
                        declared_digest: file.sha256,
                    })
                    .update({
                        state: "OBSERVED",
                        observed_path: file.path,
                        observed_size: file.size,
                        observed_digest: file.sha256,
                        observed_at: transaction.fn.now(),
                    });
                if (updated !== 1)
                    throw new Error(
                        "upload declaration finalization lost race"
                    );
            }
            const mismatch = await transaction(tables.v2UploadFiles)
                .where({ release_id: input.releaseId })
                .whereRaw(
                    "(state <> 'OBSERVED' OR observed_path IS DISTINCT FROM declared_path OR observed_size IS DISTINCT FROM declared_size OR observed_digest IS DISTINCT FROM declared_digest)"
                )
                .first();
            if (mismatch !== undefined)
                throw new Error("observed upload set is inconsistent");
            const updated = await transaction(tables.v2Releases)
                .where({
                    id: input.releaseId,
                    application_id: input.applicationId,
                    state: release.state,
                })
                .update({
                    state: "READY",
                    default_path: defaultPath,
                    manifest_digest: manifestDigest.sha256,
                    finalized_at: transaction.fn.now(),
                    updated_at: transaction.fn.now(),
                });
            if (updated !== 1)
                throw new Error("release finalization lost concurrency race");
        });
        return manifest;
    }
}

class ContentObjectStorage
    extends V2ObjectStoreBase
    implements V2ContentObjectStorage
{
    async readReleaseContent(
        applicationId: string,
        releaseId: string,
        manifestDigest: string,
        path: string
    ): Promise<Buffer | null> {
        assertId(applicationId, "application id");
        assertId(releaseId, "release id");
        if (!SHA256.test(manifestDigest))
            throw new Error("invalid manifest digest");
        const safePath = normalizeV2RelativePath(path);
        const manifestBytes = await this.read(
            releaseObjectKey(applicationId, releaseId, "manifest.json"),
            V2_OBJECT_LIMITS.maxManifestBytes
        );
        if (manifestBytes === null) return null;
        const manifest = parseManifest(
            manifestBytes,
            { sha256: manifestDigest, size: manifestBytes.length },
            applicationId,
            releaseId
        );
        const file = manifest.files.find(
            (candidate) => candidate.path === safePath
        );
        if (file === undefined) return null;
        return this.read(
            releaseKey(applicationId, releaseId, "content", safePath),
            V2_OBJECT_LIMITS.maxFileBytes,
            file
        );
    }
}

export function createV2ControlObjectStorage(
    knex: Knex,
    client: S3Client,
    bucket: string
): V2ControlObjectStorage {
    return new ControlObjectStorage(client, bucket, knex);
}

export function createV2WorkerObjectStorage(
    knex: Knex,
    client: S3Client,
    bucket: string
): V2WorkerObjectStorage {
    return new WorkerObjectStorage(client, bucket, knex);
}

export function createV2ContentObjectStorage(
    client: S3Client,
    bucket: string
): V2ContentObjectStorage {
    return new ContentObjectStorage(client, bucket);
}

/**
 * Test/local composition only. Production commands must construct one role via
 * the individual factory and inject only that role's S3 and PostgreSQL identity.
 */
export function createV2ObjectStorages(input: {
    control: { knex: Knex; client: S3Client };
    worker: { knex: Knex; client: S3Client };
    content: { client: S3Client };
    bucket: string;
}): V2ObjectStorages {
    if (
        input.control.client === input.worker.client ||
        input.control.client === input.content.client ||
        input.worker.client === input.content.client ||
        input.control.knex === input.worker.knex
    )
        throw new Error("V2 roles require distinct client identities");
    return {
        control: createV2ControlObjectStorage(
            input.control.knex,
            input.control.client,
            input.bucket
        ),
        worker: createV2WorkerObjectStorage(
            input.worker.knex,
            input.worker.client,
            input.bucket
        ),
        content: createV2ContentObjectStorage(
            input.content.client,
            input.bucket
        ),
    };
}

/** Local/provider probe; production acceptance of the same contract is B-S3. */
export async function verifyV2CreateOnlyCapability(
    first: S3Client,
    second: S3Client,
    bucket: string
): Promise<void> {
    if (first === second)
        throw new Error("capability probe requires two clients");
    const key = `v2/capabilities/create-only/${randomUUID()}`;
    const results = await Promise.allSettled([
        first.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: key,
                Body: Buffer.from("first"),
                IfNoneMatch: "*",
            })
        ),
        second.send(
            new PutObjectCommand({
                Bucket: bucket,
                Key: key,
                Body: Buffer.from("second"),
                IfNoneMatch: "*",
            })
        ),
    ]);
    if (results.filter((result) => result.status === "fulfilled").length !== 1)
        throw new Error("object store does not enforce conditional create");
    const rejected = results.find((result) => result.status === "rejected");
    if (
        rejected === undefined ||
        !isAttestedConditionalConflict(rejected.reason)
    )
        throw new Error(
            "conditional create probe failed for an unrelated reason"
        );
    const response = await first.send(
        new GetObjectCommand({ Bucket: bucket, Key: key })
    );
    if (response.Body === undefined)
        throw new Error("conditional create probe read-back mismatch");
    const body = Buffer.from(await response.Body.transformToByteArray());
    if (!["first", "second"].includes(body.toString()))
        throw new Error("conditional create probe read-back mismatch");
}
