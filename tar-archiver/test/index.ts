import { ArchiveExtractionError } from "@staticdeploy/core";
import { expect } from "chai";
import { createTree, destroyTree } from "@staticdeploy/storages-test-suite";
import { outputFile, pathExists, readFile, remove } from "fs-extra";
import { tmpdir } from "os";
import { join } from "path";
import { Header } from "tar";
import { gzipSync } from "zlib";

import tarArchiver from "../src";
import getRandomString from "../src/getRandomString";

function makeHostileArchive(
    entry: Readonly<{
        path: string;
        type?: "File" | "Link" | "SymbolicLink";
        linkpath?: string;
        content?: Buffer;
    }>
): Buffer {
    const content = entry.content || Buffer.alloc(0);
    const headerBlock = Buffer.alloc(512);
    const header = new Header({
        path: entry.path,
        type: entry.type || "File",
        linkpath: entry.linkpath,
        size: content.length,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: new Date(0),
    });
    header.encode(headerBlock);
    const padding = Buffer.alloc((512 - (content.length % 512)) % 512);
    return gzipSync(
        Buffer.concat([headerBlock, content, padding, Buffer.alloc(1024)])
    );
}

async function expectExtractionFailure(archive: Buffer): Promise<void> {
    let extractionError: unknown;
    try {
        await tarArchiver.extractFiles(archive);
    } catch (err) {
        extractionError = err;
    }
    expect(extractionError).to.be.instanceOf(ArchiveExtractionError);
}

describe("ITarArchiver", () => {
    it("extractFiles(makeArchive(files)) = files", async () => {
        const files = [
            { path: "/file", content: Buffer.from("/file") },
            { path: "/nested/file", content: Buffer.from("/nested/file") },
            {
                path: "/deeply/nested/file",
                content: Buffer.from("/deeply/nested/file"),
            },
        ];
        const archive = await tarArchiver.makeArchive(files);
        const extractedFiles = await tarArchiver.extractFiles(archive);
        expect(extractedFiles).to.deep.equalInAnyOrder(files);
    });

    it("extractFiles(makeArchiveFromPath(path)) = files @ path", async () => {
        const directoryToArchivePath = join(tmpdir(), getRandomString());
        createTree(directoryToArchivePath, {
            file: "/file",
            nested: { file: "/nested/file" },
            deeply: { nested: { file: "/deeply/nested/file" } },
        });
        const archive = await tarArchiver.makeArchiveFromPath(
            directoryToArchivePath
        );
        destroyTree(directoryToArchivePath);
        const extractedFiles = await tarArchiver.extractFiles(archive);
        expect(extractedFiles).to.deep.equalInAnyOrder([
            { path: "/file", content: Buffer.from("/file") },
            { path: "/nested/file", content: Buffer.from("/nested/file") },
            {
                path: "/deeply/nested/file",
                content: Buffer.from("/deeply/nested/file"),
            },
        ]);
    });

    it("finishes archive reads before cleaning up temporary files", async () => {
        const content = Buffer.alloc(4 * 1024 * 1024, "a");
        const archive = await tarArchiver.makeArchive([
            { path: "/large-file", content },
        ]);
        expect(await tarArchiver.extractFiles(archive)).to.deep.equal([
            { path: "/large-file", content },
        ]);
    });

    it("rejects traversal without creating a file outside the working directory", async () => {
        const escapedName = getRandomString();
        const escapedPath = join(tmpdir(), escapedName);
        await remove(escapedPath);
        try {
            await expectExtractionFailure(
                makeHostileArchive({
                    path: `../../${escapedName}`,
                    content: Buffer.from("hostile content"),
                })
            );
            expect(await pathExists(escapedPath)).to.equal(false);
        } finally {
            await remove(escapedPath);
        }
    });

    it("rejects hard links", async () => {
        await expectExtractionFailure(
            makeHostileArchive({
                path: "hard-link",
                type: "Link",
                linkpath: "target",
            })
        );
    });

    it("rejects symbolic links instead of reading their external target", async () => {
        const externalFilePath = join(tmpdir(), getRandomString());
        const externalContent = Buffer.from("external secret");
        try {
            await outputFile(externalFilePath, externalContent);
            await expectExtractionFailure(
                makeHostileArchive({
                    path: "leaked-file",
                    type: "SymbolicLink",
                    linkpath: externalFilePath,
                })
            );
            expect(await readFile(externalFilePath)).to.deep.equal(
                externalContent
            );
        } finally {
            await remove(externalFilePath);
        }
    });
});
