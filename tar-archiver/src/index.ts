import {
    ArchiveCreationError,
    ArchiveExtractionError,
    IArchiver,
    IFile,
} from "@staticdeploy/core";
import { mkdirp, outputFile, readFile, remove } from "fs-extra";
import { tmpdir } from "os";
import { join } from "path";
import recursiveReaddir from "recursive-readdir";
import { create as createTar, extract as extractTar, ReadEntry } from "tar";

import getRandomString from "./getRandomString";
import removePrefix from "./removePrefix";

interface ITarArchiver extends IArchiver {
    makeArchiveFromPath(path: string): Promise<Buffer>;
}

const tarArchiver: ITarArchiver = {
    async extractFiles(archive: Buffer): Promise<IFile[]> {
        const workingDirectoryPath = join(tmpdir(), getRandomString());
        const stagingDirectoryPath = join(workingDirectoryPath, "staging");
        const tarArchivePath = join(workingDirectoryPath, "archive.tar.gz");
        try {
            await mkdirp(workingDirectoryPath);
            await outputFile(tarArchivePath, archive);
            await mkdirp(stagingDirectoryPath);
            let archiveContainsLinks = false;
            await extractTar({
                cwd: stagingDirectoryPath,
                file: tarArchivePath,
                filter: (_path, entry) => {
                    if (
                        entry instanceof ReadEntry &&
                        (entry.type === "Link" || entry.type === "SymbolicLink")
                    ) {
                        archiveContainsLinks = true;
                        return false;
                    }
                    return true;
                },
                preservePaths: false,
                strict: true,
            });
            if (archiveContainsLinks) {
                throw new Error("Archive links are not supported");
            }
            const localPaths = await recursiveReaddir(stagingDirectoryPath);
            return await Promise.all(
                localPaths.map(async (localPath) => {
                    const path = removePrefix(localPath, stagingDirectoryPath);
                    return {
                        path: path,
                        content: await readFile(
                            join(stagingDirectoryPath, path)
                        ),
                    };
                })
            );
        } catch (err) {
            throw new ArchiveExtractionError();
        } finally {
            await remove(workingDirectoryPath);
        }
    },

    async makeArchive(files: IFile[]): Promise<Buffer> {
        const workingDirectoryPath = join(tmpdir(), getRandomString());
        const stagingDirectoryPath = join(workingDirectoryPath, "staging");
        const tarArchivePath = join(workingDirectoryPath, "archive.tar.gz");
        try {
            await mkdirp(workingDirectoryPath);
            await Promise.all(
                files.map((file) =>
                    outputFile(
                        join(stagingDirectoryPath, file.path),
                        file.content
                    )
                )
            );
            await createTar(
                {
                    cwd: stagingDirectoryPath,
                    file: tarArchivePath,
                    gzip: true,
                    portable: true,
                },
                ["."]
            );
            return await readFile(tarArchivePath);
        } catch (err) {
            throw new ArchiveCreationError();
        } finally {
            await remove(workingDirectoryPath);
        }
    },

    async makeArchiveFromPath(path: string): Promise<Buffer> {
        const workingDirectoryPath = join(tmpdir(), getRandomString());
        const tarArchivePath = join(workingDirectoryPath, "archive.tar.gz");
        try {
            await mkdirp(workingDirectoryPath);
            await createTar(
                {
                    cwd: path,
                    file: tarArchivePath,
                    gzip: true,
                    portable: true,
                },
                ["."]
            );
            return await readFile(tarArchivePath);
        } catch (err) {
            throw new ArchiveCreationError();
        } finally {
            await remove(workingDirectoryPath);
        }
    },
};
export default tarArchiver;
