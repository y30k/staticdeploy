import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface IFsTreeDefinition {
    [key: string]: string | Buffer | IFsTreeDefinition;
}

export function createTree(root: string, definition: IFsTreeDefinition): void {
    rmSync(root, { force: true, recursive: true });
    mkdirSync(root, { recursive: true });
    for (const [name, value] of Object.entries(definition)) {
        const target = join(root, name);
        if (typeof value === "string" || Buffer.isBuffer(value)) {
            mkdirSync(dirname(target), { recursive: true });
            writeFileSync(target, value);
        } else {
            createTree(target, value);
        }
    }
}

export function destroyTree(root: string): void {
    rmSync(root, { force: true, recursive: true });
}
