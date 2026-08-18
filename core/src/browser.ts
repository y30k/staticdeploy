import isFQDN from "validator/lib/isFQDN";

export type { IApp } from "./entities/App";
export type { IAsset } from "./entities/Asset";
export type { IBundle } from "./entities/Bundle";
export type { IConfiguration } from "./entities/Configuration";
export type { IEntrypoint } from "./entities/Entrypoint";
export type { IGroup } from "./entities/Group";
export { Operation } from "./entities/OperationLog";
export type { IOperationLog } from "./entities/OperationLog";
export { UserType } from "./entities/User";
export type { IUser, IUserWithGroups } from "./entities/User";

const basicChars = /^[\w./-]{1,255}$/;
const roleNames = new Set([
    "root",
    "app-manager",
    "entrypoint-manager",
    "bundle-manager",
]);

export function isAppNameValid(name: string): boolean {
    return basicChars.test(name);
}

export function isRoleValid(role: string): boolean {
    const [name, ...targets] = role.split(":");
    return (
        roleNames.has(name) &&
        (name === "root" ? targets.length === 0 : targets.length === 1)
    );
}

function normalizePosixPath(path: string) {
    const normalizedSegments: string[] = [];
    for (const segment of path.split("/")) {
        if (!segment || segment === ".") continue;
        if (segment === "..") normalizedSegments.pop();
        else normalizedSegments.push(segment);
    }
    const normalized = `/${normalizedSegments.join("/")}`;
    return path.endsWith("/") && normalized !== "/"
        ? `${normalized}/`
        : normalized;
}

export function isEntrypointUrlMatcherValid(urlMatcher: string): boolean {
    const firstSlash = urlMatcher.indexOf("/");
    if (firstSlash === -1) return false;
    const domain = urlMatcher.slice(0, firstSlash);
    const path = urlMatcher.slice(firstSlash);
    return (
        isFQDN(domain, { allow_trailing_dot: false }) &&
        path.startsWith("/") &&
        path.endsWith("/") &&
        normalizePosixPath(path) === path
    );
}
