import isFQDN from "validator/lib/isFQDN";

const unsafePathEncoding = /%(?:2e|2f|5c)/i;
const unsafePathCharacter = /[\\?#]/;

const hasControlCharacter = (value: string): boolean =>
    Array.from(value).some((character) => {
        const codePoint = character.codePointAt(0) ?? 0;
        return codePoint <= 0x1f || codePoint === 0x7f;
    });

function normalizePosixPath(path: string): string {
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

export default function isEntrypointUrlMatcherValid(
    urlMatcher: string
): boolean {
    const firstSlash = urlMatcher.indexOf("/");
    if (firstSlash === -1) return false;
    const domain = urlMatcher.slice(0, firstSlash);
    const path = urlMatcher.slice(firstSlash);
    return (
        isFQDN(domain, { allow_trailing_dot: false }) &&
        path.startsWith("/") &&
        path.endsWith("/") &&
        !unsafePathCharacter.test(path) &&
        !unsafePathEncoding.test(path) &&
        !hasControlCharacter(path) &&
        normalizePosixPath(path) === path
    );
}
