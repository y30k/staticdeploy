export const V2_CAPABILITIES = [
    "APPLICATION_CREATE",
    "APPLICATION_READ",
    "APPLICATION_UPDATE",
    "APPLICATION_ARCHIVE",
    "BINDINGS_READ",
    "BINDINGS_REPLACE",
    "RELEASE_READ",
    "RELEASE_CREATE",
    "RELEASE_PROCESS",
    "PREVIEW",
    "PUBLISH",
    "RESTORE",
    "UNPUBLISH",
    "AUDIT_READ",
    "SOURCE_DOWNLOAD",
] as const;

export type V2Capability = (typeof V2_CAPABILITIES)[number];
export type V2EffectiveRole =
    | "ADMINISTRATOR"
    | "OWNER"
    | "PUBLISHER"
    | "VIEWER"
    | "DENIED";

/** The single generated registry consumed by every v2 policy test and adapter. */
export const V2_ROLE_CAPABILITIES: Readonly<
    Record<V2EffectiveRole, readonly V2Capability[]>
> = Object.freeze({
    ADMINISTRATOR: V2_CAPABILITIES,
    OWNER: V2_CAPABILITIES.filter(
        (capability) =>
            capability !== "APPLICATION_CREATE" &&
            capability !== "APPLICATION_ARCHIVE"
    ),
    PUBLISHER: [
        "APPLICATION_READ",
        "RELEASE_READ",
        "RELEASE_CREATE",
        "RELEASE_PROCESS",
        "PREVIEW",
        "PUBLISH",
        "RESTORE",
        "UNPUBLISH",
        "AUDIT_READ",
        "SOURCE_DOWNLOAD",
    ],
    VIEWER: [
        "APPLICATION_READ",
        "RELEASE_READ",
        "PREVIEW",
        "AUDIT_READ",
        "SOURCE_DOWNLOAD",
    ],
    DENIED: [],
});

export interface IV2RequestPrincipal {
    sessionId: string;
    subjectId: string;
    issuer: string;
    groups: string[];
    claimsVersion: number;
}
