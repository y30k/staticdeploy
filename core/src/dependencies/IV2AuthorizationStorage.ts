import {
    IV2RequestPrincipal,
    V2Capability,
    V2EffectiveRole,
} from "../entities/V2Authorization";

export interface IV2AuthorizationDecision {
    allowed: boolean;
    effectiveRole: V2EffectiveRole;
    source: string;
    bindingVersion: number | null;
}

export interface IV2DesiredBinding {
    groupId: string;
    role: "OWNER" | "PUBLISHER" | "VIEWER";
}

export interface IV2BindingReplacementResult {
    outcome: "APPLIED" | "DENIED" | "VERSION_CONFLICT";
    resultingVersion: number | null;
    resultDigest: string | null;
    effectiveRole: V2EffectiveRole;
    source: string;
}

export default interface IV2AuthorizationStorage {
    authorize(
        actor: IV2RequestPrincipal,
        applicationId: string,
        capability: V2Capability
    ): Promise<IV2AuthorizationDecision>;
    authorizeApplicationCreate(
        actor: IV2RequestPrincipal
    ): Promise<IV2AuthorizationDecision>;
    replaceBindings(input: {
        actor: IV2RequestPrincipal;
        applicationId: string;
        expectedVersion: number;
        idempotencyKey: string;
        bindings: IV2DesiredBinding[];
    }): Promise<IV2BindingReplacementResult>;
}
