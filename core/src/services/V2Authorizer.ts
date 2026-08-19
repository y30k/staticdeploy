import IV2AuthorizationStorage, {
    IV2AuthorizationDecision,
    IV2BindingReplacementResult,
    IV2DesiredBinding,
} from "../dependencies/IV2AuthorizationStorage";
import { IV2RequestPrincipal, V2Capability } from "../entities/V2Authorization";

/** Authorizes only from the structured, already validated server principal. */
export default class V2Authorizer {
    constructor(
        private readonly storage: IV2AuthorizationStorage,
        private readonly principal: IV2RequestPrincipal | undefined
    ) {}

    private actor(): IV2RequestPrincipal {
        if (this.principal === undefined)
            throw new Error("v2 server principal is required");
        return this.principal;
    }

    authorize(
        applicationId: string,
        capability: V2Capability
    ): Promise<IV2AuthorizationDecision> {
        return this.storage.authorize(this.actor(), applicationId, capability);
    }

    authorizeApplicationCreate(): Promise<IV2AuthorizationDecision> {
        return this.storage.authorizeApplicationCreate(this.actor());
    }

    replaceBindings(input: {
        applicationId: string;
        expectedVersion: number;
        idempotencyKey: string;
        bindings: IV2DesiredBinding[];
    }): Promise<IV2BindingReplacementResult> {
        return this.storage.replaceBindings({
            actor: this.actor(),
            ...input,
        });
    }
}
