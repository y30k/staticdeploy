import {
    IV2BindingReplacementResult,
    IV2DesiredBinding,
} from "../dependencies/IV2AuthorizationStorage";
import V2Authorizer from "../services/V2Authorizer";

/** Internal M3 use case; HTTP exposure is deliberately deferred to M4-03. */
export default class ReplaceV2Bindings {
    constructor(private readonly authorizer: V2Authorizer) {}

    exec(input: {
        applicationId: string;
        expectedVersion: number;
        idempotencyKey: string;
        bindings: IV2DesiredBinding[];
    }): Promise<IV2BindingReplacementResult> {
        return this.authorizer.replaceBindings(input);
    }
}
