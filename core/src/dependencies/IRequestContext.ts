import { IV2RequestPrincipal } from "../entities/V2Authorization";

export default interface IRequestContext {
    authToken: string | null;
    /** Validated server-side principal; never reconstructed from browser data. */
    v2Principal?: IV2RequestPrincipal;
}
