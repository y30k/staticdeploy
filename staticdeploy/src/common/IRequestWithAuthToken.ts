import {
    IV2RequestPrincipal,
    ReplaceV2Bindings,
    V2Authorizer,
} from "@staticdeploy/core";
import { IBaseRequest } from "@staticdeploy/http-adapters";

export default interface IRequestWithAuthToken extends IBaseRequest {
    authToken: string | null;
    v2Principal?: IV2RequestPrincipal;
    /** Internal factories only; M4 owns the public authorization routes. */
    makeV2Authorizer?: () => V2Authorizer;
    makeReplaceV2Bindings?: () => ReplaceV2Bindings;
}
