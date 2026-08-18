import { GenericStoragesError } from "@staticdeploy/core";
import { isFunction, keys } from "lodash";

type AnyMethod = (this: any, ...args: any[]) => any;
type Constructor = new (...args: any[]) => any;

function withErrorsConverter(method: AnyMethod): AnyMethod {
    return function errorsConverter(this: any, ...args: any[]) {
        try {
            return method.apply(this, args);
        } catch (err) {
            throw new GenericStoragesError(err);
        }
    };
}

// Given a class, wraps all of its methods so that - when they throw an error -
// the error is converted into a GenericStoragesError
export default function convertErrors(constructor: Constructor) {
    const prototype = constructor.prototype as Record<string, AnyMethod>;
    keys(prototype).forEach((key) => {
        const method = prototype[key];
        if (isFunction(method)) {
            prototype[key] = withErrorsConverter(method);
        }
    });
}
