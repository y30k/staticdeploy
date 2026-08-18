import { clone, isFunction, keys } from "lodash";

type AnyMethod = (this: any, ...args: any[]) => any;
type Constructor = new (...args: any[]) => any;

function wrap(method: AnyMethod): AnyMethod {
    return function cloneMethodIO(this: any, ...args: any[]) {
        return clone(method.apply(this, clone(args)));
    };
}

// Given a class, wraps all of its methods so that:
// - their arguments are cloned before being passed to the function
// - their return values are cloned before being returned to the caller
// Doing this, we safeguard against the values used by the methods being
// modified from outside the class
export default function cloneMethodsIO(constructor: Constructor) {
    const prototype = constructor.prototype as Record<string, AnyMethod>;
    keys(prototype).forEach((key) => {
        const method = prototype[key];
        if (isFunction(method)) {
            prototype[key] = wrap(method);
        }
    });
}
