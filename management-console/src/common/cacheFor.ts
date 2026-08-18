type AnyFunction = (this: any, ...args: any[]) => any;

export default function cacheFor<F extends AnyFunction>(fn: F, ttl: number): F {
    let lastInvokedAt: number | null;
    let lastReturnValue: ReturnType<F>;
    return function (
        this: ThisParameterType<F>,
        ...args: Parameters<F>
    ): ReturnType<F> {
        const now = Date.now();
        if (!lastInvokedAt || now > lastInvokedAt + ttl) {
            lastInvokedAt = now;
            lastReturnValue = fn.apply(this, args);
            return lastReturnValue;
        }
        return lastReturnValue;
    } as F;
}
