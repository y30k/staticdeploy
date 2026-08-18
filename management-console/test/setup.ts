import { cleanup } from "@testing-library/react";
import chai from "chai";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import sinonChai from "sinon-chai";
import { afterEach } from "vitest";

// Match the production date formatting setup.
dayjs.extend(relativeTime);

// Ant Design uses these browser APIs in components and responsive hooks.
globalThis.matchMedia ??= (() => ({
    matches: false,
    media: "",
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
})) as typeof globalThis.matchMedia;
globalThis.ResizeObserver ??= class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
};
globalThis.requestAnimationFrame ??= (callback) =>
    setTimeout(callback, 0) as unknown as number;
globalThis.cancelAnimationFrame ??= (handle) => clearTimeout(handle);

chai.use(sinonChai);
afterEach(() => cleanup());
