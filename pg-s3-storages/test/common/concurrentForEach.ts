import { expect } from "chai";

import concurrentForEach from "../../src/common/concurrentForEach";

describe("concurrentForEach", () => {
    it("runs concurrently without exceeding the configured limit", async () => {
        let active = 0;
        let maximumActive = 0;
        const visitedIndexes: number[] = [];

        await concurrentForEach(
            Array.from({ length: 12 }),
            async (_, index) => {
                active += 1;
                maximumActive = Math.max(maximumActive, active);
                visitedIndexes.push(index);
                await new Promise((resolve) => setTimeout(resolve, 1));
                active -= 1;
            }
        );

        expect(maximumActive).to.equal(5);
        expect(
            visitedIndexes.sort((left, right) => left - right)
        ).to.deep.equal(Array.from({ length: 12 }, (_, index) => index));
    });

    it("rejects and stops assigning queued work after an iterator failure", async () => {
        const expectedError = new Error("iterator failed");
        let releaseInFlight!: () => void;
        const inFlight = new Promise<void>((resolve) => {
            releaseInFlight = resolve;
        });
        const startedIndexes: number[] = [];

        let actualError: unknown;
        try {
            await concurrentForEach(
                Array.from({ length: 10 }),
                async (_, index) => {
                    startedIndexes.push(index);
                    if (index === 0) {
                        throw expectedError;
                    }
                    await inFlight;
                }
            );
        } catch (err) {
            actualError = err;
        } finally {
            releaseInFlight();
        }

        expect(actualError).to.equal(expectedError);
        expect(startedIndexes).to.deep.equal([0, 1, 2, 3, 4]);
    });
});
