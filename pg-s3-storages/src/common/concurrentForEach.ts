// Statically set the concurrency level to a value which should be good for all
// of our use cases
const CONCURRENCY = 5;

// Run the iterator for side effects with a bounded number of native Promise
// workers. Stop assigning work after the first rejection while allowing work
// already in flight to settle normally.
export default async function concurrentForEach<T>(
    array: T[],
    iterator: (arrayElement: T, arrayElementIndex: number) => Promise<any>
): Promise<void> {
    let nextIndex = 0;
    let rejected = false;

    const worker = async () => {
        while (!rejected) {
            const index = nextIndex++;
            if (index >= array.length) {
                return;
            }
            try {
                await iterator(array[index], index);
            } catch (err) {
                rejected = true;
                throw err;
            }
        }
    };

    const workerCount = Math.min(CONCURRENCY, array.length);
    await Promise.all(Array.from({ length: workerCount }, worker));
}
